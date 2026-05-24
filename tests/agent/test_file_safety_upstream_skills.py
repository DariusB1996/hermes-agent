"""Regression tests for upstream-managed skill immutability guardrails."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest


SKILL_TEMPLATE = """---
name: {name}
description: Test skill {name}.
---

# {name}

Test body.
"""


def _write_skill(skills_root: Path, rel: str, name: str) -> Path:
    skill_dir = skills_root / rel
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(SKILL_TEMPLATE.format(name=name), encoding="utf-8")
    return skill_dir


@pytest.fixture
def upstream_skill_layout(tmp_path, monkeypatch):
    """Fake Hermes layout with bundled, hub-installed, custom, and profile-copy skills."""
    root = tmp_path / "hermes"
    bundled = tmp_path / "bundled-skills"

    bundled_skill = _write_skill(bundled, "devops/hermes-agent", "hermes-agent")
    runtime_bundled = _write_skill(root / "skills", "devops/hermes-agent", "hermes-agent")
    profile_bundled = _write_skill(
        root / "profiles" / "reviewer" / "skills",
        "devops/hermes-agent",
        "hermes-agent",
    )
    hub_skill = _write_skill(root / "skills", "community/hub-skill", "hub-skill")
    custom_skill = _write_skill(root / "skills", "custom/local-skill", "local-skill")

    (root / "skills" / ".bundled_manifest").write_text("hermes-agent:origin-hash\n", encoding="utf-8")
    hub_dir = root / "skills" / ".hub"
    hub_dir.mkdir(parents=True, exist_ok=True)
    (hub_dir / "lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "installed": {
                    "hub-skill": {
                        "source": "github",
                        "identifier": "example/repo/path",
                        "trust_level": "trusted",
                        "scan_verdict": "safe",
                        "content_hash": "sha256:test",
                        "install_path": "community/hub-skill",
                        "files": ["SKILL.md"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setenv("HERMES_BUNDLED_SKILLS", str(bundled))

    import agent.file_safety as fs

    monkeypatch.setattr(fs, "_hermes_home_path", lambda: root)
    monkeypatch.setattr(fs, "_hermes_root_path", lambda: root)
    fs._current_bundled_skill_names.cache_clear()

    import tools.skill_manager_tool as sm

    monkeypatch.setattr(sm, "HERMES_HOME", root)
    monkeypatch.setattr(sm, "SKILLS_DIR", root / "skills")

    yield {
        "root": root,
        "bundled": bundled,
        "bundled_skill": bundled_skill,
        "runtime_bundled": runtime_bundled,
        "profile_bundled": profile_bundled,
        "hub_skill": hub_skill,
        "custom_skill": custom_skill,
    }

    fs._current_bundled_skill_names.cache_clear()


class TestUpstreamManagedSkillClassification:
    def test_bundled_runtime_skill_is_classified(self, upstream_skill_layout):
        from agent.file_safety import classify_upstream_managed_skill_target

        info = classify_upstream_managed_skill_target(
            str(upstream_skill_layout["runtime_bundled"] / "SKILL.md")
        )

        assert info is not None
        assert info["name"] == "hermes-agent"
        assert "bundled" in info["source"]

    def test_bundled_profile_copy_is_classified(self, upstream_skill_layout):
        from agent.file_safety import classify_upstream_managed_skill_target

        info = classify_upstream_managed_skill_target(
            str(upstream_skill_layout["profile_bundled"] / "references" / "notes.md")
        )

        assert info is not None
        assert info["name"] == "hermes-agent"
        assert "bundled" in info["source"]

    def test_hub_installed_skill_path_is_classified(self, upstream_skill_layout):
        from agent.file_safety import classify_upstream_managed_skill_target

        info = classify_upstream_managed_skill_target(
            str(upstream_skill_layout["hub_skill"] / "templates" / "prompt.md")
        )

        assert info is not None
        assert info["name"] == "hub-skill"
        assert "hub" in info["source"]

    def test_hub_installed_skill_name_is_reserved_even_when_directory_missing(self, upstream_skill_layout):
        from agent.file_safety import is_upstream_managed_skill_name

        shutil.rmtree(upstream_skill_layout["hub_skill"])

        assert is_upstream_managed_skill_name("hub-skill") is True


class TestUpstreamManagedSkillCommandGuard:
    def test_blocks_shell_write_to_specific_protected_skill(self, upstream_skill_layout):
        from agent.file_safety import get_upstream_managed_skill_command_error

        command = (
            "python -c \"from pathlib import Path; "
            "Path('$HERMES_HOME/skills/devops/hermes-agent/SKILL.md').write_text('x')\""
        )

        err = get_upstream_managed_skill_command_error(command)

        assert err is not None
        assert "Upstream-managed skill mutation blocked" in err
        assert "hermes-agent" in err

    def test_allows_shell_write_to_custom_skill_under_skills_root(self, upstream_skill_layout):
        from agent.file_safety import get_upstream_managed_skill_command_error

        command = "mkdir -p $HERMES_HOME/skills/custom/new-skill && touch $HERMES_HOME/skills/custom/new-skill/SKILL.md"

        assert get_upstream_managed_skill_command_error(command) is None


class TestUpstreamManagedSkillToolGuards:
    def test_write_file_tool_blocks_bundled_skill_even_with_cross_profile_bypass(self, upstream_skill_layout):
        from tools.file_tools import write_file_tool

        target = upstream_skill_layout["runtime_bundled"] / "SKILL.md"
        original = target.read_text(encoding="utf-8")

        result = json.loads(write_file_tool(str(target), "changed", cross_profile=True))

        assert result.get("success") is False or "error" in result
        assert "Upstream-managed skill write blocked" in result["error"]
        assert target.read_text(encoding="utf-8") == original

    def test_skill_manage_create_refuses_hub_skill_shadow_even_when_directory_missing(self, upstream_skill_layout):
        from tools.skill_manager_tool import skill_manage

        shutil.rmtree(upstream_skill_layout["hub_skill"])

        result = json.loads(
            skill_manage(
                action="create",
                name="hub-skill",
                content=SKILL_TEMPLATE.format(name="hub-skill"),
            )
        )

        assert result["success"] is False
        assert "upstream-managed" in result["error"].lower() or "hub" in result["error"].lower()
        assert not (upstream_skill_layout["root"] / "skills" / "hub-skill").exists()
