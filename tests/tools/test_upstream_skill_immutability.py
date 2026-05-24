"""Integration tests for upstream-managed skill immutability guards."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


BUNDLED_SKILL = "kanban-orchestrator"
HUB_SKILL = "community-hub-skill"


def _skill_content(name: str) -> str:
    return (
        f"---\nname: {name}\ndescription: Test skill {name}.\n---\n\n"
        f"# {name}\n\nOriginal upstream content.\n"
    )


def _write_skill(skills_root: Path, rel: str, name: str) -> Path:
    skill_dir = skills_root / rel
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(_skill_content(name), encoding="utf-8")
    return skill_dir


@pytest.fixture
def hermes_skill_guard_home(tmp_path, monkeypatch):
    """Isolated Hermes layout; never writes into the developer's live ~/.hermes."""
    root = tmp_path / "hermes"
    bundled = tmp_path / "bundled-skills"

    _write_skill(bundled, f"devops/{BUNDLED_SKILL}", BUNDLED_SKILL)
    runtime_bundled = _write_skill(root / "skills", f"devops/{BUNDLED_SKILL}", BUNDLED_SKILL)
    profile_bundled = _write_skill(
        root / "profiles" / "reviewer" / "skills",
        f"devops/{BUNDLED_SKILL}",
        BUNDLED_SKILL,
    )
    hub_skill = _write_skill(root / "skills", f"community/{HUB_SKILL}", HUB_SKILL)
    custom_skill = _write_skill(root / "skills", "custom/local-companion-skill", "local-companion-skill")

    (root / "skills" / ".bundled_manifest").write_text(
        f"{BUNDLED_SKILL}:origin-hash\n", encoding="utf-8"
    )
    hub_dir = root / "skills" / ".hub"
    hub_dir.mkdir(parents=True, exist_ok=True)
    (hub_dir / "lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "installed": {
                    HUB_SKILL: {
                        "source": "github",
                        "identifier": "example/repo/path",
                        "trust_level": "trusted",
                        "scan_verdict": "safe",
                        "content_hash": "sha256:test",
                        "install_path": f"community/{HUB_SKILL}",
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

    with patch("agent.skill_utils.get_all_skills_dirs", return_value=[root / "skills"]):
        yield {
            "root": root,
            "bundled": bundled,
            "runtime_bundled": runtime_bundled,
            "profile_bundled": profile_bundled,
            "hub_skill": hub_skill,
            "custom_skill": custom_skill,
        }

    fs._current_bundled_skill_names.cache_clear()


def test_file_safety_classifies_profile_copy_and_hub_skill(hermes_skill_guard_home):
    from agent.file_safety import classify_upstream_managed_skill_target

    profile_info = classify_upstream_managed_skill_target(
        str(hermes_skill_guard_home["profile_bundled"] / "references" / "notes.md")
    )
    hub_info = classify_upstream_managed_skill_target(
        str(hermes_skill_guard_home["hub_skill"] / "templates" / "prompt.md")
    )

    assert profile_info is not None
    assert profile_info["name"] == BUNDLED_SKILL
    assert "bundled" in profile_info["source"]
    assert hub_info is not None
    assert hub_info["name"] == HUB_SKILL
    assert "hub" in hub_info["source"]


def test_write_and_patch_tools_refuse_upstream_skill_before_file_ops(hermes_skill_guard_home):
    from tools.file_tools import patch_tool, write_file_tool

    target = hermes_skill_guard_home["runtime_bundled"] / "SKILL.md"
    with patch("tools.file_tools._get_file_ops") as mock_get:
        write_result = json.loads(write_file_tool(str(target), "changed", cross_profile=True))
        patch_result = json.loads(
            patch_tool(
                mode="replace",
                path=str(target),
                old_string="Original",
                new_string="Changed",
                cross_profile=True,
            )
        )

    assert "Upstream-managed skill write blocked" in write_result["error"]
    assert "Upstream-managed skill write blocked" in patch_result["error"]
    mock_get.assert_not_called()


def test_skill_manage_refuses_bundled_and_hub_shadowing_but_allows_companion(hermes_skill_guard_home):
    from tools.skill_manager_tool import _create_skill

    bundled = _create_skill(BUNDLED_SKILL, _skill_content(BUNDLED_SKILL))
    hub = _create_skill(HUB_SKILL, _skill_content(HUB_SKILL))
    companion = _create_skill("local-new-companion-skill", _skill_content("local-new-companion-skill"))

    assert bundled["success"] is False
    assert "upstream-managed" in bundled["error"].lower() or "reserved" in bundled["error"].lower()
    assert hub["success"] is False
    assert "upstream-managed" in hub["error"].lower() or "hub" in hub["error"].lower()
    assert companion["success"] is True, companion


def test_terminal_approval_guard_blocks_upstream_skill_shell_write_even_in_yolo(
    hermes_skill_guard_home, monkeypatch
):
    from tools.approval import check_all_command_guards

    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    command = f"printf changed > {hermes_skill_guard_home['runtime_bundled'] / 'SKILL.md'}"

    result = check_all_command_guards(command, env_type="local")

    assert result["approved"] is False
    assert result.get("hardline") is True
    assert "Upstream-managed skill mutation blocked" in result["message"]


def test_execute_code_preflight_blocks_direct_upstream_skill_write(hermes_skill_guard_home):
    from tools.code_execution_tool import execute_code

    target = hermes_skill_guard_home["runtime_bundled"] / "SKILL.md"
    code = f"from pathlib import Path\nPath({str(target)!r}).write_text('changed')\n"

    result = json.loads(execute_code(code))

    assert "error" in result
    assert "Upstream-managed skill mutation blocked" in result["error"]


def test_execute_code_preflight_allows_read_only_skill_inspection(hermes_skill_guard_home):
    from tools.code_execution_tool import execute_code

    target = hermes_skill_guard_home["runtime_bundled"] / "SKILL.md"
    code = f"from pathlib import Path\nprint(Path({str(target)!r}).read_text()[:3])\n"
    with patch("tools.code_execution_tool._execute_remote") as mock_remote, \
         patch("tools.terminal_tool._get_env_config", return_value={"env_type": "remote"}):
        mock_remote.return_value = json.dumps({"stdout": "---\n", "stderr": "", "exit_code": 0})
        result = json.loads(execute_code(code))

    assert result["stdout"] == "---\n"
    mock_remote.assert_called_once()
