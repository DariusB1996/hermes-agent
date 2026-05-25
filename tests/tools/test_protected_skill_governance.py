"""Regression tests for upstream-managed / protected skill governance.

Official bundled/default and Hub-installed skills are upstream artifacts. Agent
mutation paths must block edits/deletes/shadow creation and route local behavior
into distinct companion/overlay skills instead.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.file_safety import is_write_denied
from tools.approval import check_all_command_guards
from tools.file_tools import patch_tool, write_file_tool
from tools.skill_manager_tool import (
    _create_skill,
    _delete_skill,
    _edit_skill,
    _patch_skill,
    _remove_file,
    _write_file,
)


PROTECTED_NAME = "hermes-agent"  # shipped in Hermes' bundled skills set


def _skill_content(name: str = PROTECTED_NAME, marker: str = "ORIGINAL_MARKER") -> str:
    return (
        "---\n"
        f"name: {name}\n"
        "description: Test skill.\n"
        "---\n\n"
        f"# {name}\n\n{marker}\n"
    )


@contextmanager
def _active_skills_root(monkeypatch: pytest.MonkeyPatch, root: Path):
    """Point active Hermes home + skill manager search at a temp skills root."""
    skills_dir = root / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(root))
    with patch("tools.skill_manager_tool.SKILLS_DIR", skills_dir), patch(
        "agent.skill_utils.get_all_skills_dirs", return_value=[skills_dir]
    ):
        yield skills_dir


def _write_skill(skills_dir: Path, name: str = PROTECTED_NAME) -> Path:
    skill_dir = skills_dir / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(_skill_content(name), encoding="utf-8")
    return skill_dir


def _assert_protected_block(result: dict):
    assert result["success"] is False
    assert "protected skill" in result["error"].lower()
    assert "upstream-managed" in result["error"].lower()


class TestSkillManageProtectedSkills:
    def test_create_blocks_shadowing_bundled_skill_name(self, tmp_path, monkeypatch):
        with _active_skills_root(monkeypatch, tmp_path):
            result = _create_skill(PROTECTED_NAME, _skill_content(PROTECTED_NAME))

        _assert_protected_block(result)
        assert not (tmp_path / "skills" / PROTECTED_NAME).exists()

    @pytest.mark.parametrize(
        "operation",
        ["edit", "patch", "delete", "write_file", "remove_file"],
    )
    def test_mutations_block_bundled_skill_copy(self, tmp_path, monkeypatch, operation):
        with _active_skills_root(monkeypatch, tmp_path) as skills_dir:
            skill_dir = _write_skill(skills_dir)
            (skill_dir / "references").mkdir()
            (skill_dir / "references" / "notes.md").write_text("ORIGINAL_MARKER", encoding="utf-8")

            if operation == "edit":
                result = _edit_skill(PROTECTED_NAME, _skill_content(PROTECTED_NAME, "NEW_MARKER"))
            elif operation == "patch":
                result = _patch_skill(PROTECTED_NAME, "ORIGINAL_MARKER", "NEW_MARKER")
            elif operation == "delete":
                result = _delete_skill(PROTECTED_NAME)
            elif operation == "write_file":
                result = _write_file(PROTECTED_NAME, "references/new.md", "NEW_MARKER")
            elif operation == "remove_file":
                result = _remove_file(PROTECTED_NAME, "references/notes.md")
            else:  # pragma: no cover
                raise AssertionError(operation)

        _assert_protected_block(result)
        assert (tmp_path / "skills" / PROTECTED_NAME / "SKILL.md").exists()
        assert "ORIGINAL_MARKER" in (tmp_path / "skills" / PROTECTED_NAME / "SKILL.md").read_text(encoding="utf-8")

    def test_hub_lock_marks_skill_as_protected(self, tmp_path, monkeypatch):
        hub_name = "hub-installed-skill"
        with _active_skills_root(monkeypatch, tmp_path) as skills_dir:
            _write_skill(skills_dir, hub_name)
            lock_dir = skills_dir / ".hub"
            lock_dir.mkdir()
            (lock_dir / "lock.json").write_text(
                json.dumps({"installed": {hub_name: {"content_hash": "abc123"}}}),
                encoding="utf-8",
            )
            result = _patch_skill(hub_name, "ORIGINAL_MARKER", "NEW_MARKER")

        _assert_protected_block(result)
        assert "ORIGINAL_MARKER" in (tmp_path / "skills" / hub_name / "SKILL.md").read_text(encoding="utf-8")


class TestFileToolsProtectedSkills:
    def test_write_denied_for_supporting_file_under_protected_skill(self, tmp_path, monkeypatch):
        with _active_skills_root(monkeypatch, tmp_path) as skills_dir:
            skill_dir = _write_skill(skills_dir)
            target = skill_dir / "references" / "notes.md"
            assert is_write_denied(str(target)) is True

    def test_write_file_tool_blocks_protected_skill_path(self, tmp_path, monkeypatch):
        with _active_skills_root(monkeypatch, tmp_path) as skills_dir:
            skill_dir = _write_skill(skills_dir)
            target = skill_dir / "references" / "notes.md"
            raw = write_file_tool(str(target), "NEW_MARKER")

        result = json.loads(raw)
        assert "error" in result
        assert "protected skill" in result["error"].lower()
        assert not target.exists()

    def test_patch_tool_blocks_before_fuzzy_matching(self, tmp_path, monkeypatch):
        with _active_skills_root(monkeypatch, tmp_path) as skills_dir:
            skill_dir = _write_skill(skills_dir)
            target = skill_dir / "SKILL.md"
            raw = patch_tool(path=str(target), old_string="DOES_NOT_EXIST", new_string="NEW_MARKER")

        result = json.loads(raw)
        assert "error" in result
        assert "protected skill" in result["error"].lower()
        assert "old_string not found" not in result["error"].lower()


class TestTerminalProtectedSkillGuard:
    def test_obvious_delete_command_is_hard_blocked_even_without_interactive_approval(self, tmp_path, monkeypatch):
        with _active_skills_root(monkeypatch, tmp_path) as skills_dir:
            skill_dir = _write_skill(skills_dir)
            decision = check_all_command_guards(f"rm -rf {skill_dir}", env_type="local")

        assert decision["approved"] is False
        assert "protected skill" in decision["message"].lower()
        assert "do not retry" in decision["message"].lower()

    def test_embedded_python_write_command_is_hard_blocked(self, tmp_path, monkeypatch):
        with _active_skills_root(monkeypatch, tmp_path) as skills_dir:
            skill_dir = _write_skill(skills_dir)
            target = skill_dir / "SKILL.md"
            command = f"python3 -c \"open('{target}','w').write('MUTATED')\""
            decision = check_all_command_guards(command, env_type="local")

        assert decision["approved"] is False
        assert "protected skill" in decision["message"].lower()
        assert "do not retry" in decision["message"].lower()
        assert "ORIGINAL_MARKER" in target.read_text(encoding="utf-8")
