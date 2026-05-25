"""Tests for shared Hermes file-safety helpers."""

import json

from agent.file_safety import (
    classify_protected_skill_target,
    get_protected_skill_write_error,
    is_write_denied,
)


def _write_skill(skills_root, rel_path, name):
    skill_dir = skills_root / rel_path
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill.\n---\n\n"
        "# Test Skill\n\nBody.\n",
        encoding="utf-8",
    )
    return skill_dir


def test_bundled_manifest_entry_protects_skill_tree(tmp_path):
    skills_root = tmp_path / "skills"
    skill_dir = _write_skill(skills_root, "devops/bundled-dir", "bundled-skill")
    (skills_root / ".bundled_manifest").write_text("bundled-skill:abc123\n", encoding="utf-8")

    target = skill_dir / "references" / "notes.md"
    info = classify_protected_skill_target(str(target))

    assert info is not None
    assert info["source"] == "bundled"
    assert info["skill_name"] == "bundled-skill"
    assert info["skills_root"] == str(skills_root.resolve())
    assert "protected skill" in get_protected_skill_write_error(str(target)).lower()
    assert is_write_denied(str(target)) is True


def test_hub_lock_install_path_protects_skill_tree(tmp_path):
    skills_root = tmp_path / "skills"
    skill_dir = _write_skill(skills_root, "hub-skill", "hub-skill")
    hub_dir = skills_root / ".hub"
    hub_dir.mkdir()
    (hub_dir / "lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "installed": {
                    "hub-skill": {
                        "source": "https://example.invalid/repo.git",
                        "install_path": "hub-skill",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    target = skill_dir / "SKILL.md"
    info = classify_protected_skill_target(str(target))

    assert info is not None
    assert info["source"] == "hub"
    assert info["skill_name"] == "hub-skill"
    assert is_write_denied(str(target)) is True


def test_poisoned_hub_lock_path_outside_skills_root_is_ignored(tmp_path):
    skills_root = tmp_path / "skills"
    skill_dir = _write_skill(skills_root, "local-skill", "local-skill")
    hub_dir = skills_root / ".hub"
    hub_dir.mkdir()
    (hub_dir / "lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "installed": {
                    "evil": {
                        "source": "https://example.invalid/repo.git",
                        "install_path": "../local-skill",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert classify_protected_skill_target(str(skill_dir / "SKILL.md")) is None
    assert is_write_denied(str(skill_dir / "SKILL.md")) is False


def test_untracked_local_skill_is_not_protected(tmp_path):
    skills_root = tmp_path / "skills"
    skill_dir = _write_skill(skills_root, "local-skill", "local-skill")

    assert classify_protected_skill_target(str(skill_dir / "SKILL.md")) is None
    assert get_protected_skill_write_error(str(skill_dir / "SKILL.md")) is None
    assert is_write_denied(str(skill_dir / "SKILL.md")) is False
