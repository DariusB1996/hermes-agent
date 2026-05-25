"""Protected-skill governance helpers.

Hermes ships bundled/default skills and can install Hub skills into profile skill
roots. Those upstream-managed skills are runtime inputs, not an agent-owned
write surface. This module centralises provenance checks so tool paths can block
silent edits, deletes, overwrites, and local shadows consistently.

This is defense-in-depth for agent tools, not an OS security boundary: a process
running as the same user can still mutate files outside Hermes' tool layer.
"""
from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


_WRITE_COMMAND_RE = re.compile(
    r"(?:^|[;&|\n]\s*)(?:rm|rmdir|mv|cp|install|rsync|touch|truncate|tee|chmod|chown|python|python3|perl|ruby|node|bash|sh)\b|(?:^|[^<])>{1,2}",
    re.IGNORECASE,
)
_REDIRECT_RE = re.compile(r"(?:>>?|2>|&>)\s*([^\s;&|]+)")
_V4A_FILE_RE = re.compile(r"^\*\*\*\s+(?:Update|Add|Delete)\s+File:\s*(.+)$", re.MULTILINE)
_SKILL_NAME_RE = re.compile(r"^name:\s*([^\s#]+)", re.MULTILINE)
_PATH_LITERAL_RE = re.compile(
    r"(?:~|\$HOME|\$\{HOME\}|\$HERMES_HOME|\$\{HERMES_HOME\}|/)[^\s'\"`;|&<>]*"
    r"|(?<![A-Za-z0-9_./-])skills/[^\s'\"`;|&<>]*"
)


@dataclass(frozen=True)
class ProtectedSkillMatch:
    """Details about a protected skill target."""

    name: str
    source: str
    skill_dir: Optional[Path] = None
    skills_root: Optional[Path] = None


def _safe_resolve(path: str | Path) -> Path:
    """Resolve a path without requiring it to exist."""
    expanded = os.path.expandvars(os.path.expanduser(str(path)))
    return Path(expanded).resolve(strict=False)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_excluded(path: Path) -> bool:
    try:
        from agent.skill_utils import is_excluded_skill_path

        return is_excluded_skill_path(path)
    except Exception:
        excluded = {".git", ".github", ".hub", ".venv", "venv", "node_modules", "__pycache__"}
        return any(part in excluded for part in path.parts)


def _skill_name_for_dir(skill_dir: Path) -> str:
    """Return the frontmatter skill name for *skill_dir*, falling back to dirname."""
    skill_md = skill_dir / "SKILL.md"
    try:
        text = skill_md.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return skill_dir.name
    # Keep this parser deliberately small/import-safe. Full YAML parsing would
    # pull optional dependencies into a safety hot path; the required field is a
    # simple scalar in every Hermes SKILL.md.
    match = _SKILL_NAME_RE.search(text[:4096])
    if not match:
        return skill_dir.name
    name = match.group(1).strip().strip("'\"")
    return name or skill_dir.name


def _canonical_source(source: str) -> str:
    if source.startswith("hub"):
        return "hub"
    if source.startswith("bundled") or source == "default":
        return "bundled"
    return source


def _canonical_sources(sources: Iterable[str]) -> list[str]:
    result: list[str] = []
    for source in sources:
        canonical = _canonical_source(source)
        if canonical not in result:
            result.append(canonical)
    return result


def _bundled_skills_dir() -> Path:
    from hermes_constants import get_bundled_skills_dir

    return _safe_resolve(get_bundled_skills_dir(Path(__file__).resolve().parent.parent / "skills"))


def _active_skills_dir() -> Path:
    from hermes_constants import get_skills_dir

    return _safe_resolve(get_skills_dir())


def _hermes_root() -> Path:
    from hermes_constants import get_default_hermes_root

    return _safe_resolve(get_default_hermes_root())


def _dedupe_paths(paths: Iterable[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        try:
            resolved = _safe_resolve(path)
        except Exception:
            continue
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        result.append(resolved)
    return result


def known_skills_roots() -> list[Path]:
    """Return known profile/external/bundled skill roots for path checks."""
    roots: list[Path] = []

    try:
        roots.append(_active_skills_dir())
    except Exception:
        pass

    try:
        root = _hermes_root()
        roots.append(root / "skills")
        profiles = root / "profiles"
        if profiles.is_dir():
            for profile in profiles.iterdir():
                if profile.is_dir():
                    roots.append(profile / "skills")
    except Exception:
        pass

    try:
        from agent.skill_utils import get_all_skills_dirs

        roots.extend(get_all_skills_dirs())
    except Exception:
        pass

    try:
        roots.append(_bundled_skills_dir())
    except Exception:
        pass

    # Longest first so nested external dirs are classified before parents.
    return sorted(_dedupe_paths(roots), key=lambda p: len(str(p)), reverse=True)


def _candidate_skills_roots_for_path(path: Path) -> list[Path]:
    """Known roots plus nearby roots inferred from the target path itself."""
    roots = list(known_skills_roots())
    for candidate in (path, *path.parents):
        try:
            if (
                candidate.name == "skills"
                or (candidate / ".bundled_manifest").exists()
                or (candidate / ".hub" / "lock.json").exists()
            ):
                roots.append(candidate)
        except OSError:
            continue
    return sorted(_dedupe_paths(roots), key=lambda p: len(str(p)), reverse=True)


def _iter_skill_dirs(skills_root: Path) -> Iterable[Path]:
    if not skills_root.is_dir():
        return []
    dirs: list[Path] = []
    try:
        for skill_md in skills_root.rglob("SKILL.md"):
            if _is_excluded(skill_md):
                continue
            dirs.append(skill_md.parent)
    except OSError:
        return []
    return dirs


def bundled_skill_names() -> set[str]:
    """Names shipped with Hermes' bundled skills."""
    try:
        return {_skill_name_for_dir(skill_dir) for skill_dir in _iter_skill_dirs(_bundled_skills_dir())}
    except Exception:
        return set()


def bundled_skill_dirs_by_name() -> dict[str, Path]:
    try:
        return {_skill_name_for_dir(skill_dir): skill_dir for skill_dir in _iter_skill_dirs(_bundled_skills_dir())}
    except Exception:
        return {}


def manifest_skill_names(skills_root: Path) -> set[str]:
    """Names recorded in a profile's bundled-skill manifest."""
    manifest = skills_root / ".bundled_manifest"
    names: set[str] = set()
    try:
        text = manifest.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return names
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        name = line.split(":", 1)[0].strip()
        if name:
            names.add(name)
    return names


def _hub_lock_entries(skills_root: Path) -> list[tuple[str, Optional[Path]]]:
    """Return Hub-installed skill names plus validated install dirs.

    Poisoned lock entries whose install_path resolves outside the skills root are
    ignored for path protection. Name-only entries are still protected by name
    for backward compatibility with older lock shapes.
    """
    root = _safe_resolve(skills_root)
    lock = root / ".hub" / "lock.json"
    try:
        data = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []

    candidates = []
    if isinstance(data, dict):
        for key in ("installed", "skills", "packages"):
            value = data.get(key)
            if isinstance(value, dict):
                candidates.append(value)
        if not candidates:
            candidates.append(data)

    entries: list[tuple[str, Optional[Path]]] = []
    metadata_keys = {"version", "schema", "schema_version", "updated_at", "generated_at", "source", "trust"}
    for candidate in candidates:
        for raw_name, value in candidate.items():
            name = str(raw_name)
            if name in metadata_keys or name.startswith("_"):
                continue
            if not isinstance(value, (dict, str)):
                continue

            install_dir: Optional[Path]
            rel_install = value.get("install_path") if isinstance(value, dict) else None
            if isinstance(rel_install, str) and rel_install.strip():
                resolved_install = _safe_resolve(root / rel_install)
                if not _is_relative_to(resolved_install, root):
                    # Path-traversal poisoning in lock.json must never expand
                    # the protected surface outside the skills root.
                    continue
                install_dir = resolved_install
            else:
                install_dir = _safe_resolve(root / name)

            entries.append((name, install_dir))
    return entries


def hub_lock_skill_names(skills_root: Path) -> set[str]:
    """Names tracked as Hub-installed in a profile's lock file."""
    names: set[str] = set()
    for name, install_dir in _hub_lock_entries(skills_root):
        names.add(name)
        if install_dir is not None:
            names.add(install_dir.name)
    return names


def hub_lock_skill_dirs(skills_root: Path) -> dict[Path, str]:
    """Validated Hub install dirs mapped to lock entry names."""
    result: dict[Path, str] = {}
    for name, install_dir in _hub_lock_entries(skills_root):
        if install_dir is not None:
            result[install_dir] = name
    return result


def protected_sources_for_name(name: str, skills_root: Path | None = None) -> list[str]:
    """Return protected provenance sources for *name* at *skills_root*."""
    sources: list[str] = []
    if name in bundled_skill_names():
        sources.append("bundled")
    if skills_root is not None:
        root = _safe_resolve(skills_root)
        if name in manifest_skill_names(root):
            sources.append("bundled")
        if name in hub_lock_skill_names(root):
            sources.append("hub")
    return _canonical_sources(sources)


def classify_protected_skill_name(name: str, skills_root: Path | None = None) -> Optional[ProtectedSkillMatch]:
    sources = protected_sources_for_name(name, skills_root)
    if not sources:
        return None
    return ProtectedSkillMatch(
        name=name,
        source="+".join(sources),
        skills_root=_safe_resolve(skills_root) if skills_root else None,
    )


def _skill_dir_from_path_under_root(path: Path, skills_root: Path) -> Optional[Path]:
    if not _is_relative_to(path, skills_root):
        return None

    # Existing skill/support file path: walk upward until a SKILL.md-bearing dir.
    candidates = [path]
    candidates.extend(path.parents)
    for candidate in candidates:
        if candidate == skills_root.parent:
            break
        if candidate == skills_root:
            break
        try:
            if (candidate / "SKILL.md").exists():
                return candidate
        except OSError:
            continue

    # New SKILL.md write: infer the skill dir even before it exists.
    try:
        rel = path.relative_to(skills_root)
    except ValueError:
        return None
    if len(rel.parts) >= 2 and rel.parts[-1] == "SKILL.md":
        return skills_root.joinpath(*rel.parts[:-1])

    # New supporting-file write under an existing or about-to-exist protected
    # skill. Covers both <root>/<name>/references/x and
    # <root>/<category>/<name>/references/x.
    allowed_support_dirs = {"references", "templates", "scripts", "assets"}
    parts = rel.parts
    if len(parts) >= 3 and parts[1] in allowed_support_dirs:
        return skills_root / parts[0]
    if len(parts) >= 4 and parts[2] in allowed_support_dirs:
        return skills_root / parts[0] / parts[1]
    return None


def classify_protected_skill_path(path: str | Path) -> Optional[ProtectedSkillMatch]:
    """Classify whether *path* targets a protected skill or its files."""
    resolved = _safe_resolve(path)
    bundled_root = _bundled_skills_dir()

    for skills_root in _candidate_skills_roots_for_path(resolved):
        skill_dir = _skill_dir_from_path_under_root(resolved, skills_root)
        if skill_dir is None:
            continue

        name = _skill_name_for_dir(skill_dir)
        if _is_relative_to(skill_dir, bundled_root):
            return ProtectedSkillMatch(
                name=name,
                source="bundled",
                skill_dir=skill_dir,
                skills_root=skills_root,
            )

        for hub_dir, hub_name in hub_lock_skill_dirs(skills_root).items():
            if skill_dir == hub_dir or _is_relative_to(resolved, hub_dir):
                return ProtectedSkillMatch(
                    name=hub_name or name,
                    source="hub",
                    skill_dir=skill_dir,
                    skills_root=skills_root,
                )

        sources = protected_sources_for_name(name, skills_root)
        if sources:
            return ProtectedSkillMatch(
                name=name,
                source="+".join(sources),
                skill_dir=skill_dir,
                skills_root=skills_root,
            )
    return None


def protected_skill_block_message(match: ProtectedSkillMatch, action: str = "write") -> str:
    location = f" at {match.skill_dir}" if match.skill_dir else ""
    return (
        f"Protected skill blocked: cannot {action} upstream-managed skill "
        f"'{match.name}' (source: {match.source}){location}. "
        "Bundled/default and Hub-installed skills are read-only to agent tools. "
        "Put local or project-specific behavior in a distinct companion/overlay "
        "skill, or use an explicit restore/fork workflow outside normal agent mutation paths."
    )


def protected_skill_name_block_message(name: str, action: str = "create", skills_root: Path | None = None) -> Optional[str]:
    match = classify_protected_skill_name(name, skills_root)
    if match is None:
        return None
    return protected_skill_block_message(match, action=action)


def protected_skill_path_block_message(path: str | Path, action: str = "write") -> Optional[str]:
    match = classify_protected_skill_path(path)
    if match is None:
        return None
    return protected_skill_block_message(match, action=action)


def _skill_name_from_content(content: str) -> Optional[str]:
    match = _SKILL_NAME_RE.search(content[:4096])
    if not match:
        return None
    name = match.group(1).strip().strip("'\"")
    return name or None


def protected_skill_content_block_message(
    path: str | Path,
    content: str,
    action: str = "write",
) -> Optional[str]:
    """Block creating a new SKILL.md whose frontmatter shadows a protected name."""
    name = _skill_name_from_content(content)
    if not name:
        return None

    resolved = _safe_resolve(path)
    if resolved.name != "SKILL.md":
        return None

    for skills_root in _candidate_skills_roots_for_path(resolved):
        try:
            rel = resolved.relative_to(skills_root)
        except ValueError:
            continue
        if len(rel.parts) < 2 or rel.parts[-1] != "SKILL.md":
            continue
        match = classify_protected_skill_name(name, skills_root)
        if match is not None:
            return protected_skill_block_message(match, action=action)
    return None


def _path_tokens(command: str) -> list[str]:
    tokens: list[str] = []
    try:
        tokens.extend(shlex.split(command, posix=True))
    except ValueError:
        tokens.extend(command.split())
    tokens.extend(match.group(1) for match in _REDIRECT_RE.finditer(command))
    tokens.extend(match.group(1).strip() for match in _V4A_FILE_RE.finditer(command))
    tokens.extend(match.group(0) for match in _PATH_LITERAL_RE.finditer(command))
    cleaned: list[str] = []
    for token in tokens:
        value = token.strip().strip("'\"")
        if not value or value.startswith("-"):
            continue
        value = value.rstrip(",;)")
        # Ignore obvious code fragments and flags; keep absolute, home, env, and
        # relative paths that mention skills.
        lowered = value.lower()
        if (
            value.startswith(("/", "~/", "$HOME", "${HOME}", "$HERMES_HOME", "${HERMES_HOME}"))
            or "/skills/" in lowered
            or lowered.startswith("skills/")
        ):
            cleaned.append(value)
    return cleaned


def detect_protected_skill_command(command: str) -> Optional[str]:
    """Best-effort hard block for obvious shell writes/deletes to protected skills."""
    if not command or not _WRITE_COMMAND_RE.search(command):
        return None
    for token in _path_tokens(command):
        message = protected_skill_path_block_message(token, action="modify via terminal command")
        if message:
            return message
    return None


def protected_skill_command_block_result(message: str) -> dict:
    return {
        "approved": False,
        "message": (
            f"BLOCKED: {message} Do NOT retry this command, do NOT rephrase it, "
            "and do NOT attempt the same protected-skill mutation through another tool. "
            "Use an explicit companion/overlay skill or a reviewed restore/fork workflow instead."
        ),
        "protected_skill": True,
        "user_consent": False,
    }
