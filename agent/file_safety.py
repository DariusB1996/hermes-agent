"""Shared file safety rules used by both tools and ACP shims."""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional


def _hermes_home_path() -> Path:
    """Resolve the active HERMES_HOME (profile-aware) without circular imports."""
    try:
        from hermes_constants import get_hermes_home  # local import to avoid cycles
        return get_hermes_home()
    except Exception:
        return Path(os.path.expanduser("~/.hermes"))


def _hermes_root_path() -> Path:
    """Resolve the Hermes root dir (always the parent of any profile, never per-profile)."""
    try:
        from hermes_constants import get_default_hermes_root  # local import to avoid cycles
        return get_default_hermes_root()
    except Exception:
        return Path(os.path.expanduser("~/.hermes"))


def build_write_denied_paths(home: str) -> set[str]:
    """Return exact sensitive paths that must never be written."""
    hermes_home = _hermes_home_path()
    hermes_root = _hermes_root_path()
    return {
        os.path.realpath(p)
        for p in [
            os.path.join(home, ".ssh", "authorized_keys"),
            os.path.join(home, ".ssh", "id_rsa"),
            os.path.join(home, ".ssh", "id_ed25519"),
            os.path.join(home, ".ssh", "config"),
            # Active profile .env (or top-level .env when not in profile mode).
            str(hermes_home / ".env"),
            # Top-level .env, even when running under a profile — overwriting it
            # leaks credentials across every profile that inherits from root (#15981).
            str(hermes_root / ".env"),
            os.path.join(home, ".bashrc"),
            os.path.join(home, ".zshrc"),
            os.path.join(home, ".profile"),
            os.path.join(home, ".bash_profile"),
            os.path.join(home, ".zprofile"),
            os.path.join(home, ".netrc"),
            os.path.join(home, ".pgpass"),
            os.path.join(home, ".npmrc"),
            os.path.join(home, ".pypirc"),
            "/etc/sudoers",
            "/etc/passwd",
            "/etc/shadow",
        ]
    }


def build_write_denied_prefixes(home: str) -> list[str]:
    """Return sensitive directory prefixes that must never be written."""
    return [
        os.path.realpath(p) + os.sep
        for p in [
            os.path.join(home, ".ssh"),
            os.path.join(home, ".aws"),
            os.path.join(home, ".gnupg"),
            os.path.join(home, ".kube"),
            "/etc/sudoers.d",
            "/etc/systemd",
            os.path.join(home, ".docker"),
            os.path.join(home, ".azure"),
            os.path.join(home, ".config", "gh"),
        ]
    ]


def get_safe_write_root() -> Optional[str]:
    """Return the resolved HERMES_WRITE_SAFE_ROOT path, or None if unset."""
    root = os.getenv("HERMES_WRITE_SAFE_ROOT", "")
    if not root:
        return None
    try:
        return os.path.realpath(os.path.expanduser(root))
    except Exception:
        return None


def is_write_denied(path: str) -> bool:
    """Return True if path is blocked by the write denylist or safe root."""
    home = os.path.realpath(os.path.expanduser("~"))
    resolved = os.path.realpath(os.path.expanduser(str(path)))

    if resolved in build_write_denied_paths(home):
        return True
    for prefix in build_write_denied_prefixes(home):
        if resolved.startswith(prefix):
            return True

    # Hermes control-plane files: block both the ACTIVE profile's view
    # (hermes_home) AND the global root view. Without the root pass, a
    # profile-mode session leaves <root>/auth.json + <root>/config.yaml
    # writable — letting a prompt-injected write_file overwrite the global
    # files that every profile inherits from (same shape as #15981).
    control_file_names = ("auth.json", "config.yaml", "webhook_subscriptions.json")
    mcp_tokens_dir_name = "mcp-tokens"

    hermes_dirs = []
    for base in (_hermes_home_path(), _hermes_root_path()):
        try:
            real = os.path.realpath(base)
            if real not in hermes_dirs:
                hermes_dirs.append(real)
        except Exception:
            continue

    for base_real in hermes_dirs:
        for name in control_file_names:
            try:
                if resolved == os.path.realpath(os.path.join(base_real, name)):
                    return True
            except Exception:
                continue
        try:
            mcp_real = os.path.realpath(os.path.join(base_real, mcp_tokens_dir_name))
            if resolved == mcp_real or resolved.startswith(mcp_real + os.sep):
                return True
        except Exception:
            pass

    safe_root = get_safe_write_root()
    if safe_root and not (resolved == safe_root or resolved.startswith(safe_root + os.sep)):
        return True

    return False


# ---------------------------------------------------------------------------
# Upstream-managed skill immutability
#
# Bundled/default and Skills Hub-installed skills are upstream artifacts. They
# are synced/reset by Hermes maintenance commands, not edited by agents. This
# guard is intentionally hard for file tools and skill_manage: cross_profile=True
# does not bypass it. Runtime shell access is still not a security boundary, but
# every native Hermes write path must refuse these targets.
# ---------------------------------------------------------------------------

_EXCLUDED_SKILL_PATH_PARTS = frozenset(
    (
        ".git",
        ".github",
        ".hub",
        ".archive",
        ".venv",
        "venv",
        "node_modules",
        "site-packages",
        "__pycache__",
        ".tox",
        ".nox",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    )
)


def _skill_path_excluded(path: Path) -> bool:
    return any(part in _EXCLUDED_SKILL_PATH_PARTS for part in path.parts)


def _read_skill_name_from_md(skill_md: Path, fallback: str) -> str:
    """Read a skill name from SKILL.md frontmatter with a safe fallback."""
    try:
        content = skill_md.read_text(encoding="utf-8", errors="replace")[:4000]
    except OSError:
        return fallback
    in_frontmatter = False
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped == "---":
            if in_frontmatter:
                break
            in_frontmatter = True
            continue
        if in_frontmatter and stripped.startswith("name:"):
            value = stripped.split(":", 1)[1].strip().strip("\"'")
            if value:
                return value
    return fallback


@lru_cache(maxsize=1)
def _current_bundled_skill_names() -> frozenset[str]:
    """Return names currently shipped as bundled Hermes skills."""
    try:
        from hermes_constants import get_bundled_skills_dir
        default = Path(__file__).resolve().parent.parent / "skills"
        bundled_dir = get_bundled_skills_dir(default)
    except Exception:
        return frozenset()
    names: set[str] = set()
    try:
        for skill_md in bundled_dir.rglob("SKILL.md"):
            if _skill_path_excluded(skill_md):
                continue
            names.add(_read_skill_name_from_md(skill_md, fallback=skill_md.parent.name))
    except OSError:
        return frozenset(names)
    return frozenset(names)


def _upstream_managed_skill_names() -> set[str]:
    """Return skill names reserved by bundled/default manifests or Hub locks.

    This intentionally looks at every runtime/profile skills root, not just the
    current bundled source tree. Hub-installed skills can be deleted from disk
    while still being present in ``.hub/lock.json``; their names must remain
    reserved so agents cannot silently recreate/shadow them as local skills.
    """
    names: set[str] = set(_current_bundled_skill_names())
    for skills_root, _root_type in _skill_roots_for_immutability_guard():
        names.update(_read_bundled_manifest_names(skills_root))
        hub_names, _hub_paths = _read_hub_installed(skills_root)
        names.update(hub_names)
    return names


def is_upstream_managed_skill_name(name: str) -> bool:
    """True when *name* is reserved by a bundled/default or Hub skill."""
    return bool(name) and name in _upstream_managed_skill_names()


def _read_bundled_manifest_names(skills_root: Path) -> set[str]:
    manifest = skills_root / ".bundled_manifest"
    if not manifest.exists():
        return set()
    names: set[str] = set()
    try:
        for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            name = line.split(":", 1)[0].strip()
            if name:
                names.add(name)
    except OSError:
        pass
    return names


def _read_hub_installed(skills_root: Path) -> tuple[set[str], set[Path]]:
    lock_path = skills_root / ".hub" / "lock.json"
    if not lock_path.exists():
        return set(), set()
    names: set[str] = set()
    paths: set[Path] = set()
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return names, paths
    installed = data.get("installed") if isinstance(data, dict) else None
    if not isinstance(installed, dict):
        return names, paths
    for key, entry in installed.items():
        if key:
            names.add(str(key))
        if not isinstance(entry, dict):
            continue
        install_path = entry.get("install_path")
        if not isinstance(install_path, str) or not install_path.strip():
            continue
        skill_dir = Path(install_path)
        if not skill_dir.is_absolute():
            skill_dir = skills_root / skill_dir
        try:
            resolved = skill_dir.resolve()
            resolved.relative_to(skills_root.resolve())
        except (OSError, RuntimeError, ValueError):
            continue
        paths.add(resolved)
        skill_md = resolved / "SKILL.md"
        if skill_md.exists():
            names.add(_read_skill_name_from_md(skill_md, fallback=resolved.name))
    return names, paths


def _bundled_source_root() -> Optional[Path]:
    try:
        from hermes_constants import get_bundled_skills_dir
        default = Path(__file__).resolve().parent.parent / "skills"
        return get_bundled_skills_dir(default).resolve()
    except Exception:
        return None


def _skill_roots_for_immutability_guard() -> list[tuple[Path, str]]:
    """Return runtime/profile skill roots plus the bundled source tree."""
    roots: list[tuple[Path, str]] = []
    seen: set[Path] = set()

    def add(path: Path, root_type: str) -> None:
        try:
            real = path.resolve()
        except (OSError, RuntimeError):
            real = path
        if real in seen:
            return
        seen.add(real)
        roots.append((real, root_type))

    for base in (_hermes_home_path(), _hermes_root_path()):
        add(base / "skills", "runtime")

    profiles_dir = _hermes_root_path() / "profiles"
    if profiles_dir.is_dir():
        try:
            for entry in profiles_dir.iterdir():
                if entry.is_dir():
                    add(entry / "skills", "runtime")
        except OSError:
            pass

    bundled = _bundled_source_root()
    if bundled is not None:
        add(bundled, "bundled-source")
    return roots


def _candidate_skill_dir_for_path(target: Path, skills_root: Path) -> Optional[Path]:
    try:
        rel = target.relative_to(skills_root)
    except ValueError:
        return None
    if not rel.parts or rel.parts[0] in _EXCLUDED_SKILL_PATH_PARTS:
        return None

    # Existing skill: ascend until the nearest directory containing SKILL.md.
    cursor = target if target.is_dir() else target.parent
    try:
        cursor.relative_to(skills_root)
    except ValueError:
        return None
    while cursor != skills_root and skills_root in cursor.parents:
        if (cursor / "SKILL.md").exists():
            return cursor
        cursor = cursor.parent

    # New/overwritten SKILL.md: parent directory is the intended skill dir.
    if target.name == "SKILL.md":
        return target.parent

    # Supporting file under a missing skill dir. Handle both category/skill/*
    # and flat skill/* layouts defensively.
    if len(rel.parts) >= 3:
        return skills_root / rel.parts[0] / rel.parts[1]
    if len(rel.parts) >= 2:
        return skills_root / rel.parts[0]
    return None


def classify_upstream_managed_skill_target(path: str) -> Optional[dict]:
    """Classify *path* if it targets a bundled/default or hub skill.

    Returns None when the path is not under a known protected skill. Otherwise
    returns source/path/name metadata suitable for a user-facing denial.
    """
    try:
        target = Path(os.path.expanduser(str(path))).resolve()
    except (OSError, RuntimeError):
        return None

    bundled_names = _current_bundled_skill_names()
    for skills_root, root_type in _skill_roots_for_immutability_guard():
        try:
            target.relative_to(skills_root)
        except ValueError:
            continue
        skill_dir = _candidate_skill_dir_for_path(target, skills_root)
        if skill_dir is None or _skill_path_excluded(skill_dir):
            return None
        skill_md = skill_dir / "SKILL.md"
        name = _read_skill_name_from_md(skill_md, fallback=skill_dir.name) if skill_md.exists() else skill_dir.name
        candidate_names = {name, skill_dir.name}

        sources: list[str] = []
        manifest_names = _read_bundled_manifest_names(skills_root)
        if root_type == "bundled-source":
            sources.append("bundled-source")
        if candidate_names & (set(bundled_names) | manifest_names):
            sources.append("bundled")
        hub_names, hub_paths = _read_hub_installed(skills_root)
        try:
            skill_real = skill_dir.resolve()
        except (OSError, RuntimeError):
            skill_real = skill_dir
        if candidate_names & hub_names or skill_real in hub_paths:
            sources.append("hub")
        if not sources:
            return None
        return {
            "name": name,
            "source": "+".join(sorted(set(sources))),
            "skill_dir": str(skill_real),
            "target_path": str(target),
            "skills_root": str(skills_root),
        }
    return None


def get_upstream_managed_skill_write_error(path: str) -> Optional[str]:
    info = classify_upstream_managed_skill_target(path)
    if info is None:
        return None
    return (
        f"Upstream-managed skill write blocked: {info['target_path']} targets "
        f"skill {info['name']!r} ({info['source']}) at {info['skill_dir']}. "
        "Bundled/default and Skills Hub-installed skills are immutable for "
        "agents and workers. Put Darius-specific behavior in AGENTS.md, "
        "project .hermes.md, memory, Kanban Worker Goal Prompts, or a separate "
        "companion skill with a distinct name. To discard existing drift for a "
        "bundled skill, use `hermes skills reset <name> --restore`; do not edit "
        "the upstream-managed skill directly."
    )


_UPSTREAM_SKILL_MUTATION_RE = re.compile(
    r"(?is)("
    r">>|>\s*|"
    r"\b(?:rm|mv|cp|install|rsync|tee|touch|mkdir|chmod|chown)\b|"
    r"\bsed\s+-[^\s;|&]*i\b|\bperl\s+-[^\s;|&]*i\b|"
    r"\b(?:tar|gtar)\b[^\n;|&]*\b(?:-x|--extract)\b|\bunzip\b|"
    r"write_text\s*\(|write_bytes\s*\(|\.write\s*\(|"
    r"open\s*\([^\n]{0,240}['\"](?:w|a|x|r\+|w\+|a\+|x\+)['\"]|"
    r"unlink\s*\(|rmdir\s*\(|rmtree\s*\(|"
    r"shutil\.(?:copy|copy2|copyfile|copytree|move|rmtree)\s*\("
    r")"
)


def _command_path_variants(path: Path) -> set[str]:
    variants = {str(path)}
    try:
        home = Path.home().resolve()
        resolved = path.resolve()
        rel = resolved.relative_to(home)
        rel_s = str(rel)
        variants.update({
            f"~/{rel_s}",
            f"$HOME/{rel_s}",
            f"${{HOME}}/{rel_s}",
        })
    except (OSError, RuntimeError, ValueError):
        pass

    try:
        hermes_home = _hermes_home_path().resolve()
        resolved = path.resolve()
        rel = resolved.relative_to(hermes_home)
        rel_s = str(rel)
        variants.update({
            f"$HERMES_HOME/{rel_s}",
            f"${{HERMES_HOME}}/{rel_s}",
        })
    except (OSError, RuntimeError, ValueError):
        pass
    return {v for v in variants if v}


def _protected_skill_dirs_for_commands() -> dict[str, str]:
    """Return command-string path fragments for known protected skill dirs.

    The command backstop must be narrower than ``$HERMES_HOME/skills``. A broad
    root match blocks legitimate creation of custom skills. Instead, collect the
    concrete protected skill directories that currently exist plus Hub lock
    install paths. Name-only reservations are handled separately by the regex in
    ``get_upstream_managed_skill_command_error``.
    """
    protected: dict[str, str] = {}
    reserved_names = _upstream_managed_skill_names()
    for root, root_type in _skill_roots_for_immutability_guard():
        hub_names, hub_paths = _read_hub_installed(root)

        for hub_path in hub_paths:
            name = hub_path.name
            skill_md = hub_path / "SKILL.md"
            if skill_md.exists():
                name = _read_skill_name_from_md(skill_md, fallback=hub_path.name)
            for variant in _command_path_variants(hub_path):
                protected[variant] = name

        if root_type == "bundled-source":
            # The bundled source tree itself is upstream-managed; every skill in
            # it is protected even before it has been copied into a runtime root.
            candidate_names = reserved_names or _current_bundled_skill_names()
        else:
            candidate_names = reserved_names | hub_names | _read_bundled_manifest_names(root)

        if not root.exists():
            continue
        try:
            skill_mds = root.rglob("SKILL.md")
        except OSError:
            continue
        for skill_md in skill_mds:
            if _skill_path_excluded(skill_md):
                continue
            skill_dir = skill_md.parent
            name = _read_skill_name_from_md(skill_md, fallback=skill_dir.name)
            if name not in candidate_names and skill_dir.name not in candidate_names:
                continue
            for variant in _command_path_variants(skill_dir):
                protected[variant] = name
    return protected


def _command_references_reserved_skill_name(command: str, reserved_names: set[str]) -> Optional[str]:
    """Return a reserved skill name if *command* targets it under a skills dir."""
    if not reserved_names:
        return None
    for name in sorted(reserved_names, key=len, reverse=True):
        # Match paths like:
        #   $HERMES_HOME/skills/category/name/SKILL.md
        #   ~/.hermes/profiles/reviewer/skills/name/SKILL.md
        #   /tmp/hermes/skills/category/subcategory/name/templates/x.md
        pattern = re.compile(
            r"(?<![\w.-])(?:~|\$HOME|\$\{HOME\}|\$HERMES_HOME|\$\{HERMES_HOME\}|/[^\s'\";|&]+)"
            r"(?:/profiles/[^/\s'\";|&]+)?/skills/(?:[^/\s'\";|&]+/)*"
            + re.escape(name)
            + r"(?:/|(?=[\s'\";|&]|$))"
        )
        if pattern.search(command):
            return name
    return None


def get_upstream_managed_skill_command_error(command: str) -> Optional[str]:
    """Return a hard-deny message for shell/code that mutates upstream skills.

    This is a best-effort pre-exec backstop for terminal/execute_code. The
    authoritative guard remains path-based in write_file/patch/skill_manage;
    this catches common shell/Python write attempts that bypass those tools.
    """
    if not isinstance(command, str) or "skill" not in command.lower():
        return None
    if not _UPSTREAM_SKILL_MUTATION_RE.search(command):
        return None

    protected_dirs = _protected_skill_dirs_for_commands()
    matched = None
    matched_name = None
    for fragment, name in sorted(protected_dirs.items(), key=lambda item: len(item[0]), reverse=True):
        if fragment and fragment in command:
            matched = fragment
            matched_name = name
            break

    if matched is None:
        matched_name = _command_references_reserved_skill_name(command, _upstream_managed_skill_names())
        if matched_name:
            matched = matched_name

    if matched is None:
        return None
    return (
        "Upstream-managed skill mutation blocked before execution: command/code "
        f"references protected skill path/name {matched!r} ({matched_name}) and contains a write/delete "
        "operation. Bundled/default and Skills Hub-installed skills must be "
        "changed only through upstream sync/reset paths, never by agents/workers."
    )


def get_read_block_error(path: str) -> Optional[str]:
    """Return an error message when a read targets a denied Hermes path.

    Two categories are blocked:

      * Internal Hermes cache files under ``HERMES_HOME/skills/.hub`` —
        readable metadata that an attacker could use as a prompt-injection
        carrier.
      * Credential / secret stores under HERMES_HOME and the global Hermes
        root: ``auth.json``, ``auth.lock``, ``.anthropic_oauth.json``,
        ``.env``, ``webhook_subscriptions.json``, and anything under
        ``mcp-tokens/``. These hold plaintext provider keys, OAuth tokens,
        and HMAC secrets that the agent never needs to read directly —
        provider tools / gateway adapters consume them through internal
        channels.

    **This is NOT a security boundary.** The terminal tool runs as the
    same OS user with shell access; the agent can still ``cat auth.json``
    or ``cat ~/.hermes/.env`` and exfiltrate the file. The read-deny exists
    as defense-in-depth that:

      * Returns a clear error to models that respect tool denials, which
        empirically prompts most modern models to stop rather than reach
        for the shell.
      * Surfaces a visible audit trail when something tries to read
        credentials — easier to spot in logs than a generic ``cat``.

    Treat any user-visible framing around this as "may help" rather than
    "stops attackers." A determined model or malicious instruction can
    always shell out.

    Callers that resolve relative paths against a non-process cwd
    (e.g. ``TERMINAL_CWD`` in ``tools/file_tools.py``) MUST pre-resolve
    and pass the absolute path string.  This function's own ``resolve()``
    is anchored at the Python process cwd, so a relative input like
    ``"auth.json"`` would otherwise miss the denylist when the task's
    terminal cwd differs from the process cwd.
    """
    resolved = Path(path).expanduser().resolve()

    # Resolve BOTH the active HERMES_HOME (profile-aware) AND the global
    # Hermes root so credential stores at <root>/auth.json etc. are also
    # blocked when running under a profile (HERMES_HOME points at
    # <root>/profiles/<name> in profile mode). Same shape as the write
    # deny widening (#15981, #14157).
    hermes_dirs: list[Path] = []
    for base in (_hermes_home_path(), _hermes_root_path()):
        try:
            real = base.resolve()
            if real not in hermes_dirs:
                hermes_dirs.append(real)
        except Exception:
            continue

    # Skills .hub: prompt-injection carriers.
    for hd in hermes_dirs:
        blocked_dirs = [
            hd / "skills" / ".hub" / "index-cache",
            hd / "skills" / ".hub",
        ]
        for blocked in blocked_dirs:
            try:
                resolved.relative_to(blocked)
            except ValueError:
                continue
            return (
                f"Access denied: {path} is an internal Hermes cache file "
                "and cannot be read directly to prevent prompt injection. "
                "Use the skills_list or skill_view tools instead."
            )

    # Credential / secret stores. Exact-file matches under either
    # HERMES_HOME or <root>.
    credential_file_names = (
        "auth.json",
        "auth.lock",
        ".anthropic_oauth.json",
        ".env",
        "webhook_subscriptions.json",
    )
    for hd in hermes_dirs:
        for name in credential_file_names:
            try:
                blocked = (hd / name).resolve()
            except Exception:
                continue
            if resolved == blocked:
                return (
                    f"Access denied: {path} is a Hermes credential store "
                    "and cannot be read directly. Provider tools consume "
                    "these credentials through internal channels. "
                    "(Defense-in-depth — not a security boundary; the "
                    "terminal tool can still bypass.)"
                )

    # mcp-tokens/: directory prefix match — anything inside is OAuth
    # token material.
    for hd in hermes_dirs:
        try:
            mcp_tokens = (hd / "mcp-tokens").resolve()
        except Exception:
            continue
        if resolved == mcp_tokens:
            return (
                f"Access denied: {path} is the Hermes MCP token directory "
                "and cannot be read directly. (Defense-in-depth — not a "
                "security boundary; the terminal tool can still bypass.)"
            )
        try:
            resolved.relative_to(mcp_tokens)
        except ValueError:
            continue
        return (
            f"Access denied: {path} is a Hermes MCP token file "
            "and cannot be read directly. (Defense-in-depth — not a "
            "security boundary; the terminal tool can still bypass.)"
        )

    return None


# ---------------------------------------------------------------------------
# Cross-profile write guard (#TBD)
#
# Hermes profiles are separate HERMES_HOME dirs under
# ``<root>/profiles/<name>/``. Each profile has its own skills/, plugins/,
# cron/, memories/. When an agent runs under one profile, writing into
# ANOTHER profile's directories is almost always wrong — those skills /
# plugins / cron jobs / memories affect a different session the user runs
# from a different shell.
#
# Soft guard, NOT a security boundary: the agent runs as the same OS user
# and has unrestricted terminal access, so this returns a warning the model
# can choose to honor or override with ``cross_profile=True``. Same shape
# as the dangerous-command approval flow — the agent is told the boundary
# exists, and explicit user direction is required to cross it.
#
# Reference: May 2026 incident where a hermes-security profile session
# edited skills under both ``~/.hermes/profiles/hermes-security/skills/``
# AND ``~/.hermes/skills/`` (the default profile's skills) without realizing
# the second path belonged to a different profile.
# ---------------------------------------------------------------------------

# Profile-scoped directories under HERMES_HOME / <root> / <root>/profiles/<X>/
# that should be guarded. Adding a new area here extends the guard with no
# other code change.
PROFILE_SCOPED_AREAS = ("skills", "plugins", "cron", "memories")


def _resolve_active_profile_name() -> str:
    """Return the active profile name derived from HERMES_HOME.

    ``~/.hermes``              -> ``"default"``
    ``~/.hermes/profiles/X``  -> ``"X"``

    Falls back to ``"default"`` on any resolution failure so the guard
    never raises into the tool path.
    """
    try:
        home_real = _hermes_home_path().resolve()
        root_real = _hermes_root_path().resolve()
    except (OSError, RuntimeError):
        return "default"
    profiles_dir = root_real / "profiles"
    try:
        rel = home_real.relative_to(profiles_dir)
        parts = rel.parts
        if len(parts) >= 1:
            return parts[0]
    except ValueError:
        pass
    return "default"


def classify_cross_profile_target(path: str) -> Optional[dict]:
    """Classify a write target as cross-profile if it lands in another
    profile's scoped area (skills/plugins/cron/memories).

    Returns ``None`` when the target is outside Hermes scope, or is inside
    the ACTIVE profile, or doesn't hit a profile-scoped area. Otherwise
    returns a dict with:

      * ``active_profile``: name of the profile the agent is running as
      * ``target_profile``: name of the profile the path belongs to
      * ``area``: which scoped area (``"skills"``, ``"plugins"``, etc.)
      * ``target_path``: the resolved path string

    The caller decides what to do with the result — surface a warning to
    the model, prompt the user, or (with explicit consent /
    ``cross_profile=True``) proceed anyway.
    """
    try:
        target = Path(os.path.expanduser(str(path))).resolve()
        root_real = _hermes_root_path().resolve()
    except (OSError, RuntimeError):
        return None

    target_profile: Optional[str] = None
    area: Optional[str] = None

    try:
        rel = target.relative_to(root_real)
    except ValueError:
        return None

    parts = rel.parts
    if not parts:
        return None

    if parts[0] in PROFILE_SCOPED_AREAS:
        # ``<root>/<area>/...`` → default profile.
        target_profile = "default"
        area = parts[0]
    elif (
        parts[0] == "profiles"
        and len(parts) >= 3
        and parts[2] in PROFILE_SCOPED_AREAS
    ):
        # ``<root>/profiles/<name>/<area>/...`` → named profile.
        target_profile = parts[1]
        area = parts[2]
    else:
        return None

    active_profile = _resolve_active_profile_name()
    if target_profile == active_profile:
        # In-profile write — not a cross-profile event.
        return None

    return {
        "active_profile": active_profile,
        "target_profile": target_profile,
        "area": area,
        "target_path": str(target),
    }


def get_cross_profile_warning(path: str) -> Optional[str]:
    """Return a model-facing warning string when ``path`` is cross-profile.

    Returns ``None`` when the write is in-scope (same profile) or outside
    Hermes entirely. Caller is expected to surface the warning to the
    agent as a tool-result error, NOT to silently allow the write — the
    agent must either get explicit user direction to proceed, or pass
    ``cross_profile=True`` to its write tool.

    This is defense-in-depth: the terminal tool runs as the same OS user
    and can write any of these paths without going through this guard.
    Treat the guard as a confusion-reducer, not a security boundary.
    """
    info = classify_cross_profile_target(path)
    if info is None:
        return None
    return (
        f"Cross-profile write blocked by soft guard: {info['target_path']} "
        f"belongs to Hermes profile {info['target_profile']!r}, but the "
        f"agent is running under profile {info['active_profile']!r}. "
        f"Editing another profile's {info['area']}/ will affect that "
        f"profile's future sessions, not the one you are currently in. "
        f"Confirm with the user before proceeding. To bypass this guard "
        f"after explicit user direction, retry the call with "
        f"``cross_profile=True``. (Defense-in-depth — not a security "
        f"boundary; the terminal tool can still bypass.)"
    )
