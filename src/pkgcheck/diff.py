"""List and diff pkgcheck logs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pkgcheck.i18n import t


@dataclass(frozen=True, slots=True)
class LogEntry:
    path: Path
    fmt: str  # "log" or "json"
    mtime: float
    size: int


def list_logs(log_dir: Path) -> list[LogEntry]:
    """Returns pkgcheck logs in `log_dir` sorted by mtime (newest first)."""
    if not log_dir.is_dir():
        return []
    entries: list[LogEntry] = []
    for p in log_dir.glob("pkgcheck-*.log"):
        try:
            st = p.stat()
        except OSError:
            continue
        entries.append(LogEntry(path=p, fmt="log", mtime=st.st_mtime, size=st.st_size))
    for p in log_dir.glob("pkgcheck-*.json"):
        try:
            st = p.stat()
        except OSError:
            continue
        entries.append(LogEntry(path=p, fmt="json", mtime=st.st_mtime, size=st.st_size))
    entries.sort(key=lambda e: e.mtime, reverse=True)
    return entries


def _load_json_report(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            t("could not load report {path}: {exc}").format(path=path, exc=exc)
        ) from exc


def _index_to_sets(index: dict[str, Any]) -> dict[str, set[str]]:
    # index is {"pkg": ["/path", ...]}
    return {pkg: set(paths) for pkg, paths in index.items()}


def diff_reports(from_path: Path, to_path: Path) -> dict[str, Any]:
    """Diffs two JSON reports and returns added/removed per category.

    Only JSON reports are supported for precise diff; text logs raise RuntimeError.
    """
    if from_path.suffix.lower() != ".json" or to_path.suffix.lower() != ".json":
        raise RuntimeError(t("diff requires JSON reports (.json); text logs not supported"))
    a = _load_json_report(from_path)
    b = _load_json_report(to_path)

    categories = [
        "missing",
        "files_backup",
        "files_pending_new",
        "no_access",
        "files_errors",
        "orphans",
        "broken_libs",
        "undefined_symbols",
    ]
    result: dict[str, Any] = {"from": str(from_path), "to": str(to_path), "diff": {}}
    for cat in categories:
        av = a.get(cat, {})
        bv = b.get(cat, {})
        # Handle dict vs list differences; normalize to dict of sets
        # For broken_libs/undefined_symbols structure is nested
        if cat in ("broken_libs", "undefined_symbols"):
            # Compare stringified
            a_str = json.dumps(av, sort_keys=True)
            b_str = json.dumps(bv, sort_keys=True)
            if a_str != b_str:
                result["diff"][cat] = {"from": av, "to": bv}
            continue
        # Normalize None to {}
        if not isinstance(av, dict):
            av = {}
        if not isinstance(bv, dict):
            bv = {}
        # Compute added/removed per package
        added: dict[str, list[str]] = {}
        removed: dict[str, list[str]] = {}
        all_pkgs = set(av.keys()) | set(bv.keys())
        for pkg in sorted(all_pkgs):
            a_set = set(av.get(pkg, []))
            b_set = set(bv.get(pkg, []))
            add = sorted(b_set - a_set)
            rem = sorted(a_set - b_set)
            if add:
                added[pkg] = add
            if rem:
                removed[pkg] = rem
        if added or removed:
            result["diff"][cat] = {"added": added, "removed": removed}
    # Summary
    summary_diff = {}
    a_sum = a.get("summary", {})
    b_sum = b.get("summary", {})
    for key in set(a_sum.keys()) | set(b_sum.keys()):
        av = a_sum.get(key, 0)
        bv = b_sum.get(key, 0)
        if av != bv:
            summary_diff[key] = {
                "from": av,
                "to": bv,
                "delta": bv - av if isinstance(av, int) and isinstance(bv, int) else None,
            }
    if summary_diff:
        result["diff"]["summary"] = summary_diff
    return result
