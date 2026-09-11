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
    try:
        if not log_dir.is_dir():
            return []
    except OSError:
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
    entries.sort(key=lambda e: (e.mtime, str(e.path)), reverse=True)
    return entries


def _load_json_report(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            t("could not load report {path}: {exc}").format(path=path, exc=exc)
        ) from exc


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
        # Orphans is a list[str], not dict
        if cat == "orphans":
            av_list = av if isinstance(av, list) else []
            bv_list = bv if isinstance(bv, list) else []
            a_set_o = set(av_list)
            b_set_o = set(bv_list)
            added_o = sorted(b_set_o - a_set_o)
            removed_o = sorted(a_set_o - b_set_o)
            if added_o or removed_o:
                result["diff"][cat] = {"added": added_o, "removed": removed_o}
            continue
        # Handle dict vs list differences; normalize to dict of sets
        # For broken_libs/undefined_symbols structure is nested, normalize order before compare
        if cat in ("broken_libs", "undefined_symbols"):
            # Normalize lists order for deterministic compare
            def _normalize(obj: Any) -> Any:
                if isinstance(obj, dict):
                    return {k: _normalize(v) for k, v in sorted(obj.items())}
                if isinstance(obj, list):
                    # For broken_libs, list of dicts: sort by binary name if possible
                    try:
                        return sorted(obj, key=lambda x: json.dumps(x, sort_keys=True))
                    except Exception:
                        return sorted(obj, key=str) if all(isinstance(x, str) for x in obj) else obj
                return obj

            av_n = _normalize(av)
            bv_n = _normalize(bv)
            a_str = json.dumps(av_n, sort_keys=True)
            b_str = json.dumps(bv_n, sort_keys=True)
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
    summary_diff: dict[str, Any] = {}
    a_sum = a.get("summary", {})
    b_sum = b.get("summary", {})
    for key in set(a_sum.keys()) | set(b_sum.keys()):
        av = a_sum.get(key, 0)
        bv = b_sum.get(key, 0)
        if av != bv:
            try:
                delta = bv - av if isinstance(av, int) and isinstance(bv, int) else None
            except TypeError:
                delta = None
            summary_diff[key] = {"from": av, "to": bv, "delta": delta}
    if summary_diff:
        result["diff"]["summary"] = summary_diff
    return result
