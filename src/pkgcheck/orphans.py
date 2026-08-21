"""Find orphan (untracked) files on the filesystem."""

from __future__ import annotations

import os
from pathlib import Path

from pkgcheck.scanner import _PSEUDO_PREFIXES

# Additional prefixes that are never considered orphans (even if not in package DB).
# Reuses scanner pseudo prefixes plus home (often noisy) and var/log/pkgcheck/, var/log/setup/
_ORPHAN_EXCLUDE = (
    *_PSEUDO_PREFIXES,
    "var/cache/",
    "var/spool/",
    "var/lock/",
    "var/tmp/",
    "var/log/",
    "var/lib/slackpkg/",
    "mnt/",
    "media/",
    "srv/",
    "lost+found/",
    "home/",
)


def _is_orphan_excluded(rel: str, extra_exclude: tuple[str, ...] = ()) -> bool:
    """Returns whether `rel` (without leading `/`) should be ignored for orphans."""
    # var/log/packages is the DB itself and pkgcheck/setup logs are not orphans
    if rel.startswith("var/log/packages/") or rel == "var/log/packages":
        return True
    if rel.startswith("var/log/pkgcheck/") or rel == "var/log/pkgcheck":
        return True
    if rel.startswith("var/log/setup/") or rel == "var/log/setup":
        return True
    prefixes = (*_ORPHAN_EXCLUDE, *extra_exclude)
    return rel.startswith(prefixes)


def find_orphans(
    owned: set[str],
    root: Path = Path("/"),
    extra_exclude: tuple[str, ...] = (),
) -> list[str]:
    """Walks `root` and returns files not in `owned`.

    `owned` contains absolute paths (``/usr/bin/foo``).  Walk is shallow for
    performance: uses ``os.walk`` with ``followlinks=False`` and skips pseudo
    prefixes early via ``_is_orphan_excluded`` on the relative path.
    """
    orphans: list[str] = []
    root_str = str(root)
    owned_rels = {p.lstrip("/") for p in owned}
    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=False, onerror=lambda _: None
    ):
        try:
            rel_dir = os.path.relpath(dirpath, root_str)
        except ValueError:
            rel_dir = ""
        if rel_dir == ".":
            rel_dir = ""
            # Prune top-level dirs that are pseudo
            for d in list(dirnames):
                if _is_orphan_excluded(f"{d}/", extra_exclude):
                    dirnames.remove(d)
        else:
            rel_dir = rel_dir.rstrip("/") + "/"
            if _is_orphan_excluded(rel_dir, extra_exclude):
                dirnames[:] = []
                continue
            for d in list(dirnames):
                rel_sub = f"{rel_dir}{d}/"
                if _is_orphan_excluded(rel_sub, extra_exclude):
                    dirnames.remove(d)
        for fname in filenames:
            rel = f"{rel_dir}{fname}" if rel_dir else fname
            if _is_orphan_excluded(rel, extra_exclude):
                continue
            if rel in owned_rels:
                continue
            # Build display path (chroot-aware) without resolving symlinks
            display_path = f"/{rel}" if root_str == "/" else str(Path(root_str) / rel)
            # Lexically normalize without following symlinks
            display_path = os.path.normpath(display_path)
            if display_path not in orphans:
                orphans.append(display_path)
    orphans.sort()
    return orphans
