"""Find orphan (untracked) files on the filesystem."""

from __future__ import annotations

import os
from pathlib import Path

from pkgcheck.scanner import _PSEUDO_PREFIXES

# Additional prefixes that are never considered orphans (even if not in package DB).
# Reuses scanner pseudo plus home (often noisy) optionally.
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
    # var/log/packages is the DB itself, never orphan
    if rel.startswith("var/log/packages/") or rel == "var/log/packages":
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
    # Normalize owned to ensure leading /
    # Walk
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        # Compute relative dir for exclusion check
        try:
            rel_dir = os.path.relpath(dirpath, root_str)
        except ValueError:
            rel_dir = ""
        if rel_dir == ".":
            rel_dir = ""
        else:
            rel_dir = rel_dir.rstrip("/") + "/"
            if _is_orphan_excluded(rel_dir, extra_exclude):
                # Prune traversal
                dirnames[:] = []
                continue
            # Also prune subdirs that are excluded
            # Filter dirnames in-place to avoid descending
            pruned = []
            for d in list(dirnames):
                rel_sub = f"{rel_dir}{d}/" if rel_dir else f"{d}/"
                if _is_orphan_excluded(rel_sub, extra_exclude):
                    pruned.append(d)
            for d in pruned:
                dirnames.remove(d)

        for fname in filenames:
            rel = f"{rel_dir}{fname}" if rel_dir else fname
            if _is_orphan_excluded(rel, extra_exclude):
                continue
            abs_path = f"/{rel}" if root_str == "/" else f"{root_str.rstrip('/')}/{rel}"
            # Normalize // -> /
            abs_path = abs_path.replace("//", "/")
            if abs_path not in owned:
                orphans.append(abs_path)
    orphans.sort()
    return orphans
