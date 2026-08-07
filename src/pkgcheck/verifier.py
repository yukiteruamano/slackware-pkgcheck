"""Parallel verification of file existence on the system."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from functools import partial
from itertools import batched

_BATCH_SIZE = 4_096

_DEFAULT_BACKUP_SUFFIXES = (".bak", ".orig")
_DEFAULT_NEW_SUFFIX = ".new"

type ProgressCallback = Callable[[int], None]
type Suffixes = tuple[str, ...]


class PathStatus(Enum):
    """Status of a path verified on disk."""

    EXISTS = "exists"
    MISSING = "missing"
    BACKUP = "backup_only"
    NEW_PENDING = "pending_review"
    NO_ACCESS = "no_access"
    ERROR = "error"


def check_path(
    path: str,
    backup_suffixes: Suffixes = _DEFAULT_BACKUP_SUFFIXES,
    new_suffix: str = _DEFAULT_NEW_SUFFIX,
) -> PathStatus:
    """Checks the existence of `path` with a single low-level call.

    Uses `os.lstat`, which does not follow the final link: a broken symbolic link counts
    as present, because the link itself exists physically on disk.

    Honors the Slackware convention for `.new` config files: a package records
    ``foo.conf.new`` and the install script renames it to ``foo.conf`` unless that file
    already exists, in which case ``foo.conf.new`` is left pending review by the user.
    Therefore:

    - If `path` ends with `new_suffix`, it is ``NEW_PENDING`` if the `.new` itself is on
      disk, ``EXISTS`` if the renamed version (without suffix) exists, or ``MISSING``.
    - If `path` does not exist but a `new_suffix` variant does, it is reported as
      ``NEW_PENDING``.
    - If none of the above exist but a backup variant (``.bak``, ``.orig``) does, it is
      reported as ``BACKUP`` instead of ``MISSING``.
    """
    if not new_suffix:
        new_suffix = _DEFAULT_NEW_SUFFIX
    try:
        os.lstat(path)
    except FileNotFoundError:
        pass
    except PermissionError:
        return PathStatus.NO_ACCESS
    except OSError:
        return PathStatus.ERROR
    else:
        if path.endswith(new_suffix):
            return PathStatus.NEW_PENDING
        return PathStatus.EXISTS

    if _lexists(path + new_suffix):
        return PathStatus.NEW_PENDING
    if path.endswith(new_suffix) and _lexists(path[: -len(new_suffix)]):
        return PathStatus.EXISTS
    for suffix in backup_suffixes:
        if _lexists(path + suffix):
            return PathStatus.BACKUP
    return PathStatus.MISSING


def _lexists(path: str) -> bool:
    """Returns whether `path` exists without following links (broken links count)."""
    try:
        os.lstat(path)
    except OSError:
        return False
    return True


def verify_paths(
    paths: Iterable[str],
    workers: int,
    on_progress: ProgressCallback | None = None,
    backup_suffixes: Suffixes = _DEFAULT_BACKUP_SUFFIXES,
    new_suffix: str = _DEFAULT_NEW_SUFFIX,
) -> list[PathStatus]:
    """Verifies `paths` in parallel and returns a status per path (order preserved).

    I/O checks are delegated to a thread pool; the GIL is released during each syscall,
    so the number of threads scales well with the `stat` load.
    """
    statuses: list[PathStatus] = []
    check = partial(check_path, backup_suffixes=backup_suffixes, new_suffix=new_suffix)
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pkgcheck") as executor:
        for batch in batched(paths, _BATCH_SIZE):
            for status in executor.map(check, batch):
                statuses.append(status)
            if on_progress is not None:
                on_progress(len(statuses))
    return statuses
