"""Parallel verification of file existence on the system."""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Any, cast

_DEFAULT_BACKUP_SUFFIXES = (".bak", ".orig")
_DEFAULT_NEW_SUFFIX = ".new"

# Minimum interval between two progress updates (seconds).
_PROGRESS_INTERVAL = 0.1

# ELF code detecttion
_ELF_MAGIC = b"\x7fELF"

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
    - If `path` ends with `new_suffix` AND a backup variant exists (e.g., foo.conf.new.bak),
      report as ``NEW_PENDING`` (new config takes precedence over backup).
    """
    if not new_suffix:
        new_suffix = _DEFAULT_NEW_SUFFIX

    is_new_variant = path.endswith(new_suffix)
    base_path = path[: -len(new_suffix)] if is_new_variant else path

    # First, check if the path itself exists
    try:
        os.lstat(path)
    except FileNotFoundError:
        pass
    except PermissionError:
        return PathStatus.NO_ACCESS
    except OSError:
        return PathStatus.ERROR
    else:
        if is_new_variant:
            return PathStatus.NEW_PENDING
        return PathStatus.EXISTS

    # Path doesn't exist. Check for .new variant (for base paths) or base (for .new paths)
    try:
        if is_new_variant:
            # Package recorded foo.conf.new - check if base foo.conf exists (renamed)
            if _lexists(base_path):
                return PathStatus.EXISTS
        else:
            # Package recorded foo.conf - check if foo.conf.new exists (pending review)
            if _lexists(path + new_suffix):
                return PathStatus.NEW_PENDING
    except PermissionError:
        return PathStatus.NO_ACCESS

    # Check for backup variants
    # For .new paths, check .new.bak first, then base.bak; for base paths, check base.bak
    candidates: list[str] = []
    if is_new_variant:
        for suffix in backup_suffixes:
            candidates.append(path + suffix)
        for suffix in backup_suffixes:
            candidates.append(base_path + suffix)
    else:
        for suffix in backup_suffixes:
            candidates.append(base_path + suffix)
    for cand in candidates:
        try:
            if _lexists(cand):
                return PathStatus.BACKUP
        except PermissionError:
            return PathStatus.NO_ACCESS

    return PathStatus.MISSING


def _lexists(path: str) -> bool:
    """Returns whether `path` exists without following links (broken links count)."""
    try:
        os.lstat(path)
    except PermissionError:
        raise
    except OSError:
        return False
    return True


def _is_elf_candidate(st_mode: int, path: str) -> bool:
    """Returns whether a regular file could be an ELF binary/library.

    Mirrors revdep-rebuild: only executable files or shared libraries (``.so`` in the
    name) are worth reading the magic header of, skipping configs/docs/data.
    """
    if st_mode & 0o111:
        return True
    name = Path(path).name
    return name.endswith(".so") or ".so." in name


def _is_elf(path: str) -> bool:
    """Returns whether `path` is a regular ELF file (checks the 4-byte magic header).

    Follows symbolic links to their final target. Uses ``O_NONBLOCK`` so FIFOs/
    sockets/devices never block, and verifies ``S_ISREG`` after open to avoid
    TOCTOU races (check-then-open replaced by open-then-check).
    """
    try:
        # Open without O_NOFOLLOW so we follow symlinks to the real file;
        # use O_NONBLOCK to avoid blocking on FIFOs.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return False

    try:
        try:
            st = os.fstat(fd)
        except OSError:
            try:
                os.close(fd)
            except OSError:
                pass
            return False

        # Must be a regular file (symlink already resolved by open)
        if not stat.S_ISREG(st.st_mode):
            try:
                os.close(fd)
            except OSError:
                pass
            return False

        if not _is_elf_candidate(st.st_mode, path):
            try:
                os.close(fd)
            except OSError:
                pass
            return False

        try:
            with os.fdopen(fd, "rb", closefd=True) as handle:
                return handle.read(4) == _ELF_MAGIC
        except OSError:
            return False
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        return False


def _is_elf_target(path: str) -> bool:
    """Check if a path is an ELF file (legacy alias, follows symlinks)."""
    return _is_elf(path)


def check_path_and_elf(
    path: str,
    backup_suffixes: Suffixes = _DEFAULT_BACKUP_SUFFIXES,
    new_suffix: str = _DEFAULT_NEW_SUFFIX,
) -> tuple[PathStatus, bool]:
    """Checks the existence of `path` and, in the same pass, whether it is an ELF file.

    The ELF check reads the first 4 bytes of the file; for a missing path the open
    fails quickly and no content is read. Used to detect the candidate binaries in a
    single pass instead of a separate, slower scan.
    """
    status = check_path(path, backup_suffixes, new_suffix)
    if status is not PathStatus.EXISTS:
        return status, False
    return status, _is_elf(path)


def _run_workers(
    paths: Iterable[str],
    workers: int,
    worker: Callable[[str], object],
    on_progress: ProgressCallback | None,
) -> list[object]:
    """Runs `worker` on every `path` in parallel, preserving input order.

    `on_progress` is called (throttled) as each path completes for a real-time bar.
    Only a bounded window of tasks is in flight at once, so memory stays low even
    with hundreds of thousands of paths.
    """
    paths = list(paths)
    total = len(paths)
    results: list[object] = [None] * total
    window = min(max(workers * 2, 64), 256)
    in_flight: dict[Future[Any], int] = {}
    last_update = 0.0
    done = 0
    index = 0
    try:
        executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pkgcheck")
    except (OSError, ValueError, RuntimeError):
        # Fallback to synchronous if threads cannot be created
        for idx, p in enumerate(paths):
            try:
                results[idx] = worker(p)
            except Exception:
                results[idx] = None
            if on_progress is not None:
                on_progress(idx + 1)
        return results
    with executor:
        while index < total or in_flight:
            while index < total and len(in_flight) < window:
                in_flight[executor.submit(worker, paths[index])] = index
                index += 1
            completed, _ = wait(in_flight, return_when=FIRST_COMPLETED)
            for future in completed:
                result_index = in_flight.pop(future)
                try:
                    results[result_index] = future.result()
                except Exception:
                    results[result_index] = None
                done += 1
                if on_progress is not None and (
                    done >= total or time.monotonic() - last_update >= _PROGRESS_INTERVAL
                ):
                    on_progress(done)
                    last_update = time.monotonic()
    return results


def verify_paths(
    paths: Iterable[str],
    workers: int,
    on_progress: ProgressCallback | None = None,
    backup_suffixes: Suffixes = _DEFAULT_BACKUP_SUFFIXES,
    new_suffix: str = _DEFAULT_NEW_SUFFIX,
) -> list[PathStatus]:
    """Verifies `paths` in parallel and returns a status per path (order preserved).

    I/O checks are delegated to a thread pool; the GIL is released during each
    syscall, so the number of threads scales well with the `stat` load. `on_progress`
    is called as each path completes so the caller can show a real-time progress bar.
    """
    check = partial(check_path, backup_suffixes=backup_suffixes, new_suffix=new_suffix)
    results = _run_workers(paths, workers, check, on_progress)
    return [PathStatus.ERROR if r is None else cast(PathStatus, r) for r in results]


def verify_paths_with_elf(
    paths: Iterable[str],
    workers: int,
    on_progress: ProgressCallback | None = None,
    backup_suffixes: Suffixes = _DEFAULT_BACKUP_SUFFIXES,
    new_suffix: str = _DEFAULT_NEW_SUFFIX,
) -> tuple[list[PathStatus], list[bool]]:
    """Verifies `paths` and, in the same pass, reports which are ELF files.

    Combines existence checking with ELF detection to avoid a second, full scan of the
    system. Returns ``(statuses, elf_flags)``, both preserving the order of `paths`.
    """
    check = partial(check_path_and_elf, backup_suffixes=backup_suffixes, new_suffix=new_suffix)
    pairs = _run_workers(paths, workers, check, on_progress)
    statuses: list[PathStatus] = []
    elf_flags: list[bool] = []
    for pair in pairs:
        if pair is None:
            statuses.append(PathStatus.ERROR)
            elf_flags.append(False)
        else:
            status, elf = cast(tuple[PathStatus, bool], pair)
            statuses.append(status)
            elf_flags.append(elf)
    return statuses, elf_flags
