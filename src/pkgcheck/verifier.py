"""Parallel verification of file existence on the system."""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from enum import Enum
from functools import partial
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


def _is_elf_candidate(st_mode: int, path: str) -> bool:
    """Returns whether a regular file could be an ELF binary/library.

    Mirrors revdep-rebuild: only executable files or shared libraries (``.so`` in the
    name) are worth reading the magic header of, skipping configs/docs/data.
    """
    if st_mode & 0o111:
        return True
    return ".so" in path


def _is_elf(path: str) -> bool:
    """Returns whether `path` is a regular ELF file (checks the 4-byte magic header).

    Safe against special files: follows symbolic links, requires a regular file
    (``S_ISREG``) so FIFOs/sockets/devices are never opened (which would block), and
    opens with ``O_NONBLOCK`` as a belt-and-suspenders against a file being swapped
    for a FIFO between the stat and the open (TOCTOU).
    """
    try:
        st = os.stat(path)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    if not _is_elf_candidate(st.st_mode, path):
        return False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        with os.fdopen(fd, "rb", closefd=True) as handle:
            return handle.read(4) == _ELF_MAGIC
    except OSError:
        return False


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
    window = max(workers * 2, 64)
    in_flight: dict[Future[Any], int] = {}
    last_update = time.monotonic()
    done = 0
    index = 0
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pkgcheck") as executor:
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
