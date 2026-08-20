"""Verification of dynamic library dependencies for installed ELF binaries.

Inspired by Gentoo's ``revdep-rebuild``: for every ELF binary or shared library
installed on the system we run ``ldd`` and look for ``not found`` entries, which
indicate a shared library that the binary requires but that is not present.
Broken binaries are then attributed to the Slackware package that owns them, and
a best-effort guess is made for which installed package should provide each
missing library.

An optional, extra mode (``--check-libs-symbols``) detects binaries that import
undefined dynamic symbols that are not exported by any installed library. This
is intentionally heuristic and can yield false positives (lazy binding,
``dlopen``-loaded libraries, symbol versioning), mirroring revdep-rebuild's
``-u`` / ``SEARCH_SYMBOLS``.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

# NOTE (security): ``ldd`` executes the target binary via the dynamic loader
# (LD_TRACE). A malicious ELF installed on the system could exploit this.
# ``--check-libs-deps`` is opt-in and should only be run on trusted
# installations. The alternative (``readelf -d NEEDED``) was considered but
# would miss runtime-resolved dependencies; ``ldd`` is kept for completeness.

# Minimum interval between two progress updates (seconds). Reports more often than
# this would redraw the progress bar too frequently for long scans.
_PROGRESS_INTERVAL = 0.1

# Lines of `ldd` output that report a missing dependency, e.g.:
#   libfoo.so.1 => not found
_NOT_FOUND = re.compile(r"^\s*(?P<lib>\S+)\s+=>\s+not found", re.MULTILINE)

# ldd reports this for scripts or non-dynamic files; it is not an error.
_NOT_DYNAMIC = re.compile(r"not a dynamic executable", re.IGNORECASE)

# Shared libraries live under these prefixes; their basename maps to a package.
_LIB_PREFIXES = ("usr/lib/", "usr/lib64/", "lib/", "lib64/", "usr/libexec/")

_LDD_TIMEOUT = 60

# Safe mode: NEEDED entries from `readelf -d`
_NEEDED = re.compile(r"\(NEEDED\)[^[]*\[([^\]]+)\]")

type ProgressCallback = Callable[[int], None]
type LibEntries = Iterable[tuple[str, str]]

# ---------------------------------------------------------------------------
# Undefined dynamic symbols (optional mode, --check-libs-symbols)
# ---------------------------------------------------------------------------
# A defined (exported) dynamic symbol, e.g. from `readelf -Ws`:
#   Num:    Value          Size Type    Bind   Vis      Ndx Name
#    6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts
#  123: 0000000000004a40    26 FUNC    GLOBAL DEFAULT   13 main
# A symbol with Ndx == "UND" is undefined; otherwise it is defined.
_DEFINED_SYMBOL = re.compile(r"^\s*\d+:\s+\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+\d+\s+(\S+)$", re.MULTILINE)
_UNDEFINED_SYMBOL = re.compile(
    r"^\s*\d+:\s+\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+UND\s+(\S+)$", re.MULTILINE
)


def _should_report(done: int, total: int, last_update: float) -> bool:
    """Returns whether a progress update should be reported now.

    Reports at most every ``_PROGRESS_INTERVAL`` seconds, but always on the final
    item so the bar reaches 100%.
    """
    if done >= total:
        return True
    return time.monotonic() - last_update >= _PROGRESS_INTERVAL


def _missing_libs_of(path: str, ldd_bin: str) -> list[str]:
    """Runs `ldd` on `path` and returns the list of missing shared libraries."""
    try:
        result = subprocess.run(
            [ldd_bin, "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_LDD_TIMEOUT,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    output = result.stdout + result.stderr
    if _NOT_DYNAMIC.search(output):
        return []
    missing: list[str] = []
    for match in _NOT_FOUND.finditer(output):
        lib = match.group("lib")
        if lib not in missing:
            missing.append(lib)
    return missing


def _needed_libs_via_readelf(path: str, readelf_bin: str, owner_index: dict[str, str]) -> list[str]:
    """Safe alternative to `ldd`: uses `readelf -d` NEEDED and owner index.

    Does not execute the binary. A needed library is considered missing if its
    basename is not provided by any installed package (best-effort, handles
    versioned sonames: ``libfoo.so.1`` satisfies ``libfoo.so.1.2`` and vice-versa).
    """
    try:
        result = subprocess.run(
            [readelf_bin, "-d", "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_LDD_TIMEOUT,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    # readelf -d failures (not ELF, etc.) return non-zero but still output empty
    needed: list[str] = []
    for match in _NEEDED.finditer(result.stdout):
        lib = match.group(1)
        if lib not in needed:
            needed.append(lib)
    # Filter to those not provided by any installed package (handle versioned sonames)
    missing: list[str] = []
    for lib in needed:
        if lib in owner_index:
            continue
        # Check if any owner provides a version-compatible soname
        # e.g. needed libssl.so.3, owner libssl.so.3.1.0 -> owner startswith needed
        # also needed libssl.so.3.1.0, owner libssl.so.3 -> needed startswith owner
        found = False
        for owner_lib in owner_index:
            if owner_lib.startswith(lib) or lib.startswith(owner_lib):
                found = True
                break
            # Also check major soname (libfoo.so.1)
            if ".so." in lib and ".so." in owner_lib:
                lib_base = lib.split(".so.")[0] + ".so." + lib.split(".so.")[1].split(".")[0]
                owner_base = (
                    owner_lib.split(".so.")[0] + ".so." + owner_lib.split(".so.")[1].split(".")[0]
                )
                if lib_base == owner_base:
                    found = True
                    break
        if not found:
            missing.append(lib)
    return missing


def check_library_deps(
    paths: Iterable[str],
    workers: int,
    ldd_bin: str,
    on_progress: ProgressCallback | None = None,
) -> list[list[str]]:
    """Checks `paths` (ELF files only) and returns missing libs per path.

    The result preserves the order of `paths`; an entry is an empty list when the
    file has all its dependencies present (or is not a dynamic binary). ``ldd`` is
    run in parallel and `on_progress` is called as each file is completed, so the
    caller can show a real-time progress bar.
    """
    paths = list(paths)
    results: list[list[str]] = [[] for _ in paths]
    futures: dict[Future[Any], int] = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pkgcheck-ldd") as executor:
        for index, path in enumerate(paths):
            futures[executor.submit(_missing_libs_of, path, ldd_bin)] = index
        last_update = time.monotonic()
        for done, future in enumerate(as_completed(futures), start=1):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception:
                results[index] = []
            if on_progress is not None and _should_report(done, len(paths), last_update):
                on_progress(done)
                last_update = time.monotonic()
    return results


def check_library_deps_safe(
    paths: Iterable[str],
    workers: int,
    readelf_bin: str,
    owner_index: dict[str, str],
    on_progress: ProgressCallback | None = None,
) -> list[list[str]]:
    """Safe `readelf -d` variant of :func:`check_library_deps` (no execution).

    Checks NEEDED entries against `owner_index`; a library is reported missing
    if no installed package provides it.
    """
    paths = list(paths)
    results: list[list[str]] = [[] for _ in paths]
    futures: dict[Future[Any], int] = {}
    with ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="pkgcheck-ldd-safe"
    ) as executor:
        for index, path in enumerate(paths):
            futures[executor.submit(_needed_libs_via_readelf, path, readelf_bin, owner_index)] = (
                index
            )
        last_update = time.monotonic()
        for done, future in enumerate(as_completed(futures), start=1):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception:
                results[index] = []
            if on_progress is not None and _should_report(done, len(paths), last_update):
                on_progress(done)
                last_update = time.monotonic()
    return results


def _is_library_path(rel: str) -> bool:
    """Returns whether `rel` looks like a shared library path."""
    name = Path(rel).name
    return rel.startswith(_LIB_PREFIXES) and (name.endswith(".so") or ".so." in name)


def build_library_owner_index(entries: LibEntries) -> dict[str, str]:
    """Maps each installed library basename to the package that provides it.

    ``usr/lib/libfoo.so.1`` → ``libfoo.so.1`` → ``pkg-x``. Several packages may
    ship a library with the same basename; the last one wins (best-effort).
    """
    index: dict[str, str] = {}
    for package, rel in entries:
        if _is_library_path(rel):
            index[Path(rel).name] = package
    return index


def find_missing_owner(
    missing_libs: Iterable[str], owner_index: dict[str, str]
) -> dict[str, str | None]:
    """Maps each missing library to the package that should provide it (or None)."""
    return {lib: owner_index.get(lib) for lib in missing_libs}


def _readelf_symbols(path: str, readelf_bin: str) -> set[str] | None:
    """Returns the set of defined (exported) dynamic symbols of `path`, or None."""
    try:
        result = subprocess.run(
            [readelf_bin, "-Ws", "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_LDD_TIMEOUT,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    symbols: set[str] = set()
    for line in result.stdout.splitlines():
        match = _DEFINED_SYMBOL.match(line)
        if match:
            symbols.add(match.group(1))
    return symbols


def _undefined_symbols(path: str, defined_globally: set[str], readelf_bin: str) -> list[str]:
    """Returns the undefined symbols of `path` that are not defined anywhere."""
    try:
        result = subprocess.run(
            [readelf_bin, "-Ws", "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_LDD_TIMEOUT,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    undefined: list[str] = []
    for line in result.stdout.splitlines():
        match = _UNDEFINED_SYMBOL.match(line)
        if match and match.group(1) not in defined_globally and match.group(1) not in undefined:
            undefined.append(match.group(1))
    return undefined


def collect_defined_symbols(
    paths: Iterable[str],
    workers: int,
    readelf_bin: str,
    on_progress: ProgressCallback | None = None,
) -> set[str]:
    """Builds the global set of dynamic symbols exported by the installed libraries.

    Runs ``readelf`` in parallel and calls `on_progress` as each file completes.
    """
    paths = list(paths)
    defined: set[str] = set()
    futures: dict[Future[Any], str] = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pkgcheck-nm") as executor:
        for path in paths:
            futures[executor.submit(_readelf_symbols, path, readelf_bin)] = path
        done = 0
        last_update = time.monotonic()
        for done, future in enumerate(as_completed(futures), start=1):
            try:
                symbols = future.result()
            except Exception:
                symbols = None
            if symbols:
                defined |= symbols
            if on_progress is not None and _should_report(done, len(paths), last_update):
                on_progress(done)
                last_update = time.monotonic()
    return defined


def check_undefined_symbols(
    paths: Iterable[str],
    defined_globally: set[str],
    workers: int,
    readelf_bin: str,
    on_progress: ProgressCallback | None = None,
) -> list[list[str]]:
    """Returns, per path (order preserved), the undefined dynamic symbols of that
    ELF file that are not provided by any installed library.

    False positives are possible (lazy binding, ``dlopen``-loaded libraries,
    symbol versioning). An empty list means the file is clean.
    """
    paths = list(paths)
    results: list[list[str]] = [[] for _ in paths]
    futures: dict[Future[Any], int] = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pkgcheck-sym") as executor:
        for index, path in enumerate(paths):
            futures[executor.submit(_undefined_symbols, path, defined_globally, readelf_bin)] = (
                index
            )
        last_update = time.monotonic()
        for done, future in enumerate(as_completed(futures), start=1):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception:
                results[index] = []
            if on_progress is not None and _should_report(done, len(paths), last_update):
                on_progress(done)
                last_update = time.monotonic()
    return results
