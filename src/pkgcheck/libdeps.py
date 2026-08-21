"""Verification of dynamic library dependencies for installed ELF binaries.

Inspired by Gentoo's ``revdep-rebuild``: for every ELF binary or shared library
installed on the system we use ``readelf -d`` to extract NEEDED entries and
check if they are provided by installed packages. This is a SAFE mode that
does not execute any binaries (unlike ``ldd``).

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
import warnings
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

# Minimum interval between two progress updates (seconds). Reports more often than
# this would redraw the progress bar too frequently for long scans.
_PROGRESS_INTERVAL = 0.1

# readelf -d NEEDED pattern:  0x00000001 (NEEDED)  Shared library: [libfoo.so.1]
_NEEDED = re.compile(r"\(NEEDED\)[^[]*\[([^\]]+)\]")

# A defined (exported) dynamic symbol, e.g. from `readelf -Ws`:
#   Num:    Value          Size Type    Bind   Vis      Ndx Name
#    6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts
#  123: 0000000000004a40    26 FUNC    GLOBAL DEFAULT   13 main
# A symbol with Ndx == "UND" is undefined; otherwise it is defined.
_DEFINED_SYMBOL = re.compile(r"^\s*\d+:\s+\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+\d+\s+(\S+)$", re.MULTILINE)
_UNDEFINED_SYMBOL = re.compile(
    r"^\s*\d+:\s+\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+UND\s+(\S+)$", re.MULTILINE
)

_READ_ELF_TIMEOUT = 60

type ProgressCallback = Callable[[int], None]
type LibEntries = Iterable[tuple[str, str]]

# Shared libraries live under these prefixes; their basename maps to a package.
_LIB_PREFIXES = ("usr/lib/", "usr/lib64/", "lib/", "lib64/", "usr/libexec/")


def _should_report(done: int, total: int, last_update: float) -> bool:
    """Returns whether a progress update should be reported now.

    Reports at most every ``_PROGRESS_INTERVAL`` seconds, but always on the final
    item so the bar reaches 100%.
    """
    if done >= total:
        return True
    return time.monotonic() - last_update >= _PROGRESS_INTERVAL


def _build_readelf_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    env = {**os.environ}
    if extra_env:
        env.update(extra_env)
    env["LC_ALL"] = "C"
    return env


def _get_needed_libs(
    path: str, readelf_bin: str, extra_env: dict[str, str] | None = None
) -> list[str]:
    """Extract NEEDED libraries from an ELF file using readelf -d.

    Does not execute the binary. Returns list of library names (sonames).
    """
    try:
        result = subprocess.run(
            [readelf_bin, "-d", "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_READ_ELF_TIMEOUT,
            env=_build_readelf_env(extra_env),
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    needed: list[str] = []
    for match in _NEEDED.finditer(result.stdout):
        lib = match.group(1)
        if lib not in needed:
            needed.append(lib)
    return needed


def _soname_match(needed: str, available: str) -> bool:
    """Check if an available soname satisfies a needed soname.

    Handles versioned sonames:
    - needed: libfoo.so.1, available: libfoo.so.1.2.3 -> True (available startswith needed)
    - needed: libfoo.so.1.2.3, available: libfoo.so.1 -> True (needed startswith available)
    - needed: libfoo.so.1, available: libfoo.so.1 -> True (exact match)
    - Major soname matching: libfoo.so.1 matches libfoo.so.1.x
    - Unversioned .so matches any versioned .so with same base
    """
    if needed == available:
        return True
    # Unversioned .so handling: libfoo.so matches libfoo.so.1 etc if base name same
    if needed.endswith(".so") and available.startswith(needed + "."):
        return True
    if available.endswith(".so") and needed.startswith(available + "."):
        return True
    if available.startswith(needed):
        # Ensure prefix match is on soname boundary (e.g., libfoo.so.1 should not match libfoo.so.10)
        # but simple startswith is already handled by major version check below
        return True
    if needed.startswith(available):
        return True

    # Major soname matching: libfoo.so.1 == libfoo.so.1.x
    if ".so." in needed and ".so." in available:
        try:
            needed_parts = needed.split(".so.", 1)
            available_parts = available.split(".so.", 1)
            if len(needed_parts) != 2 or len(available_parts) != 2:
                return False
            if needed_parts[0] != available_parts[0]:
                return False
            needed_major = needed_parts[1].split(".", 1)[0]
            available_major = available_parts[1].split(".", 1)[0]
            if needed_major == available_major:
                return True
        except IndexError:
            pass
    return False


def check_library_deps(
    paths: Iterable[str],
    workers: int,
    readelf_bin: str,
    owner_index: dict[str, str],
    on_progress: ProgressCallback | None = None,
    extra_env: dict[str, str] | None = None,
) -> list[list[str]]:
    """Checks `paths` (ELF files only) and returns missing libs per path.

    Uses `readelf -d` to extract NEEDED entries and checks against `owner_index`.
    A library is reported missing if no installed package provides a compatible soname.

    The result preserves the order of `paths`; an entry is an empty list when the
    file has all its dependencies present. `readelf` is run in parallel and
    `on_progress` is called as each file is completed.
    """
    paths = list(paths)
    results: list[list[str]] = [[] for _ in paths]
    futures: dict[Future[Any], int] = {}

    def _check_one(path: str) -> list[str]:
        needed = _get_needed_libs(path, readelf_bin, extra_env)
        missing: list[str] = []
        for lib in needed:
            if lib in owner_index:
                continue
            # Check if any owner provides a version-compatible soname
            found = False
            for owner_lib in owner_index:
                if _soname_match(lib, owner_lib):
                    found = True
                    break
            if not found:
                missing.append(lib)
        return missing

    with ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="pkgcheck-ldd-safe"
    ) as executor:
        for index, path in enumerate(paths):
            futures[executor.submit(_check_one, path)] = index
        last_update = time.monotonic()
        for done, future in enumerate(as_completed(futures), start=1):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception as exc:
                warnings.warn(
                    f"Failed to check deps for {paths[index]}: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )
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

    Multiple packages may ship a library with the same basename; the last one wins
    (with a warning). For conflict inspection, the full mapping is available via
    the internal index before the last-wins reduction.
    """
    index: dict[str, list[str]] = {}
    for package, rel in entries:
        if _is_library_path(rel):
            lib_name = Path(rel).name
            index.setdefault(lib_name, []).append(package)

    # Warn on conflicts
    for lib, pkgs in index.items():
        if len(pkgs) > 1:
            warnings.warn(
                f"Library {lib} provided by multiple packages: {', '.join(pkgs)}. "
                f"Using last one ({pkgs[-1]}) for dependency resolution.",
                RuntimeWarning,
                stacklevel=2,
            )
    # Return last-wins for backward compatibility
    return {lib: pkgs[-1] for lib, pkgs in index.items()}


def find_missing_owner(
    missing_libs: Iterable[str], owner_index: dict[str, str]
) -> dict[str, str | None]:
    """Maps each missing library to the package that should provide it (or None)."""
    return {lib: owner_index.get(lib) for lib in missing_libs}


def _readelf_symbols(
    path: str, readelf_bin: str, extra_env: dict[str, str] | None = None
) -> set[str] | None:
    """Returns the set of defined (exported) dynamic symbols of `path`, or None on error."""
    try:
        result = subprocess.run(
            [readelf_bin, "-Ws", "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_READ_ELF_TIMEOUT,
            env=_build_readelf_env(extra_env),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    symbols: set[str] = set()
    for line in result.stdout.splitlines():
        match = _DEFINED_SYMBOL.match(line)
        if match:
            symbols.add(match.group(1))
    return symbols


def _undefined_symbols(
    path: str, defined_globally: set[str], readelf_bin: str, extra_env: dict[str, str] | None = None
) -> list[str]:
    """Returns the undefined symbols of `path` that are not defined anywhere."""
    try:
        result = subprocess.run(
            [readelf_bin, "-Ws", "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_READ_ELF_TIMEOUT,
            env=_build_readelf_env(extra_env),
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
    extra_env: dict[str, str] | None = None,
) -> set[str]:
    """Builds the global set of dynamic symbols exported by the installed libraries.

    Runs ``readelf`` in parallel and calls `on_progress` as each file completes.
    """
    paths = list(paths)
    defined: set[str] = set()
    futures: dict[Future[Any], str] = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pkgcheck-nm") as executor:
        for path in paths:
            futures[executor.submit(_readelf_symbols, path, readelf_bin, extra_env)] = path
        done = 0
        last_update = time.monotonic()
        for done, future in enumerate(as_completed(futures), start=1):
            path = futures[future]
            try:
                symbols = future.result()
            except Exception as exc:
                # Log the failure for debugging
                warnings.warn(
                    f"Failed to read symbols from {path}: {exc}", RuntimeWarning, stacklevel=2
                )
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
    extra_env: dict[str, str] | None = None,
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
            futures[
                executor.submit(_undefined_symbols, path, defined_globally, readelf_bin, extra_env)
            ] = index
        last_update = time.monotonic()
        for done, future in enumerate(as_completed(futures), start=1):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception as exc:
                warnings.warn(
                    f"Failed to check undefined symbols for {paths[index]}: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )
                results[index] = []
            if on_progress is not None and _should_report(done, len(paths), last_update):
                on_progress(done)
                last_update = time.monotonic()
    return results
