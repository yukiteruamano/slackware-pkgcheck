"""Verification of dynamic library dependencies for installed ELF binaries.

Uses ``ldd`` for library deps (fast, loader-aware) and ``nm -D`` for
undefined symbols.  Requires the system tools ``ldd`` (glibc) and ``nm``
(binutils).  Only run on a trusted system - ``ldd`` executes the loader.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed, wait
from pathlib import Path
from typing import Any

wait = wait  # expose for test patching

# Minimum interval between two progress updates (seconds).
_PROGRESS_INTERVAL = 0.1

# ldd "not found" line:  libfoo.so.1 => not found
_NOT_FOUND = re.compile(r"^\s*(?P<lib>\S+)\s+=>\s+not found", re.MULTILINE)
_NOT_DYNAMIC = re.compile(r"not a dynamic executable|statically linked")

_LDD_TIMEOUT = 60
_NM_TIMEOUT = 60

type ProgressCallback = Callable[[int], None]
type LibEntries = Iterable[tuple[str, str]]

# Shared libraries live under these prefixes; their basename maps to a package.
_LIB_PREFIXES = ("usr/lib/", "usr/lib64/", "lib/", "lib64/", "usr/libexec/")

# Glibc merged stubs: since glibc 2.34 these are provided by libc.so.6
_GLIBC_MERGED_STUBS: frozenset[str] = frozenset(
    {
        "libdl.so.2",
        "libpthread.so.0",
        "libutil.so.1",
        "libanl.so.1",
    }
)


def _canonical_libname(name: str) -> str:
    """Canonicalizes Slackware hyphen versioning to dot soname."""
    if name.endswith(".so") and "-" in name:
        idx = name.rfind("-")
        base = name[:idx]
        ver = name[idx + 1 : -3]  # strip .so
        if ver and ver[0].isdigit():
            return f"{base}.so.{ver}"
    return name


def _has_libc(owner_index: dict[str, str]) -> bool:
    """Returns whether libc (provider for merged stubs) is installed."""
    return any(k.startswith("libc.so") or k.startswith("libc-") for k in owner_index)


def _should_report(done: int, total: int, last_update: float) -> bool:
    """Returns whether a progress update should be reported now."""
    if done >= total:
        return True
    return time.monotonic() - last_update >= _PROGRESS_INTERVAL


def _build_ldd_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    """Builds sanitized env for ldd (clear LD_* that could hijack)."""
    env = {**os.environ}
    if extra_env:
        env.update(extra_env)
    env["LC_ALL"] = "C"
    # Defense in depth: clear loader hijack vars (ldd respects them)
    for key in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_BIND_NOW"):
        env.pop(key, None)
    return env


def _build_nm_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    env = {**os.environ}
    if extra_env:
        env.update(extra_env)
    env["LC_ALL"] = "C"
    return env


def _ldd_missing(path: str, ldd_bin: str, extra_env: dict[str, str] | None = None) -> list[str]:
    """Runs ``ldd -- path`` and returns libraries reported as ``not found``.

    Filters glibc merged stubs when libc is known to be installed to avoid
    false positives on glibc 2.34+ systems. Returns [] for statically linked
    or non-dynamic files.
    """
    try:
        result = subprocess.run(
            [ldd_bin, "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_LDD_TIMEOUT,
            env=_build_ldd_env(extra_env),
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    # ldd writes "not a dynamic executable" to stderr or stdout for static
    combined = (result.stdout or "") + "\n" + (result.stderr or "")
    if _NOT_DYNAMIC.search(combined):
        return []
    missing: list[str] = []
    for match in _NOT_FOUND.finditer(result.stdout):
        lib = match.group("lib")
        if lib not in missing:
            missing.append(lib)
    # Also check stderr in case ldd writes there on some systems
    for match in _NOT_FOUND.finditer(result.stderr or ""):
        lib = match.group("lib")
        if lib not in missing:
            missing.append(lib)
    return missing


def _soname_match(needed: str, available: str) -> bool:
    """Check if an available soname satisfies a needed soname."""
    if needed == available:
        return True
    # Unversioned .so handling
    if needed.endswith(".so") and available.startswith(needed + "."):
        return True
    if available.endswith(".so") and needed.startswith(available + "."):
        return True
    # Major soname matching with boundary check
    if ".so." in needed and ".so." in available:
        needed_base, needed_ver = needed.split(".so.", 1)
        available_base, available_ver = available.split(".so.", 1)
        if needed_base != available_base:
            return False
        needed_major = needed_ver.split(".", 1)[0]
        available_major = available_ver.split(".", 1)[0]
        return needed_major == available_major
    # For .so.N vs .so.N.M without .so. split already handled, fallback to exact
    # Prevent libfoo.so.1 matching libfoo.so.10
    return needed.startswith(available + ".") or available.startswith(needed + ".")


def _filter_missing_with_owner(missing: list[str], owner_index: dict[str, str]) -> list[str]:
    """Filters ``missing`` using owner_index soname match.

    A library is considered NOT missing if any installed package provides a
    compatible soname, or it is a glibc merged stub and libc is installed.
    ``ldd`` output is authoritative: if ``ldd`` reports ``not found``, report it.
    """
    if not missing:
        return []
    has_libc = _has_libc(owner_index)
    filtered: list[str] = []
    for lib in missing:
        if lib in _GLIBC_MERGED_STUBS and has_libc:
            continue
        # Check owner_index first (fast, authoritative for Slackware DB)
        if lib in owner_index:
            continue
        found = False
        for owner_lib in owner_index:
            if _soname_match(lib, owner_lib):
                found = True
                break
        if found:
            continue
        # ldd is authoritative: if ldd says not found, report it.
        filtered.append(lib)
    return filtered


def check_library_deps(
    paths: Iterable[str],
    workers: int,
    ldd_bin: str,
    owner_index: dict[str, str],
    on_progress: ProgressCallback | None = None,
    extra_env: dict[str, str] | None = None,
) -> list[list[str]]:
    """Checks ``paths`` via ldd and returns missing libs per path.

    Alias kept for backwards compatibility; prefer ``check_libs_deps``.
    """
    return check_libs_deps(paths, workers, ldd_bin, owner_index, on_progress, extra_env)


def check_libs_deps(
    paths: Iterable[str],
    workers: int,
    ldd_bin: str,
    owner_index: dict[str, str],
    on_progress: ProgressCallback | None = None,
    extra_env: dict[str, str] | None = None,
) -> list[list[str]]:
    """Checks ``paths`` (ELF files only) and returns missing libs per path.

    Uses ``ldd`` to query the loader; fast and loader-aware. Filters glibc
    merged stubs. Preserves order of ``paths``. Parallel via ThreadPoolExecutor
    with throttled progress.
    """
    paths = list(paths)
    if not paths:
        return []
    results: list[list[str]] = [[] for _ in paths]
    futures: dict[Future[Any], int] = {}

    def _check_one(path: str) -> list[str]:
        raw = _ldd_missing(path, ldd_bin, extra_env)
        return _filter_missing_with_owner(raw, owner_index)

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pkgcheck-ldd") as executor:
        for index, path in enumerate(paths):
            futures[executor.submit(_check_one, path)] = index
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
    """Returns whether ``rel`` looks like a shared library path."""
    name = Path(rel).name
    return rel.startswith(_LIB_PREFIXES) and (name.endswith(".so") or ".so." in name)


def build_library_owner_index(entries: LibEntries) -> dict[str, str]:
    """Maps each installed library basename to the package that provides it."""
    index: dict[str, str] = {}
    for package, rel in entries:
        if _is_library_path(rel):
            lib_name = Path(rel).name
            # Also index canonical name for hyphen variants
            index[lib_name] = package
            canon = _canonical_libname(lib_name)
            if canon != lib_name:
                index[canon] = package
            # Also ensure dot-form is indexed if original was hyphen
    return index


def find_missing_owner(
    missing_libs: Iterable[str], owner_index: dict[str, str]
) -> dict[str, str | None]:
    """Maps each missing library to the package that should provide it (or None).

    Tries soname-compatible match if exact basename not found.
    """
    result: dict[str, str | None] = {}
    for lib in missing_libs:
        if lib in owner_index:
            result[lib] = owner_index[lib]
            continue
        # Try soname match
        owner: str | None = None
        for avail, pkg in owner_index.items():
            if _soname_match(lib, avail):
                owner = pkg
                break
        result[lib] = owner
    return result


# --- nm helpers for undefined symbols ---


def _nm_symbols(path: str, nm_bin: str, extra_env: dict[str, str] | None = None) -> set[str] | None:
    """Returns defined symbols via ``nm -D`` or None on error."""
    try:
        result = subprocess.run(
            [nm_bin, "-D", "--defined-only", "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_NM_TIMEOUT,
            env=_build_nm_env(extra_env),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 and not result.stdout:
        return None
    symbols: set[str] = set()
    for line in result.stdout.splitlines():
        # nm -D output: address type name  e.g. "0000000000000000 T main"
        # defined-only ensures no U
        parts = line.strip().split()
        if len(parts) >= 3:
            # last part is name (may contain @GLIBC...)
            name = parts[-1]
            if name and name != "U":
                symbols.add(name)
        elif len(parts) == 2 and parts[0] != "U":
            symbols.add(parts[1])
    return symbols


def _get_undefined_symbols(
    path: str, defined_globally: set[str], nm_bin: str, extra_env: dict[str, str] | None = None
) -> list[str]:
    """Returns undefined symbols via ``nm -D --undefined-only`` filtered."""
    try:
        result = subprocess.run(
            [nm_bin, "-D", "--undefined-only", "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_NM_TIMEOUT,
            env=_build_nm_env(extra_env),
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    undefined: list[str] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        # format: "                 U puts" or "                 U puts@GLIBC_2.2.5"
        stripped = line.strip()
        if not stripped:
            continue
        # nm undefined line: typically "U symbol"
        parts = stripped.split()
        if len(parts) == 2 and parts[0] == "U":
            name = parts[1]
        elif len(parts) == 1 and stripped.startswith("U "):
            name = stripped[2:].strip()
        elif " U " in line:
            # fallback: split on U
            try:
                name = line.split(" U ", 1)[1].strip().split()[0]
            except IndexError:
                continue
        else:
            continue
        if not name or name in seen or name in defined_globally:
            continue
        seen.add(name)
        undefined.append(name)
    return undefined


def collect_defined_symbols(
    paths: Iterable[str],
    workers: int,
    nm_bin: str,
    on_progress: ProgressCallback | None = None,
    extra_env: dict[str, str] | None = None,
) -> set[str]:
    """Builds the global set of dynamic symbols exported by installed libraries."""
    paths = list(paths)
    if not paths:
        return set()
    defined: set[str] = set()
    futures: dict[Future[Any], str] = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pkgcheck-nm") as executor:
        for path in paths:
            futures[executor.submit(_nm_symbols, path, nm_bin, extra_env)] = path
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
    nm_bin: str,
    on_progress: ProgressCallback | None = None,
    extra_env: dict[str, str] | None = None,
) -> list[list[str]]:
    """Returns, per path, the undefined dynamic symbols not in ``defined_globally``."""
    paths = list(paths)
    if not paths:
        return []
    results: list[list[str]] = [[] for _ in paths]
    futures: dict[Future[Any], int] = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pkgcheck-sym") as executor:
        for index, path in enumerate(paths):
            futures[
                executor.submit(_get_undefined_symbols, path, defined_globally, nm_bin, extra_env)
            ] = index
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
