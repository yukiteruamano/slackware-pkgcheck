"""Legacy test helpers — compatibility shims for old libdeps private names.

Production code (`src/pkgcheck/libdeps.py`) exposes only the canonical names
(``_ldd_missing``, ``_nm_symbols``, ``_get_undefined_symbols``). These aliases
exist solely so old tests keep importing the historic names without polluting
production. New tests must use the canonical names directly.
"""

from __future__ import annotations

from pkgcheck.libdeps import _get_undefined_symbols, _ldd_missing, _nm_symbols


def _get_needed_libs(path: str, ldd_bin: str, extra_env: dict[str, str] | None = None) -> list[str]:
    """Legacy alias for ``_ldd_missing`` (test use only)."""
    return _ldd_missing(path, ldd_bin, extra_env)


def _ldd_symbols(
    path: str, nm_bin: str, extra_env: dict[str, str] | None = None
) -> set[str] | None:
    """Legacy alias for ``_nm_symbols`` (test use only)."""
    return _nm_symbols(path, nm_bin, extra_env)


def _undefined_symbols(
    path: str, defined_globally: set[str], nm_bin: str, extra_env: dict[str, str] | None = None
) -> list[str]:
    """Legacy alias for ``_get_undefined_symbols`` (test use only)."""
    return _get_undefined_symbols(path, defined_globally, nm_bin, extra_env)
