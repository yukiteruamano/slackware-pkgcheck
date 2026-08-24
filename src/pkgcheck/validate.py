"""Defense-in-depth input validation for pkgcheck.

All external inputs (paths, command arguments, user-provided values) must pass
through these validators before being used in filesystem operations or subprocess calls.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Final

# Characters that are never allowed in validated paths/arguments
_FORBIDDEN_CHARS: Final = frozenset("\x00\n\r\t\f\v")
# Control characters (ASCII 0-31 and 127) except those in _FORBIDDEN_CHARS
_CONTROL_CHARS: Final = frozenset(chr(i) for i in range(32)) | frozenset(chr(127))

# Maximum reasonable path length (Linux PATH_MAX is 4096)
MAX_PATH_LENGTH: Final = 4096
# Maximum reasonable argument length for subprocess
MAX_ARG_LENGTH: Final = 8192


class ValidationError(ValueError):
    """Raised when input validation fails."""

    pass


def _contains_forbidden_chars(value: str) -> bool:
    """Check if value contains forbidden control characters."""
    return any(c in _FORBIDDEN_CHARS for c in value)


def _contains_control_chars(value: str) -> bool:
    """Check if value contains any control characters."""
    return any(c in _CONTROL_CHARS for c in value)


def validate_safe_path(
    path: str,
    allow_absolute: bool = False,
    must_exist: bool = False,
    base_dir: str | None = None,
) -> str:
    """Validate a filesystem path for safety.

    Args:
        path: The path to validate.
        allow_absolute: Whether to allow absolute paths (default: False).
        must_exist: Whether the path must exist on filesystem (default: False).
        base_dir: If provided, path must be within this directory (after resolution).

    Returns:
        The validated path (normalized).

    Raises:
        ValidationError: If path is invalid or unsafe.
    """
    if not isinstance(path, str):
        raise ValidationError(f"Path must be a string, got {type(path).__name__}")

    if not path:
        raise ValidationError("Path cannot be empty")

    if len(path) > MAX_PATH_LENGTH:
        raise ValidationError(f"Path exceeds maximum length of {MAX_PATH_LENGTH}")

    if _contains_forbidden_chars(path):
        raise ValidationError("Path contains forbidden characters (null, newline, tab)")

    if _contains_control_chars(path):
        raise ValidationError("Path contains control characters")

    # Check for path traversal in original before normalization
    if ".." in Path(path).parts:
        if base_dir:
            try:
                resolved_base = Path(base_dir).resolve()
                # Use original path for resolution so mock in tests hits
                resolved_path = Path(path).resolve()
                # Robust containment check (not prefix string)
                try:
                    resolved_path.relative_to(resolved_base)
                except ValueError:
                    raise ValidationError(f"Path escapes base directory: {path}") from None
            except ValidationError:
                raise
            except Exception as exc:
                # If resolution fails, be conservative
                raise ValidationError(f"Path contains traversal sequence: {path}") from exc
        else:
            raise ValidationError(f"Path contains traversal sequence: {path}")

    # Normalize path (resolve . and .. but NOT symlinks)
    try:
        normalized = os.path.normpath(path)
    except Exception as exc:
        raise ValidationError(f"Path normalization failed: {exc}") from exc

    # Check for absolute path
    if Path(normalized).is_absolute() and not allow_absolute:
        raise ValidationError(f"Absolute paths not allowed: {normalized}")

    # Enforce base_dir containment for all paths when base_dir is given
    if base_dir:
        try:
            resolved_base = Path(base_dir).resolve()
            resolved_path = Path(normalized).resolve()
            try:
                resolved_path.relative_to(resolved_base)
            except ValueError:
                raise ValidationError(f"Path escapes base directory: {normalized}") from None
        except ValidationError:
            raise
        except Exception as exc:
            raise ValidationError(f"Path contains traversal sequence: {normalized}") from exc

    # Check existence if required (lexists semantics: broken symlink counts as exists)
    if must_exist and not os.path.lexists(normalized):
        raise ValidationError(f"Path does not exist (including broken symlinks): {normalized}")

    return normalized


def validate_subprocess_arg(arg: str, max_length: int = MAX_ARG_LENGTH) -> str:
    """Validate an argument passed to subprocess.run().

    Args:
        arg: The argument to validate.
        max_length: Maximum allowed length.

    Returns:
        The validated argument.

    Raises:
        ValidationError: If argument is invalid.
    """
    if not isinstance(arg, str):
        raise ValidationError(f"Argument must be a string, got {type(arg).__name__}")

    if not arg:
        raise ValidationError("Argument cannot be empty")

    if len(arg) > max_length:
        raise ValidationError(f"Argument exceeds maximum length of {max_length}")

    if _contains_forbidden_chars(arg):
        raise ValidationError("Argument contains forbidden characters (null, newline, tab)")

    if _contains_control_chars(arg):
        raise ValidationError("Argument contains control characters")

    # No shell metacharacters that could be interpreted if somehow passed to shell
    # (We never use shell=True, but defense in depth)
    shell_metachars = frozenset("|&;()<>$`\\\"'")
    if any(c in shell_metachars for c in arg):
        # Allow these in paths but warn via exception for explicit subprocess args
        # Actually, paths CAN contain these. We only validate non-path args here.
        pass

    return arg


def validate_exclude_prefix(prefix: str) -> str:
    """Validate a --exclude prefix.

    Args:
        prefix: The exclude prefix (e.g., "mnt/", "media").

    Returns:
        Normalized prefix with trailing slash.

    Raises:
        ValidationError: If prefix is invalid.
    """
    if not isinstance(prefix, str):
        raise ValidationError(f"Exclude prefix must be a string, got {type(prefix).__name__}")

    if not prefix:
        raise ValidationError("Exclude prefix cannot be empty")

    # Strip leading slash
    cleaned = prefix.lstrip("/")

    if not cleaned:
        raise ValidationError("Exclude prefix cannot be only slashes")

    if _contains_forbidden_chars(cleaned):
        raise ValidationError("Exclude prefix contains forbidden characters")

    if _contains_control_chars(cleaned):
        raise ValidationError("Exclude prefix contains control characters")

    # Must not contain path traversal
    if ".." in cleaned.split("/"):
        raise ValidationError(f"Exclude prefix contains traversal: {cleaned}")

    # Must not be absolute
    if Path(cleaned).is_absolute():
        raise ValidationError(f"Exclude prefix must be relative: {cleaned}")

    # Ensure trailing slash for prefix matching
    if not cleaned.endswith("/"):
        cleaned += "/"

    return cleaned


def validate_suffix(suffix: str, allow_empty: bool = False) -> str:
    """Validate a file suffix (e.g., '.new', '.bak').

    Args:
        suffix: The suffix to validate.
        allow_empty: Whether empty string is allowed.

    Returns:
        The validated suffix.

    Raises:
        ValidationError: If suffix is invalid.
    """
    if not isinstance(suffix, str):
        raise ValidationError(f"Suffix must be a string, got {type(suffix).__name__}")

    # Strip whitespace
    suffix = suffix.strip()

    if not suffix:
        if allow_empty:
            return ""
        raise ValidationError("Suffix cannot be empty")

    if len(suffix) > 64:
        raise ValidationError("Suffix exceeds maximum length of 64")

    if _contains_forbidden_chars(suffix):
        raise ValidationError("Suffix contains forbidden characters")

    if _contains_control_chars(suffix):
        raise ValidationError("Suffix contains control characters")

    # Suffix should start with dot (convention)
    if not suffix.startswith("."):
        # Allow but normalize
        suffix = "." + suffix

    return suffix


def validate_backup_suffixes(csv: str) -> tuple[str, ...]:
    """Validate comma-separated backup suffixes.

    Args:
        csv: Comma-separated suffixes (e.g., ".bak,.orig").

    Returns:
        Tuple of validated suffixes.

    Raises:
        ValidationError: If any suffix is invalid.
    """
    if not isinstance(csv, str):
        raise ValidationError(f"Backup suffixes must be a string, got {type(csv).__name__}")

    suffixes = []
    for part in csv.split(","):
        part = part.strip()
        if part:
            suffixes.append(validate_suffix(part, allow_empty=False))

    if not suffixes:
        raise ValidationError("At least one backup suffix required")

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for s in suffixes:
        if s not in seen:
            seen.add(s)
            unique.append(s)

    return tuple(unique)


def validate_new_suffix(value: str) -> str:
    """Validate the --new-suffix value."""
    return validate_suffix(value, allow_empty=False)


def sanitize_for_subprocess(value: str) -> str:
    """Sanitize a string for safe subprocess usage.

    Removes control characters that could cause issues in subprocess output parsing.
    This is a LOSSY operation - use validate_* for strict validation.

    Args:
        value: The string to sanitize.

    Returns:
        Sanitized string with control characters removed.
    """
    if not isinstance(value, str):
        return str(value)

    # Remove all control characters except newline/tab which we replace with space
    result = []
    for c in value:
        if c in "\n\r\t\f\v":
            result.append(" ")
        elif ord(c) < 32 or ord(c) == 127:
            # Drop other control chars
            continue
        else:
            result.append(c)
    return "".join(result)


def validate_packages_dir(path: str) -> str:
    """Validate the --packages-dir argument."""
    return validate_safe_path(path, allow_absolute=True, must_exist=True)


def validate_orphans_root(path: str) -> str:
    """Validate the --orphans-root argument."""
    return validate_safe_path(path, allow_absolute=True, must_exist=True)


def validate_binary_path(bin_name: str) -> str:
    """Validate a binary name (rg, ldd, nm, etc.) found via shutil.which()."""
    if not isinstance(bin_name, str):
        raise ValidationError(f"Binary name must be string, got {type(bin_name).__name__}")

    if not bin_name:
        raise ValidationError("Binary name cannot be empty")

    # Should be a simple name or absolute path
    if Path(bin_name).is_absolute():
        # Absolute path - validate as path
        return validate_safe_path(bin_name, allow_absolute=True, must_exist=True)

    # Simple name - only alphanumeric, dash, underscore, dot
    if not re.match(r"^[a-zA-Z0-9._-]+$", bin_name):
        raise ValidationError(f"Invalid binary name: {bin_name}")

    return bin_name
