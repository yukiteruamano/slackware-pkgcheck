"""Bulk extraction of ``FILE LIST:`` sections from package records using ripgrep.

Instead of opening each record from Python, a single ripgrep process walks the whole
/var/log/packages tree and emits, in one pass, the path of every file listed under the
``FILE LIST:`` section. Each line is prefixed with the record name (``--with-filename``),
which allows grouping by package at no extra cost.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from pkgcheck.i18n import t

type PackageFile = tuple[str, str]

# Slackware escapes the non-ASCII bytes of file names as \NNN (octal).
_OCTAL_ESCAPE = re.compile(rb"\\[0-7]{3}")

# Captures the FILE LIST: section from the marker to the end of the file. The '\n?'
# tolerates a final line without a trailing newline; '\r?' tolerates CRLF records
# (third-party/edited files); lines that no longer belong to the section (headers
# such as 'REQUIRES:') are discarded in Python.
_SCAN_PATTERN = r"^FILE LIST:\r?\n(?:[^\n]*\n?)+"

_FILE_LIST_MARKER = "FILE LIST:"

# Section header of a package record (e.g. 'REQUIRES:', 'Depends:'), which may appear
# after the FILE LIST in third-party packages. It must not contain '/', so real file
# paths never match. Whether a matching line really ends the FILE LIST is decided by
# `_is_section_header`.
_SECTION_HEADER = re.compile(r"^[A-Z][A-Za-z0-9 _-]*:$")

_INSTALL_PREFIX = "install/"

_PSEUDO_PREFIXES = ("dev/", "sys/", "proc/", "run/", "tmp/", "var/run/")

_RG_TIMEOUT = 300

type Prefixes = tuple[str, ...]


def _is_safe_rel(rel: str) -> bool:
    """Returns whether `rel` is a safe relative path (no traversal, no absolute).

    Rejects absolute paths, ``..`` components and empty segments that would
    escape the filesystem root when later joined as ``f"/{rel}"``. Slackware
    records never contain ``..`` but third-party packages could.
    """
    if not rel or rel.startswith("/") or rel.startswith("//"):
        return False
    # Fast path: common traversal marker
    if ".." not in rel:
        return True
    parts = rel.split("/")
    return ".." not in parts


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Result of the ripgrep scan."""

    entries: list[PackageFile]
    excluded_install: int
    excluded_pseudo: int


# RG flags for control
_RG_FLAGS = (
    "--multiline",
    "--with-filename",
    "--no-heading",
    "--only-matching",
    "--color",
    "never",
    "--no-config",
    "--no-ignore",
    "--no-messages",
    "--hidden",
)


def build_rg_command(rg_bin: str, packages_dir: Path) -> list[str]:
    """Builds the ripgrep command that extracts all ``FILE LIST:`` sections.

    ``--`` stops option parsing so a directory whose name starts with ``-`` is never
    interpreted as a flag.
    """
    return [rg_bin, *_RG_FLAGS, _SCAN_PATTERN, "--", str(packages_dir)]


def _octal_to_byte(match: re.Match[bytes]) -> bytes:
    """Decodes a ``\\NNN`` octal escape into a single byte, tolerating malformed values.

    Slackware only encodes bytes 0-255, but a third-party record could contain an
    escape above ``\\377``; such a value is clamped to ``0xFF`` instead of crashing.
    """
    value = int(match.group()[1:], 8)
    return bytes([value if value <= 255 else 0xFF])


def _unescape_path(rel: str) -> str:
    """Decodes the ``\\NNN`` octal escapes Slackware uses for non-ASCII bytes."""
    if "\\" not in rel:
        return rel
    decoded = _OCTAL_ESCAPE.sub(_octal_to_byte, rel.encode())
    return decoded.decode("utf-8", "replace")


def _is_section_header(rels: list[str], index: int) -> bool:
    """Returns whether the line at `index` really ends the FILE LIST.

    A line is treated as a section header (e.g. ``REQUIRES:``) only if it matches the
    header pattern and is followed by content that does not look like file paths. A real
    file whose name looks like a header (e.g. ``README:``) is therefore kept when it is
    followed by more entries or by another header.
    """
    rel = rels[index]
    if not _SECTION_HEADER.match(rel):
        return False
    for nxt in rels[index + 1 :]:
        if not nxt or nxt.endswith("/"):
            continue
        return not ("/" in nxt or _SECTION_HEADER.match(nxt))
    return False


def scan_package_files(
    packages_dir: Path,
    rg_bin: str,
    pseudo_prefixes: Prefixes = _PSEUDO_PREFIXES,
) -> ScanResult:
    """Returns the files registered in ``FILE LIST:`` grouped by package.

    Directories (entries ending in ``/``), the ``FILE LIST:`` marker, the install scripts
    under ``install/`` (``doinst.sh``, ``slack-desc``, etc.) and the pseudo-filesystems
    (``dev/``, ``sys/``, ``proc/``, ``run/``, ``tmp/``...), which never persist on disk,
    are discarded. Later section headers (e.g. ``REQUIRES:``) end the extraction for the
    package, and non-ASCII bytes in names are decoded from their octal ``\\NNN`` escapes.
    """
    try:
        result = subprocess.run(
            build_rg_command(rg_bin, packages_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_RG_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            t("ripgrep timed out scanning {path}").format(path=packages_dir)
        ) from exc
    if result.returncode >= 2:
        detail = result.stderr.strip() or f"exit code {result.returncode}"
        raise RuntimeError(
            t("ripgrep could not scan {path}: {detail}").format(path=packages_dir, detail=detail)
        )

    lines = result.stdout.splitlines()
    by_package: dict[str, list[str]] = {}
    for line in lines:
        if not line:
            continue
        package_path, _, rel_path = line.partition(":")
        by_package.setdefault(Path(package_path).name, []).append(rel_path.rstrip("\r"))

    entries: list[PackageFile] = []
    excluded_install = 0
    excluded_pseudo = 0
    for package, rels in by_package.items():
        in_file_list = False
        for index, rel_path in enumerate(rels):
            if rel_path == _FILE_LIST_MARKER:
                in_file_list = True
                continue
            if not in_file_list:
                continue
            if not rel_path or rel_path.endswith("/"):
                continue
            if _is_section_header(rels, index):
                in_file_list = False
                continue
            if rel_path.startswith(_INSTALL_PREFIX):
                excluded_install += 1
                continue
            if rel_path.startswith(pseudo_prefixes):
                excluded_pseudo += 1
                continue
            if not _is_safe_rel(rel_path):
                # Skip path traversal attempts; count as pseudo to keep stats consistent
                excluded_pseudo += 1
                continue
            decoded = _unescape_path(rel_path)
            if not _is_safe_rel(decoded):
                excluded_pseudo += 1
                continue
            entries.append((package, decoded))
    return ScanResult(
        entries=entries,
        excluded_install=excluded_install,
        excluded_pseudo=excluded_pseudo,
    )
