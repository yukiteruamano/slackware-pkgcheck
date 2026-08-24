"""Console output (rich) and writing of the run log to file."""

from __future__ import annotations

import contextlib
import grp
import json
import os
import tempfile
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from pkgcheck import __version__
from pkgcheck.i18n import t

type MissingIndex = dict[str, list[str]]
type NoAccessIndex = dict[str, list[str]]
type BackupIndex = dict[str, list[str]]
type PendingNewIndex = dict[str, list[str]]
type ErrorsIndex = dict[str, list[str]]
type OrphansIndex = list[str]


# A single broken binary: its missing shared libraries and (best-effort) which
# installed package should provide each one.
@dataclass(frozen=True, slots=True)
class BrokenBinary:
    """A binary/library with at least one missing shared library dependency."""

    binary: str
    missing: list[str]
    provided_by: dict[str, str | None]


type BrokenLibsIndex = dict[str, list[BrokenBinary]]
type UndefinedSymbolsIndex = dict[str, dict[str, list[str]]]

_LOG_TIME_FORMAT = "%d-%m-%Y-%H-%M-%S-%f"

_BANNER_LEN = 12


def report_path(log_dir: Path, when: datetime, fmt: str) -> Path:
    """Returns the automatic log path using the ``pkgcheck-<date>.log`` convention."""
    return log_dir / f"pkgcheck-{when:{_LOG_TIME_FORMAT}}.{fmt}"


def unique_report_path(log_dir: Path, when: datetime, fmt: str) -> Path:
    """Returns a log path that does not yet exist, using microsecond precision and UUID."""
    # Use microsecond precision for the base path
    path = report_path(log_dir, when, fmt)
    # Fast path: no collision
    try:
        if not path.exists():
            return path
    except OSError:
        # If we cannot stat, return original and let write_report handle error
        return path

    # Collision - use UUID suffix for guaranteed uniqueness
    return log_dir / f"pkgcheck-{when:{_LOG_TIME_FORMAT}}-{uuid.uuid4().hex[:8]}.{fmt}"


@dataclass(frozen=True, slots=True)
class Summary:
    """Aggregated summary of a pkgcheck run."""

    packages: int
    files_checked: int
    missing: int
    backup: int
    pending_new: int
    no_access: int
    errors: int
    excluded_install: int
    excluded_pseudo: int
    broken_binaries: int = 0
    missing_libs: int = 0
    undefined_symbol_binaries: int = 0
    orphans: int = 0


def print_summary(console: Console, summary: Summary, elapsed: float) -> None:
    """Prints the final summary as a rich table."""
    table = Table(title=t("pkgcheck summary"))
    table.add_column(t("Metric"))
    table.add_column(t("Amount"), justify="right")

    table.add_row(t("Packages analyzed"), f"{summary.packages:,}")
    table.add_row(t("Files verified"), f"{summary.files_checked:,}")
    table.add_row(t("Missing files"), f"[red]{summary.missing:,}[/red]")
    if summary.backup:
        table.add_row(
            t("Files with backup only (.bak/.orig)"),
            f"[yellow]{summary.backup:,}[/yellow]",
        )
    if summary.pending_new:
        table.add_row(
            t("Configs .new pending review"),
            f"[yellow]{summary.pending_new:,}[/yellow]",
        )
    if summary.no_access:
        table.add_row(t("Files without access"), f"[yellow]{summary.no_access:,}[/yellow]")
    if summary.errors:
        table.add_row(t("Verification errors"), f"[yellow]{summary.errors:,}[/yellow]")
    if summary.excluded_install:
        table.add_row(t("Install scripts excluded"), f"{summary.excluded_install:,}")
    if summary.excluded_pseudo:
        table.add_row(t("Pseudo-filesystems excluded"), f"{summary.excluded_pseudo:,}")
    if summary.broken_binaries:
        table.add_row(
            t("Binaries with missing library deps"),
            f"[red]{summary.broken_binaries:,}[/red]",
        )
    if summary.missing_libs:
        table.add_row(
            t("Missing shared libraries"),
            f"[red]{summary.missing_libs:,}[/red]",
        )
    if summary.undefined_symbol_binaries:
        table.add_row(
            t("Binaries with undefined symbols"),
            f"[yellow]{summary.undefined_symbol_binaries:,}[/yellow]",
        )
    if summary.orphans:
        table.add_row(
            t("Orphan files"),
            f"[yellow]{summary.orphans:,}[/yellow]",
        )
    table.add_row(t("Total time"), f"{elapsed:.2f}s")

    console.print()
    console.print(table)


def _text_section(lines: list[str], header: str) -> None:
    """Adds a prominent section banner (====) around `header` in the text log."""
    lines.extend(["", "=" * 46, header, "=" * 46])


def _escape_tsv(value: str) -> str:
    """Escapes tabs and newlines for TSV log sections."""
    return (
        value.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")
    )


def _banner_heading(heading: str, style: str) -> str:
    """Wraps a breakdown heading so it stands out: color + asterisks."""
    stars = "*" * _BANNER_LEN
    return f"[{style}]{stars} {heading} {stars}[/{style}]"


def print_breakdown(
    console: Console,
    missing_by_package: MissingIndex,
    max_rows: int | None = None,
    title: str | None = None,
    style: str = "bold yellow",
) -> None:
    """Prints the breakdown of files grouped by package."""
    if max_rows is not None and max_rows < 1:
        return
    heading = title or t("Missing files by package")
    console.print()
    tree = Tree(_banner_heading(heading, style))
    for index, (package, paths) in enumerate(sorted(missing_by_package.items())):
        if max_rows is not None and index >= max_rows:
            remaining = len(missing_by_package) - index
            tree.add(t("... and {remaining} more packages").format(remaining=remaining))
            break
        branch = tree.add(f"[bold cyan]{escape(package)}[/bold cyan] ({len(paths)})")
        # Limit paths per package to respect max_rows (show max_rows files per package)
        limit = max_rows if max_rows is not None else 2500
        for p in paths[:limit]:
            branch.add(Text(p))
        if len(paths) > limit:
            branch.add(t("... and {remaining} more files").format(remaining=len(paths) - limit))
    console.print(tree)
    console.print()


def print_broken_libs(
    console: Console,
    broken_libs: BrokenLibsIndex,
    max_rows: int | None = None,
    title: str | None = None,
    style: str = "bold yellow",
) -> None:
    """Prints the breakdown of binaries with missing library deps grouped by package."""
    if max_rows is not None and max_rows < 1:
        return
    heading = title or t("Binaries with missing library deps by package")
    console.print()
    tree = Tree(_banner_heading(heading, style))
    for index, (package, items) in enumerate(sorted(broken_libs.items())):
        if max_rows is not None and index >= max_rows:
            remaining = len(broken_libs) - index
            tree.add(t("... and {remaining} more packages").format(remaining=remaining))
            break
        branch = tree.add(f"[bold cyan]{escape(package)}[/bold cyan] ({len(items)})")
        limit = max_rows if max_rows is not None else 2500
        for item in items[:limit]:
            deps = ", ".join(item.missing)
            provided = ", ".join(
                f"{lib}={owner or t('(unknown)')}" for lib, owner in item.provided_by.items()
            )
            label = f"{item.binary} -> {deps}"
            if provided:
                label = f"{label} [{provided}]"
            branch.add(Text(label))
        if len(items) > limit:
            branch.add(t("... and {remaining} more files").format(remaining=len(items) - limit))
    console.print(tree)
    console.print()


def write_report(
    output: Path,
    summary: Summary,
    missing_by_package: MissingIndex,
    no_access_by_package: NoAccessIndex,
    backup_by_package: BackupIndex,
    pending_new_by_package: PendingNewIndex,
    errors_by_package: ErrorsIndex,
    when: datetime | None = None,
    broken_libs: BrokenLibsIndex | None = None,
    undefined_symbols: UndefinedSymbolsIndex | None = None,
    orphans: OrphansIndex | None = None,
) -> None:
    """Writes the report to `output`; the format depends on the extension (.json/.log)."""
    if output.suffix.lower() == ".json":
        content = json_report(
            summary,
            missing_by_package,
            no_access_by_package,
            backup_by_package,
            pending_new_by_package,
            errors_by_package,
            when,
            broken_libs,
            undefined_symbols,
            orphans,
        )
    else:
        content = _text_report(
            summary,
            missing_by_package,
            no_access_by_package,
            backup_by_package,
            pending_new_by_package,
            errors_by_package,
            when,
            broken_libs,
            undefined_symbols,
            orphans,
        )
    # Atomic write via temp file in same directory to avoid partial logs on crash
    output.parent.mkdir(parents=True, exist_ok=True)
    # Ensure directory is 0755 (mkdir respects umask, so enforce)
    with contextlib.suppress(OSError):
        Path(output.parent).chmod(0o755)
    with contextlib.suppress(OSError, LookupError):
        gid = grp.getgrnam("wheel").gr_gid
        os.chown(output.parent, 0, gid)
    fd, tmp_path = tempfile.mkstemp(dir=str(output.parent), prefix=".pkgcheck-")
    # Ensure log is 0644 regardless of umask (mkstemp creates 0600)
    with contextlib.suppress(OSError):
        os.fchmod(fd, 0o644)
    with contextlib.suppress(OSError, LookupError):
        gid = grp.getgrnam("wheel").gr_gid
        os.fchown(fd, 0, gid)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, output)
        # Enforce 0644 on final file (replace preserves tmp perms, but ensure)
        with contextlib.suppress(OSError):
            Path(output).chmod(0o644)
        with contextlib.suppress(OSError, LookupError):
            gid = grp.getgrnam("wheel").gr_gid
            os.chown(output, 0, gid)
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def json_report(
    summary: Summary,
    missing_by_package: MissingIndex,
    no_access_by_package: NoAccessIndex,
    backup_by_package: BackupIndex,
    pending_new_by_package: PendingNewIndex,
    errors_by_package: ErrorsIndex,
    when: datetime | None = None,
    broken_libs: BrokenLibsIndex | None = None,
    undefined_symbols: UndefinedSymbolsIndex | None = None,
    orphans: OrphansIndex | None = None,
) -> str:
    """Returns the full report as a JSON document."""
    data = {
        "generator": "pkgcheck",
        "version": __version__,
        "summary": asdict(summary),
        "missing": missing_by_package,
        "files_backup": backup_by_package,
        "files_pending_new": pending_new_by_package,
        "no_access": no_access_by_package,
        "files_errors": errors_by_package,
    }
    if broken_libs:
        data["broken_libs"] = {
            package: [
                {
                    "binary": item.binary,
                    "missing": item.missing,
                    "provided_by": item.provided_by,
                }
                for item in items
            ]
            for package, items in broken_libs.items()
        }
    if undefined_symbols:
        data["undefined_symbols"] = undefined_symbols
    if orphans:
        data["orphans"] = orphans
    if when is not None:
        data["timestamp"] = when.isoformat()
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _text_report(
    summary: Summary,
    missing_by_package: MissingIndex,
    no_access_by_package: NoAccessIndex,
    backup_by_package: BackupIndex,
    pending_new_by_package: PendingNewIndex,
    errors_by_package: ErrorsIndex,
    when: datetime | None = None,
    broken_libs: BrokenLibsIndex | None = None,
    undefined_symbols: UndefinedSymbolsIndex | None = None,
    orphans: OrphansIndex | None = None,
) -> str:
    header = t("pkgcheck v{version} — Missing files by package").format(version=__version__)
    if when is not None:
        header = f"{header} ({when:{_LOG_TIME_FORMAT}})"
    summary_lines = [
        t("Packages analyzed: {count}").format(count=f"{summary.packages:,}"),
        t("Files verified: {count}").format(count=f"{summary.files_checked:,}"),
        t("Missing files: {count}").format(count=f"{summary.missing:,}"),
    ]
    if summary.backup:
        summary_lines.append(
            t("Files with backup only (.bak/.orig): {count}").format(count=f"{summary.backup:,}")
        )
    if summary.pending_new:
        summary_lines.append(
            t("Configs .new pending review: {count}").format(count=f"{summary.pending_new:,}")
        )
    if summary.no_access:
        summary_lines.append(
            t("Files without access: {count}").format(count=f"{summary.no_access:,}")
        )
    if summary.errors:
        summary_lines.append(t("Errors: {count}").format(count=f"{summary.errors:,}"))
    if summary.excluded_install:
        summary_lines.append(
            t("Install scripts excluded: {count}").format(count=f"{summary.excluded_install:,}")
        )
    if summary.excluded_pseudo:
        summary_lines.append(
            t("Pseudo-filesystems excluded: {count}").format(count=f"{summary.excluded_pseudo:,}")
        )
    if summary.broken_binaries:
        summary_lines.append(
            t("Binaries with missing library deps: {count}").format(
                count=f"{summary.broken_binaries:,}"
            )
        )
    if summary.missing_libs:
        summary_lines.append(
            t("Missing shared libraries: {count}").format(count=f"{summary.missing_libs:,}")
        )
    if summary.undefined_symbol_binaries:
        summary_lines.append(
            t("Binaries with undefined symbols: {count}").format(
                count=f"{summary.undefined_symbol_binaries:,}"
            )
        )
    if summary.orphans:
        summary_lines.append(t("Orphan files: {count}").format(count=f"{summary.orphans:,}"))
    lines = [
        header,
        "=" * 46,
        *summary_lines,
        "",
    ]
    _text_section(lines, t("MISSING:"))
    if missing_by_package:
        for package, paths in sorted(missing_by_package.items()):
            esc_pkg = _escape_tsv(package)
            for path in paths:
                lines.append(f"{esc_pkg}\t{_escape_tsv(path)}")
    else:
        lines.append(t("(none)"))

    if pending_new_by_package:
        _text_section(lines, t("NEW CONFIG PENDING (manual review):"))
        for package, paths in sorted(pending_new_by_package.items()):
            esc_pkg = _escape_tsv(package)
            for path in paths:
                lines.append(f"{esc_pkg}\t{_escape_tsv(path)}")

    if backup_by_package:
        _text_section(lines, t("BACKUP ONLY (.bak/.orig):"))
        for package, paths in sorted(backup_by_package.items()):
            esc_pkg = _escape_tsv(package)
            for path in paths:
                lines.append(f"{esc_pkg}\t{_escape_tsv(path)}")

    if no_access_by_package:
        _text_section(lines, t("NO ACCESS (requires root privileges):"))
        for package, paths in sorted(no_access_by_package.items()):
            esc_pkg = _escape_tsv(package)
            for path in paths:
                lines.append(f"{esc_pkg}\t{_escape_tsv(path)}")

    if errors_by_package:
        _text_section(lines, t("ERRORS:"))
        for package, paths in sorted(errors_by_package.items()):
            esc_pkg = _escape_tsv(package)
            for path in paths:
                lines.append(f"{esc_pkg}\t{_escape_tsv(path)}")

    if broken_libs:
        _text_section(lines, t("BROKEN LIBRARY DEPS:"))
        for package, items in sorted(broken_libs.items()):
            lines.append(_escape_tsv(package))
            for item in items:
                provided = " ".join(
                    f"{_escape_tsv(lib)}={_escape_tsv(owner) if owner else t('(unknown)')}"
                    for lib, owner in item.provided_by.items()
                )
                detail = ", ".join(_escape_tsv(m) for m in item.missing)
                if provided:
                    detail = f"{detail} [provided by: {provided}]"
                lines.append(f"\t{_escape_tsv(item.binary)}\t{_escape_tsv(detail)}")

    if undefined_symbols:
        _text_section(lines, t("UNDEFINED SYMBOLS (may be false positives):"))
        for package, binaries in sorted(undefined_symbols.items()):
            esc_pkg = _escape_tsv(package)
            for binary, symbols in binaries.items():
                lines.append(f"{esc_pkg}\t{_escape_tsv(binary)}\t{_escape_tsv(', '.join(symbols))}")

    if orphans:
        _text_section(lines, t("ORPHANS (untracked files):"))
        for path in sorted(orphans):
            lines.append(_escape_tsv(path))

    return "\n".join(lines) + "\n"
