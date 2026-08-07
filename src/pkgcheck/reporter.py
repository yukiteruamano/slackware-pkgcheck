"""Console output (rich) and writing of the run log to file."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from pkgcheck import __version__
from pkgcheck.i18n import t

type MissingIndex = dict[str, list[str]]
type NoAccessIndex = dict[str, list[str]]
type BackupIndex = dict[str, list[str]]
type PendingNewIndex = dict[str, list[str]]
type ErrorsIndex = dict[str, list[str]]

_LOG_TIME_FORMAT = "%d-%m-%Y-%H-%M-%S"


def report_path(log_dir: Path, when: datetime, fmt: str) -> Path:
    """Returns the automatic log path using the ``pkgcheck-<date>.log`` convention."""
    return log_dir / f"pkgcheck-{when:{_LOG_TIME_FORMAT}}.{fmt}"


def unique_report_path(log_dir: Path, when: datetime, fmt: str) -> Path:
    """Returns a log path that does not yet exist, appending a ``-N`` suffix on collision."""
    path = report_path(log_dir, when, fmt)
    for index in range(1, 10_000):
        if not path.exists():
            return path
        path = log_dir / f"pkgcheck-{when:{_LOG_TIME_FORMAT}}-{index}.{fmt}"
    raise OSError(t("too many pkgcheck logs in {dir} for the same second").format(dir=log_dir))


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
    table.add_row(t("Total time"), f"{elapsed:.2f}s")

    console.print()
    console.print(table)


def print_breakdown(
    console: Console,
    missing_by_package: MissingIndex,
    max_rows: int | None = None,
    title: str | None = None,
) -> None:
    """Prints the breakdown of files grouped by package."""
    if max_rows is not None and max_rows < 1:
        return
    tree = Tree(title or t("Missing files by package"))
    for index, (package, paths) in enumerate(sorted(missing_by_package.items())):
        if max_rows is not None and index >= max_rows:
            remaining = len(missing_by_package) - index
            tree.add(t("... and {remaining} more packages").format(remaining=remaining))
            break
        branch = tree.add(f"[bold cyan]{package}[/bold cyan] ({len(paths)})")
        for path in paths:
            branch.add(path)
    console.print(tree)


def write_report(
    output: Path,
    summary: Summary,
    missing_by_package: MissingIndex,
    no_access_by_package: NoAccessIndex,
    backup_by_package: BackupIndex,
    pending_new_by_package: PendingNewIndex,
    errors_by_package: ErrorsIndex,
    when: datetime | None = None,
) -> None:
    """Writes the report to `output`; the format depends on the extension (.json/.log)."""
    if output.suffix.lower() == ".json":
        output.write_text(
            json_report(
                summary,
                missing_by_package,
                no_access_by_package,
                backup_by_package,
                pending_new_by_package,
                errors_by_package,
                when,
            )
        )
    else:
        output.write_text(
            _text_report(
                summary,
                missing_by_package,
                no_access_by_package,
                backup_by_package,
                pending_new_by_package,
                errors_by_package,
                when,
            )
        )


def json_report(
    summary: Summary,
    missing_by_package: MissingIndex,
    no_access_by_package: NoAccessIndex,
    backup_by_package: BackupIndex,
    pending_new_by_package: PendingNewIndex,
    errors_by_package: ErrorsIndex,
    when: datetime | None = None,
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
    lines = [
        header,
        "=" * 46,
        *summary_lines,
        "",
        t("MISSING:"),
    ]
    if missing_by_package:
        for package, paths in sorted(missing_by_package.items()):
            lines.extend(f"{package}\t{path}" for path in paths)
    else:
        lines.append(t("(none)"))

    if pending_new_by_package:
        lines.extend(["", t("NEW CONFIG PENDING (manual review):")])
        for package, paths in sorted(pending_new_by_package.items()):
            lines.extend(f"{package}\t{path}" for path in paths)

    if backup_by_package:
        lines.extend(["", t("BACKUP ONLY (.bak/.orig):")])
        for package, paths in sorted(backup_by_package.items()):
            lines.extend(f"{package}\t{path}" for path in paths)

    if no_access_by_package:
        lines.extend(["", t("NO ACCESS (requires root privileges):")])
        for package, paths in sorted(no_access_by_package.items()):
            lines.extend(f"{package}\t{path}" for path in paths)

    if errors_by_package:
        lines.extend(["", t("ERRORS:")])
        for package, paths in sorted(errors_by_package.items()):
            lines.extend(f"{package}\t{path}" for path in paths)

    return "\n".join(lines) + "\n"
