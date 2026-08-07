"""Command-line interface of pkgcheck."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm

from pkgcheck import __version__
from pkgcheck.i18n import ALL_LANGUAGES, detect_language, is_supported, set_language, t
from pkgcheck.reporter import (
    BackupIndex,
    ErrorsIndex,
    MissingIndex,
    NoAccessIndex,
    PendingNewIndex,
    Summary,
    json_report,
    print_breakdown,
    print_summary,
    unique_report_path,
    write_report,
)
from pkgcheck.scanner import _PSEUDO_PREFIXES, ScanResult, scan_package_files
from pkgcheck.verifier import (
    _DEFAULT_BACKUP_SUFFIXES,
    _DEFAULT_NEW_SUFFIX,
    PathStatus,
    verify_paths,
)

_DEFAULT_PACKAGES_DIR = "/var/log/packages"
_DEFAULT_BACKUP_SUFFIXES_CSV = ",".join(_DEFAULT_BACKUP_SUFFIXES)
_LOG_DIR = Path("/var/log/pkgcheck")

_MAX_WORKERS = 512


def _default_workers() -> int:
    return min(32, (os.cpu_count() or 1) + 4)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pkgcheck",
        description=t(
            "Verifies that the files recorded by each package in /var/log/packages/ "
            "really exist on the system."
        ),
    )
    parser.add_argument(
        "--packages-dir",
        default=_DEFAULT_PACKAGES_DIR,
        metavar="DIR",
        help=t("Directory with the package records (default: {dir}).").format(
            dir=_DEFAULT_PACKAGES_DIR
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=_default_workers(),
        metavar="N",
        help=t("Number of threads to verify files (default: auto)."),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=t("Writes the report in JSON format (.json) instead of text (.log)."),
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        metavar="N",
        help=t("Maximum packages to show in the console breakdown (default: all)."),
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PREFIX",
        help=t(
            "Additional prefix to exclude (e.g. --exclude mnt, media); repeatable or "
            "comma-separated. Added to the default pseudo-filesystems."
        ),
    )
    parser.add_argument(
        "--backup-suffixes",
        default=_DEFAULT_BACKUP_SUFFIXES_CSV,
        metavar="SUFFIXES",
        help=t("Backup suffixes detected as backup-only (default: {suffixes}).").format(
            suffixes=_DEFAULT_BACKUP_SUFFIXES_CSV
        ),
    )
    parser.add_argument(
        "--new-suffix",
        default=_DEFAULT_NEW_SUFFIX,
        metavar="SUFFIX",
        help=t(
            "Suffix for new config files that Slackware leaves pending review (default: {suffix})."
        ).format(suffix=_DEFAULT_NEW_SUFFIX),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help=t("Hides progress and breakdown; only prints the summary."),
    )
    parser.add_argument(
        "--lang",
        default=None,
        metavar="LANG",
        help=t("Interface language ({languages}); detects the OS language by default.").format(
            languages=", ".join(ALL_LANGUAGES)
        ),
    )
    elevate_group = parser.add_mutually_exclusive_group()
    elevate_group.add_argument(
        "--elevate",
        action="store_true",
        help=t("Re-runs the command with sudo if root privileges are not available."),
    )
    elevate_group.add_argument(
        "--no-elevate",
        action="store_true",
        help=t("Does not ask for root privileges; only verifies accessible files."),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main() -> None:
    """Main entry point: validates the environment and starts the analysis."""
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--lang")
    known, _ = pre_parser.parse_known_args()
    override = known.lang
    if override is not None and not is_supported(override):
        # An invalid override is not used for localization; fall back to the OS language
        # so the error message appears in the system language.
        override = None
    set_language(detect_language(override))

    parser = _build_parser()
    args = parser.parse_args()

    if args.lang is not None and not is_supported(args.lang):
        parser.error(t("unsupported language: {lang}").format(lang=args.lang))

    packages_dir = Path(args.packages_dir).expanduser().resolve()
    if not packages_dir.is_dir():
        parser.error(t("the packages directory does not exist: {path}").format(path=packages_dir))

    if args.workers < 1:
        parser.error(t("--workers must be a positive integer"))

    if args.workers > _MAX_WORKERS:
        parser.error(t("--workers is too large (max {max})").format(max=_MAX_WORKERS))

    if args.max_rows is not None and args.max_rows < 1:
        parser.error(t("--max-rows must be a positive integer"))

    if not args.new_suffix.strip():
        parser.error(t("--new-suffix cannot be empty"))

    console = Console()
    status_console = Console(stderr=True)
    _ensure_root(args, console, status_console)

    rg_bin = shutil.which("rg")
    if rg_bin is None:
        parser.error(
            t("ripgrep (rg) was not found on the system; install it before using pkgcheck")
        )

    try:
        _run(console, status_console, args, packages_dir, rg_bin)
    except KeyboardInterrupt:
        console.print(t("\n[red]Interrupted by the user.[/red]"))
        raise SystemExit(130) from None
    except RuntimeError as exc:
        console.print(t("[red]Error:[/red] {exc}").format(exc=exc))
        raise SystemExit(1) from None


def _ensure_root(
    args: argparse.Namespace,
    console: Console,
    status_console: Console,
) -> None:
    """Requests root privileges by re-running the command with sudo if needed."""
    if os.geteuid() == 0:
        return

    if args.elevate:
        _exec_with_sudo()
        return

    if args.no_elevate or args.quiet or not sys.stdin.isatty():
        if not args.quiet:
            (status_console if args.json else console).print(
                t(
                    "[yellow]Without root privileges: some protected files cannot be "
                    "verified. Run with sudo or use --elevate to verify the whole "
                    "system.[/yellow]"
                )
            )
        return

    prompt_console = status_console if args.json else console
    if Confirm.ask(
        t("Root privileges are required to verify all files. Re-run with sudo?"),
        default=True,
        console=prompt_console,
    ):
        _exec_with_sudo()


def _exec_with_sudo() -> None:
    """Re-runs the current command under sudo, keeping all arguments."""
    sudo_bin = shutil.which("sudo")
    if sudo_bin is None:
        raise RuntimeError(t("sudo was not found on the system; run pkgcheck directly as root"))
    script = os.path.abspath(sys.argv[0])
    if Path(script).name == "__main__.py":
        cmd = [sys.executable, "-m", "pkgcheck", *sys.argv[1:]]
    else:
        cmd = [script, *sys.argv[1:]]
    os.execvp(sudo_bin, [sudo_bin, "--", *cmd])


def _pseudo_prefixes(args: argparse.Namespace) -> tuple[str, ...]:
    """Combines the default pseudo-filesystems with the --exclude prefixes."""
    extra: list[str] = []
    for value in args.exclude:
        for part in value.split(","):
            part = part.strip().lstrip("/")
            if part and not part.endswith("/"):
                part += "/"
            if part:
                extra.append(part)
    return _PSEUDO_PREFIXES + tuple(extra)


def _backup_suffixes(args: argparse.Namespace) -> tuple[str, ...]:
    """Normalizes the --backup-suffixes list."""
    return tuple(s.strip() for s in args.backup_suffixes.split(",") if s.strip())


def _new_suffix(args: argparse.Namespace) -> str:
    """Normalizes the --new-suffix value."""
    return args.new_suffix.strip()


def _write_auto_log(
    console: Console,
    when: datetime,
    fmt: str,
    summary: Summary,
    missing_by_package: MissingIndex,
    no_access_by_package: NoAccessIndex,
    backup_by_package: BackupIndex,
    pending_new_by_package: PendingNewIndex,
    errors_by_package: ErrorsIndex,
) -> Path | None:
    """Writes the automatic log to ``/var/log/pkgcheck``; requires root.

    Returns the written path, or ``None`` if it could not be written (no root or I/O error).
    """
    if os.geteuid() != 0:
        return None
    try:
        log_path = unique_report_path(_LOG_DIR, when, fmt)
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        write_report(
            log_path,
            summary,
            missing_by_package,
            no_access_by_package,
            backup_by_package,
            pending_new_by_package,
            errors_by_package,
            when,
        )
    except OSError as exc:
        console.print(
            t("[yellow]Could not write the log to {path}: {exc}[/yellow]").format(
                path=log_path, exc=exc
            )
        )
        return None
    return log_path


def _run(
    console: Console,
    status_console: Console,
    args: argparse.Namespace,
    packages_dir: Path,
    rg_bin: str,
) -> None:
    started = time.monotonic()
    when = datetime.now()
    status = status_console if args.json else console

    if not args.quiet:
        status.print(t("Scanning package records in {path}...").format(path=packages_dir))
    scan_result: ScanResult = scan_package_files(
        packages_dir,
        rg_bin,
        pseudo_prefixes=_pseudo_prefixes(args),
    )
    entries = scan_result.entries
    if not entries:
        status.print(t("[yellow]No registered files were found.[/yellow]"))
        return

    packages = sorted({package for package, _ in entries})
    abs_paths = [f"/{rel}" for _, rel in entries]

    progress_columns = (
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    )
    with Progress(*progress_columns, console=status, disable=args.quiet) as progress:
        verify_task = progress.add_task(t("Verifying existence of files..."), total=len(entries))
        statuses = verify_paths(
            abs_paths,
            args.workers,
            on_progress=lambda done: progress.update(verify_task, completed=done),
            backup_suffixes=_backup_suffixes(args),
            new_suffix=_new_suffix(args),
        )

    missing_by_package: MissingIndex = defaultdict(list)
    no_access_by_package: NoAccessIndex = defaultdict(list)
    backup_by_package: BackupIndex = defaultdict(list)
    pending_new_by_package: PendingNewIndex = defaultdict(list)
    errors_by_package: ErrorsIndex = defaultdict(list)
    counts = dict.fromkeys(PathStatus, 0)
    for (package, rel), st in zip(entries, statuses, strict=True):
        counts[st] += 1
        if st is PathStatus.MISSING:
            missing_by_package[package].append(f"/{rel}")
        elif st is PathStatus.BACKUP:
            backup_by_package[package].append(f"/{rel}")
        elif st is PathStatus.NEW_PENDING:
            pending_new_by_package[package].append(f"/{rel}")
        elif st is PathStatus.NO_ACCESS:
            no_access_by_package[package].append(f"/{rel}")
        elif st is PathStatus.ERROR:
            errors_by_package[package].append(f"/{rel}")

    elapsed = time.monotonic() - started
    summary = Summary(
        packages=len(packages),
        files_checked=len(entries),
        missing=counts[PathStatus.MISSING],
        backup=counts[PathStatus.BACKUP],
        pending_new=counts[PathStatus.NEW_PENDING],
        no_access=counts[PathStatus.NO_ACCESS],
        errors=counts[PathStatus.ERROR],
        excluded_install=scan_result.excluded_install,
        excluded_pseudo=scan_result.excluded_pseudo,
    )

    if not args.quiet and not args.json:
        if missing_by_package:
            print_breakdown(console, dict(missing_by_package), args.max_rows)
        else:
            console.print(t("[green]All registered files exist on the system.[/green]"))
        if pending_new_by_package:
            print_breakdown(
                console,
                dict(pending_new_by_package),
                args.max_rows,
                title=t("Configs .new pending review by package"),
            )
        if errors_by_package:
            print_breakdown(
                console,
                dict(errors_by_package),
                args.max_rows,
                title=t("Files with verification errors by package"),
            )

    if not args.json:
        print_summary(console, summary, elapsed)
    elif not args.quiet:
        status_console.print(
            t(
                "[green]Verification completed:[/green] {packages} packages, {files} files, "
                "{missing} missing, {errors} errors, {no_access} without access, "
                "{pending} .new configs ({elapsed:.1f}s)"
            ).format(
                packages=summary.packages,
                files=summary.files_checked,
                missing=summary.missing,
                errors=summary.errors,
                no_access=summary.no_access,
                pending=summary.pending_new,
                elapsed=elapsed,
            )
        )

    if not args.json and summary.no_access:
        console.print(
            t(
                "[yellow]There are files without access (probably require root privileges). "
                "Run again with sudo to check their real status.[/yellow]"
            )
        )

    fmt = "json" if args.json else "log"
    indexes = (
        dict(missing_by_package),
        dict(no_access_by_package),
        dict(backup_by_package),
        dict(pending_new_by_package),
        dict(errors_by_package),
    )
    if args.json and os.geteuid() != 0:
        sys.stdout.write(json_report(summary, *indexes, when))
        return
    log_path = _write_auto_log(status, when, fmt, summary, *indexes)
    if log_path is not None:
        status.print(t("[green]Log saved to:[/green] {path}").format(path=log_path))
