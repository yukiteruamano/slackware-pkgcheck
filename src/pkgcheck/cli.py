"""Command-line interface of pkgcheck."""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import cast

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
from pkgcheck.libdeps import (
    build_library_owner_index,
    check_library_deps,
    check_undefined_symbols,
    collect_defined_symbols,
    find_missing_owner,
)
from pkgcheck.reporter import (
    BackupIndex,
    BrokenBinary,
    BrokenLibsIndex,
    ErrorsIndex,
    MissingIndex,
    NoAccessIndex,
    PendingNewIndex,
    Summary,
    UndefinedSymbolsIndex,
    json_report,
    print_breakdown,
    print_broken_libs,
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
    verify_paths_with_elf,
)

_DEFAULT_PACKAGES_DIR = "/var/log/packages"
_DEFAULT_BACKUP_SUFFIXES_CSV = ",".join(_DEFAULT_BACKUP_SUFFIXES)
_LOG_DIR = Path("/var/log/pkgcheck")

_MAX_WORKERS = 512


def _default_workers() -> int:
    return min(32, (os.cpu_count() or 1) + 4)


def _is_utf8(encoding: str | None) -> bool:
    """Returns whether `encoding` is a UTF-8 codec name (case/separator-insensitive)."""
    if not encoding:
        return False
    return encoding.lower().replace("_", "").replace("-", "") == "utf8"


def _ensure_utf8_environment() -> str | None:
    """Detects a broken (non-UTF-8) terminal encoding and forces the UTF-8 fallback.

    Called before any output so pkgcheck never crashes writing to the console
    (e.g. the rich spinner uses Braille characters that latin-1 cannot encode).

    Reconfigures stdout/stderr to UTF-8 and, when something was broken, applies the
    documented fallback ``LANG=en_US`` / ``UTF-8`` (also inherited by subprocesses
    and by the ``sudo`` re-exec). Returns the previous encoding so the caller can
    warn the user, or ``None`` when the environment was already correct.
    """
    previous: str | None = None
    for stream in (sys.stdout, sys.stderr):
        encoding = getattr(stream, "encoding", None)
        if encoding is not None and not _is_utf8(encoding):
            previous = previous or encoding
            with contextlib.suppress(AttributeError, ValueError, OSError):
                cast_any = getattr(stream, "reconfigure", None)
                if callable(cast_any):
                    cast_any(encoding="utf-8", errors="replace")
    if previous is not None:
        os.environ["PYTHONIOENCODING"] = "utf-8"
        os.environ["LC_ALL"] = "en_US.UTF-8"
        os.environ["LANG"] = "en_US.UTF-8"
    return previous


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
        "--check-libs-deps",
        action="store_true",
        help=t(
            "Also checks that every installed ELF binary and shared library has all "
            "its dynamic library dependencies present (revdep-rebuild style)."
        ),
    )
    parser.add_argument(
        "--check-libs-symbols",
        action="store_true",
        help=t(
            "Also checks installed binaries for undefined dynamic symbols not provided "
            "by any installed library (requires --check-libs-deps; may report false "
            "positives)."
        ),
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
    previous_encoding = _ensure_utf8_environment()

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

    if previous_encoding is not None:
        (status_console if args.json else console).print(
            t(
                "[yellow]Warning: terminal encoding is not UTF-8 (detected: {encoding}). "
                "Using fallback LANG=en_US/UTF-8 to avoid output errors.[/yellow]"
            ).format(encoding=previous_encoding)
        )

    _ensure_root(args, console, status_console)

    rg_bin = shutil.which("rg")
    if rg_bin is None:
        parser.error(
            t("ripgrep (rg) was not found on the system; install it before using pkgcheck")
        )

    if args.check_libs_symbols and not args.check_libs_deps:
        parser.error(t("--check-libs-symbols requires --check-libs-deps"))

    ldd_bin = shutil.which("ldd") if args.check_libs_deps else None
    if args.check_libs_deps and ldd_bin is None:
        parser.error(t("ldd was not found on the system; it is required for --check-libs-deps"))

    readelf_bin = shutil.which("readelf") if args.check_libs_symbols else None
    if args.check_libs_symbols and readelf_bin is None:
        parser.error(
            t("readelf was not found on the system; it is required for --check-libs-symbols")
        )

    try:
        _run(console, status_console, args, packages_dir, rg_bin, ldd_bin, readelf_bin)
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
    script = str(Path(sys.argv[0]).resolve())
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
    raw: str = cast(str, args.backup_suffixes)
    return tuple(s.strip() for s in raw.split(",") if s.strip())


def _new_suffix(args: argparse.Namespace) -> str:
    """Normalizes the --new-suffix value."""
    raw: str = cast(str, args.new_suffix)
    return raw.strip()


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
    broken_libs: BrokenLibsIndex | None = None,
    undefined_symbols: UndefinedSymbolsIndex | None = None,
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
            broken_libs,
            undefined_symbols,
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
    ldd_bin: str | None,
    readelf_bin: str | None,
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
        if args.check_libs_deps:
            statuses, elf_flags = verify_paths_with_elf(
                abs_paths,
                args.workers,
                on_progress=lambda done: progress.update(verify_task, completed=done),
                backup_suffixes=_backup_suffixes(args),
                new_suffix=_new_suffix(args),
            )
        else:
            statuses = verify_paths(
                abs_paths,
                args.workers,
                on_progress=lambda done: progress.update(verify_task, completed=done),
                backup_suffixes=_backup_suffixes(args),
                new_suffix=_new_suffix(args),
            )
            elf_flags = None

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

    broken_libs: BrokenLibsIndex = {}
    undefined_symbols: UndefinedSymbolsIndex = {}
    broken_count = 0
    missing_lib_count = 0
    undefined_count = 0
    if args.check_libs_deps:
        assert ldd_bin is not None and elf_flags is not None
        elf_entries = [
            (package, rel)
            for (package, rel), is_elf in zip(entries, elf_flags, strict=True)
            if is_elf
        ]
        if elf_entries:
            elf_paths = [f"/{rel}" for _, rel in elf_entries]
            owner_index = build_library_owner_index(entries)

            with Progress(*progress_columns, console=status, disable=args.quiet) as progress:
                deps_task = progress.add_task(
                    t("Checking library dependencies (ldd)..."), total=len(elf_paths)
                )
                missing_per_path = check_library_deps(
                    elf_paths,
                    args.workers,
                    ldd_bin,
                    on_progress=lambda done: progress.update(deps_task, completed=done),
                )

            for (package, rel), missing in zip(elf_entries, missing_per_path, strict=True):
                if not missing:
                    continue
                provided_by = find_missing_owner(missing, owner_index)
                broken_libs.setdefault(package, []).append(
                    BrokenBinary(binary=f"/{rel}", missing=missing, provided_by=provided_by)
                )
                broken_count += 1
                missing_lib_count += len(missing)

            if args.check_libs_symbols:
                assert readelf_bin is not None
                with Progress(*progress_columns, console=status, disable=args.quiet) as progress:
                    sym_task = progress.add_task(
                        t("Collecting defined symbols..."), total=len(elf_paths)
                    )
                    defined = collect_defined_symbols(
                        elf_paths,
                        args.workers,
                        readelf_bin,
                        on_progress=lambda done: progress.update(sym_task, completed=done),
                    )
                with Progress(*progress_columns, console=status, disable=args.quiet) as progress:
                    undef_task = progress.add_task(
                        t("Checking undefined symbols..."), total=len(elf_paths)
                    )
                    undefined_by_path = check_undefined_symbols(
                        elf_paths,
                        defined,
                        args.workers,
                        readelf_bin,
                        on_progress=lambda done: progress.update(undef_task, completed=done),
                    )
                for (package, rel), symbols in zip(elf_entries, undefined_by_path, strict=True):
                    if not symbols:
                        continue
                    undefined_symbols.setdefault(package, {})[f"/{rel}"] = symbols
                    undefined_count += 1

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
        broken_binaries=broken_count,
        missing_libs=missing_lib_count,
        undefined_symbol_binaries=undefined_count,
    )

    if not args.quiet and not args.json:
        if missing_by_package:
            print_breakdown(console, dict(missing_by_package), args.max_rows, style="bold red")
        else:
            console.print(t("[green]All registered files exist on the system.[/green]"))
        if pending_new_by_package:
            print_breakdown(
                console,
                dict(pending_new_by_package),
                args.max_rows,
                title=t("Configs .new pending review by package"),
                style="bold yellow",
            )
        if errors_by_package:
            print_breakdown(
                console,
                dict(errors_by_package),
                args.max_rows,
                title=t("Files with verification errors by package"),
                style="bold red",
            )
        if broken_libs:
            print_broken_libs(console, broken_libs, args.max_rows, style="bold red")
        if undefined_symbols:
            print_broken_libs(
                console,
                {
                    package: [
                        BrokenBinary(binary=binary, missing=symbols, provided_by={})
                        for binary, symbols in binaries.items()
                    ]
                    for package, binaries in undefined_symbols.items()
                },
                args.max_rows,
                title=t("Binaries with undefined symbols by package"),
                style="bold yellow",
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
        sys.stdout.write(
            json_report(summary, *indexes, when, broken_libs or None, undefined_symbols or None)
        )
        return
    log_path = _write_auto_log(
        status, when, fmt, summary, *indexes, broken_libs or None, undefined_symbols or None
    )
    if log_path is not None:
        status.print(t("[green]Log saved to:[/green] {path}").format(path=log_path))
