"""Command-line interface of pkgcheck."""

from __future__ import annotations

import argparse
import contextlib
import grp
import json
import os
import shutil
import sys
import time
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, cast

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
from rich.table import Table

from pkgcheck import __version__
from pkgcheck.diff import diff_reports, list_logs
from pkgcheck.i18n import ALL_LANGUAGES, detect_language, is_supported, set_language, t
from pkgcheck.libdeps import (
    build_library_owner_index,
    check_libs_deps,
    check_undefined_symbols,
    collect_defined_symbols,
    find_missing_owner,
)
from pkgcheck.orphans import find_orphans
from pkgcheck.reporter import (
    BackupIndex,
    BrokenBinary,
    BrokenLibsIndex,
    ErrorsIndex,
    MissingIndex,
    NoAccessIndex,
    OrphansIndex,
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
from pkgcheck.validate import (
    ValidationError,
    validate_backup_suffixes,
    validate_binary_path,
    validate_exclude_prefix,
    validate_new_suffix,
    validate_orphans_root,
    validate_packages_dir,
    validate_safe_path,
)
from pkgcheck.verifier import (
    _DEFAULT_BACKUP_SUFFIXES,
    _DEFAULT_NEW_SUFFIX,
    PathStatus,
    verify_paths,
    verify_paths_with_elf,
)

# Backwards compatibility alias for tests that patch the old singular name
check_library_deps = check_libs_deps

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


def _ensure_utf8_environment() -> tuple[str | None, dict[str, str]]:
    """Detects a broken (non-UTF-8) terminal encoding and forces the UTF-8 fallback.

    Called before any output so pkgcheck never crashes writing to the console
    (e.g. the rich spinner uses Braille characters that latin-1 cannot encode).

    Reconfigures stdout/stderr to UTF-8 and returns the previous encoding so the caller can
    warn the user, or ``None`` when the environment was already correct.
    Also returns an environment dict with UTF-8 fallback for subprocesses.
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

    # Return subprocess env with UTF-8 fallback (without modifying global os.environ)
    subprocess_env = {}
    if previous is not None:
        subprocess_env = {
            "PYTHONIOENCODING": "utf-8",
            "LC_ALL": "en_US.UTF-8",
            "LANG": "en_US.UTF-8",
        }
    return previous, subprocess_env


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

    class _CheckLibsDepsAction(argparse.Action):
        def __call__(
            self,
            _parser: argparse.ArgumentParser,
            namespace: argparse.Namespace,
            _values: str | Sequence[Any] | None,
            _option_string: str | None = None,
        ) -> None:
            namespace.check_libs_deps = True
            namespace.check_lib_deps = True

    parser.add_argument(
        "--check-libs-deps",
        dest="check_libs_deps",
        action=_CheckLibsDepsAction,
        nargs=0,
        help=t(
            "Also checks that every installed ELF binary and shared library has all "
            "its dynamic library dependencies present using ldd."
        ),
    )
    # Backwards compatibility: singular form deprecated
    parser.add_argument(
        "--check-lib-deps",
        dest="check_lib_deps",
        action=_CheckLibsDepsAction,
        nargs=0,
        help=argparse.SUPPRESS,
    )
    parser.set_defaults(check_libs_deps=False, check_lib_deps=False)
    parser.add_argument(
        "--check-libs-symbols",
        action="store_true",
        help=t(
            "Also checks installed binaries for undefined dynamic symbols not provided "
            "by any installed library using nm -D (requires --check-libs-deps; may report false "
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
    parser.add_argument(
        "--orphans",
        action="store_true",
        help=t("Also list orphan (untracked) files not owned by any package."),
    )
    parser.add_argument(
        "--orphans-root",
        default="/",
        metavar="DIR",
        help=t("Root directory for --orphans scan (default: /)."),
    )
    parser.add_argument(
        "--list-logs",
        action="store_true",
        help=t("List existing pkgcheck logs and exit."),
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help=t("Diff two JSON logs (requires --from and --to)."),
    )
    parser.add_argument(
        "--from",
        dest="from_path",
        default=None,
        metavar="PATH",
        help=t("First log for --diff (path or 'latest')."),
    )
    parser.add_argument(
        "--to",
        dest="to_path",
        default=None,
        metavar="PATH",
        help=t("Second log for --diff (path or 'latest')."),
    )
    parser.add_argument(
        "--completion",
        choices=["bash", "zsh", "fish"],
        default=None,
        metavar="SHELL",
        help=t("Generate shell completion script and exit."),
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


def _completion_script(shell: str) -> str:
    """Returns a shell completion script for `shell`."""
    flags = [
        "--packages-dir",
        "--workers",
        "--json",
        "--max-rows",
        "--exclude",
        "--backup-suffixes",
        "--new-suffix",
        "--check-libs-deps",
        "--check-libs-symbols",
        "--quiet",
        "--lang",
        "--elevate",
        "--no-elevate",
        "--orphans",
        "--orphans-root",
        "--list-logs",
        "--diff",
        "--from",
        "--to",
        "--completion",
        "--version",
        "--help",
    ]
    joined = " ".join(flags)
    if shell == "bash":
        return f"""# bash completion for pkgcheck
_pkgcheck_completions() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    COMPREPLY=($(compgen -W "{joined}" -- "$cur"))
}}
complete -F _pkgcheck_completions pkgcheck
"""
    if shell == "zsh":
        return f"""#compdef pkgcheck
_arguments "*: :->args"
_kg() {{ compadd -- {joined} }}
_kg
"""
    if shell == "fish":
        lines = "\n".join(
            f"complete -c pkgcheck -l {f.lstrip('-')} -d '{f}'" for f in flags if f.startswith("--")
        )
        return f"# fish completion for pkgcheck\n{lines}\n"
    return ""


def _resolve_log_path(value: str | None, log_dir: Path) -> Path | None:
    """Resolves `value` which may be a path or 'latest' alias."""
    if value is None:
        return None
    if value == "latest":
        entries = list_logs(log_dir)
        if not entries:
            return None
        return entries[0].path
    if value.startswith("latest-"):
        try:
            idx = int(value.split("-", 1)[1])
        except ValueError:
            return Path(value)
        if idx < 1:
            return None
        entries = list_logs(log_dir)
        if 1 <= idx <= len(entries):
            return entries[idx - 1].path
        return None
    return Path(value)


def main() -> None:
    """Main entry point: validates the environment and starts the analysis."""
    previous_encoding, subprocess_env = _ensure_utf8_environment()

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

    # Early exits that don't need packages_dir
    if args.completion:
        sys.stdout.write(_completion_script(args.completion))
        return

    if args.list_logs:
        console = Console()
        entries = list_logs(_LOG_DIR)
        if not entries:
            console.print(t("[yellow]No logs found in {dir}.[/yellow]").format(dir=_LOG_DIR))
            return
        table = Table(title=t("pkgcheck logs"))
        table.add_column("#", justify="right")
        table.add_column(t("Date"))
        table.add_column(t("Format"))
        table.add_column(t("Size"), justify="right")
        table.add_column(t("Path"))
        for idx, e in enumerate(entries, 1):
            dt = datetime.fromtimestamp(e.mtime).strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(str(idx), dt, e.fmt, f"{e.size:,}", str(e.path))
        console.print(table)
        return

    if args.diff:
        if not args.from_path or not args.to_path:
            parser.error(t("--diff requires --from and --to"))
        from_p = _resolve_log_path(args.from_path, _LOG_DIR)
        to_p = _resolve_log_path(args.to_path, _LOG_DIR)
        if from_p is None or not from_p.exists():
            parser.error(t("diff --from path does not exist: {path}").format(path=args.from_path))
        if to_p is None or not to_p.exists():
            parser.error(t("diff --to path does not exist: {path}").format(path=args.to_path))
        try:
            diff = diff_reports(from_p, to_p)
        except RuntimeError as exc:
            console = Console()
            console.print(t("[red]Error:[/red] {exc}").format(exc=exc))
            raise SystemExit(1) from None
        if args.json:
            sys.stdout.write(json.dumps(diff, indent=2, ensure_ascii=False) + "\n")
        else:
            console = Console()
            if not diff.get("diff"):
                console.print(t("[green]No differences found.[/green]"))
            else:
                for cat, change in diff["diff"].items():
                    if cat == "summary":
                        continue
                    console.print(f"[bold]{cat}[/bold]")
                    if isinstance(change, dict) and "added" in change:
                        for pkg, paths in change.get("added", {}).items():
                            console.print(f"[green]+ {pkg}: {', '.join(paths)}[/green]")
                        for pkg, paths in change.get("removed", {}).items():
                            console.print(f"[red]- {pkg}: {', '.join(paths)}[/red]")
                    else:
                        console.print(json.dumps(change, indent=2, ensure_ascii=False))
        return

    if args.lang is not None and not is_supported(args.lang):
        parser.error(t("unsupported language: {lang}").format(lang=args.lang))

    # Validate and normalize inputs using defense-in-depth validators
    try:
        expanded_packages = str(Path(args.packages_dir).expanduser())
        packages_dir_str = validate_packages_dir(expanded_packages)
        packages_dir = Path(packages_dir_str).resolve()
        if not packages_dir.is_dir():
            parser.error(
                t("the packages directory does not exist: {path}").format(path=packages_dir)
            )
    except ValidationError as exc:
        parser.error(t("invalid packages directory: {exc}").format(exc=exc))

    if args.workers < 1:
        parser.error(t("--workers must be a positive integer"))

    if args.workers > _MAX_WORKERS:
        parser.error(t("--workers is too large (max {max})").format(max=_MAX_WORKERS))

    if args.max_rows is not None and args.max_rows < 1:
        parser.error(t("--max-rows must be a positive integer"))

    if args.max_rows is not None and args.max_rows > 2500:
        parser.error(t("--max-rows is too large (max {max})").format(max=2500))

    try:
        validate_new_suffix(args.new_suffix)
    except ValidationError as exc:
        parser.error(t("invalid new-suffix: {exc}").format(exc=exc))

    try:
        validate_backup_suffixes(args.backup_suffixes)
    except ValidationError as exc:
        parser.error(t("invalid backup-suffixes: {exc}").format(exc=exc))

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
        (status_console if args.json else console).print(
            t("[yellow]ripgrep (rg) not found, falling back to Python scan (slower).[/yellow]")
        )
    else:
        try:
            rg_bin = validate_binary_path(rg_bin)
        except ValidationError as exc:
            parser.error(t("invalid rg binary path: {exc}").format(exc=exc))

    if args.check_libs_symbols and not args.check_libs_deps:
        parser.error(t("--check-libs-symbols requires --check-libs-deps"))

    # Validate --exclude prefixes eagerly so user gets feedback
    for value in args.exclude:
        for part in value.split(","):
            cleaned = part.strip().lstrip("/")
            if not cleaned:
                continue
            if not cleaned.endswith("/"):
                cleaned += "/"
            try:
                validate_exclude_prefix(cleaned)
            except ValidationError as exc:
                parser.error(
                    t("invalid --exclude prefix '{prefix}': {exc}").format(prefix=part, exc=exc)
                )

    if args.orphans:
        try:
            expanded_orphans = str(Path(args.orphans_root).expanduser())
            orphans_root_str = validate_orphans_root(expanded_orphans)
            orphans_root = Path(orphans_root_str).resolve()
        except ValidationError as exc:
            parser.error(t("invalid orphans root: {exc}").format(exc=exc))
        if not orphans_root.is_dir():
            parser.error(t("orphans root does not exist: {path}").format(path=orphans_root))

    # ldd and nm are required for --check-libs-deps / --check-libs-symbols
    ldd_bin: str | None = None
    nm_bin: str | None = None
    if args.check_libs_deps:
        ldd_bin = shutil.which("ldd")
        if ldd_bin is None:
            parser.error(t("ldd was not found on the system; it is required for --check-libs-deps"))
        try:
            ldd_bin = validate_binary_path(ldd_bin)
        except ValidationError as exc:
            parser.error(t("invalid ldd binary path: {exc}").format(exc=exc))
        if args.check_libs_symbols:
            nm_bin = shutil.which("nm")
            if nm_bin is None:
                parser.error(
                    t("nm was not found on the system; it is required for --check-libs-symbols")
                )
            try:
                nm_bin = validate_binary_path(nm_bin)
            except ValidationError as exc:
                parser.error(t("invalid nm binary path: {exc}").format(exc=exc))

    try:
        _run(console, status_console, args, packages_dir, rg_bin, ldd_bin, nm_bin, subprocess_env)
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
    try:
        sudo_bin = validate_binary_path(sudo_bin)
    except ValidationError as exc:
        raise RuntimeError(t("invalid sudo binary path: {exc}").format(exc=exc)) from exc

    script = str(Path(sys.argv[0]).resolve())
    # Validate script path to avoid injection via argv[0]
    try:
        validate_safe_path(script, allow_absolute=True, must_exist=False)
    except ValidationError as exc:
        raise RuntimeError(t("invalid script path: {exc}").format(exc=exc)) from exc
    if Path(script).name == "__main__.py":
        cmd = [sys.executable, "-m", "pkgcheck", *sys.argv[1:]]
    else:
        cmd = [script, *sys.argv[1:]]

    # Preserve UTF-8 fallback env across sudo (sudo env_reset may drop it)
    try:
        os.execvp(
            sudo_bin,
            [sudo_bin, "--preserve-env=PYTHONIOENCODING,LC_ALL,LC_MESSAGES,LANG", "--", *cmd],
        )
    except OSError as exc:
        # execvp only returns on error
        raise RuntimeError(t("failed to execute sudo: {exc}").format(exc=exc)) from exc


def _pseudo_prefixes(args: argparse.Namespace) -> tuple[str, ...]:
    """Combines the default pseudo-filesystems with the --exclude prefixes."""
    extra: list[str] = []
    for value in args.exclude:
        for part in value.split(","):
            part = part.strip().lstrip("/")
            if part and not part.endswith("/"):
                part += "/"
            if part:
                with contextlib.suppress(ValidationError):
                    extra.append(validate_exclude_prefix(part))
    return _PSEUDO_PREFIXES + tuple(extra)


def _backup_suffixes(args: argparse.Namespace) -> tuple[str, ...]:
    """Normalizes the --backup-suffixes list."""
    raw: str = cast(str, args.backup_suffixes)
    try:
        return validate_backup_suffixes(raw)
    except ValidationError:
        # If explicitly empty (only whitespace/commas), return empty tuple
        if not raw.strip().strip(","):
            return ()
        # Fallback to defaults on validation error
        return _DEFAULT_BACKUP_SUFFIXES


def _new_suffix(args: argparse.Namespace) -> str:
    """Normalizes the --new-suffix value."""
    raw: str = cast(str, args.new_suffix)
    try:
        return validate_new_suffix(raw)
    except ValidationError:
        return _DEFAULT_NEW_SUFFIX


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
    orphans: OrphansIndex | None = None,
) -> Path | None:
    """Writes the automatic log to ``/var/log/pkgcheck``; requires root.

    Returns the written path, or ``None`` if it could not be written (no root or I/O error).
    """
    if os.geteuid() != 0:
        return None
    log_path: Path | None = None
    try:
        log_path = unique_report_path(_LOG_DIR, when, fmt)
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            Path(_LOG_DIR).chmod(0o755)
        with contextlib.suppress(OSError, LookupError):
            gid = grp.getgrnam("wheel").gr_gid
            os.chown(_LOG_DIR, 0, gid)
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
            orphans,
        )
    except OSError as exc:
        console.print(
            t("[yellow]Could not write the log to {path}: {exc}[/yellow]").format(
                path=log_path or _LOG_DIR, exc=exc
            )
        )
        return None
    return log_path


def _run(
    console: Console,
    status_console: Console,
    args: argparse.Namespace,
    packages_dir: Path,
    rg_bin: str | None,
    ldd_bin: str | None = None,
    nm_bin: str | None = None,
    subprocess_env: dict[str, str] | None = None,
) -> None:
    # Backwards compatibility: old tests call _run(..., rg_bin, ldd_bin, subprocess_env)
    # where ldd_bin is a string and subprocess_env is a dict. In that case nm_bin
    # will be the dict and subprocess_env None.
    if isinstance(nm_bin, dict) and subprocess_env is None:
        subprocess_env = nm_bin
        nm_bin = None
    if subprocess_env is None:
        subprocess_env = {}
    # Handle Mock objects used in tests: hasattr on Mock always True, so check __dict__
    args_dict = vars(args) if hasattr(args, "__dict__") else {}
    # Also handle old singular arg name
    if "check_lib_deps" in args_dict and "check_libs_deps" not in args_dict:
        args.check_libs_deps = args_dict["check_lib_deps"]
    # Normalize: ensure check_libs_deps exists even if only singular was set
    if "check_libs_deps" not in args_dict:
        args.check_libs_deps = args_dict.get("check_lib_deps", False)
    # For compatibility, also set singular
    if "check_lib_deps" not in args_dict:
        args.check_lib_deps = args.check_libs_deps
    started = time.monotonic()
    when = datetime.now()
    status = status_console if args.json else console

    if not args.quiet:
        status.print(t("Scanning package records in {path}...").format(path=packages_dir))
    scan_result: ScanResult = scan_package_files(
        packages_dir,
        rg_bin,
        pseudo_prefixes=_pseudo_prefixes(args),
        subprocess_env=subprocess_env,
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
    with Progress(*progress_columns, console=status, disable=args.quiet or args.json) as progress:
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
    orphans: list[str] = []
    broken_count = 0
    missing_lib_count = 0
    undefined_count = 0
    if args.orphans:
        owned_set = {f"/{rel}" for _, rel in entries}
        orphans_root = Path(args.orphans_root).expanduser().resolve()
        # Use user extra excludes for orphans as well
        extra_for_orphans = _pseudo_prefixes(args)
        if not args.quiet:
            status.print(t("Scanning for orphan files in {path}...").format(path=orphans_root))
        orphans = find_orphans(owned_set, root=orphans_root, extra_exclude=extra_for_orphans)
    if args.check_libs_deps:
        assert elf_flags is not None
        assert ldd_bin is not None
        elf_entries = [
            (package, rel)
            for (package, rel), is_elf in zip(entries, elf_flags, strict=True)
            if is_elf
        ]
        if elf_entries:
            elf_paths = [f"/{rel}" for _, rel in elf_entries]
            owner_index = build_library_owner_index(entries)

            with Progress(
                *progress_columns, console=status, disable=args.quiet or args.json
            ) as progress:
                deps_task = progress.add_task(
                    t("Checking library dependencies (ldd)..."), total=len(elf_paths)
                )
                missing_per_path = check_libs_deps(
                    elf_paths,
                    args.workers,
                    ldd_bin,
                    owner_index,
                    on_progress=lambda done: progress.update(deps_task, completed=done),
                    extra_env=subprocess_env,
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
                assert nm_bin is not None
                with Progress(
                    *progress_columns, console=status, disable=args.quiet or args.json
                ) as progress:
                    sym_task = progress.add_task(
                        t("Collecting defined symbols..."), total=len(elf_paths)
                    )
                    defined = collect_defined_symbols(
                        elf_paths,
                        args.workers,
                        nm_bin,
                        on_progress=lambda done: progress.update(sym_task, completed=done),
                        extra_env=subprocess_env,
                    )
                with Progress(
                    *progress_columns, console=status, disable=args.quiet or args.json
                ) as progress:
                    undef_task = progress.add_task(
                        t("Checking undefined symbols..."), total=len(elf_paths)
                    )
                    undefined_by_path = check_undefined_symbols(
                        elf_paths,
                        defined,
                        args.workers,
                        nm_bin,
                        on_progress=lambda done: progress.update(undef_task, completed=done),
                        extra_env=subprocess_env,
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
        orphans=len(orphans),
    )

    if not args.quiet and not args.json:
        has_issues = any(
            [
                missing_by_package,
                backup_by_package,
                pending_new_by_package,
                errors_by_package,
                no_access_by_package,
                broken_libs,
                undefined_symbols,
                orphans,
            ]
        )
        if has_issues:
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
        if orphans:
            # Reuse breakdown but orphans are not per-package
            from rich.text import Text
            from rich.tree import Tree

            console.print()
            tree = Tree(
                f"[bold yellow]{'*' * 12} {t('Orphan files (untracked)')} {'*' * 12}[/bold yellow]"
            )
            # group orphans under root count
            branch = tree.add(f"[bold cyan]{t('orphans')} ({len(orphans)})[/bold cyan]")
            limit = args.max_rows if args.max_rows is not None else 2500
            for p in orphans[:limit]:
                branch.add(Text(p))
            if len(orphans) > limit:
                tree.add(t("... and {remaining} more files").format(remaining=len(orphans) - limit))
            console.print(tree)
            console.print()

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
    if args.json:
        sys.stdout.write(
            json_report(
                summary,
                *indexes,
                when,
                broken_libs or None,
                undefined_symbols or None,
                orphans or None,
            )
        )
        if os.geteuid() == 0:
            log_path = _write_auto_log(
                status,
                when,
                fmt,
                summary,
                *indexes,
                broken_libs or None,
                undefined_symbols or None,
                orphans or None,
            )
            if log_path is not None:
                status.print(t("[green]Log saved to:[/green] {path}").format(path=log_path))
        return
    log_path = _write_auto_log(
        status,
        when,
        fmt,
        summary,
        *indexes,
        broken_libs or None,
        undefined_symbols or None,
        orphans or None,
    )
    if log_path is not None:
        status.print(t("[green]Log saved to:[/green] {path}").format(path=log_path))
