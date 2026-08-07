# pkgcheck

Integrity checker for Slackware Linux: verifies that the files recorded by each package
in `/var/log/packages/` really exist on the system.

- Bulk extraction of `FILE LIST:` sections with **ripgrep** in a single pass.
- Parallel verification with `ThreadPoolExecutor` (broken symbolic links count as present:
  `os.lstat` is used).
- Distinguishes **missing** files, **backup-only** (`.bak`/`.orig`) and **no access**
  (requires root), as well as **`.new` configs pending review**.
- Decodes the octal escapes (`\NNN`) Slackware uses for names with non-ASCII bytes and
  discards sections after the FILE LIST (e.g. `REQUIRES:`).
- Excludes install scripts (`install/`) and pseudo-filesystems (`dev/`, `sys/`, …).
- Reports files with **verification errors** too (JSON `files_errors` / `ERRORS` log section).
- Live progress and report with **rich**; summary + breakdown per package.
- Automatic log in `/var/log/pkgcheck/pkgcheck-<date>.log` (`.json` with `--json`).
- Internationalized interface (7 languages) with automatic OS locale detection.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- ripgrep (`rg`) in the `PATH`

## Getting started

```sh
uv sync                # creates .venv and installs the project and its dependencies
uv run pkgcheck --version
```

It can also be run as a module: `uv run python -m pkgcheck`.

## Usage

```sh
sudo uv run pkgcheck                          # analyzes /var/log/packages and writes the log
sudo uv run pkgcheck --json                   # writes the log in JSON format (.json)
uv run pkgcheck --no-elevate --json           # without root: only prints the JSON to stdout
uv run pkgcheck --workers 16                  # adjusts the parallelism
uv run pkgcheck --packages-dir /mnt/root/var/log/packages
```

### Root privileges

Some protected files (e.g. `/var/spool/atjobs`, `/root`) can only be checked with root
privileges. If the process is not running as root:

- In an interactive terminal you are asked whether to **re-run with sudo**.
- `--elevate` re-runs with `sudo` without asking.
- `--no-elevate` (or `--quiet`, or non-interactive output) verifies only what is
  accessible and warns.

### Install scripts and pseudo-filesystems

Entries under `install/` (`install/doinst.sh`, `install/slack-desc`,
`install/douninst.sh`, `install/slack-required`) are metadata that Slackware does not
leave on disk, so they are **excluded** from the analysis and shown as an informational
counter.

The pseudo-filesystems (`dev/`, `sys/`, `proc/`, `run/`, `tmp/` and `var/run/`) are also
not tracked: their entries (e.g. the device nodes of the `devs` package) are dynamic and
do not persist. More prefixes can be added with `--exclude`.

### Pending new configs (`.new`)

Slackware records configs with the `.new` suffix in `FILE LIST` (e.g.
`etc/ssl/openssl.cnf.new`). On install, the package script **renames** the file to the
name without suffix (`.new` → ``); if that file already existed on the system, it keeps
the `.new` suffix and it is left **pending review** by the user.

pkgcheck honors this semantics:

- `foo.conf.new` recorded and `foo.conf` present → installed correctly (not reported).
- `foo.conf.new` present on disk → reported as **pending review** (the new version awaits
  your decision).
- `foo.conf.new` recorded but with no trace → missing.

The suffix is adjusted with `--new-suffix` (default `.new`). The detail appears in the
report (key `files_pending_new` in JSON) and in the console tree.

### Backup-only files

If a recorded path does not exist but a backup-suffix variant (`.bak` or `.orig`) does,
it is reported as **backup-only** instead of missing. The set of suffixes is adjusted with
`--backup-suffixes`. The per-package detail appears in the report (key `files_backup` in
JSON), not in the console tree.

### Automatic log

Each run writes a log in `/var/log/pkgcheck/` (the directory is created if it does not
exist) with the convention:

```sh
pkgcheck-dd-mm-yyyy-hh-mm-ss.log    # plain text (default)
pkgcheck-dd-mm-yyyy-hh-mm-ss.json   # with --json
```

- Requires root privileges: the default run uses `sudo`, so the log is saved
  automatically. If it cannot be written, a warning is shown and the analysis continues.
- With `--no-elevate` (or non-interactive output without root) **no file is saved**: the
  result is only shown on screen (rich in text mode; with `--json` only the JSON document
  is printed to stdout).
- With `--json`, progress and process messages go to **stderr** (scan phases, progress bar
  and completion line), so **stdout** is reserved for the JSON document (no-elevate) or
  the confirmation of the saved log (root). In text mode progress is shown in the console
  itself.
- If two runs collide on the same second, a numeric suffix is added
  (`pkgcheck-<date>-1.log`, `-2`, ...).

The JSON document includes a `timestamp` (ISO 8601), `generator`, `version`, `summary`
and the per-package indexes `missing`, `files_backup`, `files_pending_new`, `no_access`
and `files_errors`. These keys are stable and never localized.

### Internationalization

The interface, the help and the text log are localized according to the operating system
language. Supported languages: `en` (base), `es`, `pt`, `fr`, `de`, `zh` (Simplified
Chinese) and `ja`.

Precedence for choosing the language:

1. `--lang {en,es,pt,fr,de,zh,ja}`
2. `PKGCHECK_LANG` environment variable
3. OS locale (`LC_ALL`, `LC_MESSAGES` or `LANG`)
4. English (default)

Translations live in `src/pkgcheck/locales/{lang}.json` (English → language mapping). To
add a new language, create `locales/xx.json` with the same keys translated; if a key is
missing, the English text is shown. The report JSON keys (`missing`, `files_backup`, ...)
are not localized: they are the stable API.

### Arguments

| Argument           | Description                                                              |
|--------------------|--------------------------------------------------------------------------|
| `--packages-dir`   | Directory with the records (default `/var/log/packages`).                |
| `--workers N`      | Verification threads (default: auto).                                    |
| `--json`           | Writes the log in JSON format (`.json`) instead of text.                 |
| `--max-rows N`     | Limits the per-package console breakdown.                                |
| `--exclude PREFIX` | Additional prefix to exclude (repeatable or comma-separated).            |
| `--backup-suffixes`| Backup suffixes detected as backup-only (default `.bak,.orig`).          |
| `--new-suffix`     | New-config suffix pending review (default `.new`).                       |
| `--lang LANG`      | Interface language (`en,es,pt,fr,de,zh,ja`); detects the OS language.    |
| `--quiet`          | Hides progress and breakdown; only prints the summary.                   |
| `--elevate`        | Re-runs with sudo if root privileges are not available.                  |
| `--no-elevate`     | Does not ask for root privileges; only verifies what is accessible.      |
| `--version`        | Shows the version.                                                       |

## Code quality

```sh
uv run ruff check
uv run ruff format --check
```

Ruff configuration in `pyproject.toml`: `target-version = "py312"` and rules
`E, F, W, I, UP, B, SIM, C4, RET, ARG, RUF`.
