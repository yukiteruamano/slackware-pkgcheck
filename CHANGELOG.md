# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-08-07
- Initial release: `FILE LIST` ripgrep bulk scan, ThreadPool verification, install/pseudo exclusion, `.new` pending, `.bak/.orig` backup-only.

## Unreleased
### Added
- (unreleased changes will be listed here)

## [0.2.0] - 2026-08-07
### Added
- `--check-libs-deps` (`ldd` revdep-rebuild style) with `broken_libs` JSON/report.
- `--check-libs-symbols` (`readelf -Ws`) with `undefined_symbols` (heuristic, false positives).
- i18n: 7 languages (en, es, pt, fr, de, zh, ja) via `PKGCHECK_LANG`/`--lang`.
- Rich progress, JSON/text logs under `/var/log/pkgcheck/`.

### Fixed
- UTF-8 fallback for non-UTF8 terminals.


## [0.3.0] - 2026-08-21
### Added
- `py.typed`, `mypy --strict`, `ruff` S/ANN/PTH/D, `coverage` 98% (fail_under 90), `pip-audit`, `pre-commit`, CI (`ci.yml`), `dependabot`, `CODEOWNERS`, `CONTRIBUTING.md`, `.editorconfig`.
- Scanner path-traversal hardening (`_is_safe_rel`) and expanded pseudo excludes (16 prefixes, `var/log/packages` exception).
- `ldd` security note (LD_TRACE) and `--safe-ldd` via `readelf -d NEEDED` (no execution) — now default safe mode via `readelf` (`--check-lib-deps`).
- Fallback Python scan when `ripgrep` not found (instead of hard error).
- `--orphans` / `--orphans-root` via `orphans.py`, `--list-logs`, `--diff` (`--from`/`--to`, `latest` aliases) via `diff.py`.
- `--completion bash|zsh|fish` generation.
- Reporter orphans handling (`orphans` JSON key, `ORPHANS` text section, summary).
- Tests 88 → 284, scanner/verifier/libdeps/reporter/cli/i18n all ≥90%.

### Changed
- CLI renamed `--check-libs-deps` → `--check-lib-deps` (always safe `readelf`); removed `--safe-ldd` flag.
- Hardened verification, reporting and i18n: ripgrep `LC_ALL=C`, Python scan `OSError` handling, `or+phans` walk prune, `diff` merge and `list_logs` `OSError` handling, `i18n` `zh_TW`/`LC_ALL` fixes.

### Security
- New `validate.py` defense-in-depth layer (`validate_safe_path`, `validate_subprocess_arg`, `validate_exclude_prefix/suffix`, `validate_backup_suffixes`, `sanitize_for_subprocess`, `validate_packages_dir/orphans_root/binary_path`) with `PATH_MAX`/`ARG_MAX`, forbidden/control char checks, `relative_to` base-dir containment and `lexists` semantics; all CLI inputs validated.
- `libdeps` fully migrated from `ldd` (which executes binaries) to safe `readelf -d NEEDED` with `soname` version matching; `verifier` anti-TOCTOU `open+fstat` and `NO_ACCESS` handling.
- `diff` merge and `CI` dependency bumps (`actions/checkout` 5→7, `actions/upload-artifact` 4→7).

