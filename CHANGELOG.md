# Changelog

All notable changes to this project will be documented in this file.

## Unreleased
### Added
- (unreleased changes will be listed here)

## [1.0.2] - 2026-09-11
### Fixed
- 3 hanging `future_exception` tests (mock retargeted `wait` → `as_completed`); `make coverage` no longer hangs
- Stale `ldd` tests rewritten to `not found` output format
### Added
- 50+ gap tests (libdeps/cli/verifier/scanner/diff/orphans/reporter); coverage 85% → 98%, `cli.py`/`validate.py` 100%
### Changed
- Coverage `fail_under` 85 → 90
### Removed
- Defensive-dead guards: soname `IndexError`, diff `_normalize` fallback + summary `TypeError`, `validate` impossible absolute check

## [1.0.1] - 2026-09-11
### Removed
- Dead code: `libdeps` ld-cache/FS helpers (`_load_ldcache`, `_in_ldcache`, `_exists_on_fs`, `_STD_LIB_DIRS`), `diff` `_index_to_sets`, `scanner` `_octal_to_byte`, `verifier` `_is_elf_target`
- Test-only aliases from production (`_get_needed_libs`, `_ldd_symbols`, `_undefined_symbols` moved to `tests/helpers.py`)
### Changed
- `validate` inputs widened from `str` to `object` (honest defense-in-depth typing; `isinstance` guards now meaningful to static analyzers)
- Stale `ldd` tests updated to `not found` output format; `check_library_deps` mock retargeted to `_ldd_missing`

## [1.0.0] - 2026-08-24
### Changed
- Stable release `1.0.0`: `libdeps` finalized on fast loader-aware `ldd` + `nm -D` (no `readelf`/`pyelftools`; `readelf` mentions purged from `src/` and `.venv`).
- `ldd` security hardened: sanitized env `LC_ALL=C`, cleared `LD_LIBRARY_PATH`/`LD_PRELOAD`/`LD_AUDIT`/`LD_BIND_NOW`, `shutil.which` + `validate_binary_path` for `ldd`/`nm`/`ldconfig`.

### Security
- Log writes hardened to atomic `mkstemp` + `fchmod 0o644` / dir `0o755` + `chown root:wheel`; console throttled with `rich.Progress` (stderr for `--json`).

## [0.3.1] - 2026-08-21
### Fixed
- `libdeps` clean console: `build_library_owner_index` now last-wins silently — removed 10+ `RuntimeWarning: Library libVkLayer_khronos_validation.so / libxul.so / libmoz* provided by multiple packages ...` spam from `--check-lib-deps` (chromium/vulkan-sdk, firefox/thunderbird duplicates).

### Changed
- `libdeps` (`ldd`/`nm -D`) optimized with `ThreadPoolExecutor` and throttled progress; `broken_libs` now uses fast loader-aware `ldd` parsing.
- `libdeps` `check_libs_deps`/`collect_defined_symbols`/`check_undefined_symbols` no longer emit `RuntimeWarning` on future exceptions.

## [0.3.0] - 2026-08-21
### Added
- `py.typed`, `mypy --strict`, `ruff` S/ANN/PTH/D, `coverage` 98% (fail_under 90), `pip-audit`, `pre-commit`, CI (`ci.yml`), `dependabot`, `CODEOWNERS`, `CONTRIBUTING.md`, `.editorconfig`.
- Scanner path-traversal hardening (`_is_safe_rel`) and expanded pseudo excludes (16 prefixes, `var/log/packages` exception).
- `ldd` security note (LD_TRACE, sanitized `LC_ALL=C` and cleared `LD_*`) — `--check-libs-deps` uses `ldd` (fast, opt-in).
- Fallback Python scan when `ripgrep` not found (instead of hard error).
- `--orphans` / `--orphans-root` via `orphans.py`, `--list-logs`, `--diff` (`--from`/`--to`, `latest` aliases) via `diff.py`.
- `--completion bash|zsh|fish` generation.
- Reporter orphans handling (`orphans` JSON key, `ORPHANS` text section, summary).
- Tests 88 → 284, scanner/verifier/libdeps/reporter/cli/i18n all ≥90%.

### Changed
- CLI normalized `--check-libs-deps` (with `--check-lib-deps` deprecated alias); removed `--safe-ldd` flag (now always `ldd`).
- Hardened verification, reporting and i18n: ripgrep `LC_ALL=C`, Python scan `OSError` handling, `orphans` walk prune, `diff` merge and `list_logs` `OSError` handling, `i18n` `zh_TW`/`LC_ALL` fixes.

### Security
- New `validate.py` defense-in-depth layer (`validate_safe_path`, `validate_subprocess_arg`, `validate_exclude_prefix/suffix`, `validate_backup_suffixes`, `sanitize_for_subprocess`, `validate_packages_dir/orphans_root/binary_path`) with `PATH_MAX`/`ARG_MAX`, forbidden/control char checks, `relative_to` base-dir containment and `lexists` semantics; all CLI inputs validated.
- `libdeps` uses fast loader-aware `ldd` with `soname` version matching and sanitized env; `verifier` anti-TOCTOU `open+fstat` and `NO_ACCESS` handling.
- `diff` merge and `CI` dependency bumps (`actions/checkout` 5→7, `actions/upload-artifact` 4→7).

## [0.2.0] - 2026-08-07
### Added
- `--check-libs-deps` (`ldd` revdep-rebuild style, fast and loader-aware) with `broken_libs` JSON/report.
- `--check-libs-symbols` (`nm -D --undefined-only`/`--defined-only`) with `undefined_symbols` (heuristic, false positives).
- i18n: 7 languages (en, es, pt, fr, de, zh, ja) via `PKGCHECK_LANG`/`--lang`.
- Rich progress, JSON/text logs under `/var/log/pkgcheck/`.

### Fixed
- UTF-8 fallback for non-UTF8 terminals.

## [0.1.0] - 2026-08-07
- Initial release: `FILE LIST` ripgrep bulk scan, ThreadPool verification, install/pseudo exclusion, `.new` pending, `.bak/.orig` backup-only.
