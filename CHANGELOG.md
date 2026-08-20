# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-08-07
### Added
- `--check-libs-deps` (`ldd` revdep-rebuild style) with `broken_libs` JSON/report.
- `--check-libs-symbols` (`readelf -Ws`) with `undefined_symbols` (heuristic, false positives).
- i18n: 7 languages (en, es, pt, fr, de, zh, ja) via `PKGCHECK_LANG`/`--lang`.
- Rich progress, JSON/text logs under `/var/log/pkgcheck/`.

### Fixed
- UTF-8 fallback for non-UTF8 terminals.

## [0.1.0] - 2026-08-??
- Initial release: `FILE LIST` ripgrep bulk scan, ThreadPool verification, install/pseudo exclusion, `.new` pending, `.bak/.orig` backup-only.

## Unreleased
### Added
- `py.typed`, `mypy --strict`, `ruff` S/ANN/PTH/D, `coverage` 80%, `pip-audit`, `pre-commit`, CI (`ci.yml`), `dependabot`, `CODEOWNERS`, `CONTRIBUTING.md`, `.editorconfig`.
- Scanner path-traversal hardening (`_is_safe_rel`).
- `ldd` security note (LD_TRACE).

