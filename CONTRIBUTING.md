# Contributing

## Setup

```sh
uv sync --group dev
uv run pre-commit install
```

Requires Python 3.12+, `uv`, `ripgrep` (`rg`).

## Workflow

```sh
make check          # lint + format-check + typecheck + test
make coverage       # coverage report (fail under 80%)
make coverage-html  # htmlcov/index.html
make audit          # pip-audit
```

Before pushing:

```sh
uv run ruff check --fix .
uv run ruff format .
uv run mypy src
make coverage
```

## Commits

Conventional commits preferred: `feat:`, `fix:`, `chore:`, `docs:`.

## i18n

Add new language: create `src/pkgcheck/locales/{lang}.json` with same keys as `es.json`. CI checks key sync.

## Security

Do not run `--check-libs-deps` on untrusted binaries (`ldd` executes them).
Report vulnerabilities via GitHub issue (private if needed).
