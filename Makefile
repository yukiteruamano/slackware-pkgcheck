# pkgcheck - calidad, build y publicación con uv.
UV          := uv
PYPI_URL    := https://upload.pypi.org/legacy/
TESTPYPI_URL := https://test.pypi.org/legacy/

.PHONY: help check lint format format-check test build typecheck coverage coverage-html audit sync publish publish-test \
        publish-dry-run push release clean

# Objetivo por defecto: `make` -> calidad
help:
	@echo "Targets:"
	@echo "  check          lint + format-check + typecheck + test"
	@echo "  lint           ruff check"
	@echo "  format         ruff format"
	@echo "  format-check   ruff format --check"
	@echo "  typecheck      mypy --strict"
	@echo "  test           unittest discover"
	@echo "  coverage       tests with coverage + report (>=80%)"
	@echo "  coverage-html  html coverage report"
	@echo "  audit          pip-audit"
	@echo "  sync           uv sync --group dev"
	@echo "  build          uv build"
	@echo "  publish        check + build + publish PyPI"
	@echo "  clean          remove artifacts"

check: lint format-check typecheck test

lint:
	$(UV) run ruff check .

format:
	$(UV) run ruff format .

format-check:
	$(UV) run ruff format --check .

typecheck:
	$(UV) run mypy src

test:
	$(UV) run python -m unittest discover -s tests

coverage:
	$(UV) run coverage run -m unittest discover -s tests
	$(UV) run coverage report

coverage-html:
	$(UV) run coverage run -m unittest discover -s tests
	$(UV) run coverage html
	@echo "HTML report: htmlcov/index.html"

audit:
	$(UV) run pip-audit --strict

sync:
	$(UV) sync --group dev

build:
	$(UV) build

# Publicación a PyPI: verifica (check), construye y sube.
publish: check build
	$(UV) publish --publish-url $(PYPI_URL)

publish-test: check build
	$(UV) publish --publish-url $(TESTPYPI_URL)

publish-dry-run:
	$(UV) publish --dry-run

push:
	git push github master
	git push gitea master

# Pipeline completa: verifica, construye y publica.
release: publish

clean:
	rm -rf dist/ build/ *.egg-info htmlcov/ .coverage coverage.xml
