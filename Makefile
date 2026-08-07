# pkgcheck - calidad, build y publicación con uv.
UV          := uv
PYPI_URL    := https://upload.pypi.org/legacy/
TESTPYPI_URL := https://test.pypi.org/legacy/

.PHONY: check lint format format-check test build publish publish-test \
        publish-dry-run push release clean

# Objetivo por defecto: `make` -> calidad
check: lint format-check test

lint:
	$(UV) run ruff check .

format:
	$(UV) run ruff format .

format-check:
	$(UV) run ruff format --check .

test:
	$(UV) run python -m unittest discover -s tests

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
	rm -rf dist/ build/ *.egg-info
