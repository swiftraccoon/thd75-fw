# Top-level Makefile — convenience targets for the Python side.
# The Rust firmware has its own Makefile at firmware/Makefile.

PYTHON ?= .venv/bin/python

.PHONY: help test lint typecheck check all

help:
	@echo "Targets:"
	@echo "  test         Run pytest and the firmware tool tests"
	@echo "  lint         Run ruff format --check and ruff check on all Python"
	@echo "  typecheck    Run mypy and pyright (strict, matching CI)"
	@echo "  check        Run lint + typecheck + test"

test:
	$(PYTHON) -m pytest tests/
	PYTHONPATH=firmware $(PYTHON) -m unittest discover -s firmware/tests -p 'test_*.py'

lint:
	$(PYTHON) -m ruff format --check src tests scripts firmware loaders
	$(PYTHON) -m ruff check src tests scripts firmware loaders

typecheck:
	$(PYTHON) -m mypy
	$(PYTHON) -m pyright --pythonpath $(PYTHON)

check: lint typecheck test
