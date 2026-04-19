.PHONY: setup test test-contract lint

setup:
	pip install -e ".[dev]"

test:
	pytest tests/unit/ -v

test-contract:
	pytest tests/contract/ -v

lint:
	ruff check . && mypy orchestrator/
