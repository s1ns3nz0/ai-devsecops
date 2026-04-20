.PHONY: setup test test-contract lint demo demo-full

setup:
	pip install -e ".[dev]"

test:
	pytest tests/unit/ -v

test-contract:
	pytest tests/contract/ -v

lint:
	ruff check . && mypy orchestrator/

demo:
	@python -m orchestrator demo tests/fixtures/sample-app --product payment-api

demo-full:
	@BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6-20250514-v1:0 python -m orchestrator demo tests/fixtures/sample-app --product payment-api
