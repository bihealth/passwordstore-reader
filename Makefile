.PHONY: format
format:
	uv run ruff format

.PHONY: format-check
format-check:
	uv run ruff format --check

.PHONY: lint
lint:
	uv run ruff check

.PHONY: type-check
type-check:
	uv run pyrefly check

.PHONY: check
check: format-check lint type-check

.PHONY: fix
fix:
	uv run ruff check --fix

.PHONY: test
test:
	uv run pytest tests/ -v --cov=src/passwordstore_reader --cov-report=html --cov-report=term-missing --cov-fail-under=95
