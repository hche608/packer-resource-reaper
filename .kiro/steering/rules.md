# Project Steering & Rules

This project adheres to the **KISS** principle and uses **uv** for high-performance dependency management.

## 1. Technology Stack
- **Python**: 3.11+
- **Manager**: `uv` (replaces pip, poetry, virtualenv)
- **Linter/Formatter**: `ruff` (replaces black, isort, flake8)
- **Testing**: `pytest` with `coverage`
- **Mocking**: `moto` for AWS services

## 2. Workflow
- **Install**: Run `uv sync` to install dependencies and setup the virtual environment.
- **Format**: Run `uv run ruff format .` to format code.
- **Lint**: Run `uv run ruff check .` to lint code.
- **Test**: Run `uv run pytest` to execute tests.
- **Coverage**: Run `make test-cov` to check coverage.

## 3. Configuration
- Configuration is consolidated in `pyproject.toml`.
- Python version is pinned in `.python-version`.
- Lockfile `uv.lock` ensures reproducible builds.

## 4. Quality Gates
- **Coverage**: Minimum 80% test coverage required (enforced by `pyproject.toml`).
- **Linting**: Zero ruff errors allowed.
- **Type Safety**: Strict typing required. All functions must define input and return types.
- **Mocking**: No real AWS API calls allowed in tests. Use `moto` to mock AWS services.
- **KISS Principle**: Keep tooling minimal. Prefer single tools (ruff, uv).
