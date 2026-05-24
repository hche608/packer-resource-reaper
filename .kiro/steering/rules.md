# Project Steering & Rules

This project adheres to the **KISS** principle and uses **uv** for high-performance dependency management.

## 1. Technology Stack
- **Python**: 3.11+ (CI tests 3.11 and 3.12)
- **Manager**: `uv` (replaces pip, poetry, virtualenv)
- **Linter/Formatter**: `ruff` (replaces black, isort, flake8)
- **Testing**: `pytest` with `coverage`
- **Mocking**: `unittest.mock.MagicMock` for unit tests

## 2. Workflow
- **Install**: Run `uv sync` to install dependencies and setup the virtual environment.
- **Format**: Run `uv run ruff format .` to format code.
- **Lint**: Run `uv run ruff check .` to lint code.
- **Test**: Run `uv run pytest` to execute tests.
- **Coverage**: Run `make test-cov` to check coverage.
- **Validate**: Run `sam validate --lint` to validate SAM template.
- **Local Run**: Run `make invoke-local` to test against real AWS (dry-run, no Docker).

## 3. Configuration
- Configuration is consolidated in `pyproject.toml`.
- Python version is pinned in `.python-version`.
- Lockfile `uv.lock` ensures reproducible builds.
- SAM deployment configs in `samconfig.toml`.

## 4. Quality Gates
- **Coverage**: Minimum 80% test coverage required (currently 96%).
- **Linting**: Zero ruff errors allowed.
- **Type Safety**: Strict typing required. All functions must define input and return types.
- **Mocking**: No real AWS API calls allowed in tests.
- **SAM Validation**: Template must pass `sam validate --lint`.
- **KISS Principle**: Keep tooling minimal. Prefer single tools (ruff, uv).

## 5. Architecture Rules
- **No cross-account**: Single account/region scope only. No role assumption.
- **Stateless**: No database, no state persistence between invocations.
- **Batch processing**: Use `ThreadPoolExecutor` (not asyncio) for concurrent boto3 calls.
- **Factory closures**: Use `_make_*_deleter()` factory methods for batch delete functions (avoids lambda capture issues in threads).
