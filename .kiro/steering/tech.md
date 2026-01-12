# Tech Stack

## Runtime
- Python 3.11+
- AWS Lambda (serverless)
- AWS SAM for deployment

## Dependencies
- `boto3` / `botocore` - AWS SDK
- `typing-extensions` - Type hints

## Dev Dependencies
- `pytest` / `pytest-cov` / `pytest-mock` - Testing
- `hypothesis` - Property-based testing
- `moto` - AWS mocking
- `ruff` - Linting & formatting
- `mypy` / `boto3-stubs` - Type checking

## Package Manager
- `uv` for dependency management
- `pyproject.toml` for project configuration
- `uv.lock` for reproducible builds

## Common Commands

```bash
# Setup
make install-dev      # Install dev dependencies (uv sync)

# Code Quality
make lint             # Run ruff check
make format           # Format with ruff
make type-check       # Run mypy
make check            # Run all checks

# Testing
make test             # Run all tests
make test-cov         # Tests with coverage
make test-fast        # Skip property-based tests

# SAM / Deployment
make build            # Build SAM application
make validate         # Validate SAM template
make invoke           # Local Lambda invocation
make deploy           # Deploy to AWS
make deploy-prod      # Deploy to production (DRY_RUN=false)
make logs             # Tail Lambda logs
```

## Configuration
Environment variables (set in SAM template):
- `MAX_INSTANCE_AGE_HOURS` - Age threshold (default: 2)
- `DRY_RUN` - Enable dry-run mode (default: true)
- `KEY_PAIR_PATTERN` - Key pattern prefix (default: `packer_`)
- `LOG_LEVEL` - DEBUG/INFO/WARNING/ERROR/CRITICAL
- `BATCH_DELETE_SIZE` - Concurrent deletions per batch
- `SNS_TOPIC_ARN` - Notifications topic
