# Tech Stack

## Runtime
- Python 3.11+ (tested on 3.11 and 3.12)
- AWS Lambda (serverless, ARM64/Graviton)
- AWS SAM for deployment
- Published to AWS Serverless Application Repository (SAR)

## Dependencies
- `boto3` / `botocore` - AWS SDK
- `typing-extensions` - Type hints

## Dev Dependencies
- `pytest` / `pytest-cov` / `pytest-mock` - Testing
- `hypothesis` - Property-based testing
- `moto` - AWS mocking (available but tests use MagicMock)
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
make check            # Run all checks (lint + format-check + type-check)

# Testing
make test             # Run all tests
make test-cov         # Tests with coverage
make test-fast        # Skip property-based tests

# Local Testing
make invoke-local     # Run reaper locally (dry-run, no Docker)
make invoke           # SAM local invoke (requires Docker)

# SAM / Deployment
make build            # Build SAM application
make validate         # Validate SAM template (sam validate --lint)
make deploy           # Deploy to AWS (default config)
make deploy-prod      # Deploy to production (DRY_RUN=false)
make logs             # Tail Lambda logs

# SAR Publishing
sam package --output-template-file packaged.yaml --resolve-s3
sam publish --template packaged.yaml --region us-east-1
```

## Configuration
Environment variables (set in SAM template):
- `MAX_INSTANCE_AGE_HOURS` - Age threshold (default: 2)
- `DRY_RUN` - Enable dry-run mode (default: true)
- `KEY_PAIR_PATTERN` - Key pattern prefix (default: `packer_`)
- `LOG_LEVEL` - DEBUG/INFO/WARNING/ERROR/CRITICAL
- `BATCH_DELETE_SIZE` - Concurrent deletions per batch (default: 1)
- `SNS_TOPIC_ARN` - Notifications topic (auto-created by SAM)

## CI/CD
- GitHub Actions: lint, format, type-check, tests (Python 3.11 + 3.12 matrix)
- SAM template validation in CI (`sam validate --lint`)
- Coverage gate: minimum 80% (currently 96%)
