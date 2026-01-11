# Packer Resource Reaper - Makefile
# ================================
# Common development tasks for the AWS Packer Resource Reaper project.

.PHONY: help install install-dev clean deep-clean lint format type-check test test-cov test-watch \
        build invoke deploy deploy-dev deploy-prod validate logs

# Default target
help:
	@echo "Packer Resource Reaper - Development Commands"
	@echo "============================================="
	@echo ""
	@echo "Setup:"
	@echo "  make install        Install production dependencies"
	@echo "  make install-dev    Install development dependencies"
	@echo "  make clean          Remove build artifacts and caches"
	@echo "  make deep-clean     Remove everything including .venv"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint           Run linters (flake8)"
	@echo "  make format         Format code (black + isort)"
	@echo "  make type-check     Run type checking (mypy)"
	@echo "  make check          Run all code quality checks"
	@echo ""
	@echo "Testing:"
	@echo "  make test           Run all tests"
	@echo "  make test-cov       Run tests with coverage report"
	@echo "  make test-fast      Run tests without property-based tests"
	@echo ""
	@echo "SAM (Local Development):"
	@echo "  make build          Build SAM application"
	@echo "  make invoke         Invoke Lambda locally (dry-run)"
	@echo "  make invoke-debug   Invoke Lambda locally with DEBUG logging"
	@echo "  make validate       Validate SAM template"
	@echo ""
	@echo "Deployment:"
	@echo "  make deploy         Deploy to AWS (default config)"
	@echo "  make deploy-dev     Deploy to dev environment"
	@echo "  make deploy-prod    Deploy to production (DRY_RUN=false)"
	@echo "  make logs           Tail Lambda logs"

# =============================================================================
# Setup
# =============================================================================

install:
	uv pip compile pyproject.toml -o requirements.txt
	uv pip install -r requirements.txt

install-dev:
	uv pip install -e ".[dev]"

clean:
	rm -rf .pytest_cache
	rm -rf .hypothesis
	rm -rf .mypy_cache
	rm -rf .coverage
	rm -rf htmlcov
	rm -rf .aws-sam
	rm -rf dist
	rm -rf *.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

deep-clean: clean
	rm -rf .venv

# =============================================================================
# Code Quality
# =============================================================================

lint:
	uv run flake8 reaper --max-line-length=100 --ignore=E501,W503,E203
	uv run flake8 tests --max-line-length=100 --ignore=E501,W503,E203

format:
	uv run isort reaper tests
	uv run black reaper tests

format-check:
	uv run isort --check-only reaper tests
	uv run black --check reaper tests

type-check:
	uv run mypy reaper --ignore-missing-imports

check: lint format-check type-check
	@echo "All code quality checks passed!"

# =============================================================================
# Testing
# =============================================================================

test:
	uv run pytest tests/ -v

test-cov:
	uv run pytest tests/ -v --cov=reaper --cov-report=term-missing --cov-report=html

test-fast:
	uv run pytest tests/ -v -m "not hypothesis" --ignore=tests/test_identity_filter.py --ignore=tests/test_temporal_filter.py

test-safety:
	uv run pytest tests/test_identity_filter.py -v -k "security_group"

# =============================================================================
# SAM Local Development
# =============================================================================

build:
	uv pip compile pyproject.toml -o requirements.txt
	sam build

invoke: build
	sam local invoke ReaperFunction --event events/scheduled.json --env-vars env.json

invoke-debug: build
	@echo "Running with DEBUG logging..."
	sam local invoke ReaperFunction --event events/scheduled.json --env-vars env.json

validate:
	sam validate --lint

# =============================================================================
# Deployment
# =============================================================================

deploy: build
	sam deploy

deploy-dev: build
	sam deploy --config-env dev

deploy-prod: build
	@echo "WARNING: Deploying to PRODUCTION with DRY_RUN=false"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ]
	sam deploy --config-env prod

logs:
	sam logs -n ReaperFunction --stack-name packer-resource-reaper --tail

logs-dev:
	sam logs -n ReaperFunction --stack-name packer-resource-reaper-dev --tail

logs-prod:
	sam logs -n ReaperFunction --stack-name packer-resource-reaper-prod --tail
