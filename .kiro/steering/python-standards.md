# Python Project Standards & Best Practices

## 1. Pre-commit Configuration

Standard hooks to ensure code hygiene, prevent debugging artifacts, and enhance security.

**File:** `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: debug-statements
      - id: check-merge-conflict
      - id: check-case-conflict
      - id: detect-aws-credentials
        args:
          - --allow-missing-credentials
      - id: detect-private-key

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.5.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
```

## 2. Linting & Formatting (Ruff)

We use **Ruff** to replace Flake8, Isort, Bandit, and Pyupgrade.

**File:** `pyproject.toml`

```toml
[tool.ruff.lint]
select = ["E", "F", "I", "W", "UP", "B", "SIM", "S", "N", "C90"]
ignore = ["E501"]  # Line length handled by formatter

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101", "S105", "S106", "N803", "SIM102", "SIM103", "SIM108", "SIM116", "SIM117", "B007", "C901"]

[tool.ruff.lint.mccabe]
max-complexity = 15  # Allows slightly higher for complex AWS orchestration logic
```

## 3. Static Typing (Mypy)

Enforce strict typing to minimize the usage of `Any` and ensure type safety.

**File:** `pyproject.toml`

```toml
[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
check_untyped_defs = true
disallow_any_generics = true
no_implicit_optional = true
ignore_missing_imports = true
exclude = ["tests/", "build/", "dist/"]
```

## 4. Testing Strategy

**Rule:** Avoid hardcoded values in tests. Use property-based testing or random data generation to ensure robustness against edge cases.

- **Library:** `hypothesis` (Preferred for logic/property testing)
- **Why:** Hardcoded values only test the "happy path". Generated data uncovers edge cases automatically.
- **Coverage:** 867 tests, 96% coverage, minimum 80% enforced.
- **Property tests:** Use `@settings(max_examples=100, deadline=5000)` for consistency.
