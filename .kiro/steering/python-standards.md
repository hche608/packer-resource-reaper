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
      # Critical Best Practices
      - id: debug-statements        # Blocks `import pdb`, `breakpoint()`, etc.
      - id: check-merge-conflict    # Blocks git merge markers (<<<<<<<)
      - id: check-case-conflict     # Prevents case-insensitive filename collisions
      - id: detect-aws-credentials  # Scans for accidental AWS key commits
        args:
          - --allow-missing-credentials
      - id: detect-private-key      # Scans for private keys

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.5.0  # Use a recent stable version
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
# E/F/W: Standard flake8 rules
# I: Isort (imports)
# UP: Pyupgrade (modernize syntax)
# B: Bugbear (potential bugs)
# SIM: Simplify (code logic)
# S: Bandit (security)
# N: PEP8 Naming
# C90: McCabe Complexity
select = ["E", "F", "I", "W", "UP", "B", "SIM", "S", "N", "C90"]
ignore = ["E501"] # Line length handled by formatter

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101"] # Allow asserts in tests

[tool.ruff.lint.mccabe]
max-complexity = 10
```

## 3. Static Typing (Mypy)

Enforce strict typing to minimize the usage of `Any` and ensure type safety.

**File:** `pyproject.toml`

```toml
[tool.mypy]
python_version = "3.11"
# Strictness & Safety Flags
warn_return_any = true          # Warn if a function returns Any
warn_unused_configs = true
disallow_untyped_defs = true    # Require type hints for all functions
check_untyped_defs = true       # Check bodies of untyped functions
disallow_any_generics = true    # Disallow generic types without arguments (e.g. List vs List[str])
no_implicit_optional = true     # Don't assume Optional just because of a default None
ignore_missing_imports = true
```

## 4. Testing Strategy

**Rule:** Avoid hardcoded values in tests. Use property-based testing or random data generation to ensure robustness against edge cases.

- **Library:** `hypothesis` (Preferred for logic/property testing)
- **Library:** `faker` (Preferred for generating dummy PII/Strings)
- **Why:** Hardcoded values (e.g., `instance_id="i-12345"`) only test the "happy path". Generated data uncovers edge cases (empty strings, unicode, max length) automatically.
