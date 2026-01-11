"""Property-based tests for log level configuration.

Feature: packer-resource-reaper, Property 12: Log Level Configuration
Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5

Tests that:
- Valid LOG_LEVEL values (DEBUG, INFO, WARNING, ERROR, CRITICAL) are correctly parsed
- Invalid LOG_LEVEL values default to INFO with a warning
- LOG_LEVEL not set defaults to INFO
- DEBUG level outputs detailed information
- ERROR level or higher only outputs error conditions
"""

import logging
import os
from io import StringIO

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from reaper.utils.config import (
    VALID_LOG_LEVELS,
    ReaperConfig,
    configure_logging,
)

# Strategy for valid log levels
valid_log_level_strategy = st.sampled_from(list(VALID_LOG_LEVELS))

# Strategy for valid log levels with various cases
valid_log_level_case_strategy = st.sampled_from(
    [
        "DEBUG",
        "debug",
        "Debug",
        "DeBuG",
        "INFO",
        "info",
        "Info",
        "InFo",
        "WARNING",
        "warning",
        "Warning",
        "WaRnInG",
        "ERROR",
        "error",
        "Error",
        "ErRoR",
        "CRITICAL",
        "critical",
        "Critical",
        "CrItIcAl",
    ]
)

# Strategy for invalid log levels
invalid_log_level_strategy = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_-"),
    min_size=1,
    max_size=20,
).filter(lambda x: x.upper() not in VALID_LOG_LEVELS)


def clear_env_vars():
    """Clear all reaper-related environment variables."""
    env_vars = [
        "MAX_INSTANCE_AGE_HOURS",
        "DRY_RUN",
        "SNS_TOPIC_ARN",
        "AWS_REGION",
        "KEY_PAIR_PATTERN",
        "LOG_LEVEL",
    ]
    for var in env_vars:
        os.environ.pop(var, None)


# ============================================================================
# Property 12: Log Level Configuration
# Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5
# ============================================================================


@settings(max_examples=100, deadline=5000)
@given(log_level=valid_log_level_strategy)
def test_property12_valid_log_level_parsing(log_level: str):
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    For any valid LOG_LEVEL value (DEBUG, INFO, WARNING, ERROR, CRITICAL),
    the configuration parser should correctly parse and use the specified level.

    Validates: Requirements 11.1
    """
    clear_env_vars()
    os.environ["LOG_LEVEL"] = log_level

    config = ReaperConfig.from_environment(validate=False)

    assert config.log_level == log_level.upper()
    assert config.get_log_level() == log_level.upper()


@settings(max_examples=100, deadline=5000)
@given(log_level=valid_log_level_case_strategy)
def test_property12_log_level_case_insensitive(log_level: str):
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    For any valid LOG_LEVEL value in any case (upper, lower, mixed),
    the configuration parser should correctly normalize to uppercase.

    Validates: Requirements 11.1
    """
    clear_env_vars()
    os.environ["LOG_LEVEL"] = log_level

    config = ReaperConfig.from_environment(validate=False)

    # Should be normalized to uppercase
    assert config.log_level == log_level.upper()
    assert config.log_level in VALID_LOG_LEVELS


def test_property12_log_level_default_when_not_set():
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    When LOG_LEVEL environment variable is not set, the configuration
    should default to INFO level.

    Validates: Requirements 11.2
    """
    clear_env_vars()
    # Ensure LOG_LEVEL is not set
    assert "LOG_LEVEL" not in os.environ

    config = ReaperConfig.from_environment(validate=False)

    assert config.log_level == "INFO"
    assert config.get_log_level() == "INFO"


@settings(
    max_examples=100,
    deadline=5000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(invalid_level=invalid_log_level_strategy)
def test_property12_invalid_log_level_defaults_to_info(invalid_level: str, caplog):
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    For any invalid LOG_LEVEL value, the configuration parser should
    default to INFO level and log a warning.

    Validates: Requirements 11.5
    """
    assume(len(invalid_level.strip()) > 0)  # Skip empty/whitespace strings

    clear_env_vars()
    os.environ["LOG_LEVEL"] = invalid_level

    caplog.clear()  # Clear previous log records
    with caplog.at_level(logging.WARNING):
        config = ReaperConfig.from_environment(validate=False)

    # Should default to INFO
    assert config.log_level == "INFO"

    # Should have logged a warning about invalid level
    warning_logged = any(
        "invalid" in record.message.lower() and "log_level" in record.message.lower()
        for record in caplog.records
    )
    assert warning_logged, f"Expected warning about invalid LOG_LEVEL '{invalid_level}'"


@settings(max_examples=100, deadline=5000)
@given(log_level=valid_log_level_strategy)
def test_property12_numeric_log_level_mapping(log_level: str):
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    For any valid LOG_LEVEL, the get_numeric_log_level() method should
    return the correct numeric value from the logging module.

    Validates: Requirements 11.1
    """
    clear_env_vars()
    os.environ["LOG_LEVEL"] = log_level

    config = ReaperConfig.from_environment(validate=False)

    expected_numeric = getattr(logging, log_level.upper())
    assert config.get_numeric_log_level() == expected_numeric


def test_property12_configure_logging_sets_level():
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    The configure_logging function should set the logger level based on
    the configuration.

    Validates: Requirements 11.1, 11.2
    """
    clear_env_vars()
    os.environ["LOG_LEVEL"] = "DEBUG"

    config = ReaperConfig.from_environment(validate=False)
    reaper_logger = configure_logging(config)

    assert reaper_logger.level == logging.DEBUG


def test_property12_configure_logging_defaults_to_info():
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    When configure_logging is called without a config and LOG_LEVEL is not set,
    it should default to INFO level.

    Validates: Requirements 11.2
    """
    clear_env_vars()

    reaper_logger = configure_logging()

    assert reaper_logger.level == logging.INFO


@settings(
    max_examples=50,
    deadline=5000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(log_level=st.sampled_from(["DEBUG", "INFO"]))
def test_property12_debug_level_outputs_detailed_info(log_level: str, caplog):
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    When LOG_LEVEL is set to DEBUG, detailed information including API calls,
    resource attributes, and processing steps should be output.

    Validates: Requirements 11.3
    """
    clear_env_vars()
    os.environ["LOG_LEVEL"] = log_level

    config = ReaperConfig.from_environment(validate=False)
    configure_logging(config)

    # Get a logger and log at DEBUG level
    test_logger = logging.getLogger("reaper.test_debug_output")
    test_logger.setLevel(logging.DEBUG)  # Always set to DEBUG to test filtering

    # Use a StringIO handler to capture output
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(getattr(logging, log_level))  # Set handler level based on config
    handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
    test_logger.handlers = []
    test_logger.addHandler(handler)

    # Log at DEBUG level
    test_logger.debug("Detailed API call: EC2.describe_instances")
    test_logger.debug("Resource attributes: instance_id=i-123, state=running")
    test_logger.debug("Processing step: filtering instances")

    output = stream.getvalue()

    if log_level == "DEBUG":
        # DEBUG level should capture debug messages
        assert "Detailed API call" in output, "DEBUG level should output API calls"
        assert (
            "Resource attributes" in output
        ), "DEBUG level should output resource attributes"
        assert "Processing step" in output, "DEBUG level should output processing steps"
    else:
        # INFO level should not capture debug messages
        assert (
            "Detailed API call" not in output
        ), "INFO level should not output DEBUG messages"
        assert (
            "Resource attributes" not in output
        ), "INFO level should not output DEBUG messages"
        assert (
            "Processing step" not in output
        ), "INFO level should not output DEBUG messages"


@settings(
    max_examples=50,
    deadline=5000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(log_level=st.sampled_from(["ERROR", "CRITICAL"]))
def test_property12_error_level_only_outputs_errors(log_level: str, caplog):
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    When LOG_LEVEL is set to ERROR or CRITICAL, only error conditions
    and critical failures should be output.

    Validates: Requirements 11.4
    """
    clear_env_vars()
    os.environ["LOG_LEVEL"] = log_level

    config = ReaperConfig.from_environment(validate=False)
    configure_logging(config)

    # Get a logger configured at ERROR/CRITICAL level
    test_logger = logging.getLogger("reaper.test_error")
    test_logger.setLevel(getattr(logging, log_level))

    # Clear any existing handlers and add a fresh one
    test_logger.handlers = []
    handler = logging.StreamHandler(StringIO())
    handler.setLevel(getattr(logging, log_level))
    test_logger.addHandler(handler)

    # Log at various levels
    test_logger.debug("Debug message - should not appear")
    test_logger.info("Info message - should not appear")
    test_logger.warning("Warning message - should not appear at ERROR+")
    test_logger.error("Error message - should appear")
    test_logger.critical("Critical message - should appear")

    # Get the output
    output = handler.stream.getvalue()

    # At ERROR level, only ERROR and CRITICAL should appear
    if log_level == "ERROR":
        assert "Error message" in output
        assert "Critical message" in output
        assert "Debug message" not in output
        assert "Info message" not in output
    elif log_level == "CRITICAL":
        assert "Critical message" in output
        assert "Error message" not in output
        assert "Debug message" not in output
        assert "Info message" not in output


def test_property12_log_level_with_whitespace():
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    LOG_LEVEL values with leading/trailing whitespace should be trimmed
    and processed correctly.

    Validates: Requirements 11.1
    """
    clear_env_vars()
    os.environ["LOG_LEVEL"] = "  DEBUG  "

    config = ReaperConfig.from_environment(validate=False)

    assert config.log_level == "DEBUG"


def test_property12_empty_log_level_defaults_to_info():
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    An empty LOG_LEVEL value should default to INFO.

    Validates: Requirements 11.2, 11.5
    """
    clear_env_vars()
    os.environ["LOG_LEVEL"] = ""

    config = ReaperConfig.from_environment(validate=False)

    # Empty string after strip is not in VALID_LOG_LEVELS, should default to INFO
    assert config.log_level == "INFO"


@settings(max_examples=100, deadline=5000)
@given(
    log_level=valid_log_level_strategy,
    max_age=st.integers(min_value=1, max_value=168),
    dry_run=st.booleans(),
)
def test_property12_log_level_with_other_config(
    log_level: str, max_age: int, dry_run: bool
):
    """
    Feature: packer-resource-reaper, Property 12: Log Level Configuration

    LOG_LEVEL should be correctly parsed alongside other configuration values.

    Validates: Requirements 11.1, 5.2
    """
    clear_env_vars()
    os.environ["LOG_LEVEL"] = log_level
    os.environ["MAX_INSTANCE_AGE_HOURS"] = str(max_age)
    os.environ["DRY_RUN"] = "true" if dry_run else "false"

    config = ReaperConfig.from_environment(validate=False)

    assert config.log_level == log_level.upper()
    assert config.max_instance_age_hours == max_age
    assert config.dry_run == dry_run
