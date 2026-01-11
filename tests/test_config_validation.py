"""Property-based tests for configuration validation and parsing.

Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing
Validates: Requirements 5.2, 9.5

The simplified configuration only supports:
- MAX_INSTANCE_AGE_HOURS: Age threshold for cleanup (1-168 hours)
- KEY_PAIR_PATTERN: Pattern for identifying Packer key pairs (default: packer_*)
- DRY_RUN: Enable/disable dry-run mode
- SNS_TOPIC_ARN: SNS topic for notifications
- AWS_REGION: AWS region for operations
"""

import os

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from reaper.utils.config import ConfigurationError, ReaperConfig

# Strategy for valid max instance age (1-168 hours)
valid_max_age_strategy = st.integers(min_value=1, max_value=168)

# Strategy for invalid max instance age
invalid_max_age_strategy = st.one_of(
    st.integers(max_value=0),  # Zero or negative
    st.integers(min_value=169),  # Too large
)

# Strategy for valid SNS ARNs
valid_sns_arn_strategy = st.from_regex(
    r"arn:aws:sns:[a-z]{2}-[a-z]+-[0-9]:[0-9]{12}:[a-zA-Z0-9_-]+", fullmatch=True
)

# Strategy for invalid SNS ARNs
invalid_sns_arn_strategy = st.text(min_size=1, max_size=50).filter(
    lambda x: not x.startswith("arn:aws:sns:")
)

# Strategy for dry run values that should be True
dry_run_true_strategy = st.sampled_from(
    ["true", "True", "TRUE", "1", "yes", "Yes", "YES"]
)

# Strategy for dry run values that should be False
dry_run_false_strategy = st.sampled_from(
    ["false", "False", "FALSE", "0", "no", "No", "NO", ""]
)

# Strategy for positive integers (valid MaxInstanceAge)
positive_integer_strategy = st.integers(min_value=1, max_value=168)

# Strategy for non-positive integers (invalid MaxInstanceAge)
non_positive_integer_strategy = st.integers(max_value=0)

# Strategy for non-integer strings
non_integer_string_strategy = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz!@#$%^&*()"),
    min_size=1,
    max_size=10,
)

# Strategy for valid key pair patterns
valid_key_pattern_strategy = st.from_regex(r"packer_[a-z0-9]*\*?", fullmatch=True)


def clear_env_vars():
    """Clear all reaper-related environment variables."""
    env_vars = [
        "MAX_INSTANCE_AGE_HOURS",
        "DRY_RUN",
        "SNS_TOPIC_ARN",
        "AWS_REGION",
        "KEY_PAIR_PATTERN",
    ]
    for var in env_vars:
        os.environ.pop(var, None)


@settings(max_examples=100, deadline=5000)
@given(max_age=valid_max_age_strategy)
def test_valid_max_instance_age_parsing(max_age: int):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any valid MAX_INSTANCE_AGE_HOURS value (1-168), the configuration parser
    should correctly parse and store the value.

    Validates: Requirements 5.2
    """
    clear_env_vars()
    os.environ["MAX_INSTANCE_AGE_HOURS"] = str(max_age)

    config = ReaperConfig.from_environment(validate=False)

    assert config.max_instance_age_hours == max_age
    assert (
        len(config.validate()) == 0
    ), f"Valid max_age {max_age} should not produce validation errors"


@settings(max_examples=100, deadline=5000)
@given(max_age=invalid_max_age_strategy)
def test_invalid_max_instance_age_validation(max_age: int):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any invalid MAX_INSTANCE_AGE_HOURS value (<=0 or >168), the configuration
    validator should return appropriate error messages.

    Validates: Requirements 5.2
    """
    clear_env_vars()

    config = ReaperConfig(max_instance_age_hours=max_age)
    errors = config.validate()

    assert (
        len(errors) > 0
    ), f"Invalid max_age {max_age} should produce validation errors"


@settings(max_examples=100, deadline=5000)
@given(dry_run_value=dry_run_true_strategy)
def test_dry_run_true_parsing(dry_run_value: str):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any truthy DRY_RUN value (true, 1, yes), the configuration parser
    should set dry_run to True.

    Validates: Requirements 9.5
    """
    clear_env_vars()
    os.environ["DRY_RUN"] = dry_run_value

    config = ReaperConfig.from_environment(validate=False)

    assert (
        config.dry_run is True
    ), f"DRY_RUN={dry_run_value} should result in dry_run=True"


@settings(max_examples=100, deadline=5000)
@given(dry_run_value=dry_run_false_strategy)
def test_dry_run_false_parsing(dry_run_value: str):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any falsy DRY_RUN value (false, 0, no, empty), the configuration parser
    should set dry_run to False.

    Validates: Requirements 9.5
    """
    clear_env_vars()
    os.environ["DRY_RUN"] = dry_run_value

    config = ReaperConfig.from_environment(validate=False)

    assert (
        config.dry_run is False
    ), f"DRY_RUN={dry_run_value} should result in dry_run=False"


@settings(max_examples=100, deadline=5000)
@given(sns_arn=valid_sns_arn_strategy)
def test_valid_sns_arn_parsing(sns_arn: str):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any valid SNS topic ARN, the configuration parser should
    correctly parse and validate the value.

    Validates: Requirements 5.2
    """
    clear_env_vars()
    os.environ["SNS_TOPIC_ARN"] = sns_arn

    config = ReaperConfig.from_environment(validate=False)

    assert config.notification_topic_arn == sns_arn
    assert (
        len(config.validate()) == 0
    ), f"Valid SNS ARN {sns_arn} should not produce validation errors"


@settings(max_examples=100, deadline=5000)
@given(sns_arn=invalid_sns_arn_strategy)
def test_invalid_sns_arn_validation(sns_arn: str):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any invalid SNS topic ARN (not starting with arn:aws:sns:),
    the configuration validator should return appropriate error messages.

    Validates: Requirements 5.2
    """
    assume(len(sns_arn) > 0)  # Skip empty strings (empty is valid - no notifications)

    config = ReaperConfig(notification_topic_arn=sns_arn)
    errors = config.validate()

    assert (
        len(errors) > 0
    ), f"Invalid SNS ARN {sns_arn} should produce validation errors"


@settings(max_examples=100, deadline=5000)
@given(
    max_age=valid_max_age_strategy,
    dry_run=st.booleans(),
)
def test_complete_valid_configuration(max_age: int, dry_run: bool):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any combination of valid configuration values, the configuration
    should pass validation without errors.

    Validates: Requirements 5.2, 9.5
    """
    config = ReaperConfig(
        max_instance_age_hours=max_age,
        dry_run=dry_run,
    )

    errors = config.validate()

    assert len(errors) == 0, f"Valid configuration should not produce errors: {errors}"


# ============================================================================
# Property 6: Configuration Validation and Parsing
# Validates: Requirements 5.2, 9.5
# ============================================================================


@settings(max_examples=100, deadline=5000)
@given(max_age=positive_integer_strategy)
def test_property6_max_instance_age_positive_integer(max_age: int):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any positive integer MAX_INSTANCE_AGE_HOURS value, the configuration
    parser should correctly parse and validate the value as a positive integer.

    Validates: Requirements 5.2
    """
    clear_env_vars()
    os.environ["MAX_INSTANCE_AGE_HOURS"] = str(max_age)

    config = ReaperConfig.from_environment(validate=False)

    # Verify it's parsed as an integer
    assert isinstance(config.max_instance_age_hours, int)
    assert config.max_instance_age_hours == max_age
    assert config.max_instance_age_hours > 0, "MaxInstanceAge must be positive"


@settings(max_examples=100, deadline=5000)
@given(max_age=non_positive_integer_strategy)
def test_property6_max_instance_age_rejects_non_positive(max_age: int):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any non-positive integer MAX_INSTANCE_AGE_HOURS value, the configuration
    validator should reject it with an appropriate error.

    Validates: Requirements 5.2
    """
    config = ReaperConfig(max_instance_age_hours=max_age)
    errors = config.validate()

    assert (
        len(errors) > 0
    ), f"Non-positive max_age {max_age} should produce validation errors"
    assert any(
        "positive integer" in e.lower() for e in errors
    ), f"Error should mention 'positive integer': {errors}"


@settings(max_examples=100, deadline=5000)
@given(invalid_value=non_integer_string_strategy)
def test_property6_max_instance_age_rejects_non_integer_string(invalid_value: str):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any non-integer string MAX_INSTANCE_AGE_HOURS value, the configuration
    parser should raise a ConfigurationError.

    Validates: Requirements 5.2
    """
    clear_env_vars()
    os.environ["MAX_INSTANCE_AGE_HOURS"] = invalid_value

    with pytest.raises(ConfigurationError) as exc_info:
        ReaperConfig.from_environment(validate=False)

    assert (
        "not a valid integer" in str(exc_info.value).lower()
        or "invalid" in str(exc_info.value).lower()
    )


@settings(max_examples=100, deadline=5000)
@given(
    initial_dry_run=st.booleans(), new_dry_run_value=st.sampled_from(["true", "false"])
)
def test_property6_dry_run_explicit_configuration_change(
    initial_dry_run: bool, new_dry_run_value: str
):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any transition between dry-run and live mode, the system should require
    an explicit configuration change (environment variable must be explicitly set).

    Validates: Requirements 9.5
    """
    clear_env_vars()

    # Set initial state
    os.environ["DRY_RUN"] = "true" if initial_dry_run else "false"
    ReaperConfig.from_environment(validate=False)

    # Change to new state - requires explicit configuration change
    os.environ["DRY_RUN"] = new_dry_run_value
    config2 = ReaperConfig.from_environment(validate=False)

    expected_new_state = new_dry_run_value.lower() == "true"

    assert (
        config2.dry_run == expected_new_state
    ), f"Explicit DRY_RUN={new_dry_run_value} should result in dry_run={expected_new_state}"


@settings(max_examples=100, deadline=5000)
@given(dry_run=st.booleans())
def test_property6_dry_run_mode_accessor(dry_run: bool):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any dry_run configuration, the is_dry_run() method should return
    the correct boolean value.

    Validates: Requirements 9.5
    """
    config = ReaperConfig(dry_run=dry_run)

    assert config.is_dry_run() == dry_run
    assert config.dry_run == dry_run


@settings(max_examples=100, deadline=5000)
@given(
    max_age=valid_max_age_strategy,
    dry_run=st.booleans(),
)
def test_property6_configuration_from_environment_validates(
    max_age: int, dry_run: bool
):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any valid configuration values, from_environment with validate=True
    should not raise an exception.

    Validates: Requirements 5.2, 9.5
    """
    clear_env_vars()
    os.environ["MAX_INSTANCE_AGE_HOURS"] = str(max_age)
    os.environ["DRY_RUN"] = "true" if dry_run else "false"

    # Should not raise
    config = ReaperConfig.from_environment(validate=True)

    assert config.max_instance_age_hours == max_age
    assert config.dry_run == dry_run


def test_property6_invalid_config_raises_configuration_error():
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    When from_environment is called with validate=True and configuration is invalid,
    it should raise ConfigurationError with the list of errors.

    Validates: Requirements 5.2
    """
    clear_env_vars()
    os.environ["MAX_INSTANCE_AGE_HOURS"] = "0"  # Invalid: not positive

    with pytest.raises(ConfigurationError) as exc_info:
        ReaperConfig.from_environment(validate=True)

    assert len(exc_info.value.errors) > 0
    assert "positive integer" in exc_info.value.errors[0].lower()


@settings(max_examples=100, deadline=5000)
@given(key_pattern=valid_key_pattern_strategy)
def test_key_pair_pattern_parsing(key_pattern: str):
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    For any valid key pair pattern, the configuration parser should
    correctly parse and store the value.

    Validates: Requirements 5.2, 1.2
    """
    clear_env_vars()
    os.environ["KEY_PAIR_PATTERN"] = key_pattern

    config = ReaperConfig.from_environment(validate=False)

    assert config.key_pair_pattern == key_pattern


def test_default_key_pair_pattern():
    """
    Feature: packer-resource-reaper, Property 6: Configuration Validation and Parsing

    When KEY_PAIR_PATTERN is not set, the default pattern should be 'packer_'.

    Validates: Requirements 5.2, 1.2
    """
    clear_env_vars()

    config = ReaperConfig.from_environment(validate=False)

    assert config.key_pair_pattern == "packer_"
