"""Tests for configuration module.

Tests for ReaperConfig and configure_logging.
"""

import logging
import os
from unittest.mock import patch

import pytest

from reaper.utils.config import (
    VALID_LOG_LEVELS,
    ConfigurationError,
    ReaperConfig,
    configure_logging,
)


class TestReaperConfig:
    """Tests for ReaperConfig class."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ReaperConfig()
        assert config.max_instance_age_hours == 2
        assert config.dry_run is False
        assert config.notification_topic_arn == ""
        assert config.key_pair_pattern == "packer_"
        assert config.log_level == "INFO"
        assert config.batch_delete_size == 1

    def test_is_dry_run(self):
        """Test is_dry_run method."""
        config = ReaperConfig(dry_run=True)
        assert config.is_dry_run() is True

        config = ReaperConfig(dry_run=False)
        assert config.is_dry_run() is False

    def test_get_max_instance_age_hours(self):
        """Test get_max_instance_age_hours method."""
        config = ReaperConfig(max_instance_age_hours=5)
        assert config.get_max_instance_age_hours() == 5

    def test_get_log_level(self):
        """Test get_log_level method."""
        config = ReaperConfig(log_level="DEBUG")
        assert config.get_log_level() == "DEBUG"

    def test_get_numeric_log_level(self):
        """Test get_numeric_log_level method."""
        config = ReaperConfig(log_level="DEBUG")
        assert config.get_numeric_log_level() == logging.DEBUG

        config = ReaperConfig(log_level="ERROR")
        assert config.get_numeric_log_level() == logging.ERROR

    def test_get_batch_delete_size(self):
        """Test get_batch_delete_size method."""
        config = ReaperConfig(batch_delete_size=5)
        assert config.get_batch_delete_size() == 5

    def test_validate_valid_config(self):
        """Test validation with valid config."""
        config = ReaperConfig(
            max_instance_age_hours=2,
            notification_topic_arn="arn:aws:sns:us-east-1:123456789012:topic",
            key_pair_pattern="packer_",
        )
        errors = config.validate()
        assert len(errors) == 0

    def test_validate_invalid_max_age_zero(self):
        """Test validation with zero max age."""
        config = ReaperConfig(max_instance_age_hours=0)
        errors = config.validate()
        assert len(errors) > 0
        assert "positive integer" in errors[0]

    def test_validate_invalid_max_age_negative(self):
        """Test validation with negative max age."""
        config = ReaperConfig(max_instance_age_hours=-1)
        errors = config.validate()
        assert len(errors) > 0

    def test_validate_invalid_max_age_too_large(self):
        """Test validation with max age exceeding limit."""
        config = ReaperConfig(max_instance_age_hours=200)
        errors = config.validate()
        assert len(errors) > 0
        assert "168" in errors[0]

    def test_validate_invalid_sns_arn(self):
        """Test validation with invalid SNS ARN."""
        config = ReaperConfig(notification_topic_arn="invalid-arn")
        errors = config.validate()
        assert len(errors) > 0
        assert "Invalid SNS topic ARN" in errors[0]

    def test_validate_empty_key_pattern(self):
        """Test validation with empty key pattern."""
        config = ReaperConfig(key_pair_pattern="")
        errors = config.validate()
        assert len(errors) > 0
        assert "cannot be empty" in errors[0]


class TestReaperConfigFromEnvironment:
    """Tests for ReaperConfig.from_environment."""

    def test_from_environment_defaults(self):
        """Test from_environment with no env vars."""
        with patch.dict(os.environ, {}, clear=True), patch("boto3.Session") as mock_session:
            mock_session.return_value.region_name = "us-east-1"
            config = ReaperConfig.from_environment(validate=False)
            assert config.max_instance_age_hours == 2
            assert config.dry_run is False

    def test_from_environment_max_age(self):
        """Test from_environment with MAX_INSTANCE_AGE_HOURS."""
        with patch.dict(os.environ, {"MAX_INSTANCE_AGE_HOURS": "5"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.max_instance_age_hours == 5

    def test_from_environment_invalid_max_age(self):
        """Test from_environment with invalid MAX_INSTANCE_AGE_HOURS."""
        with patch.dict(os.environ, {"MAX_INSTANCE_AGE_HOURS": "invalid"}, clear=True):
            with pytest.raises(ConfigurationError, match="not a valid integer"):
                ReaperConfig.from_environment(validate=False)

    def test_from_environment_dry_run_true(self):
        """Test from_environment with DRY_RUN=true."""
        with patch.dict(os.environ, {"DRY_RUN": "true"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.dry_run is True

    def test_from_environment_dry_run_yes(self):
        """Test from_environment with DRY_RUN=yes."""
        with patch.dict(os.environ, {"DRY_RUN": "yes"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.dry_run is True

    def test_from_environment_dry_run_1(self):
        """Test from_environment with DRY_RUN=1."""
        with patch.dict(os.environ, {"DRY_RUN": "1"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.dry_run is True

    def test_from_environment_dry_run_false(self):
        """Test from_environment with DRY_RUN=false."""
        with patch.dict(os.environ, {"DRY_RUN": "false"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.dry_run is False

    def test_from_environment_sns_topic(self):
        """Test from_environment with SNS_TOPIC_ARN."""
        with (
            patch.dict(
                os.environ,
                {"SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:topic"},
                clear=True,
            ),
            patch("boto3.Session") as mock_session,
        ):
            mock_session.return_value.region_name = "us-east-1"
            config = ReaperConfig.from_environment(validate=False)
            assert config.notification_topic_arn == "arn:aws:sns:us-east-1:123456789012:topic"

    def test_from_environment_region(self):
        """Test from_environment with AWS_REGION."""
        with patch.dict(os.environ, {"AWS_REGION": "eu-west-1"}, clear=True):
            config = ReaperConfig.from_environment(validate=False)
            assert config.region == "eu-west-1"

    def test_from_environment_key_pattern(self):
        """Test from_environment with KEY_PAIR_PATTERN."""
        with patch.dict(os.environ, {"KEY_PAIR_PATTERN": "custom_"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.key_pair_pattern == "custom_"

    def test_from_environment_log_level_valid(self):
        """Test from_environment with valid LOG_LEVEL."""
        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.log_level == "DEBUG"

    def test_from_environment_log_level_invalid(self):
        """Test from_environment with invalid LOG_LEVEL defaults to INFO."""
        with patch.dict(os.environ, {"LOG_LEVEL": "INVALID"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.log_level == "INFO"

    def test_from_environment_batch_size_valid(self):
        """Test from_environment with valid BATCH_DELETE_SIZE."""
        with patch.dict(os.environ, {"BATCH_DELETE_SIZE": "5"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.batch_delete_size == 5

    def test_from_environment_batch_size_invalid(self):
        """Test from_environment with invalid BATCH_DELETE_SIZE defaults to 1."""
        with patch.dict(os.environ, {"BATCH_DELETE_SIZE": "invalid"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.batch_delete_size == 1

    def test_from_environment_batch_size_negative(self):
        """Test from_environment with negative BATCH_DELETE_SIZE defaults to 1."""
        with patch.dict(os.environ, {"BATCH_DELETE_SIZE": "-1"}, clear=True):
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.region_name = "us-east-1"
                config = ReaperConfig.from_environment(validate=False)
                assert config.batch_delete_size == 1

    def test_from_environment_with_validation(self):
        """Test from_environment with validation enabled."""
        with patch.dict(
            os.environ,
            {"MAX_INSTANCE_AGE_HOURS": "2", "AWS_REGION": "us-east-1"},
            clear=True,
        ):
            config = ReaperConfig.from_environment(validate=True)
            assert config.max_instance_age_hours == 2

    def test_from_environment_validation_failure(self):
        """Test from_environment raises error on validation failure."""
        with (
            patch.dict(
                os.environ,
                {"MAX_INSTANCE_AGE_HOURS": "0", "AWS_REGION": "us-east-1"},
                clear=True,
            ),
            pytest.raises(ConfigurationError),
        ):
            ReaperConfig.from_environment(validate=True)


class TestConfigureLogging:
    """Tests for configure_logging function."""

    def test_configure_logging_with_config(self):
        """Test configure_logging with config object."""
        config = ReaperConfig(log_level="DEBUG")
        logger = configure_logging(config)
        assert logger.level == logging.DEBUG

    def test_configure_logging_without_config(self):
        """Test configure_logging without config reads from env."""
        with patch.dict(os.environ, {"LOG_LEVEL": "WARNING"}, clear=True):
            logger = configure_logging(None)
            assert logger.level == logging.WARNING

    def test_configure_logging_invalid_level(self):
        """Test configure_logging with invalid level defaults to INFO."""
        with patch.dict(os.environ, {"LOG_LEVEL": "INVALID"}, clear=True):
            logger = configure_logging(None)
            assert logger.level == logging.INFO

    def test_configure_logging_default(self):
        """Test configure_logging defaults to INFO."""
        with patch.dict(os.environ, {}, clear=True):
            logger = configure_logging(None)
            assert logger.level == logging.INFO


class TestConfigurationError:
    """Tests for ConfigurationError exception."""

    def test_configuration_error_message(self):
        """Test ConfigurationError with message."""
        error = ConfigurationError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.errors == []

    def test_configuration_error_with_errors(self):
        """Test ConfigurationError with error list."""
        error = ConfigurationError("Test error", errors=["Error 1", "Error 2"])
        assert error.message == "Test error"
        assert len(error.errors) == 2


class TestValidLogLevels:
    """Tests for VALID_LOG_LEVELS constant."""

    def test_valid_log_levels(self):
        """Test VALID_LOG_LEVELS contains expected values."""
        assert "DEBUG" in VALID_LOG_LEVELS
        assert "INFO" in VALID_LOG_LEVELS
        assert "WARNING" in VALID_LOG_LEVELS
        assert "ERROR" in VALID_LOG_LEVELS
        assert "CRITICAL" in VALID_LOG_LEVELS
