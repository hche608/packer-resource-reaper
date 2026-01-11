"""Configuration management for AWS Packer Resource Reaper.

This module provides configuration management for the reaper using
environment variables as per Requirement 5.2.

Key configuration options:
- MAX_INSTANCE_AGE_HOURS: Maximum age threshold for instances (Requirement 1.1)
- DRY_RUN: Enable dry-run mode (Requirement 9.5)
- SNS_TOPIC_ARN: SNS topic for notifications (Requirement 4.4)
- LOG_LEVEL: Configurable log level (Requirements 11.1, 11.2, 11.5)
- BATCH_DELETE_SIZE: Batch size for concurrent deletions (Requirements 12.1, 12.2, 12.7)
"""

import logging
import os
from dataclasses import dataclass
from typing import List, Optional

# Valid log levels as per Requirement 11.1
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

# Module logger for configuration warnings
_config_logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Exception raised for configuration validation errors."""

    def __init__(self, message: str, errors: Optional[List[str]] = None):
        self.message = message
        self.errors = errors or []
        super().__init__(self.message)


@dataclass
class ReaperConfig:
    """Configuration for reaper execution.

    This implements Requirement 5.2: support configuration via environment
    variables for MaxInstanceAge and check rate.

    Attributes:
        max_instance_age_hours: Maximum age in hours before an instance is considered
            a zombie. Must be a positive integer (Requirement 1.1).
        dry_run: When True, identifies cleanup candidates without executing
            destructive operations (Requirement 9.1-9.5).
        notification_topic_arn: SNS topic ARN for notifications (Requirement 4.4).
        region: AWS region for operations (Requirement 8.6).
        key_pair_pattern: Pattern prefix for identifying Packer key pairs (Requirement 1.2).
        log_level: Log level for output (Requirements 11.1, 11.2, 11.5).
        batch_delete_size: Batch size for concurrent deletions (Requirements 12.1, 12.2, 12.7).
    """

    max_instance_age_hours: int = 2
    dry_run: bool = False
    notification_topic_arn: str = ""
    region: str = "us-east-1"
    key_pair_pattern: str = "packer_"
    log_level: str = "INFO"
    batch_delete_size: int = 1

    @classmethod
    def from_environment(cls, validate: bool = True) -> "ReaperConfig":
        """Create configuration from environment variables.

        This implements Requirement 5.2: configuration via environment variables.

        Args:
            validate: If True, validates the configuration and raises
                ConfigurationError if invalid.

        Returns:
            ReaperConfig instance populated from environment variables.

        Raises:
            ConfigurationError: If validation is enabled and configuration is invalid.
            ValueError: If MAX_INSTANCE_AGE_HOURS cannot be parsed as an integer.
        """
        config = cls()

        # Parse max instance age - must be a positive integer (Requirement 5.2)
        max_age = os.environ.get("MAX_INSTANCE_AGE_HOURS")
        if max_age:
            try:
                parsed_age = int(max_age)
                config.max_instance_age_hours = parsed_age
            except ValueError:
                raise ConfigurationError(
                    f"Invalid MAX_INSTANCE_AGE_HOURS: '{max_age}' is not a valid integer"
                )

        # Parse dry run mode - explicit handling (Requirement 9.5)
        # Only "true" or "false" (case-insensitive) are valid
        dry_run_value = os.environ.get("DRY_RUN", "false").lower().strip()
        config.dry_run = dry_run_value in ("true", "1", "yes")

        # Parse notification topic ARN (Requirement 4.4)
        config.notification_topic_arn = os.environ.get("NOTIFICATION_TOPIC_ARN", "")

        # Also check SNS_TOPIC_ARN for compatibility with design doc
        if not config.notification_topic_arn:
            config.notification_topic_arn = os.environ.get("SNS_TOPIC_ARN", "")

        # Parse region (Requirement 8.6)
        config.region = os.environ.get("AWS_REGION", "us-east-1")

        # Parse key pair pattern (default: "packer_") (Requirement 1.2)
        config.key_pair_pattern = os.environ.get("KEY_PAIR_PATTERN", "packer_")

        # Parse LOG_LEVEL (Requirements 11.1, 11.2, 11.5)
        log_level_value = os.environ.get("LOG_LEVEL", "INFO").upper().strip()
        if log_level_value in VALID_LOG_LEVELS:
            config.log_level = log_level_value
        else:
            # Default to INFO with warning when invalid LOG_LEVEL is provided (Requirement 11.5)
            _config_logger.warning(
                f"Invalid LOG_LEVEL '{log_level_value}', defaulting to INFO"
            )
            config.log_level = "INFO"

        # Parse BATCH_DELETE_SIZE (Requirements 12.1, 12.2, 12.7)
        batch_size_value = os.environ.get("BATCH_DELETE_SIZE", "1").strip()
        try:
            parsed_batch_size = int(batch_size_value)
            if parsed_batch_size < 1:
                # Default to 1 with warning when non-positive value is provided (Requirement 12.7)
                _config_logger.warning(
                    f"Invalid BATCH_DELETE_SIZE '{parsed_batch_size}' (must be positive), defaulting to 1"
                )
                config.batch_delete_size = 1
            else:
                config.batch_delete_size = parsed_batch_size
        except ValueError:
            # Default to 1 with warning when invalid value is provided (Requirement 12.7)
            _config_logger.warning(
                f"Invalid BATCH_DELETE_SIZE '{batch_size_value}' (not a valid integer), defaulting to 1"
            )
            config.batch_delete_size = 1

        # Validate if requested
        if validate:
            errors = config.validate()
            if errors:
                raise ConfigurationError(
                    f"Configuration validation failed: {errors}", errors=errors
                )

        return config

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors.

        This implements Requirement 5.2: validate MaxInstanceAge is positive integer.

        Returns:
            List of error messages. Empty list if configuration is valid.
        """
        errors = []

        # MaxInstanceAge must be a positive integer (Requirement 5.2)
        if self.max_instance_age_hours < 1:
            errors.append(
                "MAX_INSTANCE_AGE_HOURS must be a positive integer (at least 1)"
            )

        if self.max_instance_age_hours > 168:  # 1 week
            errors.append("MAX_INSTANCE_AGE_HOURS should not exceed 168 (1 week)")

        if self.notification_topic_arn and not self.notification_topic_arn.startswith(
            "arn:aws:sns:"
        ):
            errors.append(f"Invalid SNS topic ARN: {self.notification_topic_arn}")

        # Validate key pair pattern is not empty
        if not self.key_pair_pattern:
            errors.append("KEY_PAIR_PATTERN cannot be empty")

        return errors

    def is_dry_run(self) -> bool:
        """Check if dry-run mode is enabled.

        This implements Requirement 9.5: explicit configuration change required
        to transition from dry-run to live mode.

        Returns:
            True if dry-run mode is enabled, False otherwise.
        """
        return self.dry_run

    def get_max_instance_age_hours(self) -> int:
        """Get the maximum instance age threshold in hours.

        Returns:
            Maximum instance age in hours.
        """
        return self.max_instance_age_hours

    def get_log_level(self) -> str:
        """Get the configured log level.

        This implements Requirement 11.1: return the configured log level.

        Returns:
            Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        """
        return self.log_level

    def get_numeric_log_level(self) -> int:
        """Get the numeric log level for use with logging module.

        Returns:
            Numeric log level (e.g., logging.DEBUG, logging.INFO).
        """
        return getattr(logging, self.log_level, logging.INFO)

    def get_batch_delete_size(self) -> int:
        """Get the configured batch delete size.

        This implements Requirement 12.1: return the configured batch size
        for concurrent deletions.

        Returns:
            Batch delete size (minimum 1 for sequential deletion).
        """
        return self.batch_delete_size


def configure_logging(config: Optional["ReaperConfig"] = None) -> logging.Logger:
    """Configure logging based on LOG_LEVEL environment variable or config.

    This implements Requirements 11.1, 11.2, 11.5:
    - 11.1: Use the specified log level if valid
    - 11.2: Default to INFO when LOG_LEVEL is not set
    - 11.5: Default to INFO with warning when invalid LOG_LEVEL is provided

    Args:
        config: Optional ReaperConfig instance. If not provided, reads from environment.

    Returns:
        Configured logger instance for the reaper.
    """
    if config is None:
        # Read LOG_LEVEL directly from environment
        log_level_str = os.environ.get("LOG_LEVEL", "INFO").upper().strip()
        if log_level_str not in VALID_LOG_LEVELS:
            # Log warning about invalid level (Requirement 11.5)
            logging.warning(f"Invalid LOG_LEVEL '{log_level_str}', defaulting to INFO")
            log_level_str = "INFO"
    else:
        log_level_str = config.log_level

    # Get numeric log level
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        force=True,  # Override any existing configuration
    )

    # Get and configure the reaper logger
    reaper_logger = logging.getLogger("reaper")
    reaper_logger.setLevel(log_level)

    return reaper_logger
