"""CloudWatch logging integration for AWS Packer Resource Reaper.

This module provides comprehensive logging functionality for resource scanning,
cleanup actions, and error handling with log sanitization for sensitive data.

Requirements: 4.2, 6.3, 7.4, 11.1-11.5
- Requirement 4.2: Log all scanned resources and actions taken to CloudWatch
- Requirement 6.3: Log detailed error information to CloudWatch
- Requirement 7.4: Do not expose sensitive information in CloudWatch logs
- Requirement 11.1: Use the specified log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Requirement 11.2: Default to INFO when LOG_LEVEL is not set
- Requirement 11.3: Output detailed information at DEBUG level
- Requirement 11.4: Output only error conditions at ERROR level or higher
- Requirement 11.5: Default to INFO with warning when invalid LOG_LEVEL is provided
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from reaper.utils.security import LogSanitizer

# Configure module logger
logger = logging.getLogger(__name__)


class LogLevel(Enum):
    """Log levels for reaper operations."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ActionType(Enum):
    """Types of actions that can be logged."""

    SCAN = "SCAN"
    FILTER = "FILTER"
    TERMINATE = "TERMINATE"
    DELETE = "DELETE"
    RELEASE = "RELEASE"
    DEFER = "DEFER"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class LogEntry:
    """Structured log entry for CloudWatch."""

    timestamp: datetime
    level: LogLevel
    action: ActionType
    resource_type: str
    resource_id: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    error_info: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary for structured logging."""
        entry = {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "action": self.action.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "message": self.message,
        }
        if self.details:
            entry["details"] = self.details
        if self.error_info:
            entry["error"] = self.error_info
        return entry


class ReaperLogger:
    """Comprehensive logging for Packer Resource Reaper operations.

    This class provides structured logging for all reaper operations including:
    - Resource scanning and discovery (Requirement 4.2)
    - Cleanup actions (terminate, delete, release)
    - Error logging with detailed information (Requirement 6.3)
    - Log sanitization for sensitive data (Requirement 7.4)

    All log output is sanitized to prevent exposure of sensitive information
    such as access keys, passwords, tokens, and secrets.
    """

    def __init__(
        self,
        account_id: str = "",
        region: str = "",
        dry_run: bool = False,
    ):
        """
        Initialize reaper logger.

        Args:
            account_id: AWS account ID for context
            region: AWS region for context
            dry_run: Whether operating in dry-run mode
        """
        self.account_id = account_id
        self.region = region
        self.dry_run = dry_run
        self._log_entries: List[LogEntry] = []

    def _create_entry(
        self,
        level: LogLevel,
        action: ActionType,
        resource_type: str,
        resource_id: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        error_info: Optional[Dict[str, Any]] = None,
    ) -> LogEntry:
        """Create a sanitized log entry."""
        # Sanitize all string values
        sanitized_message = LogSanitizer.sanitize(message)
        sanitized_resource_id = LogSanitizer.sanitize(resource_id)
        sanitized_details = LogSanitizer.sanitize_dict(details) if details else {}
        sanitized_error = LogSanitizer.sanitize_dict(error_info) if error_info else None

        return LogEntry(
            timestamp=datetime.now(timezone.utc),
            level=level,
            action=action,
            resource_type=resource_type,
            resource_id=sanitized_resource_id,
            message=sanitized_message,
            details=sanitized_details,
            error_info=sanitized_error,
        )

    def _log(self, entry: LogEntry) -> None:
        """Log entry to CloudWatch and store for reporting."""
        self._log_entries.append(entry)

        # Format message with context
        prefix = "[DRY RUN] " if self.dry_run else ""
        log_message = (
            f"{prefix}[{entry.action.value}] {entry.resource_type} "
            f"{entry.resource_id}: {entry.message}"
        )

        # Add details if present
        if entry.details:
            detail_str = ", ".join(f"{k}={v}" for k, v in entry.details.items())
            log_message += f" ({detail_str})"

        # Log at appropriate level
        if entry.level == LogLevel.DEBUG:
            logger.debug(log_message)
        elif entry.level == LogLevel.INFO:
            logger.info(log_message)
        elif entry.level == LogLevel.WARNING:
            logger.warning(log_message)
        elif entry.level == LogLevel.ERROR:
            if entry.error_info:
                log_message += f" - Error: {entry.error_info}"
            logger.error(log_message)
        elif entry.level == LogLevel.CRITICAL:
            logger.critical(log_message)

    # Resource Scanning Logging (Requirement 4.2)

    def log_scan_start(self, resource_type: str, count: int) -> None:
        """Log start of resource scanning."""
        entry = self._create_entry(
            level=LogLevel.INFO,
            action=ActionType.SCAN,
            resource_type=resource_type,
            resource_id="*",
            message=f"Starting scan for {resource_type} resources",
            details={"expected_count": count},
        )
        self._log(entry)

    def log_scan_complete(
        self,
        resource_type: str,
        total_found: int,
        matching_filter: int,
    ) -> None:
        """Log completion of resource scanning."""
        entry = self._create_entry(
            level=LogLevel.INFO,
            action=ActionType.SCAN,
            resource_type=resource_type,
            resource_id="*",
            message=f"Scan complete: {total_found} found, {matching_filter} match filters",
            details={
                "total_found": total_found,
                "matching_filter": matching_filter,
            },
        )
        self._log(entry)

    def log_resource_scanned(
        self,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log individual resource scanned.

        This outputs at DEBUG level as per Requirement 11.3:
        detailed information including resource attributes.
        """
        entry = self._create_entry(
            level=LogLevel.DEBUG,
            action=ActionType.SCAN,
            resource_type=resource_type,
            resource_id=resource_id,
            message="Resource scanned",
            details=details,
        )
        self._log(entry)

    def log_api_call(
        self,
        api_name: str,
        service: str,
        parameters: Optional[Dict[str, Any]] = None,
        response_summary: Optional[str] = None,
    ) -> None:
        """Log AWS API call at DEBUG level.

        This implements Requirement 11.3: output detailed API calls at DEBUG level.

        Args:
            api_name: Name of the API being called (e.g., "describe_instances")
            service: AWS service name (e.g., "EC2", "IAM")
            parameters: Optional parameters passed to the API (sanitized)
            response_summary: Optional summary of the response
        """
        details = {
            "api": api_name,
            "service": service,
        }
        if parameters:
            details["parameters"] = parameters
        if response_summary:
            details["response"] = response_summary

        entry = self._create_entry(
            level=LogLevel.DEBUG,
            action=ActionType.SCAN,
            resource_type=service,
            resource_id=api_name,
            message=f"API call: {service}.{api_name}",
            details=details,
        )
        self._log(entry)

    def log_processing_step(
        self,
        step_name: str,
        resource_type: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log processing step at DEBUG level.

        This implements Requirement 11.3: output processing steps at DEBUG level.

        Args:
            step_name: Name of the processing step
            resource_type: Type of resource being processed
            details: Optional details about the step
        """
        entry = self._create_entry(
            level=LogLevel.DEBUG,
            action=ActionType.FILTER,
            resource_type=resource_type,
            resource_id="*",
            message=f"Processing step: {step_name}",
            details=details,
        )
        self._log(entry)

    def log_resource_attributes(
        self,
        resource_type: str,
        resource_id: str,
        attributes: Dict[str, Any],
    ) -> None:
        """Log resource attributes at DEBUG level.

        This implements Requirement 11.3: output resource attributes at DEBUG level.

        Args:
            resource_type: Type of resource
            resource_id: Resource identifier
            attributes: Resource attributes to log
        """
        entry = self._create_entry(
            level=LogLevel.DEBUG,
            action=ActionType.SCAN,
            resource_type=resource_type,
            resource_id=resource_id,
            message="Resource attributes",
            details=attributes,
        )
        self._log(entry)

    def log_filter_applied(
        self,
        filter_name: str,
        resource_type: str,
        input_count: int,
        output_count: int,
    ) -> None:
        """Log filter application results."""
        entry = self._create_entry(
            level=LogLevel.INFO,
            action=ActionType.FILTER,
            resource_type=resource_type,
            resource_id="*",
            message=f"Filter '{filter_name}' applied: {input_count} -> {output_count}",
            details={
                "filter_name": filter_name,
                "input_count": input_count,
                "output_count": output_count,
                "filtered_out": input_count - output_count,
            },
        )
        self._log(entry)

    def log_resource_filtered(
        self,
        resource_type: str,
        resource_id: str,
        filter_name: str,
        matched: bool,
        reason: Optional[str] = None,
    ) -> None:
        """Log individual resource filter result."""
        entry = self._create_entry(
            level=LogLevel.DEBUG,
            action=ActionType.FILTER,
            resource_type=resource_type,
            resource_id=resource_id,
            message=f"Filter '{filter_name}': {'matched' if matched else 'excluded'}",
            details={
                "filter_name": filter_name,
                "matched": matched,
                "reason": reason,
            },
        )
        self._log(entry)

    # Cleanup Action Logging (Requirement 4.2)

    def log_action_start(
        self,
        action: ActionType,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log start of cleanup action."""
        action_verb = self._get_action_verb(action)
        entry = self._create_entry(
            level=LogLevel.INFO,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            message=f"Starting to {action_verb} resource",
            details=details,
        )
        self._log(entry)

    def log_action_complete(
        self,
        action: ActionType,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log successful completion of cleanup action."""
        action_verb = self._get_action_verb(action)
        entry = self._create_entry(
            level=LogLevel.INFO,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            message=f"Successfully {action_verb}d resource",
            details=details,
        )
        self._log(entry)

    def log_action_deferred(
        self,
        resource_type: str,
        resource_id: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log deferred cleanup action."""
        entry = self._create_entry(
            level=LogLevel.WARNING,
            action=ActionType.DEFER,
            resource_type=resource_type,
            resource_id=resource_id,
            message=f"Action deferred: {reason}",
            details=details,
        )
        self._log(entry)

    def log_action_skipped(
        self,
        resource_type: str,
        resource_id: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log skipped cleanup action."""
        entry = self._create_entry(
            level=LogLevel.INFO,
            action=ActionType.SKIP,
            resource_type=resource_type,
            resource_id=resource_id,
            message=f"Action skipped: {reason}",
            details=details,
        )
        self._log(entry)

    # Error Logging (Requirement 6.3)

    def log_error(
        self,
        resource_type: str,
        resource_id: str,
        error: Exception,
        action: Optional[ActionType] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log error with detailed information.

        This implements Requirement 6.3: log detailed error information
        to CloudWatch while sanitizing sensitive data (Requirement 7.4).
        """
        error_info = {
            "error_type": type(error).__name__,
            "error_message": LogSanitizer.sanitize(str(error)),
        }

        # Extract AWS error code if available
        if hasattr(error, "response"):
            response = getattr(error, "response", {})
            if isinstance(response, dict):
                error_code = response.get("Error", {}).get("Code", "Unknown")
                error_info["aws_error_code"] = error_code

        entry = self._create_entry(
            level=LogLevel.ERROR,
            action=action or ActionType.ERROR,
            resource_type=resource_type,
            resource_id=resource_id,
            message=f"Error occurred: {type(error).__name__}",
            details=details,
            error_info=error_info,
        )
        self._log(entry)

    def log_dependency_violation(
        self,
        resource_type: str,
        resource_id: str,
        dependency_info: Optional[str] = None,
    ) -> None:
        """Log DependencyViolation error specifically.

        This implements Requirement 6.1: log DependencyViolation errors
        and continue (resource will be re-identified in next execution).
        """
        entry = self._create_entry(
            level=LogLevel.WARNING,
            action=ActionType.DEFER,
            resource_type=resource_type,
            resource_id=resource_id,
            message="DependencyViolation - will retry in next execution",
            details={"dependency_info": dependency_info} if dependency_info else {},
            error_info={
                "error_type": "DependencyViolation",
                "resolution": "Resource will be re-identified in next scheduled execution",
            },
        )
        self._log(entry)

    def log_rate_limit(
        self,
        resource_type: str,
        resource_id: str,
        retry_count: int,
        delay_seconds: float,
    ) -> None:
        """Log rate limit encountered with retry information.

        This implements Requirement 6.2: exponential backoff retry logic
        for AWS API rate limits.
        """
        entry = self._create_entry(
            level=LogLevel.WARNING,
            action=ActionType.ERROR,
            resource_type=resource_type,
            resource_id=resource_id,
            message=f"Rate limit encountered, retrying (attempt {retry_count})",
            details={
                "retry_count": retry_count,
                "delay_seconds": round(delay_seconds, 2),
            },
        )
        self._log(entry)

    # Summary Logging

    def log_execution_start(self) -> None:
        """Log start of reaper execution."""
        mode = "DRY RUN" if self.dry_run else "LIVE"
        logger.info("=" * 60)
        logger.info(f"PACKER RESOURCE REAPER - EXECUTION START ({mode})")
        logger.info("=" * 60)
        logger.info(f"Account: {self.account_id}")
        logger.info(f"Region: {self.region}")
        logger.info(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
        logger.info("-" * 40)

    def log_execution_complete(
        self,
        total_scanned: int,
        total_cleaned: int,
        total_deferred: int,
        total_errors: int,
    ) -> None:
        """Log completion of reaper execution with summary."""
        mode = "DRY RUN" if self.dry_run else "LIVE"
        logger.info("-" * 40)
        logger.info(f"EXECUTION SUMMARY ({mode})")
        logger.info("-" * 40)
        logger.info(f"Total resources scanned: {total_scanned}")
        logger.info(f"Total resources cleaned: {total_cleaned}")
        logger.info(f"Total resources deferred: {total_deferred}")
        logger.info(f"Total errors: {total_errors}")
        logger.info("=" * 60)
        logger.info("PACKER RESOURCE REAPER - EXECUTION COMPLETE")
        logger.info("=" * 60)

    def get_log_entries(self) -> List[LogEntry]:
        """Get all log entries for reporting."""
        return self._log_entries.copy()

    def _get_action_verb(self, action: ActionType) -> str:
        """Get verb form of action for logging."""
        verbs = {
            ActionType.SCAN: "scan",
            ActionType.FILTER: "filter",
            ActionType.TERMINATE: "terminate",
            ActionType.DELETE: "delete",
            ActionType.RELEASE: "release",
            ActionType.DEFER: "defer",
            ActionType.SKIP: "skip",
            ActionType.ERROR: "process",
        }
        return verbs.get(action, "process")


# Convenience functions for module-level logging


def log_resource_scan(
    resource_type: str,
    resource_id: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Log resource scan at module level."""
    sanitized_id = LogSanitizer.sanitize(resource_id)
    sanitized_details = LogSanitizer.sanitize_dict(details) if details else {}

    detail_str = ""
    if sanitized_details:
        detail_str = f" ({', '.join(f'{k}={v}' for k, v in sanitized_details.items())})"

    logger.info(f"[SCAN] {resource_type} {sanitized_id}{detail_str}")


def log_cleanup_action(
    action: str,
    resource_type: str,
    resource_id: str,
    success: bool,
    error: Optional[str] = None,
) -> None:
    """Log cleanup action at module level."""
    sanitized_id = LogSanitizer.sanitize(resource_id)
    sanitized_error = LogSanitizer.sanitize(error) if error else None

    status = "SUCCESS" if success else "FAILED"
    message = f"[{action.upper()}] {resource_type} {sanitized_id}: {status}"

    if sanitized_error:
        message += f" - {sanitized_error}"

    if success:
        logger.info(message)
    else:
        logger.error(message)


def log_error_with_details(
    resource_type: str,
    resource_id: str,
    error: Exception,
    context: Optional[Dict[str, Any]] = None,
) -> None:
    """Log error with detailed information at module level.

    This implements Requirement 6.3: log detailed error information
    while sanitizing sensitive data (Requirement 7.4).

    This also implements Requirement 11.4: error conditions are logged
    at ERROR level, which is visible at ERROR level or higher.
    """
    sanitized_id = LogSanitizer.sanitize(resource_id)
    sanitized_error = LogSanitizer.sanitize(str(error))
    sanitized_context = LogSanitizer.sanitize_dict(context) if context else {}

    error_type = type(error).__name__

    message = (
        f"[ERROR] {resource_type} {sanitized_id}: {error_type} - {sanitized_error}"
    )

    if sanitized_context:
        context_str = ", ".join(f"{k}={v}" for k, v in sanitized_context.items())
        message += f" (context: {context_str})"

    logger.error(message)


def log_debug_api_call(
    api_name: str,
    service: str,
    parameters: Optional[Dict[str, Any]] = None,
) -> None:
    """Log AWS API call at DEBUG level.

    This implements Requirement 11.3: output detailed API calls at DEBUG level.
    Only visible when LOG_LEVEL is set to DEBUG.

    Args:
        api_name: Name of the API being called
        service: AWS service name
        parameters: Optional parameters (will be sanitized)
    """
    sanitized_params = LogSanitizer.sanitize_dict(parameters) if parameters else {}

    message = f"[DEBUG] API call: {service}.{api_name}"
    if sanitized_params:
        params_str = ", ".join(f"{k}={v}" for k, v in sanitized_params.items())
        message += f" ({params_str})"

    logger.debug(message)


def log_debug_processing_step(
    step_name: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Log processing step at DEBUG level.

    This implements Requirement 11.3: output processing steps at DEBUG level.
    Only visible when LOG_LEVEL is set to DEBUG.

    Args:
        step_name: Name of the processing step
        details: Optional details about the step
    """
    sanitized_details = LogSanitizer.sanitize_dict(details) if details else {}

    message = f"[DEBUG] Processing: {step_name}"
    if sanitized_details:
        details_str = ", ".join(f"{k}={v}" for k, v in sanitized_details.items())
        message += f" ({details_str})"

    logger.debug(message)


def log_debug_resource_attributes(
    resource_type: str,
    resource_id: str,
    attributes: Dict[str, Any],
) -> None:
    """Log resource attributes at DEBUG level.

    This implements Requirement 11.3: output resource attributes at DEBUG level.
    Only visible when LOG_LEVEL is set to DEBUG.

    Args:
        resource_type: Type of resource
        resource_id: Resource identifier
        attributes: Resource attributes to log
    """
    sanitized_id = LogSanitizer.sanitize(resource_id)
    sanitized_attrs = LogSanitizer.sanitize_dict(attributes)

    attrs_str = ", ".join(f"{k}={v}" for k, v in sanitized_attrs.items())
    message = f"[DEBUG] {resource_type} {sanitized_id}: {attrs_str}"

    logger.debug(message)
