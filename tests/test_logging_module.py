"""Tests for logging module functionality.

Tests for ReaperLogger, LogEntry, and module-level logging functions.
"""

from datetime import UTC, datetime
from unittest.mock import patch

from reaper.utils.logging import (
    ActionType,
    LogEntry,
    LogLevel,
    ReaperLogger,
    log_cleanup_action,
    log_debug_api_call,
    log_debug_processing_step,
    log_debug_resource_attributes,
    log_error_with_details,
    log_resource_scan,
)


class TestLogEntry:
    """Tests for LogEntry dataclass."""

    def test_log_entry_to_dict_basic(self):
        """Test LogEntry to_dict with basic fields."""
        entry = LogEntry(
            timestamp=datetime(2025, 1, 11, 12, 0, 0, tzinfo=UTC),
            level=LogLevel.INFO,
            action=ActionType.SCAN,
            resource_type="INSTANCE",
            resource_id="i-12345678",
            message="Test message",
        )

        result = entry.to_dict()

        assert result["timestamp"] == "2025-01-11T12:00:00+00:00"
        assert result["level"] == "INFO"
        assert result["action"] == "SCAN"
        assert result["resource_type"] == "INSTANCE"
        assert result["resource_id"] == "i-12345678"
        assert result["message"] == "Test message"
        assert "details" not in result
        assert "error" not in result

    def test_log_entry_to_dict_with_details(self):
        """Test LogEntry to_dict with details."""
        entry = LogEntry(
            timestamp=datetime(2025, 1, 11, 12, 0, 0, tzinfo=UTC),
            level=LogLevel.INFO,
            action=ActionType.SCAN,
            resource_type="INSTANCE",
            resource_id="i-12345678",
            message="Test message",
            details={"key": "value", "count": 5},
        )

        result = entry.to_dict()

        assert result["details"] == {"key": "value", "count": 5}

    def test_log_entry_to_dict_with_error(self):
        """Test LogEntry to_dict with error info."""
        entry = LogEntry(
            timestamp=datetime(2025, 1, 11, 12, 0, 0, tzinfo=UTC),
            level=LogLevel.ERROR,
            action=ActionType.ERROR,
            resource_type="INSTANCE",
            resource_id="i-12345678",
            message="Error occurred",
            error_info={"error_type": "ClientError", "error_message": "Access denied"},
        )

        result = entry.to_dict()

        assert result["error"] == {
            "error_type": "ClientError",
            "error_message": "Access denied",
        }


class TestReaperLogger:
    """Tests for ReaperLogger class."""

    def test_logger_initialization(self):
        """Test logger initialization."""
        logger = ReaperLogger(
            account_id="123456789012",
            region="us-east-1",
            dry_run=True,
        )

        assert logger.account_id == "123456789012"
        assert logger.region == "us-east-1"
        assert logger.dry_run is True

    def test_log_scan_start(self):
        """Test log_scan_start method."""
        logger = ReaperLogger()
        logger.log_scan_start("INSTANCE", 10)

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].action == ActionType.SCAN
        assert entries[0].level == LogLevel.INFO

    def test_log_scan_complete(self):
        """Test log_scan_complete method."""
        logger = ReaperLogger()
        logger.log_scan_complete("INSTANCE", 100, 10)

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert "100 found" in entries[0].message
        assert "10 match" in entries[0].message

    def test_log_resource_scanned(self):
        """Test log_resource_scanned method."""
        logger = ReaperLogger()
        logger.log_resource_scanned("INSTANCE", "i-12345678", {"state": "running"})

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].level == LogLevel.DEBUG

    def test_log_api_call(self):
        """Test log_api_call method."""
        logger = ReaperLogger()
        logger.log_api_call(
            "describe_instances",
            "EC2",
            parameters={"InstanceIds": ["i-12345678"]},
            response_summary="1 instance found",
        )

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].level == LogLevel.DEBUG

    def test_log_processing_step(self):
        """Test log_processing_step method."""
        logger = ReaperLogger()
        logger.log_processing_step("filter_by_age", "INSTANCE", {"threshold": 2})

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].level == LogLevel.DEBUG

    def test_log_resource_attributes(self):
        """Test log_resource_attributes method."""
        logger = ReaperLogger()
        logger.log_resource_attributes(
            "INSTANCE", "i-12345678", {"state": "running", "type": "t3.micro"}
        )

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].level == LogLevel.DEBUG

    def test_log_filter_applied(self):
        """Test log_filter_applied method."""
        logger = ReaperLogger()
        logger.log_filter_applied("temporal", "INSTANCE", 100, 10)

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert "100 -> 10" in entries[0].message

    def test_log_resource_filtered(self):
        """Test log_resource_filtered method."""
        logger = ReaperLogger()
        logger.log_resource_filtered("INSTANCE", "i-12345678", "temporal", True, "Age > 2 hours")

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].level == LogLevel.DEBUG

    def test_log_action_start(self):
        """Test log_action_start method."""
        logger = ReaperLogger()
        logger.log_action_start(ActionType.TERMINATE, "INSTANCE", "i-12345678")

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].action == ActionType.TERMINATE

    def test_log_action_complete(self):
        """Test log_action_complete method."""
        logger = ReaperLogger()
        logger.log_action_complete(ActionType.TERMINATE, "INSTANCE", "i-12345678")

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert "Successfully" in entries[0].message

    def test_log_action_deferred(self):
        """Test log_action_deferred method."""
        logger = ReaperLogger()
        logger.log_action_deferred("SECURITY_GROUP", "sg-12345678", "Has dependencies")

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].action == ActionType.DEFER
        assert entries[0].level == LogLevel.WARNING

    def test_log_action_skipped(self):
        """Test log_action_skipped method."""
        logger = ReaperLogger()
        logger.log_action_skipped("INSTANCE", "i-12345678", "Already terminated")

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].action == ActionType.SKIP

    def test_log_error(self):
        """Test log_error method."""
        logger = ReaperLogger()
        error = Exception("Test error")
        logger.log_error("INSTANCE", "i-12345678", error)

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].level == LogLevel.ERROR

    def test_log_error_with_aws_error_code(self):
        """Test log_error extracts AWS error code."""
        from botocore.exceptions import ClientError

        logger = ReaperLogger()
        error = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "TerminateInstances",
        )
        logger.log_error("INSTANCE", "i-12345678", error)

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].error_info["aws_error_code"] == "AccessDenied"

    def test_log_dependency_violation(self):
        """Test log_dependency_violation method."""
        logger = ReaperLogger()
        logger.log_dependency_violation("SECURITY_GROUP", "sg-12345678", "In use by ENI")

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].action == ActionType.DEFER
        assert "DependencyViolation" in entries[0].error_info["error_type"]

    def test_log_rate_limit(self):
        """Test log_rate_limit method."""
        logger = ReaperLogger()
        logger.log_rate_limit("INSTANCE", "i-12345678", 2, 4.5)

        entries = logger.get_log_entries()
        assert len(entries) == 1
        assert entries[0].level == LogLevel.WARNING
        assert "attempt 2" in entries[0].message

    @patch("reaper.utils.logging.logger")
    def test_log_execution_start(self, mock_logger):
        """Test log_execution_start method."""
        logger = ReaperLogger(account_id="123456789012", region="us-east-1", dry_run=True)
        logger.log_execution_start()

        assert mock_logger.info.called

    @patch("reaper.utils.logging.logger")
    def test_log_execution_complete(self, mock_logger):
        """Test log_execution_complete method."""
        logger = ReaperLogger(dry_run=False)
        logger.log_execution_complete(
            total_scanned=100,
            total_cleaned=10,
            total_deferred=5,
            total_errors=2,
        )

        assert mock_logger.info.called

    def test_get_log_entries_returns_copy(self):
        """Test get_log_entries returns a copy."""
        logger = ReaperLogger()
        logger.log_scan_start("INSTANCE", 10)

        entries1 = logger.get_log_entries()
        entries2 = logger.get_log_entries()

        assert entries1 is not entries2
        assert entries1 == entries2

    def test_get_action_verb(self):
        """Test _get_action_verb method."""
        logger = ReaperLogger()

        assert logger._get_action_verb(ActionType.SCAN) == "scan"
        assert logger._get_action_verb(ActionType.TERMINATE) == "terminate"
        assert logger._get_action_verb(ActionType.DELETE) == "delete"
        assert logger._get_action_verb(ActionType.RELEASE) == "release"


class TestModuleLevelLoggingFunctions:
    """Tests for module-level logging functions."""

    @patch("reaper.utils.logging.logger")
    def test_log_resource_scan(self, mock_logger):
        """Test log_resource_scan function."""
        log_resource_scan("INSTANCE", "i-12345678", {"state": "running"})

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "[SCAN]" in call_args
        assert "INSTANCE" in call_args
        assert "i-12345678" in call_args

    @patch("reaper.utils.logging.logger")
    def test_log_cleanup_action_success(self, mock_logger):
        """Test log_cleanup_action function with success."""
        log_cleanup_action("TERMINATE", "INSTANCE", "i-12345678", True)

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "[TERMINATE]" in call_args
        assert "SUCCESS" in call_args

    @patch("reaper.utils.logging.logger")
    def test_log_cleanup_action_failure(self, mock_logger):
        """Test log_cleanup_action function with failure."""
        log_cleanup_action("TERMINATE", "INSTANCE", "i-12345678", False, "API error")

        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args[0][0]
        assert "[TERMINATE]" in call_args
        assert "FAILED" in call_args
        assert "API error" in call_args

    @patch("reaper.utils.logging.logger")
    def test_log_error_with_details(self, mock_logger):
        """Test log_error_with_details function."""
        error = Exception("Test error")
        log_error_with_details("INSTANCE", "i-12345678", error, {"action": "terminate"})

        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args[0][0]
        assert "[ERROR]" in call_args
        assert "Exception" in call_args

    @patch("reaper.utils.logging.logger")
    def test_log_debug_api_call(self, mock_logger):
        """Test log_debug_api_call function."""
        log_debug_api_call("describe_instances", "EC2", {"InstanceIds": ["i-12345678"]})

        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args[0][0]
        assert "[DEBUG]" in call_args
        assert "EC2.describe_instances" in call_args

    @patch("reaper.utils.logging.logger")
    def test_log_debug_processing_step(self, mock_logger):
        """Test log_debug_processing_step function."""
        log_debug_processing_step("filter_instances", {"count": 10})

        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args[0][0]
        assert "[DEBUG]" in call_args
        assert "filter_instances" in call_args

    @patch("reaper.utils.logging.logger")
    def test_log_debug_resource_attributes(self, mock_logger):
        """Test log_debug_resource_attributes function."""
        log_debug_resource_attributes(
            "INSTANCE", "i-12345678", {"state": "running", "type": "t3.micro"}
        )

        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args[0][0]
        assert "[DEBUG]" in call_args
        assert "INSTANCE" in call_args
        assert "i-12345678" in call_args


class TestLogLevelEnum:
    """Tests for LogLevel enum."""

    def test_log_level_values(self):
        """Test LogLevel enum values."""
        assert LogLevel.DEBUG.value == "DEBUG"
        assert LogLevel.INFO.value == "INFO"
        assert LogLevel.WARNING.value == "WARNING"
        assert LogLevel.ERROR.value == "ERROR"
        assert LogLevel.CRITICAL.value == "CRITICAL"


class TestActionTypeEnum:
    """Tests for ActionType enum."""

    def test_action_type_values(self):
        """Test ActionType enum values."""
        assert ActionType.SCAN.value == "SCAN"
        assert ActionType.FILTER.value == "FILTER"
        assert ActionType.TERMINATE.value == "TERMINATE"
        assert ActionType.DELETE.value == "DELETE"
        assert ActionType.RELEASE.value == "RELEASE"
        assert ActionType.DEFER.value == "DEFER"
        assert ActionType.SKIP.value == "SKIP"
        assert ActionType.ERROR.value == "ERROR"
