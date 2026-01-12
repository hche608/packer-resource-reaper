"""Unit tests for batch processor functionality.

Tests for batch processing of resource deletions.
"""

from unittest.mock import MagicMock

from reaper.cleanup.batch_processor import BatchProcessor, BatchResult


class TestBatchResult:
    """Tests for BatchResult dataclass."""

    def test_batch_result_defaults(self):
        """Test BatchResult default values."""
        result = BatchResult()

        assert result.successful == []
        assert result.failed == []
        assert result.errors == {}

    def test_batch_result_with_values(self):
        """Test BatchResult with values."""
        result = BatchResult(
            successful=["r-001", "r-002"],
            failed=["r-003"],
            errors={"r-003": "Error message"},
        )

        assert len(result.successful) == 2
        assert len(result.failed) == 1
        assert "r-003" in result.errors


class TestBatchProcessor:
    """Tests for BatchProcessor class."""

    def test_init_default_batch_size(self):
        """Test default batch size is 1."""
        processor = BatchProcessor()

        assert processor.batch_size == 1

    def test_init_custom_batch_size(self):
        """Test custom batch size."""
        processor = BatchProcessor(batch_size=5)

        assert processor.batch_size == 5

    def test_init_minimum_batch_size(self):
        """Test batch size is at least 1."""
        processor = BatchProcessor(batch_size=0)
        assert processor.batch_size == 1

        processor = BatchProcessor(batch_size=-5)
        assert processor.batch_size == 1

    def test_process_deletions_empty_list(self):
        """Test processing empty resource list."""
        processor = BatchProcessor()
        delete_func = MagicMock(return_value=True)

        result = processor.process_deletions([], delete_func, "test")

        assert len(result.successful) == 0
        assert len(result.failed) == 0
        delete_func.assert_not_called()

    def test_process_deletions_sequential_success(self):
        """Test sequential processing with all successes."""
        processor = BatchProcessor(batch_size=1)
        delete_func = MagicMock(return_value=True)

        result = processor.process_deletions(["r-001", "r-002", "r-003"], delete_func, "resource")

        assert len(result.successful) == 3
        assert len(result.failed) == 0
        assert delete_func.call_count == 3

    def test_process_deletions_sequential_failure(self):
        """Test sequential processing with failures."""
        processor = BatchProcessor(batch_size=1)
        delete_func = MagicMock(side_effect=[True, False, True])

        result = processor.process_deletions(["r-001", "r-002", "r-003"], delete_func, "resource")

        assert len(result.successful) == 2
        assert len(result.failed) == 1
        assert "r-002" in result.failed

    def test_process_deletions_sequential_exception(self):
        """Test sequential processing with exceptions."""
        processor = BatchProcessor(batch_size=1)
        delete_func = MagicMock(side_effect=[True, Exception("API error"), True])

        result = processor.process_deletions(["r-001", "r-002", "r-003"], delete_func, "resource")

        assert len(result.successful) == 2
        assert len(result.failed) == 1
        assert "r-002" in result.errors
        assert "API error" in result.errors["r-002"]

    def test_process_deletions_concurrent_success(self):
        """Test concurrent processing with all successes."""
        processor = BatchProcessor(batch_size=3)
        delete_func = MagicMock(return_value=True)

        result = processor.process_deletions(["r-001", "r-002", "r-003"], delete_func, "resource")

        assert len(result.successful) == 3
        assert len(result.failed) == 0

    def test_process_deletions_concurrent_mixed(self):
        """Test concurrent processing with mixed results."""
        processor = BatchProcessor(batch_size=3)

        def delete_func(resource_id):
            if resource_id == "r-002":
                return False
            return True

        result = processor.process_deletions(["r-001", "r-002", "r-003"], delete_func, "resource")

        assert len(result.successful) == 2
        assert len(result.failed) == 1
        assert "r-002" in result.failed

    def test_process_deletions_concurrent_exception(self):
        """Test concurrent processing with exceptions."""
        processor = BatchProcessor(batch_size=3)

        def delete_func(resource_id):
            if resource_id == "r-002":
                raise Exception("API error")
            return True

        result = processor.process_deletions(["r-001", "r-002", "r-003"], delete_func, "resource")

        assert len(result.successful) == 2
        assert len(result.failed) == 1
        assert "r-002" in result.errors

    def test_process_deletions_multiple_batches(self):
        """Test processing across multiple batches."""
        processor = BatchProcessor(batch_size=2)
        delete_func = MagicMock(return_value=True)

        result = processor.process_deletions(
            ["r-001", "r-002", "r-003", "r-004", "r-005"], delete_func, "resource"
        )

        assert len(result.successful) == 5
        assert delete_func.call_count == 5

    def test_safe_delete_success(self):
        """Test _safe_delete with successful deletion."""
        processor = BatchProcessor()
        delete_func = MagicMock(return_value=True)

        success, error = processor._safe_delete(delete_func, "r-001")

        assert success is True
        assert error is None

    def test_safe_delete_failure(self):
        """Test _safe_delete with failed deletion."""
        processor = BatchProcessor()
        delete_func = MagicMock(return_value=False)

        success, error = processor._safe_delete(delete_func, "r-001")

        assert success is False
        assert error == "Delete returned False"

    def test_safe_delete_exception(self):
        """Test _safe_delete with exception."""
        processor = BatchProcessor()
        delete_func = MagicMock(side_effect=Exception("API error"))

        success, error = processor._safe_delete(delete_func, "r-001")

        assert success is False
        assert "API error" in error

    def test_process_batch_sequential(self):
        """Test _process_batch_sequential method."""
        processor = BatchProcessor()
        delete_func = MagicMock(side_effect=[True, False, True])

        result = processor._process_batch_sequential(
            ["r-001", "r-002", "r-003"], delete_func, "resource"
        )

        assert len(result.successful) == 2
        assert len(result.failed) == 1

    def test_process_batch_concurrent(self):
        """Test _process_batch_concurrent method."""
        processor = BatchProcessor(batch_size=3)
        delete_func = MagicMock(return_value=True)

        result = processor._process_batch_concurrent(
            ["r-001", "r-002", "r-003"], delete_func, "resource"
        )

        assert len(result.successful) == 3
        assert len(result.failed) == 0
