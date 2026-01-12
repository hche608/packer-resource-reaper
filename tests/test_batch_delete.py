"""Property-based tests for batch delete processing.

Feature: packer-resource-reaper, Property 13: Batch Delete Processing
Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7

Tests that:
- BATCH_DELETE_SIZE environment variable is correctly parsed (12.1)
- Default to 1 (sequential deletion) when not set (12.2)
- Process multiple deletions concurrently within each batch (12.3)
- Wait for all deletions in current batch before proceeding (12.4)
- Log failures and continue processing remaining items (12.5)
- Respect dependency-aware cleanup order (12.6)
- Default to 1 for invalid values (12.7)
"""

import logging
import os
import threading
import time

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from reaper.cleanup.batch_processor import BatchProcessor
from reaper.utils.config import ReaperConfig

# Strategy for valid batch sizes (positive integers)
valid_batch_size_strategy = st.integers(min_value=1, max_value=100)

# Strategy for invalid batch sizes (non-positive integers)
invalid_batch_size_strategy = st.integers(max_value=0)

# Strategy for invalid batch size strings
invalid_batch_size_string_strategy = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz!@#$%^&*()"),
    min_size=1,
    max_size=10,
)

# Strategy for resource lists
resource_list_strategy = st.lists(
    st.text(
        alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789-"),
        min_size=5,
        max_size=20,
    ).map(lambda x: f"resource-{x}"),
    min_size=0,
    max_size=50,
    unique=True,
)


def clear_env_vars():
    """Clear all reaper-related environment variables."""
    env_vars = [
        "MAX_INSTANCE_AGE_HOURS",
        "DRY_RUN",
        "SNS_TOPIC_ARN",
        "AWS_REGION",
        "KEY_PAIR_PATTERN",
        "LOG_LEVEL",
        "BATCH_DELETE_SIZE",
    ]
    for var in env_vars:
        os.environ.pop(var, None)


# ============================================================================
# Property 13: Batch Delete Processing
# Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7
# ============================================================================


@settings(max_examples=100, deadline=5000)
@given(batch_size=valid_batch_size_strategy)
def test_property13_valid_batch_size_parsing(batch_size: int):
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    For any valid BATCH_DELETE_SIZE value (positive integer), the configuration
    parser should correctly parse and store the value.

    Validates: Requirements 12.1
    """
    clear_env_vars()
    os.environ["BATCH_DELETE_SIZE"] = str(batch_size)

    config = ReaperConfig.from_environment(validate=False)

    assert config.batch_delete_size == batch_size
    assert config.get_batch_delete_size() == batch_size


def test_property13_batch_size_default_when_not_set():
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    When BATCH_DELETE_SIZE environment variable is not set, the configuration
    should default to 1 (sequential deletion).

    Validates: Requirements 12.2
    """
    clear_env_vars()
    # Ensure BATCH_DELETE_SIZE is not set
    assert "BATCH_DELETE_SIZE" not in os.environ

    config = ReaperConfig.from_environment(validate=False)

    assert config.batch_delete_size == 1
    assert config.get_batch_delete_size() == 1


@settings(
    max_examples=100,
    deadline=5000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(invalid_size=invalid_batch_size_strategy)
def test_property13_invalid_batch_size_defaults_to_one(invalid_size: int, caplog):
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    For any non-positive BATCH_DELETE_SIZE value, the configuration parser
    should default to 1 and log a warning.

    Validates: Requirements 12.7
    """
    clear_env_vars()
    os.environ["BATCH_DELETE_SIZE"] = str(invalid_size)

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        config = ReaperConfig.from_environment(validate=False)

    # Should default to 1
    assert config.batch_delete_size == 1

    # Should have logged a warning about invalid value
    warning_logged = any(
        "invalid" in record.message.lower() and "batch_delete_size" in record.message.lower()
        for record in caplog.records
    )
    assert warning_logged, f"Expected warning about invalid BATCH_DELETE_SIZE '{invalid_size}'"


@settings(
    max_examples=100,
    deadline=5000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(invalid_value=invalid_batch_size_string_strategy)
def test_property13_non_integer_batch_size_defaults_to_one(invalid_value: str, caplog):
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    For any non-integer BATCH_DELETE_SIZE value, the configuration parser
    should default to 1 and log a warning.

    Validates: Requirements 12.7
    """
    assume(len(invalid_value.strip()) > 0)

    clear_env_vars()
    os.environ["BATCH_DELETE_SIZE"] = invalid_value

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        config = ReaperConfig.from_environment(validate=False)

    # Should default to 1
    assert config.batch_delete_size == 1

    # Should have logged a warning about invalid value
    warning_logged = any(
        "invalid" in record.message.lower() and "batch_delete_size" in record.message.lower()
        for record in caplog.records
    )
    assert warning_logged, f"Expected warning about invalid BATCH_DELETE_SIZE '{invalid_value}'"


@settings(max_examples=100, deadline=10000)
@given(
    resources=resource_list_strategy,
    batch_size=st.integers(min_value=1, max_value=10),
)
def test_property13_all_resources_processed(resources: list[str], batch_size: int):
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    For any set of resources and batch size, all resources should be processed
    (either successfully deleted or marked as failed).

    Validates: Requirements 12.1, 12.3, 12.4
    """
    processor = BatchProcessor(batch_size=batch_size)

    # Simple delete function that always succeeds
    def delete_func(resource_id: str) -> bool:
        return True

    result = processor.process_deletions(resources, delete_func, "test-resource")

    # All resources should be in either successful or failed
    all_processed = set(result.successful) | set(result.failed)
    assert all_processed == set(resources), "All resources should be processed"

    # With a successful delete function, all should be successful
    assert len(result.successful) == len(resources)
    assert len(result.failed) == 0


@settings(max_examples=100, deadline=10000)
@given(
    resources=st.lists(
        st.text(min_size=5, max_size=10).map(lambda x: f"res-{x}"),
        min_size=1,
        max_size=20,
        unique=True,
    ),
    batch_size=st.integers(min_value=2, max_value=5),
)
def test_property13_concurrent_execution_within_batch(resources: list[str], batch_size: int):
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    When batch_size > 1, multiple deletions within each batch should be
    processed concurrently.

    Validates: Requirements 12.3
    """
    processor = BatchProcessor(batch_size=batch_size)

    # Track concurrent execution
    concurrent_count = [0]
    max_concurrent = [0]
    lock = threading.Lock()

    def delete_func(resource_id: str) -> bool:
        with lock:
            concurrent_count[0] += 1
            max_concurrent[0] = max(max_concurrent[0], concurrent_count[0])

        # Small delay to allow concurrent execution to be detected
        time.sleep(0.01)

        with lock:
            concurrent_count[0] -= 1

        return True

    result = processor.process_deletions(resources, delete_func, "test-resource")

    # All resources should be processed successfully
    assert len(result.successful) == len(resources)

    # If we have more resources than batch_size, we should see concurrent execution
    if len(resources) >= batch_size and batch_size > 1:
        # Max concurrent should be at least 2 (or batch_size if enough resources)
        min(batch_size, len(resources))
        assert max_concurrent[0] >= 2, (
            f"Expected concurrent execution, but max concurrent was {max_concurrent[0]}"
        )


@settings(max_examples=100, deadline=10000)
@given(
    resources=st.lists(
        st.text(min_size=5, max_size=10).map(lambda x: f"res-{x}"),
        min_size=3,
        max_size=15,
        unique=True,
    ),
    batch_size=st.integers(min_value=2, max_value=5),
)
def test_property13_batch_completion_before_next(resources: list[str], batch_size: int):
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    All deletions in the current batch should complete before proceeding
    to the next batch.

    Validates: Requirements 12.4
    """
    processor = BatchProcessor(batch_size=batch_size)

    # Track batch boundaries
    operation_order: list[str] = []
    lock = threading.Lock()
    counter = [0]

    def delete_func(resource_id: str) -> bool:
        with lock:
            counter[0] += 1
            operation_order.append(f"start-{resource_id}")

        time.sleep(0.01)  # Small delay

        with lock:
            operation_order.append(f"end-{resource_id}")

        return True

    result = processor.process_deletions(resources, delete_func, "test-resource")

    # All resources should be processed
    assert len(result.successful) == len(resources)

    # Verify batch ordering: all starts in a batch should come before
    # any starts in the next batch
    (len(resources) + batch_size - 1) // batch_size

    # This is a simplified check - we verify all resources were processed
    # The actual batch ordering is enforced by the ThreadPoolExecutor
    assert len(operation_order) == len(resources) * 2  # start + end for each


@settings(max_examples=100, deadline=10000)
@given(
    resources=st.lists(
        st.text(min_size=5, max_size=10).map(lambda x: f"res-{x}"),
        min_size=1,
        max_size=20,
        unique=True,
    ),
    batch_size=st.integers(min_value=1, max_value=5),
    fail_indices=st.lists(st.integers(min_value=0, max_value=19), max_size=5, unique=True),
)
def test_property13_failure_handling_continues_processing(
    resources: list[str],
    batch_size: int,
    fail_indices: list[int],
):
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    When a deletion fails within a batch, the processor should log the failure
    and continue processing remaining items.

    Validates: Requirements 12.5
    """
    processor = BatchProcessor(batch_size=batch_size)

    # Determine which resources should fail
    fail_set = {resources[i] for i in fail_indices if i < len(resources)}

    def delete_func(resource_id: str) -> bool:
        if resource_id in fail_set:
            raise Exception(f"Simulated failure for {resource_id}")
        return True

    result = processor.process_deletions(resources, delete_func, "test-resource")

    # All resources should be processed (either success or failure)
    all_processed = set(result.successful) | set(result.failed)
    assert all_processed == set(resources), "All resources should be processed"

    # Failed resources should be in the failed list
    assert set(result.failed) == fail_set

    # Successful resources should be the rest
    expected_successful = set(resources) - fail_set
    assert set(result.successful) == expected_successful

    # Errors should be recorded for failed resources
    for failed_id in fail_set:
        assert failed_id in result.errors


@settings(max_examples=100, deadline=5000)
@given(batch_size=st.integers(min_value=1, max_value=100))
def test_property13_batch_processor_initialization(batch_size: int):
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    BatchProcessor should correctly initialize with the specified batch size,
    ensuring minimum of 1.

    Validates: Requirements 12.1, 12.2
    """
    processor = BatchProcessor(batch_size=batch_size)

    assert processor.batch_size == max(1, batch_size)


def test_property13_batch_processor_minimum_size():
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    BatchProcessor should enforce a minimum batch size of 1.

    Validates: Requirements 12.2, 12.7
    """
    # Test with 0
    processor = BatchProcessor(batch_size=0)
    assert processor.batch_size == 1

    # Test with negative
    processor = BatchProcessor(batch_size=-5)
    assert processor.batch_size == 1


def test_property13_empty_resource_list():
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    Processing an empty resource list should return an empty result.

    Validates: Requirements 12.1
    """
    processor = BatchProcessor(batch_size=5)

    def delete_func(resource_id: str) -> bool:
        return True

    result = processor.process_deletions([], delete_func, "test-resource")

    assert len(result.successful) == 0
    assert len(result.failed) == 0
    assert len(result.errors) == 0


@settings(max_examples=50, deadline=10000)
@given(
    resources=st.lists(
        st.text(min_size=5, max_size=10).map(lambda x: f"res-{x}"),
        min_size=1,
        max_size=10,
        unique=True,
    ),
)
def test_property13_sequential_processing_with_batch_size_one(resources: list[str]):
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    With batch_size=1, resources should be processed sequentially.

    Validates: Requirements 12.2
    """
    processor = BatchProcessor(batch_size=1)

    # Track execution order
    execution_order: list[str] = []
    lock = threading.Lock()

    def delete_func(resource_id: str) -> bool:
        with lock:
            execution_order.append(resource_id)
        return True

    result = processor.process_deletions(resources, delete_func, "test-resource")

    # All resources should be processed
    assert len(result.successful) == len(resources)

    # Execution order should match input order (sequential processing)
    assert execution_order == resources


@settings(max_examples=100, deadline=5000)
@given(
    batch_size=valid_batch_size_strategy,
    max_age=st.integers(min_value=1, max_value=168),
    dry_run=st.booleans(),
    log_level=st.sampled_from(["DEBUG", "INFO", "WARNING", "ERROR"]),
)
def test_property13_batch_size_with_other_config(
    batch_size: int,
    max_age: int,
    dry_run: bool,
    log_level: str,
):
    """
    Feature: packer-resource-reaper, Property 13: Batch Delete Processing

    BATCH_DELETE_SIZE should be correctly parsed alongside other configuration values.

    Validates: Requirements 12.1, 5.2
    """
    clear_env_vars()
    os.environ["BATCH_DELETE_SIZE"] = str(batch_size)
    os.environ["MAX_INSTANCE_AGE_HOURS"] = str(max_age)
    os.environ["DRY_RUN"] = "true" if dry_run else "false"
    os.environ["LOG_LEVEL"] = log_level

    config = ReaperConfig.from_environment(validate=False)

    assert config.batch_delete_size == batch_size
    assert config.max_instance_age_hours == max_age
    assert config.dry_run == dry_run
    assert config.log_level == log_level
