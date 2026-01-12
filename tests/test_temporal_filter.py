"""Property-based tests for temporal filter.

Feature: packer-resource-reaper, Property 7: Age Threshold Filtering
Validates: Requirements 1.1

The temporal filter identifies resources that exceed the configured
MaxInstanceAge threshold. This is a simple age-based filter.
"""

from datetime import UTC, datetime, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from reaper.filters.temporal import TemporalFilter
from reaper.models import PackerInstance, ResourceType


def create_instance(
    launch_time: datetime,
    tags: dict = None,
    instance_id: str = "i-test123",
) -> PackerInstance:
    """Helper to create a PackerInstance for testing."""
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=launch_time,
        tags=tags or {},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state="running",
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name="packer_key",
        launch_time=launch_time,
    )


# Strategy for generating age in hours (positive values)
age_hours_strategy = st.integers(min_value=1, max_value=168)  # 1 hour to 1 week

# Strategy for max age threshold
max_age_strategy = st.integers(min_value=1, max_value=48)  # 1 to 48 hours


@settings(max_examples=100, deadline=5000)
@given(
    instance_age_hours=age_hours_strategy,
    max_age_hours=max_age_strategy,
)
def test_temporal_filter_age_threshold(instance_age_hours: int, max_age_hours: int):
    """
    Feature: packer-resource-reaper, Property 7: Age Threshold Filtering

    For any instance age and max age threshold, the temporal filter should
    correctly identify instances that exceed the threshold.

    Validates: Requirements 1.1
    """
    # Create instance with specific age
    now = datetime.now(UTC)
    launch_time = now - timedelta(hours=instance_age_hours)
    instance = create_instance(launch_time=launch_time)

    # Create filter with threshold
    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)

    # Filter the instance
    result = temporal_filter.filter_instances([instance])

    # Instance should be in result if age >= threshold
    if instance_age_hours >= max_age_hours:
        assert len(result) == 1, (
            f"Instance aged {instance_age_hours}h should be filtered with threshold {max_age_hours}h"
        )
        assert result[0].resource_id == instance.resource_id
    else:
        assert len(result) == 0, (
            f"Instance aged {instance_age_hours}h should NOT be filtered with threshold {max_age_hours}h"
        )


@settings(max_examples=100, deadline=5000)
@given(
    max_age_hours=max_age_strategy,
)
def test_temporal_filter_boundary_condition(max_age_hours: int):
    """
    Feature: packer-resource-reaper, Property 7: Age Threshold Filtering

    For any max age threshold, instances exactly at the threshold should
    be filtered (>= comparison).

    Validates: Requirements 1.1
    """
    now = datetime.now(UTC)

    # Create instance exactly at threshold
    launch_time = now - timedelta(hours=max_age_hours)
    instance = create_instance(launch_time=launch_time)

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    result = temporal_filter.filter_instances([instance])

    assert len(result) == 1, f"Instance exactly at threshold {max_age_hours}h should be filtered"


@settings(max_examples=100, deadline=5000)
@given(
    max_age_hours=max_age_strategy,
)
def test_temporal_filter_just_under_threshold(max_age_hours: int):
    """
    Feature: packer-resource-reaper, Property 7: Age Threshold Filtering

    For any max age threshold, instances just under the threshold should
    NOT be filtered.

    Validates: Requirements 1.1
    """
    now = datetime.now(UTC)

    # Create instance just under threshold (1 minute less)
    launch_time = now - timedelta(hours=max_age_hours) + timedelta(minutes=1)
    instance = create_instance(launch_time=launch_time)

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    result = temporal_filter.filter_instances([instance])

    assert len(result) == 0, (
        f"Instance just under threshold {max_age_hours}h should NOT be filtered"
    )


@settings(max_examples=100, deadline=5000)
@given(
    num_instances=st.integers(min_value=2, max_value=10),
    max_age_hours=max_age_strategy,
)
def test_temporal_filter_multiple_instances(num_instances: int, max_age_hours: int):
    """
    Feature: packer-resource-reaper, Property 7: Age Threshold Filtering

    For any set of instances with varying ages, the temporal filter should
    correctly identify all instances that exceed the threshold.

    Validates: Requirements 1.1
    """
    now = datetime.now(UTC)
    instances = []
    expected_filtered_count = 0

    for i in range(num_instances):
        # Create instances with varying ages
        # Even indices: old (should be filtered)
        # Odd indices: young (should not be filtered)
        if i % 2 == 0:
            # Old instance - age is max_age + some extra hours
            age_hours = max_age_hours + 10 + i
            expected_filtered_count += 1
        else:
            # Young instance - age is less than max_age
            age_hours = max(0.5, max_age_hours / 2 - i)

        launch_time = now - timedelta(hours=age_hours)
        instance = create_instance(launch_time=launch_time, instance_id=f"i-test{i:03d}")
        instances.append(instance)

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    result = temporal_filter.filter_instances(instances)

    assert len(result) == expected_filtered_count, (
        f"Expected {expected_filtered_count} filtered instances, got {len(result)}"
    )


@settings(max_examples=100, deadline=5000)
@given(
    max_age_hours=max_age_strategy,
)
def test_temporal_filter_empty_list(max_age_hours: int):
    """
    Feature: packer-resource-reaper, Property 7: Age Threshold Filtering

    For an empty list of instances, the temporal filter should return
    an empty list.

    Validates: Requirements 1.1
    """
    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    result = temporal_filter.filter_instances([])

    assert len(result) == 0, "Empty input should produce empty output"


@settings(max_examples=100, deadline=5000)
@given(
    instance_age_hours=age_hours_strategy,
    max_age_hours=max_age_strategy,
)
def test_temporal_filter_is_deterministic(instance_age_hours: int, max_age_hours: int):
    """
    Feature: packer-resource-reaper, Property 7: Age Threshold Filtering

    For any instance and threshold, filtering should produce the same
    result when applied multiple times.

    Validates: Requirements 1.1
    """
    now = datetime.now(UTC)
    launch_time = now - timedelta(hours=instance_age_hours)
    instance = create_instance(launch_time=launch_time)

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)

    result1 = temporal_filter.filter_instances([instance])
    result2 = temporal_filter.filter_instances([instance])
    result3 = temporal_filter.filter_instances([instance])

    assert len(result1) == len(result2) == len(result3)


def test_default_max_age():
    """
    Feature: packer-resource-reaper, Property 7: Age Threshold Filtering

    The default max age should be 2 hours.

    Validates: Requirements 1.1
    """
    temporal_filter = TemporalFilter()

    assert temporal_filter.max_age_hours == 2


@settings(max_examples=100, deadline=5000)
@given(
    instance_age_hours=age_hours_strategy,
    max_age_hours=max_age_strategy,
)
def test_temporal_filter_ignores_tags(instance_age_hours: int, max_age_hours: int):
    """
    Feature: packer-resource-reaper, Property 7: Age Threshold Filtering

    The temporal filter should only consider instance age, not tags.
    Tags should not affect filtering behavior.

    Validates: Requirements 1.1
    """
    now = datetime.now(UTC)
    launch_time = now - timedelta(hours=instance_age_hours)

    # Create instance with various tags
    tags = {
        "Name": "Test Instance",
        "Environment": "test",
        "SomeTag": "SomeValue",
    }
    instance = create_instance(launch_time=launch_time, tags=tags)

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    result = temporal_filter.filter_instances([instance])

    # Result should be based purely on age
    if instance_age_hours >= max_age_hours:
        assert len(result) == 1
    else:
        assert len(result) == 0
