"""Property-based tests for two-criteria filter selection.

Feature: packer-resource-reaper, Property 1: Two-Criteria Filter Selection
Validates: Requirements 1.1, 1.2

This test validates that only instances matching BOTH criteria are selected:
1. Key pair name starts with "packer_*" (Identity Filter)
2. Instance age exceeds MaxInstanceAge threshold (Temporal Filter)
"""

from datetime import UTC, datetime, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from reaper.filters.identity import IdentityFilter
from reaper.filters.temporal import TemporalFilter
from reaper.models import PackerInstance, ResourceType


def create_instance(
    launch_time: datetime,
    key_name: str = None,
    instance_id: str = "i-test123",
    tags: dict = None,
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
        key_name=key_name,
        launch_time=launch_time,
    )


def apply_two_criteria_filter(
    instances: list[PackerInstance],
    temporal_filter: TemporalFilter,
    identity_filter: IdentityFilter,
) -> list[PackerInstance]:
    """
    Apply the two-criteria filter: temporal AND identity.

    Only instances that pass BOTH filters are returned.
    """
    # Apply temporal filter first (age threshold)
    result = temporal_filter.filter_instances(instances)
    # Then apply identity filter (key pair pattern)
    result = identity_filter.filter_instances(result)
    return result


# Strategies for generating test data
age_hours_strategy = st.integers(min_value=1, max_value=168)  # 1 hour to 1 week
max_age_strategy = st.integers(min_value=1, max_value=48)  # 1 to 48 hours

# Strategy for packer-style key names (valid packer keys)
packer_key_suffix = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_"),
    min_size=1,
    max_size=20,
)

# Strategy for non-packer key names
non_packer_key_name = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_-"),
    min_size=1,
    max_size=30,
).filter(lambda x: not x.lower().startswith("packer_"))


@settings(max_examples=100, deadline=5000)
@given(
    instance_age_hours=age_hours_strategy,
    max_age_hours=max_age_strategy,
    packer_suffix=packer_key_suffix,
)
def test_two_criteria_both_match_selects_instance(
    instance_age_hours: int,
    max_age_hours: int,
    packer_suffix: str,
):
    """
    Feature: packer-resource-reaper, Property 1: Two-Criteria Filter Selection

    For any instance that satisfies BOTH criteria (packer_* key AND age >= threshold),
    the two-criteria filter should select it for cleanup.

    Validates: Requirements 1.1, 1.2
    """
    now = datetime.now(UTC)

    # Create instance that is old enough
    actual_age = max(instance_age_hours, max_age_hours)  # Ensure it's old enough
    launch_time = now - timedelta(hours=actual_age)

    # Use packer_* key name
    key_name = f"packer_{packer_suffix}"

    instance = create_instance(
        launch_time=launch_time,
        key_name=key_name,
    )

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    identity_filter = IdentityFilter()

    result = apply_two_criteria_filter([instance], temporal_filter, identity_filter)

    assert len(result) == 1, (
        f"Instance with packer key '{key_name}' and age {actual_age}h "
        f"(threshold {max_age_hours}h) should be selected"
    )
    assert result[0].resource_id == instance.resource_id


@settings(max_examples=100, deadline=5000)
@given(
    instance_age_hours=age_hours_strategy,
    max_age_hours=max_age_strategy,
    non_packer_key=non_packer_key_name,
)
def test_two_criteria_wrong_key_excludes_instance(
    instance_age_hours: int,
    max_age_hours: int,
    non_packer_key: str,
):
    """
    Feature: packer-resource-reaper, Property 1: Two-Criteria Filter Selection

    For any instance with a non-packer key name (doesn't start with packer_*),
    the two-criteria filter should NOT select it, regardless of age.

    Validates: Requirements 1.2
    """
    now = datetime.now(UTC)

    # Create instance that is old enough to pass temporal filter
    actual_age = max_age_hours + 10
    launch_time = now - timedelta(hours=actual_age)

    instance = create_instance(
        launch_time=launch_time,
        key_name=non_packer_key,
    )

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    identity_filter = IdentityFilter()

    result = apply_two_criteria_filter([instance], temporal_filter, identity_filter)

    assert len(result) == 0, (
        f"Instance with non-packer key '{non_packer_key}' should NOT be selected "
        f"even though age {actual_age}h exceeds threshold {max_age_hours}h"
    )


@settings(max_examples=100, deadline=5000)
@given(
    max_age_hours=max_age_strategy,
    packer_suffix=packer_key_suffix,
)
def test_two_criteria_young_instance_excluded(
    max_age_hours: int,
    packer_suffix: str,
):
    """
    Feature: packer-resource-reaper, Property 1: Two-Criteria Filter Selection

    For any instance with a packer_* key but age below threshold,
    the two-criteria filter should NOT select it.

    Validates: Requirements 1.1
    """
    now = datetime.now(UTC)

    # Create instance that is too young (below threshold)
    young_age = max(1, max_age_hours - 1)  # At least 1 hour but below threshold
    launch_time = now - timedelta(hours=young_age)

    key_name = f"packer_{packer_suffix}"

    instance = create_instance(
        launch_time=launch_time,
        key_name=key_name,
    )

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    identity_filter = IdentityFilter()

    result = apply_two_criteria_filter([instance], temporal_filter, identity_filter)

    # Only exclude if actually below threshold
    if young_age < max_age_hours:
        assert len(result) == 0, (
            f"Instance with packer key '{key_name}' but age {young_age}h "
            f"(below threshold {max_age_hours}h) should NOT be selected"
        )


@settings(max_examples=100, deadline=5000)
@given(
    instance_age_hours=age_hours_strategy,
    max_age_hours=max_age_strategy,
    has_packer_key=st.booleans(),
    packer_suffix=packer_key_suffix,
    non_packer_key=non_packer_key_name,
)
def test_two_criteria_both_must_match(
    instance_age_hours: int,
    max_age_hours: int,
    has_packer_key: bool,
    packer_suffix: str,
    non_packer_key: str,
):
    """
    Feature: packer-resource-reaper, Property 1: Two-Criteria Filter Selection

    For any instance, it should be selected if and only if BOTH criteria are met:
    1. Key pair starts with "packer_*"
    2. Age >= MaxInstanceAge threshold

    Validates: Requirements 1.1, 1.2
    """
    now = datetime.now(UTC)
    launch_time = now - timedelta(hours=instance_age_hours)

    key_name = f"packer_{packer_suffix}" if has_packer_key else non_packer_key

    instance = create_instance(
        launch_time=launch_time,
        key_name=key_name,
    )

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    identity_filter = IdentityFilter()

    result = apply_two_criteria_filter([instance], temporal_filter, identity_filter)

    # Determine expected outcome
    passes_temporal = instance_age_hours >= max_age_hours
    passes_identity = has_packer_key
    should_be_selected = passes_temporal and passes_identity

    if should_be_selected:
        assert len(result) == 1, (
            f"Instance should be selected: "
            f"temporal={passes_temporal} (age={instance_age_hours}h, threshold={max_age_hours}h), "
            f"identity={passes_identity} (key={key_name})"
        )
    else:
        assert len(result) == 0, (
            f"Instance should NOT be selected: "
            f"temporal={passes_temporal} (age={instance_age_hours}h, threshold={max_age_hours}h), "
            f"identity={passes_identity} (key={key_name})"
        )


@settings(max_examples=100, deadline=5000)
@given(
    num_instances=st.integers(min_value=1, max_value=20),
    max_age_hours=max_age_strategy,
)
def test_two_criteria_preserves_matching_subset(
    num_instances: int,
    max_age_hours: int,
):
    """
    Feature: packer-resource-reaper, Property 1: Two-Criteria Filter Selection

    For any set of instances, the two-criteria filter should return exactly
    the subset that matches BOTH criteria.

    Validates: Requirements 1.1, 1.2
    """
    now = datetime.now(UTC)
    instances = []
    expected_matches = []

    for i in range(num_instances):
        # Alternate between matching and non-matching instances
        is_old = i % 2 == 0
        has_packer_key = i % 3 != 0

        age_hours = max_age_hours + 5 if is_old else max(1, max_age_hours - 1)
        launch_time = now - timedelta(hours=age_hours)

        key_name = f"packer_key_{i}" if has_packer_key else f"prod_key_{i}"

        instance = create_instance(
            launch_time=launch_time,
            key_name=key_name,
            instance_id=f"i-{i:08d}",
        )
        instances.append(instance)

        # Determine if this instance should match BOTH criteria
        passes_temporal = age_hours >= max_age_hours
        passes_identity = has_packer_key

        if passes_temporal and passes_identity:
            expected_matches.append(instance.resource_id)

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    identity_filter = IdentityFilter()

    result = apply_two_criteria_filter(instances, temporal_filter, identity_filter)
    result_ids = [r.resource_id for r in result]

    assert set(result_ids) == set(expected_matches), (
        f"Filter should return exactly matching instances. "
        f"Expected: {expected_matches}, Got: {result_ids}"
    )


@settings(max_examples=100, deadline=5000)
@given(
    max_age_hours=max_age_strategy,
)
def test_two_criteria_no_key_excludes_instance(
    max_age_hours: int,
):
    """
    Feature: packer-resource-reaper, Property 1: Two-Criteria Filter Selection

    For any instance without a key pair (key_name is None),
    the two-criteria filter should NOT select it.

    Validates: Requirements 1.2
    """
    now = datetime.now(UTC)

    # Create old instance without key pair
    launch_time = now - timedelta(hours=max_age_hours + 10)

    instance = create_instance(
        launch_time=launch_time,
        key_name=None,  # No key pair
    )

    temporal_filter = TemporalFilter(max_age_hours=max_age_hours)
    identity_filter = IdentityFilter()

    result = apply_two_criteria_filter([instance], temporal_filter, identity_filter)

    assert len(result) == 0, "Instance without key pair should NOT be selected"
