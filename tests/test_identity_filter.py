"""Property-based tests for identity filter pattern matching.

Feature: packer-resource-reaper, Property 2: Pattern Matching Consistency
Validates: Requirements 1.2, 1.3, 2.4, 2.5

The identity filter identifies Packer resources by key pair pattern (packer_*).
This is the primary identification mechanism per the requirements.
"""

from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st

from reaper.filters.identity import IdentityFilter
from reaper.models import (
    PackerElasticIP,
    PackerInstance,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerSnapshot,
    PackerVolume,
    ResourceType,
)


def create_instance(
    tags: dict = None,
    key_name: str = None,
    instance_id: str = "i-test123",
) -> PackerInstance:
    """Helper to create a PackerInstance for testing."""
    now = datetime.now(UTC)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=now,
        tags=tags or {},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state="running",
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name=key_name,
        launch_time=now,
    )


def create_security_group(
    group_name: str,
    tags: dict = None,
    group_id: str = "sg-test123",
) -> PackerSecurityGroup:
    """Helper to create a PackerSecurityGroup for testing."""
    now = datetime.now(UTC)
    return PackerSecurityGroup(
        resource_id=group_id,
        resource_type=ResourceType.SECURITY_GROUP,
        creation_time=now,
        tags=tags or {},
        region="us-east-1",
        account_id="123456789012",
        group_name=group_name,
        vpc_id="vpc-12345678",
        description="Test security group",
    )


def create_key_pair(
    key_name: str,
    key_id: str = "key-test123",
) -> PackerKeyPair:
    """Helper to create a PackerKeyPair for testing."""
    now = datetime.now(UTC)
    return PackerKeyPair(
        resource_id=key_id,
        resource_type=ResourceType.KEY_PAIR,
        creation_time=now,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        key_name=key_name,
        key_fingerprint="ab:cd:ef:12:34:56",
    )


def create_volume(
    tags: dict = None,
    volume_id: str = "vol-test123",
) -> PackerVolume:
    """Helper to create a PackerVolume for testing."""
    now = datetime.now(UTC)
    return PackerVolume(
        resource_id=volume_id,
        resource_type=ResourceType.VOLUME,
        creation_time=now,
        tags=tags or {},
        region="us-east-1",
        account_id="123456789012",
        size=8,
        state="available",
        attached_instance=None,
        snapshot_id=None,
    )


def create_snapshot(
    tags: dict = None,
    snapshot_id: str = "snap-test123",
) -> PackerSnapshot:
    """Helper to create a PackerSnapshot for testing."""
    now = datetime.now(UTC)
    return PackerSnapshot(
        resource_id=snapshot_id,
        resource_type=ResourceType.SNAPSHOT,
        creation_time=now,
        tags=tags or {},
        region="us-east-1",
        account_id="123456789012",
        volume_id="vol-12345678",
        state="completed",
        progress="100%",
        owner_id="123456789012",
    )


def create_elastic_ip(
    tags: dict = None,
    allocation_id: str = "eipalloc-test123",
) -> PackerElasticIP:
    """Helper to create a PackerElasticIP for testing."""
    now = datetime.now(UTC)
    return PackerElasticIP(
        resource_id=allocation_id,
        resource_type=ResourceType.ELASTIC_IP,
        creation_time=now,
        tags=tags or {},
        region="us-east-1",
        account_id="123456789012",
        public_ip="1.2.3.4",
        allocation_id=allocation_id,
        association_id=None,
        instance_id=None,
    )


# Strategy for generating packer-style key names
packer_key_suffix = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_"),
    min_size=1,
    max_size=20,
)


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_key_suffix)
def test_packer_pattern_matches_instances_with_key_name(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Pattern Matching Consistency

    For any key name matching pattern "packer_*", the identity filter should
    consistently identify instances launched with that key pair.

    Validates: Requirements 1.2, 1.3
    """
    key_name = f"packer_{suffix}"
    instance = create_instance(key_name=key_name)

    identity_filter = IdentityFilter()
    result = identity_filter.filter_instances([instance])

    assert len(result) == 1, f"Instance with key_name '{key_name}' should match packer_* pattern"
    assert result[0].resource_id == instance.resource_id


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_key_suffix)
def test_packer_pattern_matches_security_groups(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Pattern Matching Consistency

    For any security group name matching pattern "packer_*", the identity filter
    should consistently identify it for cleanup.

    Validates: Requirements 2.4
    """
    group_name = f"packer_{suffix}"
    sg = create_security_group(group_name=group_name)

    identity_filter = IdentityFilter()
    result = identity_filter.filter_security_groups([sg])

    assert len(result) == 1, f"Security group '{group_name}' should match packer_* pattern"
    assert result[0].resource_id == sg.resource_id


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_key_suffix)
def test_packer_pattern_matches_key_pairs(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Pattern Matching Consistency

    For any key pair name matching pattern "packer_*", the identity filter
    should consistently identify it for cleanup.

    Validates: Requirements 2.5
    """
    key_name = f"packer_{suffix}"
    kp = create_key_pair(key_name=key_name)

    identity_filter = IdentityFilter()
    result = identity_filter.filter_key_pairs([kp])

    assert len(result) == 1, f"Key pair '{key_name}' should match packer_* pattern"
    assert result[0].resource_id == kp.resource_id


# Strategy for non-matching names (not starting with packer_)
non_matching_key_name = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_-"),
    min_size=1,
    max_size=30,
).filter(lambda x: not x.lower().startswith("packer_"))


@settings(max_examples=100, deadline=5000)
@given(key_name=non_matching_key_name)
def test_non_matching_key_names_excluded(key_name: str):
    """
    Feature: packer-resource-reaper, Property 2: Pattern Matching Consistency

    For any instance without a key name matching packer_* pattern, the identity
    filter should NOT identify it for cleanup.

    Validates: Requirements 1.2, 1.3
    """
    instance = create_instance(key_name=key_name)

    identity_filter = IdentityFilter()
    result = identity_filter.filter_instances([instance])

    assert len(result) == 0, (
        f"Instance with non-matching key_name '{key_name}' should not be filtered"
    )


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_key_suffix)
def test_instances_without_key_name_excluded(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Pattern Matching Consistency

    For any instance without a key name, the identity filter should NOT
    identify it for cleanup.

    Validates: Requirements 1.2, 1.3
    """
    instance = create_instance(key_name=None)

    identity_filter = IdentityFilter()
    result = identity_filter.filter_instances([instance])

    assert len(result) == 0, "Instance without key_name should not be filtered"


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_key_suffix)
def test_filter_preserves_all_matching_instances(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Pattern Matching Consistency

    For any set of instances, the filter should preserve all instances
    that match the packer_* pattern and exclude all others.

    Validates: Requirements 1.2, 1.3
    """
    # Create matching and non-matching instances
    matching_instance = create_instance(key_name=f"packer_{suffix}", instance_id="i-matching")
    non_matching_instance = create_instance(
        key_name=f"production_{suffix}", instance_id="i-nonmatching"
    )
    no_key_instance = create_instance(key_name=None, instance_id="i-nokey")

    instances = [matching_instance, non_matching_instance, no_key_instance]

    identity_filter = IdentityFilter()
    result = identity_filter.filter_instances(instances)

    assert len(result) == 1, "Only matching instance should be filtered"
    assert result[0].resource_id == "i-matching"


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_key_suffix)
def test_custom_key_pattern(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Pattern Matching Consistency

    For any custom key pattern prefix, the identity filter should correctly
    identify resources matching that pattern.

    Validates: Requirements 1.2
    """
    custom_prefix = f"custom_{suffix}_"
    key_name = f"custom_{suffix}_test"

    instance = create_instance(key_name=key_name)

    # Use prefix (without wildcard) for pattern matching
    identity_filter = IdentityFilter(key_pattern=custom_prefix)
    result = identity_filter.filter_instances([instance])

    assert len(result) == 1, (
        f"Instance with key_name '{key_name}' should match pattern '{custom_prefix}'"
    )


def test_default_pattern_is_packer_prefix():
    """
    Feature: packer-resource-reaper, Property 2: Pattern Matching Consistency

    The default key pattern should be 'packer_' (prefix matching).

    Validates: Requirements 1.2
    """
    identity_filter = IdentityFilter()

    assert identity_filter.key_pattern == "packer_"


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_key_suffix)
def test_filter_is_deterministic(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Pattern Matching Consistency

    For any set of instances, filtering should produce the same result
    when applied multiple times.

    Validates: Requirements 1.2, 1.3
    """
    key_name = f"packer_{suffix}"
    instance = create_instance(key_name=key_name)

    identity_filter = IdentityFilter()

    result1 = identity_filter.filter_instances([instance])
    result2 = identity_filter.filter_instances([instance])
    result3 = identity_filter.filter_instances([instance])

    assert len(result1) == len(result2) == len(result3) == 1
    assert result1[0].resource_id == result2[0].resource_id == result3[0].resource_id


# =============================================================================
# CRITICAL SAFETY TESTS: Security Group Filtering
# =============================================================================
# These tests ensure that production security groups are NEVER returned by the
# filter. This is a critical safety requirement to prevent accidental deletion
# of non-Packer resources.


def test_security_group_filter_excludes_production_groups():
    """
    CRITICAL SAFETY TEST: Production security groups must be excluded.

    This test verifies that security groups with common production naming
    patterns are NOT returned by the filter, preventing accidental deletion.
    """
    production_groups = [
        create_security_group(group_name="production-web-sg", group_id="sg-prod1"),
        create_security_group(group_name="prod-database", group_id="sg-prod2"),
        create_security_group(group_name="api-gateway-sg", group_id="sg-prod3"),
        create_security_group(group_name="default", group_id="sg-default"),
        create_security_group(group_name="launch-wizard-1", group_id="sg-wizard"),
    ]

    identity_filter = IdentityFilter()
    result = identity_filter.filter_security_groups(production_groups)

    assert len(result) == 0, (
        "CRITICAL SAFETY FAILURE: Production security groups were returned by filter! "
        f"Returned: {[sg.group_name for sg in result]}"
    )


def test_security_group_filter_only_returns_packer_groups():
    """
    CRITICAL SAFETY TEST: Only packer_* security groups should be returned.

    When given a mix of Packer and non-Packer security groups, the filter
    must return ONLY the Packer groups.
    """
    mixed_groups = [
        create_security_group(group_name="packer_abc123", group_id="sg-packer1"),
        create_security_group(group_name="production-web", group_id="sg-prod1"),
        create_security_group(group_name="packer_def456", group_id="sg-packer2"),
        create_security_group(group_name="database-sg", group_id="sg-db"),
        create_security_group(group_name="default", group_id="sg-default"),
    ]

    identity_filter = IdentityFilter()
    result = identity_filter.filter_security_groups(mixed_groups)

    assert len(result) == 2, f"Expected 2 packer groups, got {len(result)}"
    result_ids = {sg.resource_id for sg in result}
    assert result_ids == {
        "sg-packer1",
        "sg-packer2",
    }, f"CRITICAL SAFETY FAILURE: Wrong security groups returned: {result_ids}"


@settings(max_examples=100, deadline=5000)
@given(group_name=non_matching_key_name)
def test_non_matching_security_groups_excluded(group_name: str):
    """
    CRITICAL SAFETY TEST: Non-matching security group names must be excluded.

    For any security group without a name matching packer_* pattern, the
    identity filter must NOT return it for cleanup.

    Validates: Requirement 2.4 safety constraint
    """
    sg = create_security_group(group_name=group_name)

    identity_filter = IdentityFilter()
    result = identity_filter.filter_security_groups([sg])

    assert len(result) == 0, (
        f"CRITICAL SAFETY FAILURE: Non-matching security group '{group_name}' "
        "was returned by filter!"
    )


def test_security_group_filter_handles_empty_group_name():
    """
    CRITICAL SAFETY TEST: Security groups with empty/None names must be excluded.

    Edge case: If a security group somehow has no group_name attribute or
    an empty string, it must NOT be returned.
    """
    # Create SG with empty group name
    sg_empty = create_security_group(group_name="", group_id="sg-empty")

    identity_filter = IdentityFilter()
    result = identity_filter.filter_security_groups([sg_empty])

    assert len(result) == 0, "CRITICAL SAFETY FAILURE: Security group with empty name was returned!"


def test_security_group_filter_handles_missing_group_name_attribute():
    """
    CRITICAL SAFETY TEST: Security groups missing group_name attribute must be excluded.

    Edge case: If getattr fails to find group_name, the filter must safely
    exclude the resource rather than crash or include it.
    """

    from reaper.models import ResourceType

    # Create a minimal resource without group_name attribute
    class FakeSecurityGroup:
        def __init__(self):
            self.resource_id = "sg-fake"
            self.resource_type = ResourceType.SECURITY_GROUP

    fake_sg = FakeSecurityGroup()

    identity_filter = IdentityFilter()
    # This should not crash and should return empty list
    result = identity_filter.filter_security_groups([fake_sg])

    assert len(result) == 0, (
        "CRITICAL SAFETY FAILURE: Security group without group_name attribute was returned!"
    )


def test_security_group_filter_case_sensitive():
    """
    CRITICAL SAFETY TEST: Pattern matching must be case-sensitive.

    "Packer_" or "PACKER_" should NOT match the "packer_" pattern.
    This prevents false positives from similarly-named resources.
    """
    case_variant_groups = [
        create_security_group(group_name="Packer_abc123", group_id="sg-upper1"),
        create_security_group(group_name="PACKER_def456", group_id="sg-upper2"),
        create_security_group(group_name="PaCkEr_ghi789", group_id="sg-mixed"),
    ]

    identity_filter = IdentityFilter()
    result = identity_filter.filter_security_groups(case_variant_groups)

    assert len(result) == 0, (
        f"CRITICAL SAFETY FAILURE: Case-variant security groups were matched! "
        f"Returned: {[sg.group_name for sg in result]}"
    )


def test_security_group_filter_does_not_pass_through_all():
    """
    CRITICAL SAFETY TEST: Filter must NOT be a pass-through.

    This test explicitly verifies that the filter does NOT simply return
    all input security groups (which would be a critical safety bug).
    """
    # Create 100 non-packer security groups
    non_packer_groups = [
        create_security_group(group_name=f"prod-sg-{i}", group_id=f"sg-{i}") for i in range(100)
    ]

    identity_filter = IdentityFilter()
    result = identity_filter.filter_security_groups(non_packer_groups)

    assert len(result) == 0, (
        f"CRITICAL SAFETY FAILURE: Filter returned {len(result)} of {len(non_packer_groups)} "
        "non-packer security groups! This indicates a pass-through bug."
    )
    assert len(result) != len(non_packer_groups), (
        "CRITICAL SAFETY FAILURE: Filter appears to be a pass-through!"
    )


def test_mixed_security_groups_filter_detailed():
    """
    CRITICAL SAFETY TEST: Detailed verification of mixed security group filtering.

    This test creates a realistic mix of security groups that might exist in
    a production AWS account and verifies that ONLY packer_* groups are returned.
    Each group is explicitly checked.
    """
    # Simulate a realistic AWS account with various security groups
    all_groups = [
        # Packer groups - SHOULD be returned
        create_security_group(group_name="packer_abc123", group_id="sg-packer1"),
        create_security_group(group_name="packer_build_temp", group_id="sg-packer2"),
        create_security_group(group_name="packer_", group_id="sg-packer3"),  # Edge: just prefix
        # Production groups - MUST NOT be returned
        create_security_group(group_name="production-web-tier", group_id="sg-prod1"),
        create_security_group(group_name="production-api", group_id="sg-prod2"),
        create_security_group(group_name="prod-database-primary", group_id="sg-prod3"),
        # Default/AWS groups - MUST NOT be returned
        create_security_group(group_name="default", group_id="sg-default"),
        create_security_group(group_name="launch-wizard-1", group_id="sg-wizard1"),
        create_security_group(group_name="launch-wizard-2", group_id="sg-wizard2"),
        # Infrastructure groups - MUST NOT be returned
        create_security_group(group_name="bastion-host-sg", group_id="sg-bastion"),
        create_security_group(group_name="vpn-endpoint", group_id="sg-vpn"),
        create_security_group(group_name="load-balancer-sg", group_id="sg-alb"),
        # Tricky names that look similar but aren't packer_ - MUST NOT be returned
        create_security_group(group_name="packer", group_id="sg-tricky1"),  # No underscore
        create_security_group(group_name="packers_team", group_id="sg-tricky2"),  # Wrong prefix
        create_security_group(group_name="my-packer_sg", group_id="sg-tricky3"),  # Prefix in middle
        create_security_group(group_name="Packer_uppercase", group_id="sg-tricky4"),  # Wrong case
    ]

    identity_filter = IdentityFilter()
    result = identity_filter.filter_security_groups(all_groups)

    # Verify count
    assert len(result) == 3, (
        f"Expected exactly 3 packer_* groups, got {len(result)}. "
        f"Returned: {[sg.group_name for sg in result]}"
    )

    # Verify correct groups returned
    result_ids = {sg.resource_id for sg in result}
    expected_ids = {"sg-packer1", "sg-packer2", "sg-packer3"}
    assert result_ids == expected_ids, (
        f"Wrong security groups returned!\nExpected: {expected_ids}\nGot: {result_ids}"
    )

    # Verify NO production groups leaked through
    {sg.group_name for sg in result}
    for sg in all_groups:
        if not sg.group_name.startswith("packer_"):
            assert sg.resource_id not in result_ids, (
                f"CRITICAL SAFETY FAILURE: Non-packer group '{sg.group_name}' "
                f"({sg.resource_id}) was returned!"
            )

    # Verify all returned groups match pattern
    for sg in result:
        assert sg.group_name.startswith("packer_"), (
            f"CRITICAL SAFETY FAILURE: Returned group '{sg.group_name}' "
            "does not match packer_* pattern!"
        )
