"""Property-based tests for key pair pattern matching consistency.

Feature: packer-resource-reaper, Property 2: Key Pair Pattern Matching Consistency
Validates: Requirements 1.2

This test validates that the pattern matching logic consistently identifies
key pairs that start with the "packer_" prefix.
"""

from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from reaper.filters.identity import IdentityFilter
from reaper.models import PackerInstance, PackerKeyPair, ResourceType


def create_instance(
    key_name: str = None,
    instance_id: str = "i-test123",
) -> PackerInstance:
    """Helper to create a PackerInstance for testing."""
    now = datetime.now(timezone.utc)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=now,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state="running",
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name=key_name,
        launch_time=now,
    )


def create_key_pair(
    key_name: str,
    key_id: str = "key-test123",
) -> PackerKeyPair:
    """Helper to create a PackerKeyPair for testing."""
    now = datetime.now(timezone.utc)
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


# Strategy for valid packer key suffixes (alphanumeric and underscore)
packer_suffix_strategy = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_"),
    min_size=0,
    max_size=30,
)

# Strategy for non-packer key names that don't start with packer_
non_packer_key_strategy = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_-"),
    min_size=1,
    max_size=30,
).filter(lambda x: not x.lower().startswith("packer_"))


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_suffix_strategy)
def test_packer_prefix_always_matches(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Key Pair Pattern Matching Consistency

    For any key name starting with "packer_", the identity filter should
    consistently identify it as a Packer key pair.

    Validates: Requirements 1.2
    """
    key_name = f"packer_{suffix}"

    identity_filter = IdentityFilter()

    # Test with instance
    instance = create_instance(key_name=key_name)
    result = identity_filter.filter_instances([instance])
    assert (
        len(result) == 1
    ), f"Instance with key '{key_name}' should match packer_* pattern"

    # Test with key pair
    key_pair = create_key_pair(key_name=key_name)
    result = identity_filter.filter_key_pairs([key_pair])
    assert len(result) == 1, f"Key pair '{key_name}' should match packer_* pattern"


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_suffix_strategy)
def test_packer_prefix_lowercase_required(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Key Pair Pattern Matching Consistency

    For any key name starting with lowercase "packer_", the identity filter
    should identify it. Packer generates keys with lowercase prefix.

    Validates: Requirements 1.2
    """
    # Packer generates lowercase key names
    key_name = f"packer_{suffix}"

    identity_filter = IdentityFilter()

    key_pair = create_key_pair(key_name=key_name)
    result = identity_filter.filter_key_pairs([key_pair])
    assert len(result) == 1, f"Key pair '{key_name}' should match pattern"


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_suffix_strategy)
def test_uppercase_packer_prefix_not_matched(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Key Pair Pattern Matching Consistency

    For any key name with uppercase PACKER_ prefix, the identity filter
    should NOT match (Packer generates lowercase keys).

    Validates: Requirements 1.2
    """
    # Uppercase variations should NOT match (Packer uses lowercase)
    uppercase_variations = [
        f"PACKER_{suffix}",
        f"Packer_{suffix}",
        f"PaCkEr_{suffix}",
    ]

    identity_filter = IdentityFilter()

    for key_name in uppercase_variations:
        key_pair = create_key_pair(key_name=key_name)
        result = identity_filter.filter_key_pairs([key_pair])
        assert (
            len(result) == 0
        ), f"Key pair '{key_name}' should NOT match (case-sensitive)"


@settings(max_examples=100, deadline=5000)
@given(non_packer_key=non_packer_key_strategy)
def test_non_packer_prefix_never_matches(non_packer_key: str):
    """
    Feature: packer-resource-reaper, Property 2: Key Pair Pattern Matching Consistency

    For any key name NOT starting with "packer_", the identity filter should
    NOT identify it as a Packer key pair (unless it has other Packer indicators).

    Validates: Requirements 1.2
    """
    identity_filter = IdentityFilter()

    # Test with instance (no packer tags or name)
    instance = create_instance(key_name=non_packer_key)
    result = identity_filter.filter_instances([instance])
    assert (
        len(result) == 0
    ), f"Instance with non-packer key '{non_packer_key}' should NOT match"

    # Test with key pair
    key_pair = create_key_pair(key_name=non_packer_key)
    result = identity_filter.filter_key_pairs([key_pair])
    assert (
        len(result) == 0
    ), f"Key pair '{non_packer_key}' should NOT match packer_* pattern"


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_suffix_strategy)
def test_pattern_matching_idempotent(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Key Pair Pattern Matching Consistency

    For any key name, applying the filter multiple times should produce
    the same result (idempotence).

    Validates: Requirements 1.2
    """
    key_name = f"packer_{suffix}"

    identity_filter = IdentityFilter()

    key_pair = create_key_pair(key_name=key_name)

    # Apply filter multiple times
    result1 = identity_filter.filter_key_pairs([key_pair])
    result2 = identity_filter.filter_key_pairs(result1)
    result3 = identity_filter.filter_key_pairs(result2)

    # All results should be the same
    assert len(result1) == len(result2) == len(result3) == 1
    assert result1[0].key_name == result2[0].key_name == result3[0].key_name


@settings(max_examples=100, deadline=5000)
@given(
    packer_suffix=packer_suffix_strategy,
    non_packer_key=non_packer_key_strategy,
)
def test_pattern_matching_preserves_order(packer_suffix: str, non_packer_key: str):
    """
    Feature: packer-resource-reaper, Property 2: Key Pair Pattern Matching Consistency

    For any list of key pairs, the filter should preserve the relative order
    of matching key pairs.

    Validates: Requirements 1.2
    """
    packer_key = f"packer_{packer_suffix}"

    # Create key pairs in specific order
    key_pairs = [
        create_key_pair(key_name=packer_key, key_id="key-001"),
        create_key_pair(key_name=non_packer_key, key_id="key-002"),
        create_key_pair(key_name=f"packer_second_{packer_suffix}", key_id="key-003"),
    ]

    identity_filter = IdentityFilter()
    result = identity_filter.filter_key_pairs(key_pairs)

    # Should have 2 matching key pairs in original order
    assert len(result) == 2
    assert result[0].resource_id == "key-001"
    assert result[1].resource_id == "key-003"


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_suffix_strategy)
def test_exact_packer_underscore_prefix_required(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Key Pair Pattern Matching Consistency

    For any key name, only those starting with exactly "packer_" should match.
    Similar prefixes like "packer-" or "packerkey" should NOT match.

    Validates: Requirements 1.2
    """
    identity_filter = IdentityFilter()

    # These should NOT match (similar but not exact prefix)
    non_matching_keys = [
        f"packerkey{suffix}",  # No underscore
        f"packer-{suffix}",  # Hyphen instead of underscore
        f"my_packer_{suffix}",  # Prefix before packer_
        f"_packer_{suffix}",  # Underscore before packer_
    ]

    for key_name in non_matching_keys:
        key_pair = create_key_pair(key_name=key_name)
        result = identity_filter.filter_key_pairs([key_pair])
        assert (
            len(result) == 0
        ), f"Key pair '{key_name}' should NOT match packer_* pattern"

    # This SHOULD match
    matching_key = f"packer_{suffix}"
    key_pair = create_key_pair(key_name=matching_key)
    result = identity_filter.filter_key_pairs([key_pair])
    assert len(result) == 1, f"Key pair '{matching_key}' SHOULD match packer_* pattern"


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_suffix_strategy)
def test_empty_and_none_key_names_excluded(suffix: str):
    """
    Feature: packer-resource-reaper, Property 2: Key Pair Pattern Matching Consistency

    For any instance with None or empty key_name, the filter should NOT match.

    Validates: Requirements 1.2
    """
    identity_filter = IdentityFilter()

    # Test with None key_name
    instance_none = create_instance(key_name=None)
    result = identity_filter.filter_instances([instance_none])
    assert len(result) == 0, "Instance with None key_name should NOT match"

    # Test with empty string key_name
    instance_empty = create_instance(key_name="")
    result = identity_filter.filter_instances([instance_empty])
    assert len(result) == 0, "Instance with empty key_name should NOT match"
