"""Property-based tests for single account/region boundary enforcement.

Feature: packer-resource-reaper, Property 9: Single Account/Region Boundary
Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6

This module tests that the system operates strictly within a single AWS account
and region, using default Lambda execution environment credentials, and never
attempts cross-account or cross-region operations.

Key Requirements:
- 8.1: SHALL NOT support cross-account role assumption or operations
- 8.2: SHALL NOT scan or modify resources in other AWS accounts
- 8.3: SHALL NOT support cross-region operations or resource discovery
- 8.4: SHALL NOT scan or modify resources in other AWS regions
- 8.5: SHALL use default AWS credentials from Lambda execution environment
- 8.6: SHALL be scoped to exactly one AWS account and one AWS region
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from reaper.handler import (
    enforce_scope,
)
from reaper.models import (
    PackerInstance,
    PackerSecurityGroup,
    PackerVolume,
    ResourceCollection,
    ResourceType,
)
from reaper.utils.security import ScopeEnforcer

# =============================================================================
# Strategies for generating test data
# =============================================================================

# Valid AWS resource ID patterns
valid_instance_id_strategy = st.from_regex(r"i-[a-f0-9]{8,17}", fullmatch=True)
valid_volume_id_strategy = st.from_regex(r"vol-[a-f0-9]{8,17}", fullmatch=True)
valid_sg_id_strategy = st.from_regex(r"sg-[a-f0-9]{8,17}", fullmatch=True)
valid_vpc_id_strategy = st.from_regex(r"vpc-[a-f0-9]{8,17}", fullmatch=True)
valid_account_id_strategy = st.from_regex(r"[0-9]{12}", fullmatch=True)
valid_region_strategy = st.sampled_from(
    [
        "us-east-1",
        "us-west-2",
        "eu-west-1",
        "ap-southeast-1",
        "sa-east-1",
        "ap-northeast-1",
        "eu-central-1",
        "us-east-2",
        "ca-central-1",
    ]
)

# Strategy for Packer key names
packer_key_name_strategy = st.from_regex(r"packer_[a-z0-9]{8,16}", fullmatch=True)

# Strategy for non-Packer key names
non_packer_key_name_strategy = st.from_regex(
    r"[a-z]{1,10}_key_[a-z0-9]{4,8}", fullmatch=True
).filter(lambda x: not x.startswith("packer_"))

# Strategy for valid tags
valid_tags_strategy = st.dictionaries(
    keys=st.from_regex(r"[a-zA-Z][a-zA-Z0-9_-]{0,30}", fullmatch=True),
    values=st.from_regex(r"[a-zA-Z0-9_-]{0,50}", fullmatch=True),
    min_size=0,
    max_size=3,
)


def create_test_instance(
    instance_id: str,
    region: str,
    account_id: str,
    age_hours: float = 3.0,
    key_name: Optional[str] = "packer_test_key",
    vpc_id: str = "vpc-12345678",
    tags: Optional[Dict[str, str]] = None,
) -> PackerInstance:
    """Create a test PackerInstance with specified parameters."""
    launch_time = datetime.now(timezone.utc) - timedelta(hours=age_hours)
    default_tags = {"Name": "Packer Builder", "packer": "true"}
    if tags:
        default_tags.update(tags)

    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=launch_time,
        tags=default_tags,
        region=region,
        account_id=account_id,
        instance_type="t3.micro",
        state="running",
        vpc_id=vpc_id,
        security_groups=["sg-12345678"],
        key_name=key_name,
        launch_time=launch_time,
    )


def create_test_volume(
    volume_id: str,
    region: str,
    account_id: str,
    age_hours: float = 3.0,
    tags: Optional[Dict[str, str]] = None,
) -> PackerVolume:
    """Create a test PackerVolume with specified parameters."""
    creation_time = datetime.now(timezone.utc) - timedelta(hours=age_hours)
    default_tags = {"Name": "Packer Volume", "packer": "true"}
    if tags:
        default_tags.update(tags)

    return PackerVolume(
        resource_id=volume_id,
        resource_type=ResourceType.VOLUME,
        creation_time=creation_time,
        tags=default_tags,
        region=region,
        account_id=account_id,
        size=8,
        state="available",
        attached_instance=None,
        snapshot_id=None,
    )


def create_test_security_group(
    sg_id: str,
    region: str,
    account_id: str,
    group_name: str = "packer_sg_test",
    vpc_id: str = "vpc-12345678",
    tags: Optional[Dict[str, str]] = None,
) -> PackerSecurityGroup:
    """Create a test PackerSecurityGroup with specified parameters."""
    return PackerSecurityGroup(
        resource_id=sg_id,
        resource_type=ResourceType.SECURITY_GROUP,
        creation_time=datetime.now(timezone.utc),
        tags=tags or {},
        region=region,
        account_id=account_id,
        group_name=group_name,
        vpc_id=vpc_id,
        description="Packer security group",
    )


# =============================================================================
# Property 9: Single Account/Region Boundary
# Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
# =============================================================================


@settings(max_examples=100, deadline=5000)
@given(
    current_account=valid_account_id_strategy,
    current_region=valid_region_strategy,
    other_accounts=st.lists(valid_account_id_strategy, min_size=1, max_size=3),
    other_regions=st.lists(valid_region_strategy, min_size=1, max_size=3),
    instance_id=valid_instance_id_strategy,
)
def test_scope_enforcer_rejects_cross_account_resources(
    current_account: str,
    current_region: str,
    other_accounts: List[str],
    other_regions: List[str],
    instance_id: str,
):
    """
    Feature: packer-resource-reaper, Property 9: Single Account/Region Boundary

    For any system execution scoped to a single account/region, resources from
    other accounts should NEVER be in scope, regardless of other attributes.

    Validates: Requirements 8.1, 8.2, 8.6
    """
    # Ensure other accounts are actually different
    other_accounts = [acc for acc in other_accounts if acc != current_account]
    assume(len(other_accounts) > 0)

    # Create scope enforcer for single account/region
    enforcer = ScopeEnforcer(
        allowed_account_ids={current_account},
        allowed_regions={current_region},
    )

    # Resources from current account should be in scope
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=current_region,
        account_id=current_account,
    )
    assert in_scope, "Resource from current account should be in scope"

    # Resources from other accounts should NEVER be in scope
    for other_account in other_accounts:
        in_scope, reasons = enforcer.is_resource_in_scope(
            region=current_region,  # Same region, different account
            account_id=other_account,
        )
        assert (
            not in_scope
        ), f"Resource from account {other_account} should NOT be in scope"
        assert len(reasons) > 0, "Exclusion reason should be provided"


@settings(max_examples=100, deadline=5000)
@given(
    current_account=valid_account_id_strategy,
    current_region=valid_region_strategy,
    other_regions=st.lists(valid_region_strategy, min_size=1, max_size=5),
    instance_id=valid_instance_id_strategy,
)
def test_scope_enforcer_rejects_cross_region_resources(
    current_account: str,
    current_region: str,
    other_regions: List[str],
    instance_id: str,
):
    """
    Feature: packer-resource-reaper, Property 9: Single Account/Region Boundary

    For any system execution scoped to a single account/region, resources from
    other regions should NEVER be in scope, regardless of other attributes.

    Validates: Requirements 8.3, 8.4, 8.6
    """
    # Ensure other regions are actually different
    other_regions = [reg for reg in other_regions if reg != current_region]
    assume(len(other_regions) > 0)

    # Create scope enforcer for single account/region
    enforcer = ScopeEnforcer(
        allowed_account_ids={current_account},
        allowed_regions={current_region},
    )

    # Resources from current region should be in scope
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=current_region,
        account_id=current_account,
    )
    assert in_scope, "Resource from current region should be in scope"

    # Resources from other regions should NEVER be in scope
    for other_region in other_regions:
        in_scope, reasons = enforcer.is_resource_in_scope(
            region=other_region,  # Different region, same account
            account_id=current_account,
        )
        assert (
            not in_scope
        ), f"Resource from region {other_region} should NOT be in scope"
        assert len(reasons) > 0, "Exclusion reason should be provided"


@settings(max_examples=100, deadline=5000)
@given(
    current_account=valid_account_id_strategy,
    current_region=valid_region_strategy,
    num_same_account_instances=st.integers(min_value=1, max_value=5),
    num_other_account_instances=st.integers(min_value=1, max_value=5),
)
def test_enforce_scope_filters_out_cross_account_instances(
    current_account: str,
    current_region: str,
    num_same_account_instances: int,
    num_other_account_instances: int,
):
    """
    Feature: packer-resource-reaper, Property 9: Single Account/Region Boundary

    For any collection of instances from multiple accounts, the enforce_scope
    function should filter out ALL instances from other accounts.

    Validates: Requirements 8.1, 8.2, 8.6
    """
    # Create instances from current account
    same_account_instances = [
        create_test_instance(
            instance_id=f"i-same{i:08x}",
            region=current_region,
            account_id=current_account,
        )
        for i in range(num_same_account_instances)
    ]

    # Create instances from other accounts
    other_account_instances = [
        create_test_instance(
            instance_id=f"i-other{i:08x}",
            region=current_region,
            account_id=f"{999999999000 + i:012d}",  # Different accounts
        )
        for i in range(num_other_account_instances)
    ]

    # Combine all instances
    all_instances = same_account_instances + other_account_instances
    resources = ResourceCollection(instances=all_instances)

    # Create scope enforcer for single account
    scope_enforcer = ScopeEnforcer(
        allowed_account_ids={current_account},
        allowed_regions={current_region},
    )

    # Apply scope enforcement
    filtered = enforce_scope(resources, scope_enforcer)

    # Only instances from current account should remain
    assert len(filtered.instances) == num_same_account_instances

    # Verify all remaining instances are from current account
    for instance in filtered.instances:
        assert (
            instance.account_id == current_account
        ), f"Instance {instance.resource_id} from account {instance.account_id} should not be in filtered results"


@settings(max_examples=100, deadline=5000)
@given(
    current_account=valid_account_id_strategy,
    current_region=valid_region_strategy,
    num_same_region_instances=st.integers(min_value=1, max_value=5),
    num_other_region_instances=st.integers(min_value=1, max_value=5),
    other_regions=st.lists(valid_region_strategy, min_size=1, max_size=3),
)
def test_enforce_scope_filters_out_cross_region_instances(
    current_account: str,
    current_region: str,
    num_same_region_instances: int,
    num_other_region_instances: int,
    other_regions: List[str],
):
    """
    Feature: packer-resource-reaper, Property 9: Single Account/Region Boundary

    For any collection of instances from multiple regions, the enforce_scope
    function should filter out ALL instances from other regions.

    Validates: Requirements 8.3, 8.4, 8.6
    """
    # Ensure other regions are different
    other_regions = [r for r in other_regions if r != current_region]
    assume(len(other_regions) > 0)

    # Create instances from current region
    same_region_instances = [
        create_test_instance(
            instance_id=f"i-samereg{i:06x}",
            region=current_region,
            account_id=current_account,
        )
        for i in range(num_same_region_instances)
    ]

    # Create instances from other regions
    other_region_instances = [
        create_test_instance(
            instance_id=f"i-otherreg{i:06x}",
            region=other_regions[i % len(other_regions)],
            account_id=current_account,
        )
        for i in range(num_other_region_instances)
    ]

    # Combine all instances
    all_instances = same_region_instances + other_region_instances
    resources = ResourceCollection(instances=all_instances)

    # Create scope enforcer for single region
    scope_enforcer = ScopeEnforcer(
        allowed_account_ids={current_account},
        allowed_regions={current_region},
    )

    # Apply scope enforcement
    filtered = enforce_scope(resources, scope_enforcer)

    # Only instances from current region should remain
    assert len(filtered.instances) == num_same_region_instances

    # Verify all remaining instances are from current region
    for instance in filtered.instances:
        assert (
            instance.region == current_region
        ), f"Instance {instance.resource_id} from region {instance.region} should not be in filtered results"


@settings(max_examples=100, deadline=5000)
@given(
    current_account=valid_account_id_strategy,
    current_region=valid_region_strategy,
    num_volumes=st.integers(min_value=1, max_value=3),
    num_sgs=st.integers(min_value=1, max_value=3),
)
def test_enforce_scope_filters_all_resource_types_by_account(
    current_account: str,
    current_region: str,
    num_volumes: int,
    num_sgs: int,
):
    """
    Feature: packer-resource-reaper, Property 9: Single Account/Region Boundary

    For any collection of different resource types, the enforce_scope function
    should filter out resources from other accounts for ALL resource types.

    Validates: Requirements 8.1, 8.2, 8.6
    """
    other_account = f"{int(current_account) + 1:012d}"
    assume(other_account != current_account)

    # Create resources from current account
    same_account_volumes = [
        create_test_volume(
            volume_id=f"vol-same{i:08x}",
            region=current_region,
            account_id=current_account,
        )
        for i in range(num_volumes)
    ]

    same_account_sgs = [
        create_test_security_group(
            sg_id=f"sg-same{i:08x}",
            region=current_region,
            account_id=current_account,
        )
        for i in range(num_sgs)
    ]

    # Create resources from other account
    other_account_volumes = [
        create_test_volume(
            volume_id=f"vol-other{i:08x}",
            region=current_region,
            account_id=other_account,
        )
        for i in range(num_volumes)
    ]

    other_account_sgs = [
        create_test_security_group(
            sg_id=f"sg-other{i:08x}",
            region=current_region,
            account_id=other_account,
        )
        for i in range(num_sgs)
    ]

    # Combine all resources
    resources = ResourceCollection(
        volumes=same_account_volumes + other_account_volumes,
        security_groups=same_account_sgs + other_account_sgs,
    )

    # Create scope enforcer for single account
    scope_enforcer = ScopeEnforcer(
        allowed_account_ids={current_account},
        allowed_regions={current_region},
    )

    # Apply scope enforcement
    filtered = enforce_scope(resources, scope_enforcer)

    # Only resources from current account should remain
    assert len(filtered.volumes) == num_volumes
    assert len(filtered.security_groups) == num_sgs

    # Verify all remaining resources are from current account
    for volume in filtered.volumes:
        assert volume.account_id == current_account
    for sg in filtered.security_groups:
        assert sg.account_id == current_account


@settings(max_examples=100, deadline=5000)
@given(
    current_account=valid_account_id_strategy,
    current_region=valid_region_strategy,
    other_account=valid_account_id_strategy,
    other_region=valid_region_strategy,
)
def test_scope_enforcer_requires_both_account_and_region_match(
    current_account: str,
    current_region: str,
    other_account: str,
    other_region: str,
):
    """
    Feature: packer-resource-reaper, Property 9: Single Account/Region Boundary

    For any resource to be in scope, it must match BOTH the allowed account
    AND the allowed region. Matching only one is not sufficient.

    Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.6
    """
    assume(current_account != other_account)
    assume(current_region != other_region)

    # Create scope enforcer for single account/region
    enforcer = ScopeEnforcer(
        allowed_account_ids={current_account},
        allowed_regions={current_region},
    )

    # Case 1: Both match - should be in scope
    in_scope, _ = enforcer.is_resource_in_scope(
        region=current_region,
        account_id=current_account,
    )
    assert in_scope, "Resource matching both account and region should be in scope"

    # Case 2: Only account matches - should NOT be in scope
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=other_region,  # Wrong region
        account_id=current_account,  # Correct account
    )
    assert not in_scope, "Resource with wrong region should NOT be in scope"

    # Case 3: Only region matches - should NOT be in scope
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=current_region,  # Correct region
        account_id=other_account,  # Wrong account
    )
    assert not in_scope, "Resource with wrong account should NOT be in scope"

    # Case 4: Neither matches - should NOT be in scope
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=other_region,  # Wrong region
        account_id=other_account,  # Wrong account
    )
    assert not in_scope, "Resource with wrong account and region should NOT be in scope"


@settings(max_examples=100, deadline=5000)
@given(
    current_account=valid_account_id_strategy,
    current_region=valid_region_strategy,
    num_instances=st.integers(min_value=1, max_value=10),
)
def test_all_filtered_resources_have_same_account_and_region(
    current_account: str,
    current_region: str,
    num_instances: int,
):
    """
    Feature: packer-resource-reaper, Property 9: Single Account/Region Boundary

    For any set of resources after scope enforcement, ALL resources should
    have the same account ID and region as the configured scope.

    Validates: Requirements 8.5, 8.6
    """
    # Create instances with mixed accounts and regions
    instances = []
    for i in range(num_instances):
        # Randomly assign account and region
        if i % 3 == 0:
            account = current_account
            region = current_region
        elif i % 3 == 1:
            account = f"{int(current_account) + 1:012d}"
            region = current_region
        else:
            account = current_account
            region = "eu-west-1" if current_region != "eu-west-1" else "us-west-2"

        instances.append(
            create_test_instance(
                instance_id=f"i-mixed{i:08x}",
                region=region,
                account_id=account,
            )
        )

    resources = ResourceCollection(instances=instances)

    # Create scope enforcer
    scope_enforcer = ScopeEnforcer(
        allowed_account_ids={current_account},
        allowed_regions={current_region},
    )

    # Apply scope enforcement
    filtered = enforce_scope(resources, scope_enforcer)

    # ALL remaining resources must have the exact same account and region
    for instance in filtered.instances:
        assert (
            instance.account_id == current_account
        ), f"Instance {instance.resource_id} has wrong account {instance.account_id}"
        assert (
            instance.region == current_region
        ), f"Instance {instance.resource_id} has wrong region {instance.region}"


@settings(max_examples=100, deadline=5000)
@given(
    current_account=valid_account_id_strategy,
    current_region=valid_region_strategy,
)
def test_empty_resource_collection_remains_empty_after_scope_enforcement(
    current_account: str,
    current_region: str,
):
    """
    Feature: packer-resource-reaper, Property 9: Single Account/Region Boundary

    For an empty resource collection, scope enforcement should return an
    empty collection without errors.

    Validates: Requirements 8.5, 8.6
    """
    resources = ResourceCollection()

    scope_enforcer = ScopeEnforcer(
        allowed_account_ids={current_account},
        allowed_regions={current_region},
    )

    filtered = enforce_scope(resources, scope_enforcer)

    assert (
        filtered.is_empty()
    ), "Empty collection should remain empty after scope enforcement"
    assert filtered.total_count() == 0


@settings(max_examples=100, deadline=5000)
@given(
    current_account=valid_account_id_strategy,
    current_region=valid_region_strategy,
    num_instances=st.integers(min_value=1, max_value=5),
)
def test_scope_enforcement_is_idempotent(
    current_account: str,
    current_region: str,
    num_instances: int,
):
    """
    Feature: packer-resource-reaper, Property 9: Single Account/Region Boundary

    Applying scope enforcement multiple times should produce the same result
    as applying it once (idempotent operation).

    Validates: Requirements 8.5, 8.6
    """
    # Create instances from current account/region
    instances = [
        create_test_instance(
            instance_id=f"i-idem{i:08x}",
            region=current_region,
            account_id=current_account,
        )
        for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    scope_enforcer = ScopeEnforcer(
        allowed_account_ids={current_account},
        allowed_regions={current_region},
    )

    # Apply scope enforcement once
    filtered_once = enforce_scope(resources, scope_enforcer)

    # Apply scope enforcement again
    filtered_twice = enforce_scope(filtered_once, scope_enforcer)

    # Results should be identical
    assert len(filtered_once.instances) == len(filtered_twice.instances)

    once_ids = {i.resource_id for i in filtered_once.instances}
    twice_ids = {i.resource_id for i in filtered_twice.instances}
    assert once_ids == twice_ids, "Scope enforcement should be idempotent"
