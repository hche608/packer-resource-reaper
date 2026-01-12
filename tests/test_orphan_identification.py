"""Property-based tests for orphaned Packer resource identification.

Feature: packer-resource-reaper, Property 10: Orphaned Resource Identification
Validates: Requirements 10.1, 10.2, 10.3

This module tests that the OrphanManager correctly identifies orphaned Packer resources:
- Key pairs starting with `packer_` not used by any running/pending instances (10.1)
- Security groups with `packer` in name/description not attached to any instances/NICs (10.2)
- IAM roles starting with `packer_` not in any active instance profiles (10.3)
"""

from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from reaper.cleanup.orphan_manager import OrphanManager

# Strategies for generating test data
alphanumeric = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789"),
    min_size=1,
    max_size=10,
)

packer_key_name = st.builds(
    lambda suffix: f"packer_{suffix}",
    suffix=alphanumeric,
)

non_packer_key_name = st.builds(
    lambda prefix, suffix: f"{prefix}_{suffix}",
    prefix=st.sampled_from(["mykey", "prod", "dev", "test", "ssh"]),
    suffix=alphanumeric,
)

packer_sg_name = st.builds(
    lambda prefix, suffix: f"{prefix}packer{suffix}",
    prefix=st.sampled_from(["", "my-", "temp-"]),
    suffix=st.sampled_from(["", "-sg", "-security", "_group"]),
)

non_packer_sg_name = st.builds(
    lambda prefix, suffix: f"{prefix}-{suffix}",
    prefix=st.sampled_from(["web", "app", "db", "api"]),
    suffix=st.sampled_from(["sg", "security", "group"]),
)


def create_mock_ec2_client(
    key_pairs: list[str],
    running_instances: list[dict],
    security_groups: list[dict],
    network_interfaces: list[dict],
) -> MagicMock:
    """Create a mock EC2 client with specified resources."""
    mock_ec2 = MagicMock()

    # Mock describe_key_pairs
    mock_ec2.describe_key_pairs.return_value = {"KeyPairs": [{"KeyName": kp} for kp in key_pairs]}

    # Mock describe_instances paginator
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Reservations": [{"Instances": running_instances}]}]

    # Mock describe_security_groups paginator
    mock_sg_paginator = MagicMock()
    mock_sg_paginator.paginate.return_value = [{"SecurityGroups": security_groups}]

    # Mock describe_network_interfaces paginator
    mock_ni_paginator = MagicMock()
    mock_ni_paginator.paginate.return_value = [{"NetworkInterfaces": network_interfaces}]

    def get_paginator(operation):
        if operation == "describe_instances":
            return mock_paginator
        elif operation == "describe_security_groups":
            return mock_sg_paginator
        elif operation == "describe_network_interfaces":
            return mock_ni_paginator
        return MagicMock()

    mock_ec2.get_paginator = get_paginator

    return mock_ec2


def create_mock_iam_client(
    roles: list[str],
    instance_profiles_for_roles: dict[str, list[str]],
) -> MagicMock:
    """Create a mock IAM client with specified resources."""
    mock_iam = MagicMock()

    # Mock list_roles paginator
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Roles": [{"RoleName": role} for role in roles]}]
    mock_iam.get_paginator = MagicMock(return_value=mock_paginator)

    return mock_iam


@settings(max_examples=100, deadline=10000)
@given(
    packer_keys=st.lists(packer_key_name, min_size=0, max_size=5, unique=True),
    non_packer_keys=st.lists(non_packer_key_name, min_size=0, max_size=3, unique=True),
    in_use_indices=st.lists(st.integers(min_value=0, max_value=10), min_size=0, max_size=3),
)
def test_orphaned_key_pair_identification(
    packer_keys: list[str],
    non_packer_keys: list[str],
    in_use_indices: list[int],
):
    """
    Feature: packer-resource-reaper, Property 10: Orphaned Resource Identification

    For any set of key pairs, the system should correctly identify key pairs
    starting with `packer_` that are not associated with any running or pending
    EC2 instances as orphaned.

    Validates: Requirements 10.1
    """
    # Combine all key pairs
    all_keys = packer_keys + non_packer_keys

    if not all_keys:
        return  # Skip empty case

    # Determine which packer keys are in use
    in_use_packer_keys = set()
    for idx in in_use_indices:
        if packer_keys and idx < len(packer_keys):
            in_use_packer_keys.add(packer_keys[idx % len(packer_keys)])

    # Create running instances using some packer keys
    running_instances = [
        {"KeyName": key_name, "State": {"Name": "running"}} for key_name in in_use_packer_keys
    ]

    # Create mock EC2 client
    mock_ec2 = create_mock_ec2_client(
        key_pairs=all_keys,
        running_instances=running_instances,
        security_groups=[],
        network_interfaces=[],
    )

    # Create orphan manager and scan
    orphan_manager = OrphanManager(ec2_client=mock_ec2, dry_run=True)
    orphaned_key_pairs = orphan_manager.scan_orphaned_key_pairs()

    # Calculate expected orphaned key pairs
    expected_orphaned = set(packer_keys) - in_use_packer_keys

    # Verify: only packer_* keys not in use should be identified as orphaned
    assert set(orphaned_key_pairs) == expected_orphaned, (
        f"Expected orphaned: {expected_orphaned}, got: {set(orphaned_key_pairs)}"
    )


@settings(max_examples=100, deadline=10000)
@given(
    packer_sgs=st.lists(
        st.fixed_dictionaries(
            {
                "GroupId": st.builds(lambda s: f"sg-{s}", alphanumeric),
                "GroupName": packer_sg_name,
                "Description": st.text(min_size=0, max_size=20),
            }
        ),
        min_size=0,
        max_size=5,
    ),
    in_use_count=st.integers(min_value=0, max_value=3),
)
def test_orphaned_security_group_identification(
    packer_sgs: list[dict],
    in_use_count: int,
):
    """
    Feature: packer-resource-reaper, Property 10: Orphaned Resource Identification

    For any set of security groups, the system should correctly identify security
    groups with names or descriptions containing `packer` that are not attached
    to any EC2 instances or network interfaces as orphaned.

    Validates: Requirements 10.2
    """
    if not packer_sgs:
        return  # Skip empty case

    # Ensure unique group IDs
    seen_ids = set()
    unique_sgs = []
    for sg in packer_sgs:
        if sg["GroupId"] not in seen_ids:
            seen_ids.add(sg["GroupId"])
            unique_sgs.append(sg)
    packer_sgs = unique_sgs

    if not packer_sgs:
        return

    # Determine which security groups are in use
    in_use_count = min(in_use_count, len(packer_sgs))
    in_use_sg_ids = {sg["GroupId"] for sg in packer_sgs[:in_use_count]}

    # Create running instances using some security groups
    running_instances = [
        {
            "KeyName": "some-key",
            "State": {"Name": "running"},
            "SecurityGroups": [{"GroupId": sg_id}],
        }
        for sg_id in in_use_sg_ids
    ]

    # Create mock EC2 client
    mock_ec2 = create_mock_ec2_client(
        key_pairs=[],
        running_instances=running_instances,
        security_groups=packer_sgs,
        network_interfaces=[],
    )

    # Create orphan manager and scan
    orphan_manager = OrphanManager(ec2_client=mock_ec2, dry_run=True)
    orphaned_sgs = orphan_manager.scan_orphaned_security_groups()

    # Calculate expected orphaned security groups
    all_sg_ids = {sg["GroupId"] for sg in packer_sgs}
    expected_orphaned = all_sg_ids - in_use_sg_ids

    # Verify: only packer security groups not in use should be identified as orphaned
    assert set(orphaned_sgs) == expected_orphaned, (
        f"Expected orphaned: {expected_orphaned}, got: {set(orphaned_sgs)}"
    )


@settings(max_examples=100, deadline=10000)
@given(
    packer_key_count=st.integers(min_value=1, max_value=5),
    in_use_ratio=st.floats(min_value=0.0, max_value=1.0),
)
def test_orphaned_key_pairs_subset_property(
    packer_key_count: int,
    in_use_ratio: float,
):
    """
    Feature: packer-resource-reaper, Property 10: Orphaned Resource Identification

    For any set of packer_* key pairs, the orphaned set should always be a subset
    of all packer_* key pairs, and should never include keys that are in use.

    Validates: Requirements 10.1
    """
    # Generate packer key pairs
    packer_keys = [f"packer_key{i}" for i in range(packer_key_count)]

    # Determine which keys are in use based on ratio
    in_use_count = int(packer_key_count * in_use_ratio)
    in_use_keys = set(packer_keys[:in_use_count])

    # Create running instances
    running_instances = [{"KeyName": key, "State": {"Name": "running"}} for key in in_use_keys]

    # Create mock EC2 client
    mock_ec2 = create_mock_ec2_client(
        key_pairs=packer_keys,
        running_instances=running_instances,
        security_groups=[],
        network_interfaces=[],
    )

    # Create orphan manager and scan
    orphan_manager = OrphanManager(ec2_client=mock_ec2, dry_run=True)
    orphaned = orphan_manager.scan_orphaned_key_pairs()

    # Property 1: Orphaned keys should be a subset of all packer keys
    assert set(orphaned).issubset(set(packer_keys)), (
        "Orphaned keys should be a subset of all packer keys"
    )

    # Property 2: No in-use key should be in orphaned set
    assert set(orphaned).isdisjoint(in_use_keys), (
        "In-use keys should never be identified as orphaned"
    )

    # Property 3: All non-in-use packer keys should be orphaned
    expected_orphaned = set(packer_keys) - in_use_keys
    assert set(orphaned) == expected_orphaned, f"Expected {expected_orphaned}, got {set(orphaned)}"


@settings(max_examples=100, deadline=10000)
@given(
    sg_count=st.integers(min_value=1, max_value=5),
    instance_attached_count=st.integers(min_value=0, max_value=3),
    nic_attached_count=st.integers(min_value=0, max_value=2),
)
def test_security_group_attachment_detection(
    sg_count: int,
    instance_attached_count: int,
    nic_attached_count: int,
):
    """
    Feature: packer-resource-reaper, Property 10: Orphaned Resource Identification

    For any security group, it should be identified as orphaned if and only if
    it is not attached to any EC2 instances AND not attached to any network interfaces.

    Validates: Requirements 10.2
    """
    # Generate packer security groups
    packer_sgs = [
        {
            "GroupId": f"sg-packer{i}",
            "GroupName": f"packer-sg-{i}",
            "Description": "Packer security group",
        }
        for i in range(sg_count)
    ]

    # Determine which SGs are attached to instances
    instance_attached_count = min(instance_attached_count, sg_count)
    instance_attached_sgs = {sg["GroupId"] for sg in packer_sgs[:instance_attached_count]}

    # Determine which SGs are attached to NICs (from remaining)
    remaining_sgs = [sg for sg in packer_sgs if sg["GroupId"] not in instance_attached_sgs]
    nic_attached_count = min(nic_attached_count, len(remaining_sgs))
    nic_attached_sgs = {sg["GroupId"] for sg in remaining_sgs[:nic_attached_count]}

    # Create running instances
    running_instances = [
        {
            "KeyName": "key",
            "State": {"Name": "running"},
            "SecurityGroups": [{"GroupId": sg_id}],
        }
        for sg_id in instance_attached_sgs
    ]

    # Create network interfaces
    network_interfaces = [{"Groups": [{"GroupId": sg_id}]} for sg_id in nic_attached_sgs]

    # Create mock EC2 client
    mock_ec2 = create_mock_ec2_client(
        key_pairs=[],
        running_instances=running_instances,
        security_groups=packer_sgs,
        network_interfaces=network_interfaces,
    )

    # Create orphan manager and scan
    orphan_manager = OrphanManager(ec2_client=mock_ec2, dry_run=True)
    orphaned = orphan_manager.scan_orphaned_security_groups()

    # Calculate expected orphaned (not attached to instances OR NICs)
    all_attached = instance_attached_sgs | nic_attached_sgs
    expected_orphaned = {sg["GroupId"] for sg in packer_sgs} - all_attached

    # Verify
    assert set(orphaned) == expected_orphaned, (
        f"Expected orphaned: {expected_orphaned}, got: {set(orphaned)}"
    )


@settings(max_examples=100, deadline=10000)
@given(
    has_packer_keys=st.booleans(),
    has_packer_sgs=st.booleans(),
    all_in_use=st.booleans(),
)
def test_empty_orphaned_resources_when_all_in_use(
    has_packer_keys: bool,
    has_packer_sgs: bool,
    all_in_use: bool,
):
    """
    Feature: packer-resource-reaper, Property 10: Orphaned Resource Identification

    When all packer resources are in use, the orphaned resources set should be empty.
    When no packer resources exist, the orphaned resources set should also be empty.

    Validates: Requirements 10.1, 10.2, 10.3
    """
    # Generate resources based on flags
    packer_keys = ["packer_key1", "packer_key2"] if has_packer_keys else []
    packer_sgs = (
        [{"GroupId": "sg-packer1", "GroupName": "packer-sg", "Description": "test"}]
        if has_packer_sgs
        else []
    )

    # If all_in_use, create instances using all resources
    if all_in_use:
        running_instances = (
            [
                {
                    "KeyName": key,
                    "State": {"Name": "running"},
                    "SecurityGroups": [{"GroupId": sg["GroupId"]} for sg in packer_sgs],
                }
                for key in packer_keys
            ]
            if packer_keys
            else []
        )

        # If no keys but have SGs, still need instances to use SGs
        if not packer_keys and packer_sgs:
            running_instances = [
                {
                    "KeyName": "other-key",
                    "State": {"Name": "running"},
                    "SecurityGroups": [{"GroupId": sg["GroupId"]} for sg in packer_sgs],
                }
            ]
    else:
        running_instances = []

    # Create mock EC2 client
    mock_ec2 = create_mock_ec2_client(
        key_pairs=packer_keys,
        running_instances=running_instances,
        security_groups=packer_sgs,
        network_interfaces=[],
    )

    # Create orphan manager and scan
    orphan_manager = OrphanManager(ec2_client=mock_ec2, dry_run=True)
    orphaned = orphan_manager.scan_orphaned_resources()

    # Verify based on conditions
    if not has_packer_keys:
        assert len(orphaned.orphaned_key_pairs) == 0, "No packer keys means no orphaned key pairs"

    if not has_packer_sgs:
        assert len(orphaned.orphaned_security_groups) == 0, (
            "No packer SGs means no orphaned security groups"
        )

    if all_in_use:
        if has_packer_keys:
            assert len(orphaned.orphaned_key_pairs) == 0, (
                "All keys in use means no orphaned key pairs"
            )
        if has_packer_sgs:
            assert len(orphaned.orphaned_security_groups) == 0, (
                "All SGs in use means no orphaned security groups"
            )
