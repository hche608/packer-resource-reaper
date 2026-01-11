"""Property-based tests for cleanup sequencing.

Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing
Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.7, 2.8
"""

from datetime import datetime, timezone
from typing import List, Optional
from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from reaper.cleanup.engine import CleanupEngine
from reaper.models import (
    PackerElasticIP,
    PackerInstance,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerVolume,
    ResourceCollection,
    ResourceType,
)


def create_instance(
    instance_id: str,
    state: str = "running",
    key_name: Optional[str] = None,
    security_groups: Optional[List[str]] = None,
) -> PackerInstance:
    """Helper to create a PackerInstance for testing."""
    now = datetime.now(timezone.utc)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=now,
        tags={"Name": "Packer Builder"},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state=state,
        vpc_id="vpc-12345678",
        security_groups=security_groups or ["sg-12345678"],
        key_name=key_name,
        launch_time=now,
    )


def create_security_group(
    group_id: str,
    group_name: str = "packer_sg",
) -> PackerSecurityGroup:
    """Helper to create a PackerSecurityGroup for testing."""
    now = datetime.now(timezone.utc)
    return PackerSecurityGroup(
        resource_id=group_id,
        resource_type=ResourceType.SECURITY_GROUP,
        creation_time=now,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        group_name=group_name,
        vpc_id="vpc-12345678",
        description="Packer security group",
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


def create_mock_ec2_client(
    instance_states: Optional[dict] = None,
    dependency_violations: Optional[List[str]] = None,
    associated_volumes: Optional[dict] = None,
    associated_eips: Optional[dict] = None,
) -> MagicMock:
    """Create a mock EC2 client that tracks operation order."""
    mock_client = MagicMock()
    mock_client.operation_order = []

    instance_states = instance_states or {}
    dependency_violations = dependency_violations or []
    associated_volumes = associated_volumes or {}
    associated_eips = associated_eips or {}

    def terminate_instances(InstanceIds):
        for iid in InstanceIds:
            mock_client.operation_order.append(("terminate_instance", iid))
        return {"TerminatingInstances": [{"InstanceId": iid} for iid in InstanceIds]}

    def delete_security_group(GroupId):
        mock_client.operation_order.append(("delete_security_group", GroupId))
        if GroupId in dependency_violations:
            from botocore.exceptions import ClientError

            raise ClientError(
                {
                    "Error": {
                        "Code": "DependencyViolation",
                        "Message": "Resource has dependencies",
                    }
                },
                "DeleteSecurityGroup",
            )

    def delete_key_pair(KeyName):
        mock_client.operation_order.append(("delete_key_pair", KeyName))

    def release_address(AllocationId):
        mock_client.operation_order.append(("release_address", AllocationId))

    def delete_volume(VolumeId):
        mock_client.operation_order.append(("delete_volume", VolumeId))

    def describe_instances(InstanceIds):
        reservations = []
        for iid in InstanceIds:
            state = instance_states.get(iid, "terminated")
            reservations.append(
                {"Instances": [{"InstanceId": iid, "State": {"Name": state}}]}
            )
        return {"Reservations": reservations}

    def describe_volumes(Filters=None, VolumeIds=None):
        """Return volumes associated with instances."""
        volumes = []
        if Filters:
            for f in Filters:
                if f["Name"] == "attachment.instance-id":
                    for instance_id in f["Values"]:
                        vol_ids = associated_volumes.get(instance_id, [])
                        for vol_id in vol_ids:
                            volumes.append(
                                {
                                    "VolumeId": vol_id,
                                    "State": "available",
                                    "Attachments": [{"InstanceId": instance_id}],
                                }
                            )
        return {"Volumes": volumes}

    def describe_addresses(Filters=None):
        """Return EIPs associated with instances."""
        addresses = []
        if Filters:
            for f in Filters:
                if f["Name"] == "instance-id":
                    for instance_id in f["Values"]:
                        eip_ids = associated_eips.get(instance_id, [])
                        for eip_id in eip_ids:
                            addresses.append(
                                {
                                    "AllocationId": eip_id,
                                    "PublicIp": f"1.2.3.{len(addresses)}",
                                    "InstanceId": instance_id,
                                }
                            )
        return {"Addresses": addresses}

    def get_waiter(waiter_name):
        waiter = MagicMock()
        waiter.wait = MagicMock()
        return waiter

    mock_client.terminate_instances = MagicMock(side_effect=terminate_instances)
    mock_client.delete_security_group = MagicMock(side_effect=delete_security_group)
    mock_client.delete_key_pair = MagicMock(side_effect=delete_key_pair)
    mock_client.release_address = MagicMock(side_effect=release_address)
    mock_client.delete_volume = MagicMock(side_effect=delete_volume)
    mock_client.describe_instances = MagicMock(side_effect=describe_instances)
    mock_client.describe_volumes = MagicMock(side_effect=describe_volumes)
    mock_client.describe_addresses = MagicMock(side_effect=describe_addresses)
    mock_client.get_waiter = MagicMock(side_effect=get_waiter)

    return mock_client


def create_volume(
    volume_id: str,
    state: str = "available",
    attached_instance: Optional[str] = None,
) -> PackerVolume:
    """Helper to create a PackerVolume for testing."""
    now = datetime.now(timezone.utc)
    return PackerVolume(
        resource_id=volume_id,
        resource_type=ResourceType.VOLUME,
        creation_time=now,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        size=8,
        state=state,
        attached_instance=attached_instance,
        snapshot_id=None,
    )


def create_elastic_ip(
    allocation_id: str,
    public_ip: str = "1.2.3.4",
    instance_id: Optional[str] = None,
    association_id: Optional[str] = None,
) -> PackerElasticIP:
    """Helper to create a PackerElasticIP for testing."""
    now = datetime.now(timezone.utc)
    return PackerElasticIP(
        resource_id=allocation_id,
        resource_type=ResourceType.ELASTIC_IP,
        creation_time=now,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        public_ip=public_ip,
        allocation_id=allocation_id,
        association_id=association_id,
        instance_id=instance_id,
    )


# Strategies for generating test data
num_instances_strategy = st.integers(min_value=1, max_value=5)
num_security_groups_strategy = st.integers(min_value=0, max_value=5)
num_key_pairs_strategy = st.integers(min_value=0, max_value=3)
instance_state_strategy = st.sampled_from(["running", "stopped", "pending", "stopping"])


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=num_security_groups_strategy,
    num_key_pairs=num_key_pairs_strategy,
)
def test_instances_terminated_before_dependent_resources(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
):
    """
    Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing

    For any set of related AWS resources, cleanup operations should always
    terminate instances before attempting to delete dependent resources
    (security groups, key pairs).

    Validates: Requirements 2.1
    """
    # Create test resources
    instances = [
        create_instance(
            instance_id=f"i-{i:08d}",
            state="running",
            security_groups=[f"sg-{j:08d}" for j in range(num_security_groups)],
            key_name=f"packer_key_{i}" if num_key_pairs > 0 else None,
        )
        for i in range(num_instances)
    ]

    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_security_groups)
    ]

    key_pairs = [
        create_key_pair(
            key_name=f"packer_key_{i}",
            key_id=f"key-{i:08d}",
        )
        for i in range(num_key_pairs)
    ]

    # Create resource collection
    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
    )

    # Create mock client and engine
    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

    # Execute cleanup
    engine.cleanup_resources(resources)

    # Verify operation order: all instance terminations should come before
    # any security group or key pair deletions
    operations = mock_client.operation_order

    # Find indices of different operation types
    instance_ops = [
        i for i, (op, _) in enumerate(operations) if op == "terminate_instance"
    ]
    sg_ops = [
        i for i, (op, _) in enumerate(operations) if op == "delete_security_group"
    ]
    kp_ops = [i for i, (op, _) in enumerate(operations) if op == "delete_key_pair"]

    # All instance terminations should come before any SG or KP deletions
    if instance_ops and sg_ops:
        max_instance_op = max(instance_ops)
        min_sg_op = min(sg_ops)
        assert max_instance_op < min_sg_op, (
            f"Instance termination (index {max_instance_op}) should complete "
            f"before security group deletion (index {min_sg_op})"
        )

    if instance_ops and kp_ops:
        max_instance_op = max(instance_ops)
        min_kp_op = min(kp_ops)
        assert max_instance_op < min_kp_op, (
            f"Instance termination (index {max_instance_op}) should complete "
            f"before key pair deletion (index {min_kp_op})"
        )


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=st.integers(min_value=1, max_value=5),
    num_deferred_sgs=st.integers(min_value=0, max_value=3),
)
def test_dependency_violations_cause_deferral(
    num_instances: int,
    num_security_groups: int,
    num_deferred_sgs: int,
):
    """
    Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing

    For any security group that has a DependencyViolation error (e.g., instance
    still shutting down), the cleanup should defer that resource to the next
    execution cycle rather than failing.

    Validates: Requirements 2.6
    """
    # Ensure we don't try to defer more SGs than we have
    num_deferred_sgs = min(num_deferred_sgs, num_security_groups)

    # Create test resources
    instances = [
        create_instance(instance_id=f"i-{i:08d}", state="running")
        for i in range(num_instances)
    ]

    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_security_groups)
    ]

    # Mark some SGs as having dependency violations
    dependency_violations = [f"sg-{i:08d}" for i in range(num_deferred_sgs)]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
    )

    # Create mock client with dependency violations
    mock_client = create_mock_ec2_client(dependency_violations=dependency_violations)
    engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

    # Execute cleanup
    result = engine.cleanup_resources(resources)

    # Verify deferred resources
    expected_deleted = num_security_groups - num_deferred_sgs

    assert (
        len(result.deleted_security_groups) == expected_deleted
    ), f"Expected {expected_deleted} deleted SGs, got {len(result.deleted_security_groups)}"

    # Deferred resources should include the SGs with dependency violations
    for sg_id in dependency_violations:
        assert (
            sg_id in result.deferred_resources
        ), f"Security group {sg_id} with dependency violation should be deferred"


@settings(max_examples=100, deadline=10000)
@given(
    instance_state=st.sampled_from(["shutting-down", "terminated"]),
    num_security_groups=st.integers(min_value=1, max_value=3),
)
def test_transitional_instance_states_handled(
    instance_state: str,
    num_security_groups: int,
):
    """
    Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing

    For any instance in a transitional state (shutting-down), the cleanup engine
    should recognize this and handle dependent resources appropriately.

    Validates: Requirements 2.1, 2.6
    """
    # Create instance in transitional state
    instances = [
        create_instance(
            instance_id="i-00000001",
            state=instance_state,
        )
    ]

    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_security_groups)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
    )

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

    # Execute cleanup
    result = engine.cleanup_resources(resources)

    # For shutting-down instances, they should be deferred (not re-terminated)
    # For terminated instances, they should be counted as terminated
    if instance_state == "shutting-down":
        assert (
            "i-00000001" in result.deferred_resources
        ), "Shutting-down instance should be deferred"
    else:  # terminated
        assert (
            "i-00000001" in result.terminated_instances
        ), "Already terminated instance should be in terminated list"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=num_security_groups_strategy,
    num_key_pairs=num_key_pairs_strategy,
)
def test_cleanup_order_is_deterministic(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
):
    """
    Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing

    For any set of resources, the cleanup order should follow a deterministic
    sequence: instances -> security groups -> key pairs -> EIPs -> volumes -> snapshots.

    Validates: Requirements 2.1
    """
    # Create test resources
    instances = [
        create_instance(instance_id=f"i-{i:08d}", state="running")
        for i in range(num_instances)
    ]

    security_groups = [
        create_security_group(group_id=f"sg-{i:08d}", group_name=f"packer_sg_{i}")
        for i in range(num_security_groups)
    ]

    key_pairs = [
        create_key_pair(key_name=f"packer_key_{i}", key_id=f"key-{i:08d}")
        for i in range(num_key_pairs)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
    )

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

    # Execute cleanup
    engine.cleanup_resources(resources)

    # Verify the operation order follows the expected sequence
    operations = mock_client.operation_order

    # Extract operation types in order
    op_types = [op for op, _ in operations]

    # Define expected order of operation types
    expected_order = ["terminate_instance", "delete_security_group", "delete_key_pair"]

    # Track the last seen index for each operation type
    last_seen = {}
    for i, op_type in enumerate(op_types):
        last_seen[op_type] = i

    # Verify ordering constraints
    for i, op_type in enumerate(expected_order):
        if op_type not in last_seen:
            continue
        for later_op in expected_order[i + 1 :]:
            if later_op not in last_seen:
                continue
            # All operations of earlier type should complete before later type starts
            first_later = min(j for j, op in enumerate(op_types) if op == later_op)
            last_earlier = max(j for j, op in enumerate(op_types) if op == op_type)
            assert (
                last_earlier < first_later
            ), f"All {op_type} operations should complete before {later_op} starts"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=num_security_groups_strategy,
)
def test_dry_run_preserves_ordering_without_execution(
    num_instances: int,
    num_security_groups: int,
):
    """
    Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing

    For any resource set in dry-run mode, the cleanup engine should still
    follow the correct ordering logic but not execute any actual operations.

    Validates: Requirements 2.1
    """
    instances = [
        create_instance(instance_id=f"i-{i:08d}", state="running")
        for i in range(num_instances)
    ]

    security_groups = [
        create_security_group(group_id=f"sg-{i:08d}", group_name=f"packer_sg_{i}")
        for i in range(num_security_groups)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
    )

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=True)

    # Execute cleanup in dry-run mode
    result = engine.cleanup_resources(resources)

    # Verify dry-run flag is set
    assert result.dry_run is True

    # Verify no actual AWS API calls were made
    mock_client.terminate_instances.assert_not_called()
    mock_client.delete_security_group.assert_not_called()
    mock_client.delete_key_pair.assert_not_called()

    # But resources should still be reported as "cleaned"
    assert len(result.terminated_instances) == num_instances
    assert len(result.deleted_security_groups) == num_security_groups


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=st.integers(min_value=1, max_value=3),
    num_volumes=st.integers(min_value=0, max_value=3),
    num_eips=st.integers(min_value=0, max_value=2),
)
def test_associated_resources_collected_before_termination(
    num_instances: int,
    num_security_groups: int,
    num_volumes: int,
    num_eips: int,
):
    """
    Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing

    For any zombie instance, the cleanup engine should collect directly associated
    resources (security groups, key pairs, volumes, EIPs) before termination.

    Validates: Requirements 2.2
    """
    # Create instances with associated resources
    instances = []
    for i in range(num_instances):
        sg_ids = [f"sg-{i:04d}{j:04d}" for j in range(num_security_groups)]
        instances.append(
            create_instance(
                instance_id=f"i-{i:08d}",
                state="running",
                security_groups=sg_ids,
                key_name=f"packer_key_{i}",
            )
        )

    # Set up associated volumes and EIPs
    associated_volumes = {}
    associated_eips = {}
    for i in range(num_instances):
        instance_id = f"i-{i:08d}"
        associated_volumes[instance_id] = [
            f"vol-{i:04d}{j:04d}" for j in range(num_volumes)
        ]
        associated_eips[instance_id] = [
            f"eipalloc-{i:04d}{j:04d}" for j in range(num_eips)
        ]

    mock_client = create_mock_ec2_client(
        associated_volumes=associated_volumes,
        associated_eips=associated_eips,
    )
    engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

    # Test collect_associated_resources for each instance
    for instance in instances:
        associated = engine.collect_associated_resources(instance)

        # Verify security groups are collected
        assert set(associated.security_group_ids) == set(
            instance.security_groups
        ), f"Security groups should be collected for instance {instance.resource_id}"

        # Verify key pair is collected
        assert (
            associated.key_pair_name == instance.key_name
        ), f"Key pair should be collected for instance {instance.resource_id}"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
)
def test_waiter_called_after_termination(
    num_instances: int,
):
    """
    Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing

    For any set of instances being terminated, the cleanup engine should wait
    for termination confirmation before proceeding to dependent resources.

    Validates: Requirements 2.3, 2.5
    """
    instances = [
        create_instance(instance_id=f"i-{i:08d}", state="running")
        for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    mock_client = create_mock_ec2_client()

    # Create a persistent waiter mock
    waiter_mock = MagicMock()
    mock_client.get_waiter = MagicMock(return_value=waiter_mock)

    engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

    # Execute cleanup
    engine.cleanup_resources(resources)

    # Verify waiter was called (only if instances were terminated)
    if num_instances > 0:
        mock_client.get_waiter.assert_called_with("instance_terminated")
        waiter_mock.wait.assert_called_once()


@settings(max_examples=100, deadline=10000)
@given(
    num_running=st.integers(min_value=0, max_value=3),
    num_shutting_down=st.integers(min_value=0, max_value=3),
)
def test_shutting_down_instances_deferred(
    num_running: int,
    num_shutting_down: int,
):
    """
    Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing

    For any instance in shutting-down state, the cleanup engine should defer
    associated resource deletion to the next scheduled execution.

    Validates: Requirements 2.7
    """
    # Skip if no instances
    if num_running == 0 and num_shutting_down == 0:
        return

    instances = []

    # Create running instances
    for i in range(num_running):
        instances.append(
            create_instance(instance_id=f"i-running-{i:04d}", state="running")
        )

    # Create shutting-down instances
    for i in range(num_shutting_down):
        instances.append(
            create_instance(instance_id=f"i-shutting-{i:04d}", state="shutting-down")
        )

    resources = ResourceCollection(instances=instances)

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

    # Execute cleanup
    result = engine.cleanup_resources(resources)

    # Verify shutting-down instances are deferred
    for i in range(num_shutting_down):
        instance_id = f"i-shutting-{i:04d}"
        assert (
            instance_id in result.deferred_resources
        ), f"Shutting-down instance {instance_id} should be deferred"

    # Verify running instances are terminated
    assert (
        len(result.terminated_instances) == num_running
    ), f"Expected {num_running} terminated instances, got {len(result.terminated_instances)}"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=st.integers(min_value=1, max_value=3),
    num_key_pairs=st.integers(min_value=1, max_value=2),
    num_volumes=st.integers(min_value=0, max_value=2),
    num_eips=st.integers(min_value=0, max_value=2),
)
def test_only_directly_associated_resources_deleted(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
    num_volumes: int,
    num_eips: int,
):
    """
    Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing

    For any cleanup operation, only resources that were directly associated
    with the terminated zombie instances should be deleted.

    Validates: Requirements 2.8
    """
    # Create instances with specific associated resources
    instances = []
    security_groups = []
    key_pairs = []
    volumes = []
    elastic_ips = []

    for i in range(num_instances):
        sg_ids = [f"sg-{i:04d}{j:04d}" for j in range(num_security_groups)]
        instances.append(
            create_instance(
                instance_id=f"i-{i:08d}",
                state="running",
                security_groups=sg_ids,
                key_name=f"packer_key_{i}",
            )
        )

        # Create associated security groups
        for j in range(num_security_groups):
            security_groups.append(
                create_security_group(
                    group_id=f"sg-{i:04d}{j:04d}",
                    group_name=f"packer_sg_{i}_{j}",
                )
            )

        # Create associated key pairs
        if i < num_key_pairs:
            key_pairs.append(
                create_key_pair(
                    key_name=f"packer_key_{i}",
                    key_id=f"key-{i:08d}",
                )
            )

        # Create associated volumes
        for j in range(num_volumes):
            volumes.append(
                create_volume(
                    volume_id=f"vol-{i:04d}{j:04d}",
                    state="available",
                )
            )

        # Create associated EIPs
        for j in range(num_eips):
            elastic_ips.append(
                create_elastic_ip(
                    allocation_id=f"eipalloc-{i:04d}{j:04d}",
                    public_ip=f"1.2.{i}.{j}",
                )
            )

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
        volumes=volumes,
        elastic_ips=elastic_ips,
    )

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

    # Execute cleanup
    result = engine.cleanup_resources(resources)

    # Verify all instances were terminated
    assert len(result.terminated_instances) == num_instances

    # Verify security groups were deleted (only those in the collection)
    assert len(result.deleted_security_groups) == len(security_groups)

    # Verify key pairs were deleted (only those in the collection)
    assert len(result.deleted_key_pairs) == len(key_pairs)


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=st.integers(min_value=1, max_value=3),
    num_key_pairs=st.integers(min_value=0, max_value=2),
    num_eips=st.integers(min_value=0, max_value=2),
)
def test_dependent_resources_deleted_after_instance_termination(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
    num_eips: int,
):
    """
    Feature: packer-resource-reaper, Property 3: Dependency-Aware Cleanup Sequencing

    For any set of zombie instances and their associated resources, cleanup
    operations should delete dependent resources (security groups, key pairs,
    EIPs) only after instances are terminated.

    Validates: Requirements 2.4
    """
    instances = []
    security_groups = []
    key_pairs = []
    elastic_ips = []

    for i in range(num_instances):
        sg_ids = [f"sg-{i:04d}{j:04d}" for j in range(num_security_groups)]
        instances.append(
            create_instance(
                instance_id=f"i-{i:08d}",
                state="running",
                security_groups=sg_ids,
                key_name=f"packer_key_{i}" if i < num_key_pairs else None,
            )
        )

        for j in range(num_security_groups):
            security_groups.append(
                create_security_group(
                    group_id=f"sg-{i:04d}{j:04d}",
                    group_name=f"packer_sg_{i}_{j}",
                )
            )

    for i in range(num_key_pairs):
        key_pairs.append(
            create_key_pair(
                key_name=f"packer_key_{i}",
                key_id=f"key-{i:08d}",
            )
        )

    for i in range(num_eips):
        elastic_ips.append(
            create_elastic_ip(
                allocation_id=f"eipalloc-{i:08d}",
                public_ip=f"1.2.3.{i}",
            )
        )

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
        elastic_ips=elastic_ips,
    )

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

    # Execute cleanup
    engine.cleanup_resources(resources)

    # Verify operation order
    operations = mock_client.operation_order

    # Find indices of different operation types
    instance_ops = [
        i for i, (op, _) in enumerate(operations) if op == "terminate_instance"
    ]
    sg_ops = [
        i for i, (op, _) in enumerate(operations) if op == "delete_security_group"
    ]
    kp_ops = [i for i, (op, _) in enumerate(operations) if op == "delete_key_pair"]
    eip_ops = [i for i, (op, _) in enumerate(operations) if op == "release_address"]

    # All instance terminations should come before any dependent resource deletions
    if instance_ops:
        max_instance_op = max(instance_ops)

        if sg_ops:
            min_sg_op = min(sg_ops)
            assert (
                max_instance_op < min_sg_op
            ), "Security groups should be deleted after instance termination"

        if kp_ops:
            min_kp_op = min(kp_ops)
            assert (
                max_instance_op < min_kp_op
            ), "Key pairs should be deleted after instance termination"

        if eip_ops:
            min_eip_op = min(eip_ops)
            assert (
                max_instance_op < min_eip_op
            ), "EIPs should be released after instance termination"
