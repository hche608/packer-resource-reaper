"""Property-based tests for dry-run safety guarantee.

Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee
Validates: Requirements 9.1, 9.2, 9.3, 9.4

Requirements:
- 9.1: WHEN the DRY_RUN environment variable is set to True, THE Reaper SHALL
       identify all cleanup candidates without executing destructive operations
- 9.2: WHEN operating in Dry_Run_Mode, THE Reaper SHALL log all resources that
       would be deleted to CloudWatch
- 9.3: WHEN operating in Dry_Run_Mode, THE Reaper SHALL send a simulation report
       via SNS detailing planned actions
- 9.4: WHEN operating in Dry_Run_Mode, THE Reaper SHALL NOT execute any terminate,
       delete, or release API calls
"""

from datetime import datetime, timezone
from typing import List, Optional
from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from reaper.cleanup.dry_run import DryRunExecutor
from reaper.cleanup.engine import CleanupEngine
from reaper.models import (
    PackerElasticIP,
    PackerInstance,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerSnapshot,
    PackerVolume,
    ResourceCollection,
    ResourceType,
)


# Helper functions to create test resources
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
        tags={"Name": "Packer Volume"},
        region="us-east-1",
        account_id="123456789012",
        size=8,
        state=state,
        attached_instance=attached_instance,
        snapshot_id=None,
    )


def create_snapshot(
    snapshot_id: str,
    state: str = "completed",
) -> PackerSnapshot:
    """Helper to create a PackerSnapshot for testing."""
    now = datetime.now(timezone.utc)
    return PackerSnapshot(
        resource_id=snapshot_id,
        resource_type=ResourceType.SNAPSHOT,
        creation_time=now,
        tags={"Name": "Packer Snapshot"},
        region="us-east-1",
        account_id="123456789012",
        volume_id="vol-12345678",
        state=state,
        progress="100%",
        owner_id="123456789012",
    )


def create_elastic_ip(
    allocation_id: str,
    public_ip: str = "1.2.3.4",
    association_id: Optional[str] = None,
    instance_id: Optional[str] = None,
) -> PackerElasticIP:
    """Helper to create a PackerElasticIP for testing."""
    now = datetime.now(timezone.utc)
    return PackerElasticIP(
        resource_id=allocation_id,
        resource_type=ResourceType.ELASTIC_IP,
        creation_time=now,
        tags={"Name": "packer_eip"},
        region="us-east-1",
        account_id="123456789012",
        public_ip=public_ip,
        allocation_id=allocation_id,
        association_id=association_id,
        instance_id=instance_id,
    )


def create_mock_ec2_client() -> MagicMock:
    """Create a mock EC2 client that tracks all API calls."""
    mock_client = MagicMock()
    mock_client.destructive_calls = []

    def track_terminate(InstanceIds):
        mock_client.destructive_calls.append(("terminate_instances", InstanceIds))
        return {"TerminatingInstances": [{"InstanceId": iid} for iid in InstanceIds]}

    def track_delete_sg(GroupId):
        mock_client.destructive_calls.append(("delete_security_group", GroupId))

    def track_delete_kp(KeyName):
        mock_client.destructive_calls.append(("delete_key_pair", KeyName))

    def track_release_eip(AllocationId):
        mock_client.destructive_calls.append(("release_address", AllocationId))

    def track_delete_volume(VolumeId):
        mock_client.destructive_calls.append(("delete_volume", VolumeId))

    def track_delete_snapshot(SnapshotId):
        mock_client.destructive_calls.append(("delete_snapshot", SnapshotId))

    mock_client.terminate_instances = MagicMock(side_effect=track_terminate)
    mock_client.delete_security_group = MagicMock(side_effect=track_delete_sg)
    mock_client.delete_key_pair = MagicMock(side_effect=track_delete_kp)
    mock_client.release_address = MagicMock(side_effect=track_release_eip)
    mock_client.delete_volume = MagicMock(side_effect=track_delete_volume)
    mock_client.delete_snapshot = MagicMock(side_effect=track_delete_snapshot)

    # Mock paginator for get_registered_ami_snapshots
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Images": []}]
    mock_client.get_paginator = MagicMock(return_value=mock_paginator)

    return mock_client


# Hypothesis strategies for generating test data
num_instances_strategy = st.integers(min_value=0, max_value=5)
num_security_groups_strategy = st.integers(min_value=0, max_value=5)
num_key_pairs_strategy = st.integers(min_value=0, max_value=3)
num_volumes_strategy = st.integers(min_value=0, max_value=5)
num_snapshots_strategy = st.integers(min_value=0, max_value=5)
num_elastic_ips_strategy = st.integers(min_value=0, max_value=3)
instance_state_strategy = st.sampled_from(["running", "stopped", "pending", "stopping"])


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=num_security_groups_strategy,
    num_key_pairs=num_key_pairs_strategy,
    num_volumes=num_volumes_strategy,
    num_snapshots=num_snapshots_strategy,
    num_elastic_ips=num_elastic_ips_strategy,
)
def test_dry_run_no_destructive_operations(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
    num_volumes: int,
    num_snapshots: int,
    num_elastic_ips: int,
):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any resource set and configuration, when dry-run mode is enabled,
    the system should NOT execute any destructive AWS API operations
    (terminate, delete, release).

    Validates: Requirements 9.1, 9.4
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
    volumes = [
        create_volume(volume_id=f"vol-{i:08d}", state="available")
        for i in range(num_volumes)
    ]
    snapshots = [
        create_snapshot(snapshot_id=f"snap-{i:08d}", state="completed")
        for i in range(num_snapshots)
    ]
    elastic_ips = [
        create_elastic_ip(
            allocation_id=f"eipalloc-{i:08d}",
            public_ip=f"1.2.3.{i}",
        )
        for i in range(num_elastic_ips)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
        volumes=volumes,
        snapshots=snapshots,
        elastic_ips=elastic_ips,
    )

    # Create mock client and engine with dry_run=True
    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=True)

    # Execute cleanup in dry-run mode
    engine.cleanup_resources(resources)

    # CRITICAL: Verify NO destructive API calls were made
    assert len(mock_client.destructive_calls) == 0, (
        f"Dry-run mode should not execute any destructive operations, "
        f"but found: {mock_client.destructive_calls}"
    )

    # Verify specific API methods were not called
    mock_client.terminate_instances.assert_not_called()
    mock_client.delete_security_group.assert_not_called()
    mock_client.delete_key_pair.assert_not_called()
    mock_client.release_address.assert_not_called()
    mock_client.delete_volume.assert_not_called()
    mock_client.delete_snapshot.assert_not_called()


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
    num_security_groups=st.integers(min_value=1, max_value=5),
    num_key_pairs=st.integers(min_value=1, max_value=3),
    num_volumes=st.integers(min_value=1, max_value=5),
    num_snapshots=st.integers(min_value=1, max_value=5),
    num_elastic_ips=st.integers(min_value=1, max_value=3),
)
def test_dry_run_identifies_all_cleanup_candidates(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
    num_volumes: int,
    num_snapshots: int,
    num_elastic_ips: int,
):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any resource set, when dry-run mode is enabled, the system should
    identify ALL cleanup candidates and report them in the result.

    Validates: Requirements 9.1, 9.2
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
    volumes = [
        create_volume(volume_id=f"vol-{i:08d}", state="available")
        for i in range(num_volumes)
    ]
    snapshots = [
        create_snapshot(snapshot_id=f"snap-{i:08d}", state="completed")
        for i in range(num_snapshots)
    ]
    elastic_ips = [
        create_elastic_ip(
            allocation_id=f"eipalloc-{i:08d}",
            public_ip=f"1.2.3.{i}",
        )
        for i in range(num_elastic_ips)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
        volumes=volumes,
        snapshots=snapshots,
        elastic_ips=elastic_ips,
    )

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=True)

    # Execute cleanup in dry-run mode
    result = engine.cleanup_resources(resources)

    # Verify dry-run flag is set in result
    assert result.dry_run is True, "Result should indicate dry-run mode"

    # Verify all resources are identified as "would be cleaned"
    assert (
        len(result.terminated_instances) == num_instances
    ), f"Expected {num_instances} instances identified, got {len(result.terminated_instances)}"
    assert (
        len(result.deleted_security_groups) == num_security_groups
    ), f"Expected {num_security_groups} SGs identified, got {len(result.deleted_security_groups)}"
    assert (
        len(result.deleted_key_pairs) == num_key_pairs
    ), f"Expected {num_key_pairs} key pairs identified, got {len(result.deleted_key_pairs)}"
    assert (
        len(result.deleted_volumes) == num_volumes
    ), f"Expected {num_volumes} volumes identified, got {len(result.deleted_volumes)}"
    assert (
        len(result.deleted_snapshots) == num_snapshots
    ), f"Expected {num_snapshots} snapshots identified, got {len(result.deleted_snapshots)}"
    assert (
        len(result.released_elastic_ips) == num_elastic_ips
    ), f"Expected {num_elastic_ips} EIPs identified, got {len(result.released_elastic_ips)}"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=num_security_groups_strategy,
    num_volumes=num_volumes_strategy,
)
def test_dry_run_result_matches_live_identification(
    num_instances: int,
    num_security_groups: int,
    num_volumes: int,
):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any resource set, dry-run mode should identify the same resources
    that would be cleaned in live mode (ensuring accurate simulation reports).

    Validates: Requirements 9.2, 9.3
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
    volumes = [
        create_volume(volume_id=f"vol-{i:08d}", state="available")
        for i in range(num_volumes)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        volumes=volumes,
    )

    # Execute in dry-run mode
    dry_run_client = create_mock_ec2_client()
    dry_run_engine = CleanupEngine(ec2_client=dry_run_client, dry_run=True)
    dry_run_result = dry_run_engine.cleanup_resources(resources)

    # Execute in live mode
    live_client = create_mock_ec2_client()
    live_engine = CleanupEngine(ec2_client=live_client, dry_run=False)
    live_result = live_engine.cleanup_resources(resources)

    # Verify dry-run identifies the same resources as live mode
    assert set(dry_run_result.terminated_instances) == set(
        live_result.terminated_instances
    ), "Dry-run should identify same instances as live mode"
    assert set(dry_run_result.deleted_security_groups) == set(
        live_result.deleted_security_groups
    ), "Dry-run should identify same security groups as live mode"
    assert set(dry_run_result.deleted_volumes) == set(
        live_result.deleted_volumes
    ), "Dry-run should identify same volumes as live mode"

    # But dry-run should NOT have made any destructive calls
    assert (
        len(dry_run_client.destructive_calls) == 0
    ), "Dry-run should not make destructive calls"
    # Live mode SHOULD have made destructive calls (if there were resources)
    if num_instances > 0 or num_security_groups > 0 or num_volumes > 0:
        assert (
            len(live_client.destructive_calls) > 0
        ), "Live mode should make destructive calls when resources exist"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
    instance_state=st.sampled_from(
        ["running", "stopped", "pending", "stopping", "rebooting"]
    ),
)
def test_dry_run_handles_all_instance_states(
    num_instances: int,
    instance_state: str,
):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any instance state (running, stopped, pending, stopping, rebooting),
    dry-run mode should identify the instance without executing termination.

    Validates: Requirements 9.1, 9.4
    """
    instances = [
        create_instance(instance_id=f"i-{i:08d}", state=instance_state)
        for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=True)

    engine.cleanup_resources(resources)

    # No destructive calls should be made regardless of instance state
    assert (
        len(mock_client.destructive_calls) == 0
    ), f"Dry-run should not terminate instances in {instance_state} state"
    mock_client.terminate_instances.assert_not_called()


@settings(max_examples=100, deadline=10000)
@given(
    num_resources=st.integers(min_value=1, max_value=10),
)
def test_dry_run_total_cleaned_count_accurate(num_resources: int):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any resource set in dry-run mode, the total_cleaned() count should
    accurately reflect all resources that would be cleaned.

    Validates: Requirements 9.2, 9.3
    """
    # Create a mix of resources
    instances = [
        create_instance(instance_id=f"i-{i:08d}") for i in range(num_resources)
    ]
    volumes = [create_volume(volume_id=f"vol-{i:08d}") for i in range(num_resources)]

    resources = ResourceCollection(
        instances=instances,
        volumes=volumes,
    )

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=True)

    result = engine.cleanup_resources(resources)

    # Total cleaned should equal all resources
    expected_total = num_resources * 2  # instances + volumes
    assert (
        result.total_cleaned() == expected_total
    ), f"Expected total_cleaned={expected_total}, got {result.total_cleaned()}"

    # But no actual API calls
    assert len(mock_client.destructive_calls) == 0


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=num_security_groups_strategy,
    num_key_pairs=num_key_pairs_strategy,
    num_volumes=num_volumes_strategy,
    num_snapshots=num_snapshots_strategy,
    num_elastic_ips=num_elastic_ips_strategy,
)
def test_dry_run_no_errors_without_api_calls(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
    num_volumes: int,
    num_snapshots: int,
    num_elastic_ips: int,
):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any resource set in dry-run mode, the result should have no errors
    since no actual API calls are made that could fail.

    Validates: Requirements 9.1, 9.4
    """
    instances = [
        create_instance(instance_id=f"i-{i:08d}") for i in range(num_instances)
    ]
    security_groups = [
        create_security_group(group_id=f"sg-{i:08d}")
        for i in range(num_security_groups)
    ]
    key_pairs = [
        create_key_pair(key_name=f"packer_key_{i}", key_id=f"key-{i:08d}")
        for i in range(num_key_pairs)
    ]
    volumes = [create_volume(volume_id=f"vol-{i:08d}") for i in range(num_volumes)]
    snapshots = [
        create_snapshot(snapshot_id=f"snap-{i:08d}") for i in range(num_snapshots)
    ]
    elastic_ips = [
        create_elastic_ip(allocation_id=f"eipalloc-{i:08d}", public_ip=f"1.2.3.{i}")
        for i in range(num_elastic_ips)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
        volumes=volumes,
        snapshots=snapshots,
        elastic_ips=elastic_ips,
    )

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(ec2_client=mock_client, dry_run=True)

    result = engine.cleanup_resources(resources)

    # No errors should occur in dry-run mode
    assert (
        len(result.errors) == 0
    ), f"Dry-run should not produce errors, but got: {result.errors}"
    # No deferred resources either (since no actual operations)
    assert (
        len(result.deferred_resources) == 0
    ), f"Dry-run should not defer resources, but got: {result.deferred_resources}"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
    num_security_groups=st.integers(min_value=1, max_value=5),
    num_key_pairs=st.integers(min_value=1, max_value=3),
    num_volumes=st.integers(min_value=1, max_value=5),
    num_snapshots=st.integers(min_value=1, max_value=5),
    num_elastic_ips=st.integers(min_value=1, max_value=3),
)
def test_dry_run_executor_generates_complete_report(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
    num_volumes: int,
    num_snapshots: int,
    num_elastic_ips: int,
):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any resource set, the DryRunExecutor should generate a complete
    DryRunReport containing all resources that would be cleaned.

    Validates: Requirements 9.2, 9.3
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
    volumes = [
        create_volume(volume_id=f"vol-{i:08d}", state="available")
        for i in range(num_volumes)
    ]
    snapshots = [
        create_snapshot(snapshot_id=f"snap-{i:08d}", state="completed")
        for i in range(num_snapshots)
    ]
    elastic_ips = [
        create_elastic_ip(
            allocation_id=f"eipalloc-{i:08d}",
            public_ip=f"1.2.3.{i}",
        )
        for i in range(num_elastic_ips)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
        volumes=volumes,
        snapshots=snapshots,
        elastic_ips=elastic_ips,
    )

    # Execute dry-run using DryRunExecutor directly
    executor = DryRunExecutor(account_id="123456789012", region="us-east-1")
    result, report = executor.execute_dry_run(resources)

    # Verify report contains all resources
    assert len(report.instances_to_terminate) == num_instances
    assert len(report.security_groups_to_delete) == num_security_groups
    assert len(report.key_pairs_to_delete) == num_key_pairs
    assert len(report.volumes_to_delete) == num_volumes
    assert len(report.snapshots_to_delete) == num_snapshots
    assert len(report.elastic_ips_to_release) == num_elastic_ips

    # Verify report total matches
    expected_total = (
        num_instances
        + num_security_groups
        + num_key_pairs
        + num_volumes
        + num_snapshots
        + num_elastic_ips
    )
    assert report.total_resources() == expected_total

    # Verify result matches report
    assert result.dry_run is True
    assert result.total_cleaned() == expected_total


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
)
def test_dry_run_report_contains_instance_details(num_instances: int):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any instance in dry-run mode, the report should contain detailed
    information including instance ID, type, state, and termination reason.

    Validates: Requirements 9.2, 9.3
    """
    instances = [
        create_instance(
            instance_id=f"i-{i:08d}",
            state="running",
            key_name=f"packer_key_{i}",
        )
        for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    executor = DryRunExecutor(account_id="123456789012", region="us-east-1")
    result, report = executor.execute_dry_run(resources)

    # Verify each instance has required details
    for i, instance_info in enumerate(report.instances_to_terminate):
        assert "instance_id" in instance_info
        assert "instance_type" in instance_info
        assert "state" in instance_info
        assert "key_name" in instance_info
        assert "termination_reason" in instance_info
        assert instance_info["instance_id"] == f"i-{i:08d}"


@settings(max_examples=100, deadline=10000)
@given(
    account_id=st.text(alphabet="0123456789", min_size=12, max_size=12),
    region=st.sampled_from(["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]),
)
def test_dry_run_report_includes_account_and_region(account_id: str, region: str):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any dry-run execution, the report should include the account ID
    and region for proper identification in SNS notifications.

    Validates: Requirements 9.2, 9.3
    """
    instances = [create_instance(instance_id="i-12345678", state="running")]
    resources = ResourceCollection(instances=instances)

    executor = DryRunExecutor(account_id=account_id, region=region)
    result, report = executor.execute_dry_run(resources)

    # Verify account and region are captured
    assert report.account_id == account_id
    assert report.region == region

    # Verify report can be serialized to dict for SNS
    report_dict = report.to_dict()
    assert report_dict["account_id"] == account_id
    assert report_dict["region"] == region
    assert "timestamp" in report_dict
    assert "total_resources" in report_dict


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=num_security_groups_strategy,
    num_key_pairs=num_key_pairs_strategy,
    num_volumes=num_volumes_strategy,
    num_snapshots=num_snapshots_strategy,
    num_elastic_ips=num_elastic_ips_strategy,
)
def test_dry_run_engine_stores_report_for_sns(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
    num_volumes: int,
    num_snapshots: int,
    num_elastic_ips: int,
):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any dry-run execution via CleanupEngine, the engine should store
    the DryRunReport for subsequent SNS notification.

    Validates: Requirements 9.3
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
    volumes = [
        create_volume(volume_id=f"vol-{i:08d}", state="available")
        for i in range(num_volumes)
    ]
    snapshots = [
        create_snapshot(snapshot_id=f"snap-{i:08d}", state="completed")
        for i in range(num_snapshots)
    ]
    elastic_ips = [
        create_elastic_ip(
            allocation_id=f"eipalloc-{i:08d}",
            public_ip=f"1.2.3.{i}",
        )
        for i in range(num_elastic_ips)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
        volumes=volumes,
        snapshots=snapshots,
        elastic_ips=elastic_ips,
    )

    mock_client = create_mock_ec2_client()
    engine = CleanupEngine(
        ec2_client=mock_client,
        dry_run=True,
        account_id="123456789012",
        region="us-east-1",
    )

    # Execute cleanup in dry-run mode
    engine.cleanup_resources(resources)

    # Verify report is stored
    report = engine.get_last_dry_run_report()

    total_resources = (
        num_instances
        + num_security_groups
        + num_key_pairs
        + num_volumes
        + num_snapshots
        + num_elastic_ips
    )

    if total_resources > 0:
        assert report is not None
        assert report.total_resources() == total_resources
    else:
        # Empty resources still generate a report
        assert report is not None
        assert report.total_resources() == 0


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=0, max_value=5),
    num_volumes=st.integers(min_value=0, max_value=5),
)
def test_dry_run_empty_resources_no_errors(
    num_instances: int,
    num_volumes: int,
):
    """
    Feature: packer-resource-reaper, Property 5: Dry Run Safety Guarantee

    For any resource set (including empty), dry-run mode should complete
    without errors and produce a valid report.

    Validates: Requirements 9.1, 9.4
    """
    instances = [
        create_instance(instance_id=f"i-{i:08d}", state="running")
        for i in range(num_instances)
    ]
    volumes = [
        create_volume(volume_id=f"vol-{i:08d}", state="available")
        for i in range(num_volumes)
    ]

    resources = ResourceCollection(
        instances=instances,
        volumes=volumes,
    )

    executor = DryRunExecutor(account_id="123456789012", region="us-east-1")
    result, report = executor.execute_dry_run(resources)

    # Should complete without errors
    assert result.dry_run is True
    assert len(result.errors) == 0
    assert len(result.deferred_resources) == 0

    # Report should be valid
    assert report.total_resources() == num_instances + num_volumes
    assert len(report.instances_to_terminate) == num_instances
    assert len(report.volumes_to_delete) == num_volumes
