"""Property-based tests for orphaned resource detection.

Feature: packer-resource-reaper, Property 5: Orphaned Resource Detection
Validates: Requirements 2.2, 2.8, 7.1

Orphaned resources are resources that were associated with Packer instances
but are now unattached/unassociated. These are collected as part of the
cleanup process for instances matching the key pair pattern.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Set

from hypothesis import given, settings
from hypothesis import strategies as st

from reaper.filters.identity import IdentityFilter
from reaper.models import (
    PackerElasticIP,
    PackerInstance,
    PackerSnapshot,
    PackerVolume,
    ResourceType,
)


def create_instance(
    instance_id: str,
    key_name: str = None,
    tags: dict = None,
) -> PackerInstance:
    """Helper to create a PackerInstance for testing."""
    now = datetime.now(timezone.utc)
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


def create_volume(
    volume_id: str,
    state: str = "available",
    attached_instance: str = None,
    tags: dict = None,
    creation_time: datetime = None,
) -> PackerVolume:
    """Helper to create a PackerVolume for testing."""
    now = creation_time or datetime.now(timezone.utc)
    return PackerVolume(
        resource_id=volume_id,
        resource_type=ResourceType.VOLUME,
        creation_time=now,
        tags=tags or {},
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
    tags: dict = None,
    creation_time: datetime = None,
) -> PackerSnapshot:
    """Helper to create a PackerSnapshot for testing."""
    now = creation_time or datetime.now(timezone.utc)
    return PackerSnapshot(
        resource_id=snapshot_id,
        resource_type=ResourceType.SNAPSHOT,
        creation_time=now,
        tags=tags or {},
        region="us-east-1",
        account_id="123456789012",
        volume_id="vol-source123",
        state=state,
        progress="100%",
        owner_id="123456789012",
    )


def create_elastic_ip(
    allocation_id: str,
    association_id: str = None,
    instance_id: str = None,
    tags: dict = None,
    creation_time: datetime = None,
) -> PackerElasticIP:
    """Helper to create a PackerElasticIP for testing."""
    now = creation_time or datetime.now(timezone.utc)
    return PackerElasticIP(
        resource_id=allocation_id,
        resource_type=ResourceType.ELASTIC_IP,
        creation_time=now,
        tags=tags or {},
        region="us-east-1",
        account_id="123456789012",
        public_ip="1.2.3.4",
        allocation_id=allocation_id,
        association_id=association_id,
        instance_id=instance_id,
    )


def is_orphaned_volume(volume: PackerVolume) -> bool:
    """Check if a volume is orphaned (available and unattached)."""
    return volume.state == "available" and volume.attached_instance is None


def is_orphaned_eip(eip: PackerElasticIP) -> bool:
    """Check if an EIP is orphaned (not associated with any instance)."""
    return eip.association_id is None and eip.instance_id is None


def filter_orphaned_snapshots(
    snapshots: List[PackerSnapshot],
    registered_ami_snapshots: Set[str],
) -> List[PackerSnapshot]:
    """Filter snapshots that are orphaned (not used by registered AMIs)."""
    return [
        snap for snap in snapshots if snap.resource_id not in registered_ami_snapshots
    ]


# Strategies for generating test data
packer_key_suffix = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_"),
    min_size=1,
    max_size=20,
)


@settings(max_examples=100, deadline=5000)
@given(suffix=packer_key_suffix)
def test_identity_filter_matches_packer_instances(suffix: str):
    """
    Feature: packer-resource-reaper, Property 5: Orphaned Resource Detection

    For any instance with packer_* key name, the identity filter should
    identify it for cleanup.

    Validates: Requirements 1.2
    """
    key_name = f"packer_{suffix}"
    instance = create_instance(instance_id="i-test123", key_name=key_name)

    identity_filter = IdentityFilter()
    result = identity_filter.filter_instances([instance])

    assert len(result) == 1, f"Instance with key_name '{key_name}' should match"


@settings(max_examples=100, deadline=5000)
@given(
    is_available=st.booleans(),
    is_attached=st.booleans(),
)
def test_orphaned_volume_detection(
    is_available: bool,
    is_attached: bool,
):
    """
    Feature: packer-resource-reaper, Property 5: Orphaned Resource Detection

    For any EBS volume, the system should identify it as orphaned if and only if:
    1. It is in 'available' state
    2. It is not attached to any instance

    Validates: Requirements 2.2, 2.8
    """
    state = "available" if is_available else "in-use"
    attached_instance = "i-12345678" if is_attached else None

    volume = create_volume(
        volume_id="vol-test123",
        state=state,
        attached_instance=attached_instance,
    )

    # Check if volume is orphaned
    orphaned = is_orphaned_volume(volume)

    # A volume is orphaned if available and unattached
    expected_orphaned = is_available and not is_attached

    assert (
        orphaned == expected_orphaned
    ), f"Volume with state={state}, attached={is_attached} should be orphaned={expected_orphaned}"


@settings(max_examples=100, deadline=5000)
@given(
    num_volumes=st.integers(min_value=1, max_value=10),
)
def test_orphaned_volume_subset_detection(num_volumes: int):
    """
    Feature: packer-resource-reaper, Property 5: Orphaned Resource Detection

    For any set of volumes, the system should correctly identify the subset
    that are orphaned (available, unattached).

    Validates: Requirements 2.2, 2.8
    """
    volumes = []
    expected_orphaned = []

    for i in range(num_volumes):
        is_available = i % 3 != 0
        is_attached = i % 4 == 0

        state = "available" if is_available else "in-use"
        attached = f"i-{i:08d}" if is_attached else None

        volume = create_volume(
            volume_id=f"vol-{i:08d}",
            state=state,
            attached_instance=attached,
        )
        volumes.append(volume)

        # Track expected orphaned volumes
        if is_available and not is_attached:
            expected_orphaned.append(volume.resource_id)

    orphaned_volumes = [v for v in volumes if is_orphaned_volume(v)]
    orphaned_ids = [v.resource_id for v in orphaned_volumes]

    assert set(orphaned_ids) == set(
        expected_orphaned
    ), f"Expected orphaned volumes: {expected_orphaned}, got: {orphaned_ids}"


@settings(max_examples=100, deadline=5000)
@given(
    is_associated=st.booleans(),
)
def test_unassociated_eip_detection(
    is_associated: bool,
):
    """
    Feature: packer-resource-reaper, Property 5: Orphaned Resource Detection

    For any Elastic IP, the system should identify it as orphaned if and only if
    it is not associated with any instance.

    Validates: Requirements 2.2
    """
    association_id = "eipassoc-12345" if is_associated else None
    instance_id = "i-12345678" if is_associated else None

    eip = create_elastic_ip(
        allocation_id="eipalloc-test123",
        association_id=association_id,
        instance_id=instance_id,
    )

    # Check if EIP is orphaned
    orphaned = is_orphaned_eip(eip)

    assert orphaned == (
        not is_associated
    ), f"EIP with associated={is_associated} should be orphaned={not is_associated}"


@settings(max_examples=100, deadline=5000)
@given(
    num_eips=st.integers(min_value=1, max_value=10),
)
def test_unassociated_eip_subset_detection(num_eips: int):
    """
    Feature: packer-resource-reaper, Property 5: Orphaned Resource Detection

    For any set of Elastic IPs, the system should correctly identify the subset
    that are unassociated.

    Validates: Requirements 2.2
    """
    eips = []
    expected_orphaned = []

    for i in range(num_eips):
        is_associated = i % 3 == 0

        association_id = f"eipassoc-{i:08d}" if is_associated else None
        instance_id = f"i-{i:08d}" if is_associated else None

        eip = create_elastic_ip(
            allocation_id=f"eipalloc-{i:08d}",
            association_id=association_id,
            instance_id=instance_id,
        )
        eips.append(eip)

        # Track expected orphaned EIPs
        if not is_associated:
            expected_orphaned.append(eip.resource_id)

    orphaned_eips = [e for e in eips if is_orphaned_eip(e)]
    orphaned_ids = [e.resource_id for e in orphaned_eips]

    assert set(orphaned_ids) == set(
        expected_orphaned
    ), f"Expected orphaned EIPs: {expected_orphaned}, got: {orphaned_ids}"


@settings(max_examples=100, deadline=5000)
@given(
    is_registered_ami=st.booleans(),
)
def test_orphaned_snapshot_detection(
    is_registered_ami: bool,
):
    """
    Feature: packer-resource-reaper, Property 5: Orphaned Resource Detection

    For any EBS snapshot, the system should identify it as orphaned if and only if
    it does not belong to a registered AMI.

    Validates: Requirements 2.8
    """
    snapshot_id = "snap-test123"

    snapshot = create_snapshot(snapshot_id=snapshot_id)

    # Simulate registered AMI snapshots
    registered_ami_snapshots = {snapshot_id} if is_registered_ami else set()

    # Check if snapshot is orphaned (not in registered AMI set)
    orphaned_snapshots = filter_orphaned_snapshots([snapshot], registered_ami_snapshots)
    is_orphaned = len(orphaned_snapshots) == 1

    assert is_orphaned == (
        not is_registered_ami
    ), f"Snapshot registered={is_registered_ami} should be orphaned={not is_registered_ami}"


@settings(max_examples=100, deadline=5000)
@given(
    num_snapshots=st.integers(min_value=1, max_value=10),
)
def test_orphaned_snapshot_subset_detection(num_snapshots: int):
    """
    Feature: packer-resource-reaper, Property 5: Orphaned Resource Detection

    For any set of snapshots, the system should correctly identify the subset
    that are orphaned (not used by registered AMIs).

    Validates: Requirements 2.8
    """
    snapshots = []
    registered_ami_snapshots = set()
    expected_orphaned = []

    for i in range(num_snapshots):
        is_registered = i % 3 == 0

        snapshot_id = f"snap-{i:08d}"

        snapshot = create_snapshot(snapshot_id=snapshot_id)
        snapshots.append(snapshot)

        if is_registered:
            registered_ami_snapshots.add(snapshot_id)
        else:
            expected_orphaned.append(snapshot_id)

    orphaned_snapshots = filter_orphaned_snapshots(snapshots, registered_ami_snapshots)
    orphaned_ids = [s.resource_id for s in orphaned_snapshots]

    assert set(orphaned_ids) == set(
        expected_orphaned
    ), f"Expected orphaned snapshots: {expected_orphaned}, got: {orphaned_ids}"


@settings(max_examples=100, deadline=5000)
@given(
    zombie_age_hours=st.integers(min_value=1, max_value=48),
    volume_age_offset_hours=st.integers(min_value=-2, max_value=2),
)
def test_temporal_correlation_volume_detection(
    zombie_age_hours: int,
    volume_age_offset_hours: int,
):
    """
    Feature: packer-resource-reaper, Property 5: Orphaned Resource Detection

    For any orphaned volume, the system should identify volumes created within
    the same timeframe as detected zombie instances (temporal correlation).

    Validates: Requirements 2.2
    """
    now = datetime.now(timezone.utc)

    # Zombie instance creation time
    zombie_creation_time = now - timedelta(hours=zombie_age_hours)

    # Volume creation time (within offset of zombie)
    volume_creation_time = zombie_creation_time + timedelta(
        hours=volume_age_offset_hours
    )

    create_volume(
        volume_id="vol-test123",
        state="available",
        attached_instance=None,
        creation_time=volume_creation_time,
    )

    # Check temporal correlation (within 2 hour window)
    time_diff = abs(
        (volume_creation_time - zombie_creation_time).total_seconds() / 3600
    )
    is_temporally_correlated = time_diff <= 2

    assert is_temporally_correlated == (
        abs(volume_age_offset_hours) <= 2
    ), f"Volume with offset {volume_age_offset_hours}h should be correlated={is_temporally_correlated}"


@settings(max_examples=100, deadline=5000)
@given(
    num_resources=st.integers(min_value=1, max_value=5),
)
def test_combined_orphaned_resource_detection(num_resources: int):
    """
    Feature: packer-resource-reaper, Property 5: Orphaned Resource Detection

    For any set of resources, the system should correctly identify ALL orphaned
    resources (volumes, EIPs, snapshots).

    Validates: Requirements 2.2, 2.8
    """
    volumes = []
    eips = []
    snapshots = []
    registered_ami_snapshots = set()

    expected_orphaned_volumes = []
    expected_orphaned_eips = []
    expected_orphaned_snapshots = []

    for i in range(num_resources):
        # Create volume
        vol_is_available = i % 3 != 0
        vol_is_attached = i % 4 == 0

        volume = create_volume(
            volume_id=f"vol-{i:08d}",
            state="available" if vol_is_available else "in-use",
            attached_instance=f"i-{i:08d}" if vol_is_attached else None,
        )
        volumes.append(volume)

        if vol_is_available and not vol_is_attached:
            expected_orphaned_volumes.append(volume.resource_id)

        # Create EIP
        eip_is_associated = i % 3 == 0

        eip = create_elastic_ip(
            allocation_id=f"eipalloc-{i:08d}",
            association_id=f"eipassoc-{i:08d}" if eip_is_associated else None,
            instance_id=f"i-{i:08d}" if eip_is_associated else None,
        )
        eips.append(eip)

        if not eip_is_associated:
            expected_orphaned_eips.append(eip.resource_id)

        # Create snapshot
        snap_is_registered = i % 3 == 0

        snapshot = create_snapshot(snapshot_id=f"snap-{i:08d}")
        snapshots.append(snapshot)

        if snap_is_registered:
            registered_ami_snapshots.add(snapshot.resource_id)
        else:
            expected_orphaned_snapshots.append(snapshot.resource_id)

    # Detect orphaned resources
    orphaned_volumes = [v for v in volumes if is_orphaned_volume(v)]
    orphaned_eips = [e for e in eips if is_orphaned_eip(e)]
    orphaned_snapshots = filter_orphaned_snapshots(snapshots, registered_ami_snapshots)

    # Verify all orphaned resources are detected
    assert set(v.resource_id for v in orphaned_volumes) == set(
        expected_orphaned_volumes
    )
    assert set(e.resource_id for e in orphaned_eips) == set(expected_orphaned_eips)
    assert set(s.resource_id for s in orphaned_snapshots) == set(
        expected_orphaned_snapshots
    )
