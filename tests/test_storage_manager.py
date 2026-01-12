"""Tests for storage manager functionality.

Tests for volume and snapshot management.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

from reaper.cleanup.storage_manager import StorageManager
from reaper.models import PackerSnapshot, PackerVolume, ResourceType


def create_packer_volume(
    volume_id: str,
    state: str = "available",
    attached_instance: str = None,
    snapshot_id: str = None,
) -> PackerVolume:
    """Create a PackerVolume for testing."""
    return PackerVolume(
        resource_id=volume_id,
        resource_type=ResourceType.VOLUME,
        creation_time=datetime.now(UTC),
        tags={"Name": "Packer Volume"},
        region="us-east-1",
        account_id="123456789012",
        size=8,
        state=state,
        attached_instance=attached_instance,
        snapshot_id=snapshot_id,
    )


def create_packer_snapshot(
    snapshot_id: str,
    state: str = "completed",
    volume_id: str = "vol-12345678",
) -> PackerSnapshot:
    """Create a PackerSnapshot for testing."""
    return PackerSnapshot(
        resource_id=snapshot_id,
        resource_type=ResourceType.SNAPSHOT,
        creation_time=datetime.now(UTC),
        tags={"Name": "Packer Snapshot"},
        region="us-east-1",
        account_id="123456789012",
        volume_id=volume_id,
        state=state,
        progress="100%",
        owner_id="123456789012",
    )


class TestStorageManagerGetVolumesForInstance:
    """Tests for get_volumes_for_instance method."""

    def test_get_volumes_success(self):
        """Test getting volumes for instance successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.return_value = {
            "Volumes": [
                {
                    "VolumeId": "vol-001",
                    "Size": 8,
                    "State": "in-use",
                    "CreateTime": datetime.now(UTC),
                    "Attachments": [{"InstanceId": "i-001"}],
                    "Tags": [{"Key": "Name", "Value": "Packer Volume"}],
                },
                {
                    "VolumeId": "vol-002",
                    "Size": 16,
                    "State": "in-use",
                    "CreateTime": datetime.now(UTC),
                    "Attachments": [{"InstanceId": "i-001"}],
                    "Tags": [],
                },
            ]
        }

        manager = StorageManager(mock_ec2)
        volumes = manager.get_volumes_for_instance("i-001", "123456789012", "us-east-1")

        assert len(volumes) == 2
        assert volumes[0].resource_id == "vol-001"
        assert volumes[0].attached_instance == "i-001"

    def test_get_volumes_handles_exception(self):
        """Test getting volumes handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.side_effect = Exception("API error")

        manager = StorageManager(mock_ec2)
        volumes = manager.get_volumes_for_instance("i-001", "123456789012", "us-east-1")

        assert len(volumes) == 0


class TestStorageManagerGetVolumesByIds:
    """Tests for get_volumes_by_ids method."""

    def test_get_volumes_by_ids_success(self):
        """Test getting volumes by IDs successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.return_value = {
            "Volumes": [
                {
                    "VolumeId": "vol-001",
                    "Size": 8,
                    "State": "available",
                    "CreateTime": datetime.now(UTC),
                    "Attachments": [],
                    "Tags": [],
                }
            ]
        }

        manager = StorageManager(mock_ec2)
        volumes = manager.get_volumes_by_ids(["vol-001"], "123456789012", "us-east-1")

        assert len(volumes) == 1
        assert volumes[0].resource_id == "vol-001"

    def test_get_volumes_by_ids_empty_list(self):
        """Test getting volumes with empty list."""
        mock_ec2 = MagicMock()
        manager = StorageManager(mock_ec2)

        volumes = manager.get_volumes_by_ids([], "123456789012", "us-east-1")

        assert len(volumes) == 0
        mock_ec2.describe_volumes.assert_not_called()

    def test_get_volumes_by_ids_handles_exception(self):
        """Test getting volumes by IDs handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.side_effect = Exception("API error")

        manager = StorageManager(mock_ec2)
        volumes = manager.get_volumes_by_ids(["vol-001"], "123456789012", "us-east-1")

        assert len(volumes) == 0


class TestStorageManagerScanVolumes:
    """Tests for scan_volumes method."""

    def test_scan_volumes_success(self):
        """Test scanning volumes successfully."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Volumes": [
                    {
                        "VolumeId": "vol-001",
                        "Size": 8,
                        "State": "available",
                        "CreateTime": datetime.now(UTC),
                        "Attachments": [],
                        "Tags": [],
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = StorageManager(mock_ec2)
        volumes = manager.scan_volumes("123456789012", "us-east-1")

        assert len(volumes) == 1

    def test_scan_volumes_with_filters(self):
        """Test scanning volumes with filters."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Volumes": []}]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = StorageManager(mock_ec2)
        filters = [{"Name": "status", "Values": ["available"]}]
        manager.scan_volumes("123456789012", "us-east-1", filters=filters)

        mock_paginator.paginate.assert_called_with(Filters=filters)

    def test_scan_volumes_handles_exception(self):
        """Test scanning volumes handles exceptions."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = StorageManager(mock_ec2)
        volumes = manager.scan_volumes("123456789012", "us-east-1")

        assert len(volumes) == 0


class TestStorageManagerDeleteVolumes:
    """Tests for delete_volumes method."""

    def test_delete_volumes_success(self):
        """Test deleting volumes successfully."""
        mock_ec2 = MagicMock()
        manager = StorageManager(mock_ec2, dry_run=False)

        volumes = [
            create_packer_volume("vol-001", state="available"),
            create_packer_volume("vol-002", state="available"),
        ]

        deleted, deferred, errors = manager.delete_volumes(volumes)

        assert len(deleted) == 2
        assert len(deferred) == 0
        assert len(errors) == 0

    def test_delete_volumes_dry_run(self):
        """Test deleting volumes in dry run mode."""
        mock_ec2 = MagicMock()
        manager = StorageManager(mock_ec2, dry_run=True)

        volumes = [create_packer_volume("vol-001", state="available")]

        deleted, deferred, errors = manager.delete_volumes(volumes)

        assert len(deleted) == 1
        mock_ec2.delete_volume.assert_not_called()

    def test_delete_volumes_attached(self):
        """Test deleting attached volumes defers them."""
        mock_ec2 = MagicMock()
        manager = StorageManager(mock_ec2, dry_run=False)

        volumes = [create_packer_volume("vol-001", attached_instance="i-001")]

        deleted, deferred, errors = manager.delete_volumes(volumes)

        assert len(deleted) == 0
        assert len(deferred) == 1
        mock_ec2.delete_volume.assert_not_called()

    def test_delete_volumes_not_available(self):
        """Test deleting volumes not in available state defers them."""
        mock_ec2 = MagicMock()
        manager = StorageManager(mock_ec2, dry_run=False)

        volumes = [create_packer_volume("vol-001", state="in-use")]

        deleted, deferred, errors = manager.delete_volumes(volumes)

        assert len(deleted) == 0
        assert len(deferred) == 1

    def test_delete_volumes_error(self):
        """Test deleting volumes handles errors."""
        mock_ec2 = MagicMock()
        mock_ec2.delete_volume.side_effect = Exception("API error")
        manager = StorageManager(mock_ec2, dry_run=False)

        volumes = [create_packer_volume("vol-001", state="available")]

        deleted, deferred, errors = manager.delete_volumes(volumes)

        assert len(deleted) == 0
        assert len(errors) == 1


class TestStorageManagerDeleteSnapshots:
    """Tests for delete_snapshots method."""

    def test_delete_snapshots_success(self):
        """Test deleting snapshots successfully."""
        mock_ec2 = MagicMock()
        manager = StorageManager(mock_ec2, dry_run=False)

        snapshots = [
            create_packer_snapshot("snap-001"),
            create_packer_snapshot("snap-002"),
        ]

        deleted, deferred, errors = manager.delete_snapshots(snapshots)

        assert len(deleted) == 2
        assert len(deferred) == 0
        assert len(errors) == 0

    def test_delete_snapshots_dry_run(self):
        """Test deleting snapshots in dry run mode."""
        mock_ec2 = MagicMock()
        manager = StorageManager(mock_ec2, dry_run=True)

        snapshots = [create_packer_snapshot("snap-001")]

        deleted, deferred, errors = manager.delete_snapshots(snapshots)

        assert len(deleted) == 1
        mock_ec2.delete_snapshot.assert_not_called()

    def test_delete_snapshots_used_by_ami(self):
        """Test deleting snapshots used by AMI defers them."""
        mock_ec2 = MagicMock()
        manager = StorageManager(mock_ec2, dry_run=False)

        snapshots = [create_packer_snapshot("snap-001")]
        registered_ami_snapshots = {"snap-001"}

        deleted, deferred, errors = manager.delete_snapshots(snapshots, registered_ami_snapshots)

        assert len(deleted) == 0
        assert len(deferred) == 1
        mock_ec2.delete_snapshot.assert_not_called()

    def test_delete_snapshots_not_completed(self):
        """Test deleting snapshots not in completed state defers them."""
        mock_ec2 = MagicMock()
        manager = StorageManager(mock_ec2, dry_run=False)

        snapshots = [create_packer_snapshot("snap-001", state="pending")]

        deleted, deferred, errors = manager.delete_snapshots(snapshots)

        assert len(deleted) == 0
        assert len(deferred) == 1

    def test_delete_snapshots_error(self):
        """Test deleting snapshots handles errors."""
        mock_ec2 = MagicMock()
        mock_ec2.delete_snapshot.side_effect = Exception("API error")
        manager = StorageManager(mock_ec2, dry_run=False)

        snapshots = [create_packer_snapshot("snap-001")]

        deleted, deferred, errors = manager.delete_snapshots(snapshots)

        assert len(deleted) == 0
        assert len(errors) == 1


class TestStorageManagerGetRegisteredAMISnapshots:
    """Tests for get_registered_ami_snapshots method."""

    def test_get_registered_ami_snapshots_success(self):
        """Test getting registered AMI snapshots successfully."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Images": [
                    {
                        "ImageId": "ami-001",
                        "BlockDeviceMappings": [
                            {"Ebs": {"SnapshotId": "snap-001"}},
                            {"Ebs": {"SnapshotId": "snap-002"}},
                        ],
                    },
                    {
                        "ImageId": "ami-002",
                        "BlockDeviceMappings": [
                            {"Ebs": {"SnapshotId": "snap-003"}},
                            {"DeviceName": "/dev/sdb"},  # No Ebs
                        ],
                    },
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = StorageManager(mock_ec2)
        snapshot_ids = manager.get_registered_ami_snapshots()

        assert len(snapshot_ids) == 3
        assert "snap-001" in snapshot_ids
        assert "snap-002" in snapshot_ids
        assert "snap-003" in snapshot_ids

    def test_get_registered_ami_snapshots_empty(self):
        """Test getting registered AMI snapshots when none exist."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Images": []}]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = StorageManager(mock_ec2)
        snapshot_ids = manager.get_registered_ami_snapshots()

        assert len(snapshot_ids) == 0

    def test_get_registered_ami_snapshots_handles_exception(self):
        """Test getting registered AMI snapshots handles exceptions."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = StorageManager(mock_ec2)
        snapshot_ids = manager.get_registered_ami_snapshots()

        assert len(snapshot_ids) == 0
