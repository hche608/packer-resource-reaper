"""Storage management for EBS volumes and snapshots cleanup.

This module provides EBS volume and snapshot management functionality
for the Packer Resource Reaper. It handles volume identification for
instances being terminated and cleanup operations as per Requirements 2.2, 2.8.
"""

import logging
from typing import Any

from reaper.models import PackerSnapshot, PackerVolume, ResourceType

logger = logging.getLogger(__name__)


class StorageManager:
    """Manages EBS volume and snapshot cleanup operations.

    Handles:
    - Volume identification for instances being terminated (Requirement 2.2)
    - Cleanup operations for attached volumes (Requirement 2.8)
    - Snapshot cleanup with AMI protection
    """

    def __init__(self, ec2_client: Any, dry_run: bool = False):
        """
        Initialize storage manager.

        Args:
            ec2_client: Boto3 EC2 client
            dry_run: If True, simulate operations without executing
        """
        self.ec2 = ec2_client
        self.dry_run = dry_run

    def get_volumes_for_instance(
        self, instance_id: str, account_id: str, region: str
    ) -> list[PackerVolume]:
        """
        Get EBS volumes attached to a specific instance.

        This identifies volumes that are directly associated with an instance
        for cleanup after termination (Requirement 2.2).

        Args:
            instance_id: EC2 instance ID
            account_id: AWS account ID
            region: AWS region

        Returns:
            List of PackerVolume objects attached to the instance
        """
        volumes = []
        try:
            response = self.ec2.describe_volumes(
                Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
            )
            for volume in response.get("Volumes", []):
                tags = {t["Key"]: t["Value"] for t in volume.get("Tags", [])}

                attachments = volume.get("Attachments", [])
                attached_instance = attachments[0]["InstanceId"] if attachments else None

                volumes.append(
                    PackerVolume(
                        resource_id=volume["VolumeId"],
                        resource_type=ResourceType.VOLUME,
                        creation_time=volume["CreateTime"],
                        tags=tags,
                        region=region,
                        account_id=account_id,
                        size=volume["Size"],
                        state=volume["State"],
                        attached_instance=attached_instance,
                        snapshot_id=volume.get("SnapshotId"),
                    )
                )
        except Exception as e:
            logger.error(f"Error getting volumes for instance {instance_id}: {e}")

        return volumes

    def get_volumes_by_ids(
        self, volume_ids: list[str], account_id: str, region: str
    ) -> list[PackerVolume]:
        """
        Get EBS volumes by their IDs.

        Args:
            volume_ids: List of volume IDs to retrieve
            account_id: AWS account ID
            region: AWS region

        Returns:
            List of PackerVolume objects
        """
        if not volume_ids:
            return []

        volumes = []
        try:
            response = self.ec2.describe_volumes(VolumeIds=volume_ids)
            for volume in response.get("Volumes", []):
                tags = {t["Key"]: t["Value"] for t in volume.get("Tags", [])}

                attachments = volume.get("Attachments", [])
                attached_instance = attachments[0]["InstanceId"] if attachments else None

                volumes.append(
                    PackerVolume(
                        resource_id=volume["VolumeId"],
                        resource_type=ResourceType.VOLUME,
                        creation_time=volume["CreateTime"],
                        tags=tags,
                        region=region,
                        account_id=account_id,
                        size=volume["Size"],
                        state=volume["State"],
                        attached_instance=attached_instance,
                        snapshot_id=volume.get("SnapshotId"),
                    )
                )
        except Exception as e:
            logger.error(f"Error getting volumes by IDs: {e}")

        return volumes

    def scan_volumes(
        self,
        account_id: str,
        region: str,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[PackerVolume]:
        """
        Scan all EBS volumes in the account.

        Args:
            account_id: AWS account ID
            region: AWS region
            filters: Optional list of EC2 filters

        Returns:
            List of PackerVolume objects
        """
        volumes = []
        try:
            paginator = self.ec2.get_paginator("describe_volumes")
            paginate_kwargs = {}
            if filters:
                paginate_kwargs["Filters"] = filters

            for page in paginator.paginate(**paginate_kwargs):
                for volume in page.get("Volumes", []):
                    tags = {t["Key"]: t["Value"] for t in volume.get("Tags", [])}

                    attachments = volume.get("Attachments", [])
                    attached_instance = attachments[0]["InstanceId"] if attachments else None

                    volumes.append(
                        PackerVolume(
                            resource_id=volume["VolumeId"],
                            resource_type=ResourceType.VOLUME,
                            creation_time=volume["CreateTime"],
                            tags=tags,
                            region=region,
                            account_id=account_id,
                            size=volume["Size"],
                            state=volume["State"],
                            attached_instance=attached_instance,
                            snapshot_id=volume.get("SnapshotId"),
                        )
                    )
        except Exception as e:
            logger.error(f"Error scanning volumes: {e}")

        logger.info(f"Scanned {len(volumes)} volumes")
        return volumes

    def delete_volumes(
        self, volumes: list[PackerVolume]
    ) -> tuple[list[str], list[str], dict[str, str]]:
        """
        Delete EBS volumes.

        Args:
            volumes: List of volumes to delete

        Returns:
            Tuple of (deleted_ids, deferred_ids, errors)
        """
        deleted = []
        deferred = []
        errors = {}

        for volume in volumes:
            try:
                result = self._delete_volume(volume)
                if result == "deleted":
                    deleted.append(volume.resource_id)
                elif result == "deferred":
                    deferred.append(volume.resource_id)
            except Exception as e:
                logger.error(f"Error deleting volume {volume.resource_id}: {e}")
                errors[volume.resource_id] = str(e)

        return deleted, deferred, errors

    def _delete_volume(self, volume: PackerVolume) -> str:
        """
        Delete a single volume.

        Returns:
            "deleted" if successful, "deferred" if attached
        """
        volume_id = volume.resource_id

        # Check if volume is attached
        if volume.attached_instance:
            logger.info(f"Volume {volume_id} attached to {volume.attached_instance}, deferring")
            return "deferred"

        # Check volume state
        if volume.state != "available":
            logger.info(f"Volume {volume_id} not available (state: {volume.state})")
            return "deferred"

        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete volume {volume_id}")
            return "deleted"

        logger.info(f"Deleting volume {volume_id}")
        self.ec2.delete_volume(VolumeId=volume_id)
        return "deleted"

    def delete_snapshots(
        self, snapshots: list[PackerSnapshot], registered_ami_snapshots: set[str] | None = None
    ) -> tuple[list[str], list[str], dict[str, str]]:
        """
        Delete EBS snapshots.

        Args:
            snapshots: List of snapshots to delete
            registered_ami_snapshots: Set of snapshot IDs used by registered AMIs

        Returns:
            Tuple of (deleted_ids, deferred_ids, errors)
        """
        deleted = []
        deferred = []
        errors = {}
        registered_ami_snapshots = registered_ami_snapshots or set()

        for snapshot in snapshots:
            try:
                result = self._delete_snapshot(snapshot, registered_ami_snapshots)
                if result == "deleted":
                    deleted.append(snapshot.resource_id)
                elif result == "deferred":
                    deferred.append(snapshot.resource_id)
            except Exception as e:
                logger.error(f"Error deleting snapshot {snapshot.resource_id}: {e}")
                errors[snapshot.resource_id] = str(e)

        return deleted, deferred, errors

    def _delete_snapshot(self, snapshot: PackerSnapshot, registered_ami_snapshots: set[str]) -> str:
        """
        Delete a single snapshot.

        Returns:
            "deleted" if successful, "deferred" if used by AMI
        """
        snapshot_id = snapshot.resource_id

        # Check if snapshot is used by a registered AMI
        if snapshot_id in registered_ami_snapshots:
            logger.info(f"Snapshot {snapshot_id} used by registered AMI, skipping")
            return "deferred"

        # Check snapshot state
        if snapshot.state != "completed":
            logger.info(f"Snapshot {snapshot_id} not completed (state: {snapshot.state})")
            return "deferred"

        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete snapshot {snapshot_id}")
            return "deleted"

        logger.info(f"Deleting snapshot {snapshot_id}")
        self.ec2.delete_snapshot(SnapshotId=snapshot_id)
        return "deleted"

    def get_registered_ami_snapshots(self) -> set[str]:
        """Get set of snapshot IDs used by registered AMIs."""
        snapshot_ids = set()

        try:
            paginator = self.ec2.get_paginator("describe_images")
            for page in paginator.paginate(Owners=["self"]):
                for image in page.get("Images", []):
                    for block_device in image.get("BlockDeviceMappings", []):
                        ebs = block_device.get("Ebs", {})
                        snapshot_id = ebs.get("SnapshotId")
                        if snapshot_id:
                            snapshot_ids.add(snapshot_id)
        except Exception as e:
            logger.error(f"Error getting registered AMI snapshots: {e}")

        return snapshot_ids
