"""Dry-run execution mode for safe resource identification.

This module provides comprehensive dry-run functionality that identifies
cleanup candidates without executing destructive operations, as per
Requirements 9.1, 9.2, 9.3, 9.4.

Key features:
- Resource identification without destructive operations (Requirement 9.1)
- Comprehensive logging of planned cleanup actions (Requirement 9.2)
- Simulation report generation for SNS notifications (Requirement 9.3)
- Safety guarantee - no terminate, delete, or release API calls (Requirement 9.4)
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from reaper.models import (
    CleanupResult,
    PackerElasticIP,
    PackerInstance,
    PackerInstanceProfile,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerSnapshot,
    PackerVolume,
    ResourceCollection,
)

logger = logging.getLogger(__name__)


@dataclass
class DryRunReport:
    """Report of planned cleanup actions in dry-run mode.

    This captures all resources that would be cleaned up in live mode,
    providing comprehensive information for logging and SNS notifications
    as per Requirements 9.2 and 9.3.
    """

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    account_id: str = ""
    region: str = ""

    # Resources that would be cleaned
    instances_to_terminate: list[dict[str, Any]] = field(default_factory=list)
    security_groups_to_delete: list[dict[str, Any]] = field(default_factory=list)
    key_pairs_to_delete: list[dict[str, Any]] = field(default_factory=list)
    volumes_to_delete: list[dict[str, Any]] = field(default_factory=list)
    snapshots_to_delete: list[dict[str, Any]] = field(default_factory=list)
    elastic_ips_to_release: list[dict[str, Any]] = field(default_factory=list)
    instance_profiles_to_delete: list[dict[str, Any]] = field(default_factory=list)

    def total_resources(self) -> int:
        """Get total number of resources that would be cleaned."""
        return (
            len(self.instances_to_terminate)
            + len(self.security_groups_to_delete)
            + len(self.key_pairs_to_delete)
            + len(self.volumes_to_delete)
            + len(self.snapshots_to_delete)
            + len(self.elastic_ips_to_release)
            + len(self.instance_profiles_to_delete)
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "account_id": self.account_id,
            "region": self.region,
            "total_resources": self.total_resources(),
            "instances_to_terminate": self.instances_to_terminate,
            "security_groups_to_delete": self.security_groups_to_delete,
            "key_pairs_to_delete": self.key_pairs_to_delete,
            "volumes_to_delete": self.volumes_to_delete,
            "snapshots_to_delete": self.snapshots_to_delete,
            "elastic_ips_to_release": self.elastic_ips_to_release,
            "instance_profiles_to_delete": self.instance_profiles_to_delete,
        }


class DryRunExecutor:
    """Executes dry-run mode for safe resource identification.

    This class provides comprehensive dry-run functionality that:
    - Identifies all cleanup candidates without executing destructive operations (Requirement 9.1)
    - Logs all resources that would be deleted to CloudWatch (Requirement 9.2)
    - Generates simulation reports for SNS notifications (Requirement 9.3)
    - Guarantees no terminate, delete, or release API calls are made (Requirement 9.4)
    """

    def __init__(self, account_id: str = "", region: str = ""):
        """
        Initialize dry-run executor.

        Args:
            account_id: AWS account ID for reporting
            region: AWS region for reporting
        """
        self.account_id = account_id
        self.region = region

    def execute_dry_run(self, resources: ResourceCollection) -> tuple[CleanupResult, DryRunReport]:
        """
        Execute dry-run cleanup simulation.

        This method identifies all cleanup candidates and generates a comprehensive
        report without executing any destructive operations.

        Args:
            resources: Collection of resources to simulate cleanup for

        Returns:
            Tuple of (CleanupResult with dry_run=True, DryRunReport)
        """
        result = CleanupResult(dry_run=True)
        report = DryRunReport(
            account_id=self.account_id,
            region=self.region,
        )

        # Log start of dry-run
        logger.info(f"[DRY RUN] Starting simulation for {resources.total_count()} resources")

        # Process instances
        self._process_instances(resources.instances, result, report)

        # Process security groups
        self._process_security_groups(resources.security_groups, result, report)

        # Process key pairs
        self._process_key_pairs(resources.key_pairs, result, report)

        # Process volumes
        self._process_volumes(resources.volumes, result, report)

        # Process snapshots
        self._process_snapshots(resources.snapshots, result, report)

        # Process elastic IPs
        self._process_elastic_ips(resources.elastic_ips, result, report)

        # Process instance profiles
        self._process_instance_profiles(resources.instance_profiles, result, report)

        # Log summary
        self._log_dry_run_summary(report)

        return result, report

    def _process_instances(
        self,
        instances: list[PackerInstance],
        result: CleanupResult,
        report: DryRunReport,
    ) -> None:
        """Process instances in dry-run mode."""
        if not instances:
            return

        logger.info(f"[DRY RUN] Would terminate {len(instances)} instances:")

        for instance in instances:
            # Log planned action
            logger.info(
                f"[DRY RUN]   - {instance.resource_id} "
                f"(type: {instance.instance_type}, state: {instance.state}, "
                f"key: {instance.key_name or 'N/A'})"
            )

            # Add to result
            result.terminated_instances.append(instance.resource_id)

            # Add to report with details
            report.instances_to_terminate.append(
                {
                    "instance_id": instance.resource_id,
                    "instance_type": instance.instance_type,
                    "state": instance.state,
                    "key_name": instance.key_name,
                    "vpc_id": instance.vpc_id,
                    "security_groups": instance.security_groups,
                    "tags": instance.tags,
                    "launch_time": (
                        instance.launch_time.isoformat() if instance.launch_time else None
                    ),
                    "termination_reason": "Matches Packer key pair pattern and exceeds age threshold",
                }
            )

    def _process_security_groups(
        self,
        security_groups: list[PackerSecurityGroup],
        result: CleanupResult,
        report: DryRunReport,
    ) -> None:
        """Process security groups in dry-run mode."""
        if not security_groups:
            return

        logger.info(f"[DRY RUN] Would delete {len(security_groups)} security groups:")

        for sg in security_groups:
            logger.info(f"[DRY RUN]   - {sg.resource_id} ({sg.group_name})")

            result.deleted_security_groups.append(sg.resource_id)

            report.security_groups_to_delete.append(
                {
                    "group_id": sg.resource_id,
                    "group_name": sg.group_name,
                    "vpc_id": sg.vpc_id,
                    "description": sg.description,
                    "tags": sg.tags,
                }
            )

    def _process_key_pairs(
        self,
        key_pairs: list[PackerKeyPair],
        result: CleanupResult,
        report: DryRunReport,
    ) -> None:
        """Process key pairs in dry-run mode."""
        if not key_pairs:
            return

        logger.info(f"[DRY RUN] Would delete {len(key_pairs)} key pairs:")

        for kp in key_pairs:
            logger.info(f"[DRY RUN]   - {kp.key_name}")

            result.deleted_key_pairs.append(kp.key_name)

            report.key_pairs_to_delete.append(
                {
                    "key_pair_id": kp.resource_id,
                    "key_name": kp.key_name,
                    "key_fingerprint": kp.key_fingerprint,
                    "tags": kp.tags,
                }
            )

    def _process_volumes(
        self,
        volumes: list[PackerVolume],
        result: CleanupResult,
        report: DryRunReport,
    ) -> None:
        """Process volumes in dry-run mode."""
        if not volumes:
            return

        logger.info(f"[DRY RUN] Would delete {len(volumes)} volumes:")

        for volume in volumes:
            logger.info(
                f"[DRY RUN]   - {volume.resource_id} ({volume.size} GB, state: {volume.state})"
            )

            result.deleted_volumes.append(volume.resource_id)

            report.volumes_to_delete.append(
                {
                    "volume_id": volume.resource_id,
                    "size_gb": volume.size,
                    "state": volume.state,
                    "attached_instance": volume.attached_instance,
                    "snapshot_id": volume.snapshot_id,
                    "tags": volume.tags,
                }
            )

    def _process_snapshots(
        self,
        snapshots: list[PackerSnapshot],
        result: CleanupResult,
        report: DryRunReport,
    ) -> None:
        """Process snapshots in dry-run mode."""
        if not snapshots:
            return

        logger.info(f"[DRY RUN] Would delete {len(snapshots)} snapshots:")

        for snapshot in snapshots:
            logger.info(
                f"[DRY RUN]   - {snapshot.resource_id} "
                f"(volume: {snapshot.volume_id}, state: {snapshot.state})"
            )

            result.deleted_snapshots.append(snapshot.resource_id)

            report.snapshots_to_delete.append(
                {
                    "snapshot_id": snapshot.resource_id,
                    "volume_id": snapshot.volume_id,
                    "state": snapshot.state,
                    "progress": snapshot.progress,
                    "tags": snapshot.tags,
                }
            )

    def _process_elastic_ips(
        self,
        elastic_ips: list[PackerElasticIP],
        result: CleanupResult,
        report: DryRunReport,
    ) -> None:
        """Process elastic IPs in dry-run mode."""
        if not elastic_ips:
            return

        logger.info(f"[DRY RUN] Would release {len(elastic_ips)} elastic IPs:")

        for eip in elastic_ips:
            logger.info(f"[DRY RUN]   - {eip.allocation_id} ({eip.public_ip})")

            result.released_elastic_ips.append(eip.allocation_id)

            report.elastic_ips_to_release.append(
                {
                    "allocation_id": eip.allocation_id,
                    "public_ip": eip.public_ip,
                    "association_id": eip.association_id,
                    "instance_id": eip.instance_id,
                    "tags": eip.tags,
                }
            )

    def _process_instance_profiles(
        self,
        instance_profiles: list[PackerInstanceProfile],
        result: CleanupResult,
        report: DryRunReport,
    ) -> None:
        """Process instance profiles in dry-run mode."""
        if not instance_profiles:
            return

        logger.info(f"[DRY RUN] Would delete {len(instance_profiles)} instance profiles:")

        for profile in instance_profiles:
            logger.info(
                f"[DRY RUN]   - {profile.instance_profile_name} (roles: {profile.roles or 'none'})"
            )

            result.deleted_instance_profiles.append(profile.instance_profile_name)

            report.instance_profiles_to_delete.append(
                {
                    "instance_profile_id": profile.instance_profile_id,
                    "instance_profile_name": profile.instance_profile_name,
                    "arn": profile.arn,
                    "path": profile.path,
                    "roles": profile.roles,
                }
            )

    def _log_dry_run_summary(self, report: DryRunReport) -> None:
        """Log comprehensive dry-run summary to CloudWatch."""
        logger.info("=" * 60)
        logger.info("[DRY RUN] SIMULATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"[DRY RUN] Account: {report.account_id}")
        logger.info(f"[DRY RUN] Region: {report.region}")
        logger.info(f"[DRY RUN] Timestamp: {report.timestamp.isoformat()}")
        logger.info("-" * 40)
        logger.info(f"[DRY RUN] Total resources that would be cleaned: {report.total_resources()}")
        logger.info(f"[DRY RUN]   - Instances to terminate: {len(report.instances_to_terminate)}")
        logger.info(
            f"[DRY RUN]   - Security groups to delete: {len(report.security_groups_to_delete)}"
        )
        logger.info(f"[DRY RUN]   - Key pairs to delete: {len(report.key_pairs_to_delete)}")
        logger.info(f"[DRY RUN]   - Volumes to delete: {len(report.volumes_to_delete)}")
        logger.info(f"[DRY RUN]   - Snapshots to delete: {len(report.snapshots_to_delete)}")
        logger.info(f"[DRY RUN]   - Elastic IPs to release: {len(report.elastic_ips_to_release)}")
        logger.info(
            f"[DRY RUN]   - Instance profiles to delete: {len(report.instance_profiles_to_delete)}"
        )
        logger.info("=" * 60)
        logger.info("[DRY RUN] No destructive operations were executed")
        logger.info("=" * 60)


def is_dry_run_enabled(config: Any) -> bool:
    """
    Check if dry-run mode is enabled in configuration.

    This provides a centralized check for dry-run mode status
    as per Requirement 9.5 (explicit configuration change required).

    Args:
        config: ReaperConfig instance

    Returns:
        True if dry-run mode is enabled, False otherwise
    """
    return getattr(config, "dry_run", False)


def log_dry_run_planned_action(
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any] | None = None,
) -> None:
    """
    Log a planned action in dry-run mode.

    This provides comprehensive logging of planned cleanup actions
    as per Requirement 9.2.

    Args:
        action: The action that would be performed (e.g., "terminate", "delete", "release")
        resource_type: Type of resource (e.g., "instance", "security_group")
        resource_id: ID of the resource
        details: Optional additional details about the resource
    """
    detail_str = ""
    if details:
        detail_parts = [f"{k}={v}" for k, v in details.items() if v is not None]
        if detail_parts:
            detail_str = f" ({', '.join(detail_parts)})"

    logger.info(f"[DRY RUN] Would {action} {resource_type} {resource_id}{detail_str}")
