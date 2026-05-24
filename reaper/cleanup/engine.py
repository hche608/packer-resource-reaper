"""Cleanup orchestration engine with dependency-aware sequencing.

This module implements the cleanup orchestration engine that executes
resource cleanup in a dependency-aware order as per Requirements 2.1-2.8.

Key features:
- Collects directly associated resources before termination (Requirement 2.2)
- Terminates instances and waits for confirmation (Requirement 2.3, 2.5)
- Handles state-based deferral for shutting-down instances (Requirement 2.7)
- Only deletes resources directly associated with terminated instances (Requirement 2.8)
- Implements exponential backoff with jitter for AWS API calls (Requirement 6.2)
- Handles DependencyViolation errors gracefully (Requirement 2.6, 6.1)
- Dry-run mode for safe resource identification (Requirements 9.1-9.4)
- IAM instance profile cleanup for profiles matching `packer_*` pattern (Requirement 2.4)
- Two-phase cleanup: primary zombie cleanup followed by orphaned resource cleanup (Requirement 10.7)
- Batch delete operations for concurrent deletions (Requirements 12.1-12.7)
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from botocore.exceptions import ClientError

from reaper.cleanup.batch_processor import BatchProcessor
from reaper.cleanup.dry_run import DryRunExecutor, DryRunReport
from reaper.cleanup.ec2_manager import EC2Manager
from reaper.cleanup.iam_manager import IAMManager
from reaper.cleanup.network_manager import NetworkManager
from reaper.cleanup.orphan_manager import (
    OrphanCleanupResult,
    OrphanManager,
)
from reaper.cleanup.storage_manager import StorageManager
from reaper.models import (
    CleanupResult,
    PackerInstance,
    ResourceCollection,
)
from reaper.utils.aws_client import RetryStrategy

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Error code indicating a resource still has dependencies
_DEPENDENCY_VIOLATION = "DependencyViolation"


@dataclass
class AssociatedResources:
    """Resources directly associated with a zombie instance.

    This tracks resources that should be cleaned up after instance termination
    as per Requirement 2.2.
    """

    instance_id: str
    security_group_ids: list[str] = field(default_factory=list)
    key_pair_name: str | None = None
    volume_ids: list[str] = field(default_factory=list)
    eip_allocation_ids: list[str] = field(default_factory=list)


class CleanupEngine:
    """Orchestrates resource cleanup with dependency awareness.

    Implements dependency-aware cleanup sequencing as per Requirements 2.1-2.8:
    1. Identify zombie instances (Requirement 2.1)
    2. Collect directly associated resources before termination (Requirement 2.2)
    3. Terminate instances and wait for confirmation (Requirement 2.3, 2.5)
    4. Delete associated resources after termination (Requirement 2.4)
    5. Handle DependencyViolation gracefully (Requirement 2.6)
    6. Defer shutting-down instances to next execution (Requirement 2.7)
    7. Only delete directly associated resources (Requirement 2.8)

    Error handling (Requirements 6.1, 6.2, 6.3):
    - DependencyViolation errors are logged and deferred to next execution
    - API rate limits are handled with exponential backoff retry logic
    - All errors are logged with detailed information to CloudWatch
    """

    # Instance states that indicate termination is in progress
    SHUTTING_DOWN_STATE = "shutting-down"
    TERMINATED_STATE = "terminated"

    def __init__(
        self,
        ec2_client: Any,
        dry_run: bool = False,
        retry_strategy: RetryStrategy | None = None,
        account_id: str = "",
        region: str = "",
        iam_client: Any | None = None,
        batch_delete_size: int = 1,
        max_resource_age_hours: int = 2,
    ):
        """
        Initialize cleanup engine.

        Args:
            ec2_client: Boto3 EC2 client
            dry_run: If True, simulate operations without executing
            retry_strategy: Optional retry strategy for AWS API calls
            account_id: AWS account ID for dry-run reporting
            region: AWS region for dry-run reporting
            iam_client: Optional Boto3 IAM client for instance profile cleanup
            batch_delete_size: Batch size for concurrent deletions (Requirement 12.1)
            max_resource_age_hours: Age threshold for orphaned resources (default: 2)
        """
        self.dry_run = dry_run
        self.ec2_client = ec2_client
        self.iam_client = iam_client
        self.account_id = account_id
        self.region = region
        self.batch_delete_size = max(1, batch_delete_size)
        self.max_resource_age_hours = max(1, max_resource_age_hours)
        self.retry_strategy = retry_strategy or RetryStrategy(
            max_retries=3,
            base_delay=1.0,
            max_delay=60.0,
            jitter=True,
        )

        # Initialize batch processor (Requirements 12.1-12.7)
        self.batch_processor = BatchProcessor(batch_size=self.batch_delete_size)

        # Initialize resource managers
        self.ec2_manager = EC2Manager(ec2_client, dry_run)
        self.storage_manager = StorageManager(ec2_client, dry_run)
        self.network_manager = NetworkManager(ec2_client, dry_run)

        # Initialize IAM manager if client is provided
        self.iam_manager = IAMManager(iam_client, dry_run) if iam_client else None

        # Initialize orphan manager for Phase 2 cleanup (Requirement 10.7)
        # Pass age threshold to prevent race conditions with active Packer builds
        self.orphan_manager = OrphanManager(ec2_client, iam_client, dry_run, max_resource_age_hours)

        # Initialize dry-run executor for comprehensive logging
        self.dry_run_executor = DryRunExecutor(
            account_id=account_id,
            region=region,
        )

        # Store last orphan cleanup result for notifications
        self._last_orphan_cleanup_result: OrphanCleanupResult | None = None

    def cleanup_resources(self, resources: ResourceCollection) -> CleanupResult:
        """
        Execute cleanup operations in dependency-aware order.

        Two-Phase Cleanup Model (per Requirements 2.1-2.8 and 10.7):

        Phase 1 - Primary Zombie Instance Cleanup:
        1. Terminate EC2 instances and wait for confirmation
        2. Delete security groups (handle DependencyViolation gracefully)
        3. Delete key pairs
        4. Release elastic IPs
        5. Delete EBS volumes and snapshots
        6. Delete IAM instance profiles (with role detachment)

        Phase 2 - Orphaned Resource Cleanup (Requirement 10.7):
        7. Scan and delete orphaned Packer key pairs, security groups, IAM roles

        In dry-run mode (Requirements 9.1-9.4, 10.8):
        - Identifies all cleanup candidates without executing destructive operations
        - Logs all resources that would be deleted to CloudWatch
        - Does NOT execute any terminate, delete, or release API calls

        Args:
            resources: Collection of resources to clean up

        Returns:
            CleanupResult with details of operations performed
        """
        if self.dry_run:
            return self._execute_dry_run(resources)

        return self._execute_live_cleanup(resources)

    def get_last_orphan_cleanup_result(self) -> OrphanCleanupResult | None:
        """Get the last orphan cleanup result for SNS notifications (Requirement 10.10)."""
        return self._last_orphan_cleanup_result

    def get_last_dry_run_report(self) -> DryRunReport | None:
        """Get the last dry-run report for SNS notifications (Requirement 9.3)."""
        return getattr(self, "_last_dry_run_report", None)

    # -------------------------------------------------------------------------
    # Execution modes
    # -------------------------------------------------------------------------

    def _execute_dry_run(self, resources: ResourceCollection) -> CleanupResult:
        """Execute cleanup in dry-run mode (Requirements 9.1-9.4, 10.8)."""
        result, report = self.dry_run_executor.execute_dry_run(resources)
        self._last_dry_run_report = report

        # Also scan for orphaned resources in dry-run mode
        orphaned = self.orphan_manager.scan_orphaned_resources()
        orphan_result = self.orphan_manager.cleanup_orphaned_resources(orphaned)
        self._last_orphan_cleanup_result = orphan_result
        self._merge_orphan_results(result, orphan_result)

        return result

    def _execute_live_cleanup(self, resources: ResourceCollection) -> CleanupResult:
        """Execute live cleanup in two phases."""
        result = CleanupResult(dry_run=False)

        # Phase 1: Primary zombie instance cleanup
        if resources.is_empty():
            logger.info("No resources to clean up in Phase 1")
        else:
            logger.info(f"Phase 1: Starting cleanup of {resources.total_count()} resources")

            if resources.instances:
                self._cleanup_instances_with_dependencies(resources, result)
            if resources.security_groups:
                self._cleanup_security_groups(resources, result)
            if resources.key_pairs:
                self._cleanup_key_pairs(resources, result)
            if resources.elastic_ips:
                self._cleanup_elastic_ips(resources, result)
            if resources.volumes:
                self._cleanup_volumes(resources, result)
            if resources.snapshots:
                self._cleanup_snapshots(resources, result)
            if resources.instance_profiles:
                self._cleanup_instance_profiles(resources, result)

            logger.info(
                f"Phase 1 complete: {result.total_cleaned()} resources cleaned, "
                f"{len(result.deferred_resources)} deferred, {len(result.errors)} errors"
            )

        # Phase 2: Orphaned Resource Cleanup (Requirement 10.7)
        logger.info("Phase 2: Starting orphaned resource cleanup")
        orphaned = self.orphan_manager.scan_orphaned_resources()
        orphan_result = self.orphan_manager.cleanup_orphaned_resources(orphaned)
        self._last_orphan_cleanup_result = orphan_result
        self._merge_orphan_results(result, orphan_result)

        logger.info(
            f"Cleanup complete: {result.total_cleaned()} total resources cleaned, "
            f"{len(result.deferred_resources)} deferred, {len(result.errors)} errors"
        )

        return result

    # -------------------------------------------------------------------------
    # Resource cleanup methods
    # -------------------------------------------------------------------------

    def _cleanup_instances_with_dependencies(
        self, resources: ResourceCollection, result: CleanupResult
    ) -> None:
        """Terminate EC2 instances with dependency-aware handling (Requirements 2.1-2.7)."""
        logger.info(f"Processing {len(resources.instances)} instances")

        instances_to_terminate = []

        for instance in resources.instances:
            if self._should_defer_instance(instance):
                logger.info(
                    f"Instance {instance.resource_id} in shutting-down state, "
                    "deferring to next execution"
                )
                result.deferred_resources.append(instance.resource_id)
            elif instance.state.lower() == self.TERMINATED_STATE:
                logger.info(f"Instance {instance.resource_id} already terminated")
                result.terminated_instances.append(instance.resource_id)
            else:
                instances_to_terminate.append(instance)

        if not instances_to_terminate:
            logger.info("No instances to terminate")
            return

        terminated, deferred, errors = self.ec2_manager.terminate_instances(instances_to_terminate)
        result.terminated_instances.extend(terminated)
        result.deferred_resources.extend(deferred)
        result.errors.update(errors)

        # Wait for termination confirmation (Requirement 2.5)
        if terminated:
            logger.info("Waiting for instance termination confirmation...")
            self.ec2_manager.wait_for_termination(terminated, timeout_seconds=120)

    def _cleanup_security_groups(
        self, resources: ResourceCollection, result: CleanupResult
    ) -> None:
        """Delete security groups, using batch processor when configured."""
        logger.info(f"Deleting {len(resources.security_groups)} security groups")

        if self._should_use_batch(len(resources.security_groups)):
            sg_ids = [sg.resource_id for sg in resources.security_groups]
            batch_result = self.batch_processor.process_deletions(
                resources=sg_ids,
                delete_func=self._make_sg_deleter(),
                resource_type="security_group",
            )
            result.deleted_security_groups.extend(batch_result.successful)
            # Separate DependencyViolation errors into deferred
            for resource_id, error_msg in list(batch_result.errors.items()):
                if _DEPENDENCY_VIOLATION in error_msg:
                    result.deferred_resources.append(resource_id)
                else:
                    result.errors[resource_id] = error_msg
        else:
            deleted, deferred, errors = self.network_manager.delete_security_groups(
                resources.security_groups
            )
            result.deleted_security_groups.extend(deleted)
            result.deferred_resources.extend(deferred)
            result.errors.update(errors)

    def _cleanup_key_pairs(self, resources: ResourceCollection, result: CleanupResult) -> None:
        """Delete key pairs, using batch processor when configured."""
        logger.info(f"Deleting {len(resources.key_pairs)} key pairs")

        if self._should_use_batch(len(resources.key_pairs)):
            key_names = [kp.key_name for kp in resources.key_pairs]
            batch_result = self.batch_processor.process_deletions(
                resources=key_names,
                delete_func=self._make_key_pair_deleter(),
                resource_type="key_pair",
            )
            result.deleted_key_pairs.extend(batch_result.successful)
            result.errors.update(batch_result.errors)
        else:
            deleted, deferred, errors = self.network_manager.delete_key_pairs(resources.key_pairs)
            result.deleted_key_pairs.extend(deleted)
            result.deferred_resources.extend(deferred)
            result.errors.update(errors)

    def _cleanup_elastic_ips(self, resources: ResourceCollection, result: CleanupResult) -> None:
        """Release elastic IPs."""
        logger.info(f"Releasing {len(resources.elastic_ips)} elastic IPs")

        released, deferred, errors = self.network_manager.release_elastic_ips(resources.elastic_ips)
        result.released_elastic_ips.extend(released)
        result.deferred_resources.extend(deferred)
        result.errors.update(errors)

    def _cleanup_volumes(self, resources: ResourceCollection, result: CleanupResult) -> None:
        """Delete EBS volumes, using batch processor when configured."""
        logger.info(f"Deleting {len(resources.volumes)} volumes")

        if self._should_use_batch(len(resources.volumes)):
            # Pre-filter: only attempt deletion on available, unattached volumes
            deletable_ids = []
            for volume in resources.volumes:
                if volume.attached_instance or volume.state != "available":
                    result.deferred_resources.append(volume.resource_id)
                else:
                    deletable_ids.append(volume.resource_id)

            if deletable_ids:
                batch_result = self.batch_processor.process_deletions(
                    resources=deletable_ids,
                    delete_func=self._make_volume_deleter(),
                    resource_type="volume",
                )
                result.deleted_volumes.extend(batch_result.successful)
                result.errors.update(batch_result.errors)
        else:
            deleted, deferred, errors = self.storage_manager.delete_volumes(resources.volumes)
            result.deleted_volumes.extend(deleted)
            result.deferred_resources.extend(deferred)
            result.errors.update(errors)

    def _cleanup_snapshots(self, resources: ResourceCollection, result: CleanupResult) -> None:
        """Delete EBS snapshots, protecting those used by registered AMIs."""
        logger.info(f"Deleting {len(resources.snapshots)} snapshots")

        registered_snapshots = self.storage_manager.get_registered_ami_snapshots()
        deleted, deferred, errors = self.storage_manager.delete_snapshots(
            resources.snapshots, registered_snapshots
        )
        result.deleted_snapshots.extend(deleted)
        result.deferred_resources.extend(deferred)
        result.errors.update(errors)

    def _cleanup_instance_profiles(
        self, resources: ResourceCollection, result: CleanupResult
    ) -> None:
        """Delete IAM instance profiles with role detachment (Requirement 2.4)."""
        logger.info(f"Deleting {len(resources.instance_profiles)} instance profiles")

        if not self.iam_manager:
            logger.warning("IAM manager not initialized, skipping instance profile cleanup")
            return

        deleted, deferred, errors = self.iam_manager.delete_instance_profiles(
            resources.instance_profiles
        )
        result.deleted_instance_profiles.extend(deleted)
        result.deferred_resources.extend(deferred)
        result.errors.update(errors)

    # -------------------------------------------------------------------------
    # Batch delete helpers
    # -------------------------------------------------------------------------

    def _should_use_batch(self, resource_count: int) -> bool:
        """Determine if batch processing should be used for this operation."""
        return self.batch_delete_size > 1 and resource_count > 1

    def _make_sg_deleter(self) -> Callable[[str], bool]:
        """Create a delete function for security groups.

        Returns a closure that handles DependencyViolation by raising
        an exception (which BatchProcessor records as a failure).
        """
        ec2 = self.ec2_client
        dry_run = self.dry_run

        def delete_security_group(sg_id: str) -> bool:
            if dry_run:
                logger.info(f"[DRY RUN] Would delete security group {sg_id}")
                return True
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return True
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == _DEPENDENCY_VIOLATION:
                    raise Exception(f"{_DEPENDENCY_VIOLATION}: {sg_id} has dependencies") from e
                raise

        return delete_security_group

    def _make_key_pair_deleter(self) -> Callable[[str], bool]:
        """Create a delete function for key pairs."""
        ec2 = self.ec2_client
        dry_run = self.dry_run

        def delete_key_pair(key_name: str) -> bool:
            if dry_run:
                logger.info(f"[DRY RUN] Would delete key pair {key_name}")
                return True
            ec2.delete_key_pair(KeyName=key_name)
            return True

        return delete_key_pair

    def _make_volume_deleter(self) -> Callable[[str], bool]:
        """Create a delete function for EBS volumes."""
        ec2 = self.ec2_client
        dry_run = self.dry_run

        def delete_volume(volume_id: str) -> bool:
            if dry_run:
                logger.info(f"[DRY RUN] Would delete volume {volume_id}")
                return True
            ec2.delete_volume(VolumeId=volume_id)
            return True

        return delete_volume

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _should_defer_instance(self, instance: PackerInstance) -> bool:
        """Check if instance should be deferred to next execution (Requirement 2.7)."""
        return instance.state.lower() == self.SHUTTING_DOWN_STATE

    def _execute_with_retry(self, operation: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Execute an operation with exponential backoff retry (Requirement 6.2)."""
        return self.retry_strategy.execute_with_retry(operation, *args, **kwargs)

    def _merge_orphan_results(
        self, result: CleanupResult, orphan_result: OrphanCleanupResult
    ) -> None:
        """Merge orphan cleanup results into main cleanup result."""
        result.deleted_key_pairs.extend(orphan_result.deleted_key_pairs)
        result.deleted_security_groups.extend(orphan_result.deleted_security_groups)
        result.deferred_resources.extend(orphan_result.deferred_resources)
        result.errors.update(orphan_result.errors)

    def collect_associated_resources(self, instance: PackerInstance) -> AssociatedResources:
        """
        Collect resources directly associated with an instance (Requirement 2.2).

        Args:
            instance: The PackerInstance to collect associated resources for

        Returns:
            AssociatedResources containing all directly associated resource IDs
        """
        associated = AssociatedResources(instance_id=instance.resource_id)
        associated.security_group_ids = list(instance.security_groups)
        associated.key_pair_name = instance.key_name

        ec2_associated = self.ec2_manager.get_associated_resources(instance)
        associated.volume_ids = ec2_associated.get("volume_ids", [])
        associated.eip_allocation_ids = ec2_associated.get("eip_allocation_ids", [])

        logger.debug(
            f"Collected associated resources for {instance.resource_id}: "
            f"SGs={associated.security_group_ids}, "
            f"KeyPair={associated.key_pair_name}, "
            f"Volumes={associated.volume_ids}, "
            f"EIPs={associated.eip_allocation_ids}"
        )

        return associated
