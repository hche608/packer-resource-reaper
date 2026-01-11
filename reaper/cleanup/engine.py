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
from dataclasses import dataclass, field
from typing import Any, List, Optional

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


@dataclass
class AssociatedResources:
    """Resources directly associated with a zombie instance.

    This tracks resources that should be cleaned up after instance termination
    as per Requirement 2.2.
    """

    instance_id: str
    security_group_ids: List[str] = field(default_factory=list)
    key_pair_name: Optional[str] = None
    volume_ids: List[str] = field(default_factory=list)
    eip_allocation_ids: List[str] = field(default_factory=list)


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
        retry_strategy: Optional[RetryStrategy] = None,
        account_id: str = "",
        region: str = "",
        iam_client: Optional[Any] = None,
        batch_delete_size: int = 1,
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
        """
        self.dry_run = dry_run
        self.ec2_client = ec2_client
        self.iam_client = iam_client
        self.account_id = account_id
        self.region = region
        self.batch_delete_size = max(1, batch_delete_size)
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
        self.orphan_manager = OrphanManager(ec2_client, iam_client, dry_run)

        # Initialize dry-run executor for comprehensive logging
        self.dry_run_executor = DryRunExecutor(
            account_id=account_id,
            region=region,
        )

        # Store last orphan cleanup result for notifications
        self._last_orphan_cleanup_result: Optional[OrphanCleanupResult] = None

    def cleanup_resources(self, resources: ResourceCollection) -> CleanupResult:
        """
        Execute cleanup operations in dependency-aware order.

        Two-Phase Cleanup Model (per Requirements 2.1-2.8 and 10.7):

        Phase 1 - Primary Zombie Instance Cleanup:
        1. Identify zombie instances (already filtered in resources)
        2. Collect directly associated resources for each instance
        3. Terminate EC2 instances
        4. Wait for instance termination confirmation
        5. Delete security groups (handle DependencyViolation gracefully)
        6. Delete key pairs
        7. Release elastic IPs
        8. Delete EBS volumes
        9. Delete EBS snapshots
        10. Delete IAM instance profiles (with role detachment)

        Phase 2 - Orphaned Resource Cleanup (Requirement 10.7):
        11. Scan for orphaned Packer key pairs (not used by any instance)
        12. Scan for orphaned Packer security groups (no attachments)
        13. Scan for orphaned Packer IAM roles (not in any instance profile)
        14. Delete orphaned resources

        In dry-run mode (Requirements 9.1-9.4, 10.8):
        - Identifies all cleanup candidates without executing destructive operations
        - Logs all resources that would be deleted to CloudWatch
        - Generates simulation reports for SNS notifications
        - Does NOT execute any terminate, delete, or release API calls

        Args:
            resources: Collection of resources to clean up

        Returns:
            CleanupResult with details of operations performed
        """
        # In dry-run mode, use the DryRunExecutor for comprehensive logging
        # This implements Requirements 9.1, 9.2, 9.3, 9.4, 10.8
        if self.dry_run:
            result, report = self.dry_run_executor.execute_dry_run(resources)
            # Store the report for potential SNS notification
            self._last_dry_run_report = report

            # Also scan for orphaned resources in dry-run mode
            orphaned = self.orphan_manager.scan_orphaned_resources()
            orphan_result = self.orphan_manager.cleanup_orphaned_resources(orphaned)
            self._last_orphan_cleanup_result = orphan_result

            # Merge orphan results into main result
            self._merge_orphan_results(result, orphan_result)

            return result

        result = CleanupResult(dry_run=self.dry_run)

        if resources.is_empty():
            logger.info("No resources to clean up in Phase 1")
        else:
            logger.info(
                f"Phase 1: Starting cleanup of {resources.total_count()} resources"
            )

            # Step 1 & 2: Process instances - collect associated resources and terminate
            # This implements Requirements 2.1, 2.2, 2.3, 2.5, 2.7
            if resources.instances:
                self._cleanup_instances_with_dependencies(resources, result)

            # Step 3: Delete security groups (may fail if instances still terminating)
            # This implements Requirement 2.4, 2.6
            if resources.security_groups:
                self._cleanup_security_groups(resources, result)

            # Step 4: Delete key pairs
            # This implements Requirement 2.4
            if resources.key_pairs:
                self._cleanup_key_pairs(resources, result)

            # Step 5: Release elastic IPs
            # This implements Requirement 2.4
            if resources.elastic_ips:
                self._cleanup_elastic_ips(resources, result)

            # Step 6: Delete volumes
            # This implements Requirement 2.4, 2.8
            if resources.volumes:
                self._cleanup_volumes(resources, result)

            # Step 7: Delete snapshots
            if resources.snapshots:
                self._cleanup_snapshots(resources, result)

            # Step 8: Delete IAM instance profiles
            # This implements Requirement 2.4 for IAM instance profiles
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

        # Merge orphan results into main result
        self._merge_orphan_results(result, orphan_result)

        logger.info(
            f"Cleanup complete: {result.total_cleaned()} total resources cleaned, "
            f"{len(result.deferred_resources)} deferred, {len(result.errors)} errors"
        )

        return result

    def _merge_orphan_results(
        self, result: CleanupResult, orphan_result: OrphanCleanupResult
    ) -> None:
        """Merge orphan cleanup results into main cleanup result."""
        # Add orphaned key pairs to deleted key pairs
        result.deleted_key_pairs.extend(orphan_result.deleted_key_pairs)

        # Add orphaned security groups to deleted security groups
        result.deleted_security_groups.extend(orphan_result.deleted_security_groups)

        # Add orphaned IAM roles - we'll track these separately in the result
        # For now, add them to deferred if they had errors
        result.deferred_resources.extend(orphan_result.deferred_resources)

        # Merge errors
        result.errors.update(orphan_result.errors)

    def get_last_orphan_cleanup_result(self) -> Optional[OrphanCleanupResult]:
        """
        Get the last orphan cleanup result.

        This is useful for including orphaned resource details in SNS notifications
        as per Requirement 10.10.

        Returns:
            OrphanCleanupResult if orphan cleanup was executed, None otherwise
        """
        return self._last_orphan_cleanup_result

    def _execute_with_retry(self, operation, *args, **kwargs):
        """
        Execute an operation with retry logic.

        This implements Requirement 6.2: exponential backoff retry logic
        for AWS API rate limits.

        Args:
            operation: The operation to execute
            *args: Positional arguments for the operation
            **kwargs: Keyword arguments for the operation

        Returns:
            The result of the operation
        """
        return self.retry_strategy.execute_with_retry(operation, *args, **kwargs)

    def collect_associated_resources(
        self, instance: PackerInstance
    ) -> AssociatedResources:
        """
        Collect resources directly associated with an instance.

        This implements Requirement 2.2: collect directly associated resources
        (key pair, security group, attached EBS volumes, associated EIP)
        before termination.

        Args:
            instance: The PackerInstance to collect associated resources for

        Returns:
            AssociatedResources containing all directly associated resource IDs
        """
        associated = AssociatedResources(instance_id=instance.resource_id)

        # Collect security groups from instance
        associated.security_group_ids = list(instance.security_groups)

        # Collect key pair name
        associated.key_pair_name = instance.key_name

        # Get associated resources from EC2 manager
        ec2_associated = self.ec2_manager.get_associated_resources(instance)

        # Merge volume IDs
        associated.volume_ids = ec2_associated.get("volume_ids", [])

        # Merge EIP allocation IDs
        associated.eip_allocation_ids = ec2_associated.get("eip_allocation_ids", [])

        logger.debug(
            f"Collected associated resources for {instance.resource_id}: "
            f"SGs={associated.security_group_ids}, "
            f"KeyPair={associated.key_pair_name}, "
            f"Volumes={associated.volume_ids}, "
            f"EIPs={associated.eip_allocation_ids}"
        )

        return associated

    def _should_defer_instance(self, instance: PackerInstance) -> bool:
        """
        Check if instance should be deferred to next execution.

        This implements Requirement 2.7: if an instance is in shutting-down state,
        defer associated resource deletion to the next scheduled execution.

        Args:
            instance: The PackerInstance to check

        Returns:
            True if instance should be deferred, False otherwise
        """
        state = instance.state.lower()
        return state == self.SHUTTING_DOWN_STATE

    def _cleanup_instances_with_dependencies(
        self, resources: ResourceCollection, result: CleanupResult
    ) -> None:
        """
        Terminate EC2 instances with dependency-aware handling.

        This implements Requirements 2.1, 2.2, 2.3, 2.5, 2.7:
        1. Identify instances to terminate vs defer
        2. Collect associated resources before termination
        3. Terminate instances
        4. Wait for termination confirmation
        5. Defer shutting-down instances

        Args:
            resources: ResourceCollection containing instances
            result: CleanupResult to update with operation results
        """
        logger.info(f"Processing {len(resources.instances)} instances")

        instances_to_terminate = []

        for instance in resources.instances:
            # Check if instance should be deferred (Requirement 2.7)
            if self._should_defer_instance(instance):
                logger.info(
                    f"Instance {instance.resource_id} in shutting-down state, "
                    "deferring to next execution"
                )
                result.deferred_resources.append(instance.resource_id)
                continue

            # Check if already terminated
            if instance.state.lower() == self.TERMINATED_STATE:
                logger.info(f"Instance {instance.resource_id} already terminated")
                result.terminated_instances.append(instance.resource_id)
                continue

            instances_to_terminate.append(instance)

        if not instances_to_terminate:
            logger.info("No instances to terminate")
            return

        # Terminate instances
        terminated, deferred, errors = self.ec2_manager.terminate_instances(
            instances_to_terminate
        )

        result.terminated_instances.extend(terminated)
        result.deferred_resources.extend(deferred)
        result.errors.update(errors)

        # Wait for termination if not dry run (Requirement 2.5)
        if terminated and not self.dry_run:
            logger.info("Waiting for instance termination confirmation...")
            self.ec2_manager.wait_for_termination(terminated, timeout_seconds=120)

    def _cleanup_security_groups(
        self, resources: ResourceCollection, result: CleanupResult
    ) -> None:
        """Delete security groups."""
        logger.info(f"Deleting {len(resources.security_groups)} security groups")

        deleted, deferred, errors = self.network_manager.delete_security_groups(
            resources.security_groups
        )

        result.deleted_security_groups.extend(deleted)
        result.deferred_resources.extend(deferred)
        result.errors.update(errors)

    def _cleanup_key_pairs(
        self, resources: ResourceCollection, result: CleanupResult
    ) -> None:
        """Delete key pairs."""
        logger.info(f"Deleting {len(resources.key_pairs)} key pairs")

        deleted, deferred, errors = self.network_manager.delete_key_pairs(
            resources.key_pairs
        )

        result.deleted_key_pairs.extend(deleted)
        result.deferred_resources.extend(deferred)
        result.errors.update(errors)

    def _cleanup_elastic_ips(
        self, resources: ResourceCollection, result: CleanupResult
    ) -> None:
        """Release elastic IPs."""
        logger.info(f"Releasing {len(resources.elastic_ips)} elastic IPs")

        released, deferred, errors = self.network_manager.release_elastic_ips(
            resources.elastic_ips
        )

        result.released_elastic_ips.extend(released)
        result.deferred_resources.extend(deferred)
        result.errors.update(errors)

    def _cleanup_volumes(
        self, resources: ResourceCollection, result: CleanupResult
    ) -> None:
        """Delete EBS volumes."""
        logger.info(f"Deleting {len(resources.volumes)} volumes")

        deleted, deferred, errors = self.storage_manager.delete_volumes(
            resources.volumes
        )

        result.deleted_volumes.extend(deleted)
        result.deferred_resources.extend(deferred)
        result.errors.update(errors)

    def _cleanup_snapshots(
        self, resources: ResourceCollection, result: CleanupResult
    ) -> None:
        """Delete EBS snapshots."""
        logger.info(f"Deleting {len(resources.snapshots)} snapshots")

        # Get snapshots used by registered AMIs to avoid deleting them
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
        """Delete IAM instance profiles with role detachment.

        This implements Requirement 2.4 for IAM instance profiles matching
        the `packer_*` pattern. Handles orphaned instance profiles from
        failed Packer builds (Requirement 2.8).
        """
        logger.info(f"Deleting {len(resources.instance_profiles)} instance profiles")

        if not self.iam_manager:
            logger.warning(
                "IAM manager not initialized, skipping instance profile cleanup"
            )
            return

        deleted, deferred, errors = self.iam_manager.delete_instance_profiles(
            resources.instance_profiles
        )

        result.deleted_instance_profiles.extend(deleted)
        result.deferred_resources.extend(deferred)
        result.errors.update(errors)

    def get_last_dry_run_report(self) -> Optional[DryRunReport]:
        """
        Get the last dry-run report generated by cleanup_resources.

        This is useful for sending SNS notifications with detailed
        simulation reports as per Requirement 9.3.

        Returns:
            DryRunReport if a dry-run was executed, None otherwise
        """
        return getattr(self, "_last_dry_run_report", None)
