"""SNS notification system for cleanup operations.

This module provides SNS notification functionality for the Packer Resource Reaper,
implementing Requirements 4.3, 4.4, 10.9, and 10.10:
- Requirement 4.3: Include instance ID, type, termination reason, and list of deleted resources
- Requirement 4.4: Send SNS notifications when cleanup actions are performed
- Requirement 10.9: Log each deleted orphaned resource type and identifier to CloudWatch
- Requirement 10.10: Include orphaned resource details in SNS notifications

The notification system handles both live cleanup and dry-run scenarios, providing
comprehensive reports with all required fields including orphaned resources.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reaper.models import CleanupResult, PackerInstance, ResourceCollection
from reaper.utils.security import LogSanitizer

logger = logging.getLogger(__name__)


# Default termination reason for Packer instances
DEFAULT_TERMINATION_REASON = (
    "Matches Packer key pair pattern (packer_*) and exceeds age threshold"
)


class SNSNotifier:
    """Sends notifications via SNS for cleanup operations.

    This class implements Requirements 4.3, 4.4, 10.9, and 10.10:
    - Sends SNS notifications when cleanup actions are performed (4.4)
    - Includes instance ID, type, termination reason, and deleted resources (4.3)
    - Logs each deleted orphaned resource type and identifier (10.9)
    - Includes orphaned resource details in SNS notifications (10.10)

    Notifications are sent for both live cleanup operations and dry-run simulations,
    with appropriate formatting for each scenario.
    """

    AWS_CONSOLE_BASE_URL = "https://console.aws.amazon.com"

    def __init__(self, sns_client: Any, topic_arn: str, region: str = "us-east-1"):
        """
        Initialize SNS notifier.

        Args:
            sns_client: Boto3 SNS client
            topic_arn: ARN of the SNS topic
            region: AWS region for console links
        """
        self.sns = sns_client
        self.topic_arn = topic_arn
        self.region = region

    def send_cleanup_notification(
        self,
        result: CleanupResult,
        resources: ResourceCollection,
        account_id: str,
        orphan_result: Optional[Any] = None,
    ) -> bool:
        """
        Send notification about cleanup operations.

        Args:
            result: Cleanup result with details
            resources: Original resource collection
            account_id: AWS account ID
            orphan_result: Optional OrphanCleanupResult for orphaned resources

        Returns:
            True if notification sent successfully
        """
        if not self.topic_arn:
            logger.warning("No SNS topic ARN configured, skipping notification")
            return False

        try:
            subject = self._build_subject(result)
            message = self._build_message(result, resources, account_id, orphan_result)

            self.sns.publish(
                TopicArn=self.topic_arn,
                Subject=subject,
                Message=message,
            )

            logger.info(f"Sent cleanup notification to {self.topic_arn}")
            return True
        except Exception as e:
            logger.error(f"Error sending SNS notification: {e}")
            return False

    def send_dry_run_report(
        self,
        resources: ResourceCollection,
        account_id: str,
        orphan_result: Optional[Any] = None,
    ) -> bool:
        """
        Send dry-run simulation report.

        Args:
            resources: Resources that would be cleaned up
            account_id: AWS account ID
            orphan_result: Optional OrphanCleanupResult for orphaned resources

        Returns:
            True if notification sent successfully
        """
        if not self.topic_arn:
            logger.warning("No SNS topic ARN configured, skipping notification")
            return False

        try:
            subject = "[DRY RUN] Packer Resource Reaper - Simulation Report"
            message = self._build_dry_run_message(resources, account_id, orphan_result)

            self.sns.publish(
                TopicArn=self.topic_arn,
                Subject=subject,
                Message=message,
            )

            logger.info(f"Sent dry-run report to {self.topic_arn}")
            return True
        except Exception as e:
            logger.error(f"Error sending SNS notification: {e}")
            return False

    def _build_subject(self, result: CleanupResult) -> str:
        """Build notification subject line."""
        if result.dry_run:
            return "[DRY RUN] Packer Resource Reaper - Simulation Complete"

        total = result.total_cleaned()
        errors = len(result.errors)

        if errors > 0:
            return (
                f"Packer Resource Reaper - Cleaned {total} resources ({errors} errors)"
            )
        return f"Packer Resource Reaper - Cleaned {total} resources"

    def _build_message(
        self,
        result: CleanupResult,
        resources: ResourceCollection,
        account_id: str,
        orphan_result: Optional[Any] = None,
    ) -> str:
        """Build detailed notification message.

        This implements Requirements 4.3 and 10.10: notifications include instance ID, type,
        termination reason, list of deleted associated resources, and orphaned resource details.
        """
        lines = [
            "=" * 60,
            "PACKER RESOURCE REAPER - CLEANUP REPORT",
            "=" * 60,
            "",
            f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
            f"Account: {account_id}",
            f"Region: {self.region}",
            f"Mode: {'DRY RUN' if result.dry_run else 'LIVE'}",
            "",
        ]

        # Summary
        lines.extend(
            [
                "SUMMARY",
                "-" * 40,
                f"Total resources processed: {resources.total_count()}",
                f"Resources cleaned: {result.total_cleaned()}",
                f"Resources deferred: {len(result.deferred_resources)}",
                f"Errors: {len(result.errors)}",
                "",
            ]
        )

        # Terminated instances with detailed information (Requirement 4.3)
        if result.terminated_instances:
            lines.extend(
                [
                    "TERMINATED INSTANCES",
                    "-" * 40,
                ]
            )

            # Build a lookup map for instance details
            instance_map: Dict[str, PackerInstance] = {
                inst.resource_id: inst for inst in resources.instances
            }

            for instance_id in result.terminated_instances:
                link = self._get_instance_link(instance_id)
                instance = instance_map.get(instance_id)

                lines.append(f"  - Instance ID: {instance_id}")

                if instance:
                    # Include instance type (Requirement 4.3)
                    lines.append(f"    Type: {instance.instance_type}")
                    lines.append(f"    State: {instance.state}")
                    lines.append(f"    Key Name: {instance.key_name or 'N/A'}")
                    name = instance.tags.get("Name", "N/A")
                    lines.append(f"    Name Tag: {name}")

                # Include termination reason (Requirement 4.3)
                lines.append(f"    Termination Reason: {DEFAULT_TERMINATION_REASON}")
                lines.append(f"    Console Link: {link}")
                lines.append("")

        # Deleted resources (Requirement 4.3 - list of deleted associated resources)
        self._add_resource_section(
            lines, "DELETED SECURITY GROUPS", result.deleted_security_groups
        )
        self._add_resource_section(lines, "DELETED KEY PAIRS", result.deleted_key_pairs)
        self._add_resource_section(
            lines, "RELEASED ELASTIC IPS", result.released_elastic_ips
        )
        self._add_resource_section(lines, "DELETED VOLUMES", result.deleted_volumes)
        self._add_resource_section(lines, "DELETED SNAPSHOTS", result.deleted_snapshots)

        # Orphaned resources section (Requirement 10.10)
        if orphan_result:
            self._add_orphaned_resources_section(lines, orphan_result)

        # Deferred resources
        if result.deferred_resources:
            lines.extend(
                [
                    "DEFERRED RESOURCES",
                    "-" * 40,
                ]
            )
            for resource_id in result.deferred_resources:
                lines.append(f"  - {resource_id}")
            lines.append("")

        # Errors
        if result.errors:
            lines.extend(
                [
                    "ERRORS",
                    "-" * 40,
                ]
            )
            for resource_id, error in result.errors.items():
                # Sanitize error messages to avoid exposing sensitive data
                sanitized_error = LogSanitizer.sanitize(str(error))
                lines.append(f"  - {resource_id}: {sanitized_error}")
            lines.append("")

        return "\n".join(lines)

    def _add_orphaned_resources_section(
        self, lines: List[str], orphan_result: Any
    ) -> None:
        """Add orphaned resources section to the message.

        This implements Requirement 10.10: include orphaned resource details
        in SNS notifications.
        """
        has_orphaned = (
            orphan_result.deleted_key_pairs
            or orphan_result.deleted_security_groups
            or orphan_result.deleted_iam_roles
        )

        if not has_orphaned:
            return

        lines.extend(
            [
                "ORPHANED PACKER RESOURCES CLEANED",
                "-" * 40,
            ]
        )

        if orphan_result.deleted_key_pairs:
            lines.append("  Orphaned Key Pairs:")
            for kp in orphan_result.deleted_key_pairs:
                lines.append(f"    - {kp}")
                # Log to CloudWatch (Requirement 10.9)
                logger.info(f"Deleted orphaned key pair: {kp}")

        if orphan_result.deleted_security_groups:
            lines.append("  Orphaned Security Groups:")
            for sg in orphan_result.deleted_security_groups:
                lines.append(f"    - {sg}")
                # Log to CloudWatch (Requirement 10.9)
                logger.info(f"Deleted orphaned security group: {sg}")

        if orphan_result.deleted_iam_roles:
            lines.append("  Orphaned IAM Roles:")
            for role in orphan_result.deleted_iam_roles:
                lines.append(f"    - {role}")
                # Log to CloudWatch (Requirement 10.9)
                logger.info(f"Deleted orphaned IAM role: {role}")

        lines.append("")

    def _build_dry_run_message(
        self,
        resources: ResourceCollection,
        account_id: str,
        orphan_result: Optional[Any] = None,
    ) -> str:
        """Build dry-run simulation report message.

        This implements Requirements 9.3 and 10.10: send a simulation report via SNS
        detailing planned actions, including instance ID, type, termination reason,
        and orphaned resource details.
        """
        lines = [
            "=" * 60,
            "PACKER RESOURCE REAPER - DRY RUN SIMULATION",
            "=" * 60,
            "",
            f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
            f"Account: {account_id}",
            f"Region: {self.region}",
            "",
            "The following resources WOULD be cleaned up in live mode:",
            "",
        ]

        # Phase 1: Primary zombie instance cleanup
        lines.extend(
            [
                "PHASE 1: PRIMARY ZOMBIE INSTANCE CLEANUP",
                "=" * 40,
                "",
            ]
        )

        # Instances with detailed information (Requirement 4.3)
        if resources.instances:
            lines.extend(
                [
                    "INSTANCES TO TERMINATE",
                    "-" * 40,
                ]
            )
            for instance in resources.instances:
                link = self._get_instance_link(instance.resource_id)
                name = instance.tags.get("Name", "N/A")

                # Include instance ID and type (Requirement 4.3)
                lines.append(f"  - Instance ID: {instance.resource_id}")
                lines.append(f"    Type: {instance.instance_type}")
                lines.append(f"    Name: {name}")
                lines.append(f"    State: {instance.state}")
                lines.append(f"    Key Name: {instance.key_name or 'N/A'}")
                # Include termination reason (Requirement 4.3)
                lines.append(f"    Termination Reason: {DEFAULT_TERMINATION_REASON}")
                lines.append(f"    Console Link: {link}")
                lines.append("")

        # Other resources (list of associated resources that would be deleted)
        if resources.security_groups:
            lines.extend(["SECURITY GROUPS TO DELETE", "-" * 40])
            for sg in resources.security_groups:
                lines.append(f"  - {sg.resource_id} ({sg.group_name})")
            lines.append("")

        if resources.key_pairs:
            lines.extend(["KEY PAIRS TO DELETE", "-" * 40])
            for kp in resources.key_pairs:
                lines.append(f"  - {kp.key_name}")
            lines.append("")

        if resources.elastic_ips:
            lines.extend(["ELASTIC IPS TO RELEASE", "-" * 40])
            for eip in resources.elastic_ips:
                lines.append(f"  - {eip.allocation_id} ({eip.public_ip})")
            lines.append("")

        if resources.volumes:
            lines.extend(["VOLUMES TO DELETE", "-" * 40])
            for vol in resources.volumes:
                lines.append(f"  - {vol.resource_id} ({vol.size} GB)")
            lines.append("")

        if resources.snapshots:
            lines.extend(["SNAPSHOTS TO DELETE", "-" * 40])
            for snap in resources.snapshots:
                lines.append(f"  - {snap.resource_id}")
            lines.append("")

        # Phase 2: Orphaned resource cleanup (Requirement 10.10)
        if orphan_result:
            self._add_orphaned_dry_run_section(lines, orphan_result)

        lines.extend(
            [
                "=" * 60,
                f"Total Phase 1 resources that would be cleaned: {resources.total_count()}",
            ]
        )

        if orphan_result:
            orphan_total = orphan_result.total_cleaned()
            lines.append(
                f"Total Phase 2 orphaned resources that would be cleaned: {orphan_total}"
            )
            lines.append(f"Grand total: {resources.total_count() + orphan_total}")

        lines.append("=" * 60)

        return "\n".join(lines)

    def _add_orphaned_dry_run_section(
        self, lines: List[str], orphan_result: Any
    ) -> None:
        """Add orphaned resources section to dry-run message.

        This implements Requirement 10.10: include orphaned resource details
        in SNS notifications for dry-run mode.
        """
        has_orphaned = (
            orphan_result.deleted_key_pairs
            or orphan_result.deleted_security_groups
            or orphan_result.deleted_iam_roles
        )

        if not has_orphaned:
            return

        lines.extend(
            [
                "",
                "PHASE 2: ORPHANED PACKER RESOURCE CLEANUP",
                "=" * 40,
                "",
            ]
        )

        if orphan_result.deleted_key_pairs:
            lines.extend(["ORPHANED KEY PAIRS TO DELETE", "-" * 40])
            for kp in orphan_result.deleted_key_pairs:
                lines.append(f"  - {kp}")
                # Log to CloudWatch (Requirement 10.9)
                logger.info(f"[DRY RUN] Would delete orphaned key pair: {kp}")
            lines.append("")

        if orphan_result.deleted_security_groups:
            lines.extend(["ORPHANED SECURITY GROUPS TO DELETE", "-" * 40])
            for sg in orphan_result.deleted_security_groups:
                lines.append(f"  - {sg}")
                # Log to CloudWatch (Requirement 10.9)
                logger.info(f"[DRY RUN] Would delete orphaned security group: {sg}")
            lines.append("")

        if orphan_result.deleted_iam_roles:
            lines.extend(["ORPHANED IAM ROLES TO DELETE", "-" * 40])
            for role in orphan_result.deleted_iam_roles:
                lines.append(f"  - {role}")
                # Log to CloudWatch (Requirement 10.9)
                logger.info(f"[DRY RUN] Would delete orphaned IAM role: {role}")
            lines.append("")

    def _add_resource_section(
        self, lines: List[str], title: str, resources: List[str]
    ) -> None:
        """Add a resource section to the message."""
        if resources:
            lines.extend([title, "-" * 40])
            for resource_id in resources:
                lines.append(f"  - {resource_id}")
            lines.append("")

    def _get_instance_link(self, instance_id: str) -> str:
        """Generate AWS Console link for an instance."""
        return (
            f"{self.AWS_CONSOLE_BASE_URL}/ec2/v2/home?"
            f"region={self.region}#InstanceDetails:instanceId={instance_id}"
        )
