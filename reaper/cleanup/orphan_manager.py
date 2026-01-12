"""Orphan manager for detecting and cleaning up orphaned Packer resources.

This module provides functionality to identify and clean up orphaned Packer-created
resources that persist after builds complete or fail, as per Requirements 10.1-10.10.

Key features:
- Scan for orphaned key pairs starting with `packer_` not used by any instance (Requirement 10.1)
- Scan for orphaned security groups with `packer` in name/description (Requirement 10.2)
- Scan for orphaned IAM roles starting with `packer_` not in any instance profile (Requirement 10.3)
- Delete orphaned resources after confirming no dependencies (Requirements 10.4, 10.5, 10.6)
- Execute as Phase 2 after primary zombie instance cleanup (Requirement 10.7)
- Respect dry-run mode for all operations (Requirement 10.8)
- Log and notify about orphaned resource cleanup (Requirements 10.9, 10.10)

SAFETY: All orphaned resources must meet an age threshold before deletion to prevent
race conditions with active Packer builds that are still provisioning.
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class OrphanedResources:
    """Packer-created resources that exist without any instance association.

    This tracks resources that should be cleaned up as Phase 2 after
    primary zombie instance cleanup completes.
    """

    orphaned_key_pairs: list[str] = field(default_factory=list)
    orphaned_security_groups: list[str] = field(default_factory=list)
    orphaned_iam_roles: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Check if there are no orphaned resources."""
        return (
            len(self.orphaned_key_pairs) == 0
            and len(self.orphaned_security_groups) == 0
            and len(self.orphaned_iam_roles) == 0
        )

    def total_count(self) -> int:
        """Get total number of orphaned resources."""
        return (
            len(self.orphaned_key_pairs)
            + len(self.orphaned_security_groups)
            + len(self.orphaned_iam_roles)
        )


@dataclass
class OrphanCleanupResult:
    """Result of orphaned resource cleanup operations."""

    deleted_key_pairs: list[str] = field(default_factory=list)
    deleted_security_groups: list[str] = field(default_factory=list)
    deleted_iam_roles: list[str] = field(default_factory=list)
    deferred_resources: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    dry_run: bool = False

    def total_cleaned(self) -> int:
        """Get total number of orphaned resources cleaned up."""
        return (
            len(self.deleted_key_pairs)
            + len(self.deleted_security_groups)
            + len(self.deleted_iam_roles)
        )


class OrphanManager:
    """Manager for identifying and cleaning up orphaned Packer resources.

    This class implements Requirements 10.1-10.10 for orphaned resource cleanup:
    - Scans for key pairs starting with `packer_` not used by any instance (10.1)
    - Scans for security groups with `packer` in name/description (10.2)
    - Scans for IAM roles starting with `packer_` not in any instance profile (10.3)
    - Deletes orphaned resources after confirming no dependencies (10.4, 10.5, 10.6)
    - Executes as Phase 2 after primary cleanup (10.7)
    - Respects dry-run mode (10.8)
    - Logs and notifies about cleanup (10.9, 10.10)
    """

    # Pattern for Packer-generated resources
    # Key pairs use packer_ prefix (e.g., packer_12345678-abcd-...)
    PACKER_KEY_PATTERN = "packer_"
    # IAM roles can use packer_ or packer- prefix (e.g., packer-role-name)
    PACKER_IAM_ROLE_PATTERNS = ("packer_", "packer-")
    # Exclude the reaper's own resources from cleanup
    REAPER_RESOURCE_PREFIX = "packer-resource-reaper"
    PACKER_SG_PATTERN = "packer"

    def __init__(
        self,
        ec2_client: Any,
        iam_client: Any | None = None,
        dry_run: bool = False,
        max_resource_age_hours: int = 2,
    ):
        """
        Initialize orphan manager.

        Args:
            ec2_client: Boto3 EC2 client
            iam_client: Optional Boto3 IAM client for role cleanup
            dry_run: If True, simulate operations without executing
            max_resource_age_hours: Minimum age in hours before orphaned resources
                can be deleted. This prevents race conditions with active Packer
                builds that are still provisioning. Defaults to 2 hours.
        """
        self.ec2 = ec2_client
        self.iam = iam_client
        self.dry_run = dry_run
        self.max_resource_age_hours = max(1, max_resource_age_hours)  # Minimum 1 hour

    def scan_orphaned_resources(self) -> OrphanedResources:
        """
        Scan for all orphaned Packer resources.

        This method scans for:
        - Key pairs starting with `packer_` not used by any instance (Requirement 10.1)
        - Security groups with `packer` in name/description not attached (Requirement 10.2)
        - IAM roles starting with `packer_` not in any instance profile (Requirement 10.3)

        Returns:
            OrphanedResources containing all identified orphaned resources
        """
        orphaned = OrphanedResources()

        # Scan for orphaned key pairs
        orphaned.orphaned_key_pairs = self.scan_orphaned_key_pairs()

        # Scan for orphaned security groups
        orphaned.orphaned_security_groups = self.scan_orphaned_security_groups()

        # Scan for orphaned IAM roles (if IAM client is available)
        if self.iam:
            orphaned.orphaned_iam_roles = self.scan_orphaned_iam_roles()

        logger.info(
            f"Found {orphaned.total_count()} orphaned resources: "
            f"{len(orphaned.orphaned_key_pairs)} key pairs, "
            f"{len(orphaned.orphaned_security_groups)} security groups, "
            f"{len(orphaned.orphaned_iam_roles)} IAM roles"
        )

        return orphaned

    def scan_orphaned_key_pairs(self) -> list[str]:
        """
        Identify key pairs starting with 'packer_' not used by any instance.

        This implements Requirement 10.1: scan for key pairs with names starting
        with `packer_` that are not associated with any running or pending EC2 instances.

        Returns:
            List of orphaned key pair names
        """
        orphaned_key_pairs = []

        try:
            # Get all key pairs starting with packer_
            packer_key_pairs = self._get_packer_key_pairs()

            if not packer_key_pairs:
                logger.debug("No packer_* key pairs found")
                return []

            # Get key pairs currently in use by running/pending instances
            in_use_key_pairs = self._get_key_pairs_in_use()

            # Find orphaned key pairs (not in use by any instance)
            for key_name in packer_key_pairs:
                if key_name not in in_use_key_pairs:
                    orphaned_key_pairs.append(key_name)
                    logger.debug(f"Found orphaned key pair: {key_name}")

            logger.info(
                f"Scanned {len(packer_key_pairs)} packer_* key pairs, "
                f"{len(orphaned_key_pairs)} are orphaned"
            )

        except Exception as e:
            logger.error(f"Error scanning orphaned key pairs: {e}")

        return orphaned_key_pairs

    def _get_packer_key_pairs(self) -> list[str]:
        """Get all key pairs starting with packer_ prefix that meet age threshold.

        SAFETY: Only returns key pairs that are older than max_resource_age_hours to prevent
        race conditions with active Packer builds that are still provisioning.
        """
        packer_key_pairs = []
        cutoff_time = datetime.now(UTC) - timedelta(hours=self.max_resource_age_hours)

        try:
            response = self.ec2.describe_key_pairs()
            for kp in response.get("KeyPairs", []):
                key_name = kp.get("KeyName", "")
                if key_name.startswith(self.PACKER_KEY_PATTERN):
                    # SAFETY: Check key pair age before considering for cleanup
                    create_time = kp.get("CreateTime")
                    if create_time and create_time > cutoff_time:
                        logger.debug(
                            f"Skipping key pair {key_name}: too young "
                            f"(created {create_time}, cutoff {cutoff_time})"
                        )
                        continue
                    packer_key_pairs.append(key_name)
        except Exception as e:
            logger.error(f"Error getting packer key pairs: {e}")

        return packer_key_pairs

    def _get_key_pairs_in_use(self) -> set[str]:
        """Get key pairs currently in use by running or pending instances."""
        in_use_key_pairs = set()

        try:
            # Only check running and pending instances
            paginator = self.ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "pending"]}]
            ):
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        key_name = instance.get("KeyName")
                        if key_name:
                            in_use_key_pairs.add(key_name)
        except Exception as e:
            logger.error(f"Error getting key pairs in use: {e}")

        return in_use_key_pairs

    def scan_orphaned_security_groups(self) -> list[str]:
        """
        Identify security groups with 'packer' in name/description not attached.

        This implements Requirement 10.2: scan for security groups with names or
        descriptions containing `packer` that are not attached to any EC2 instances
        or network interfaces.

        Returns:
            List of orphaned security group IDs
        """
        orphaned_security_groups = []

        try:
            # Get all security groups with packer in name or description
            packer_security_groups = self._get_packer_security_groups()

            if not packer_security_groups:
                logger.debug("No packer security groups found")
                return []

            # Get security groups currently in use
            in_use_security_groups = self._get_security_groups_in_use()

            # Find orphaned security groups (not in use)
            for sg_id in packer_security_groups:
                if sg_id not in in_use_security_groups:
                    orphaned_security_groups.append(sg_id)
                    logger.debug(f"Found orphaned security group: {sg_id}")

            logger.info(
                f"Scanned {len(packer_security_groups)} packer security groups, "
                f"{len(orphaned_security_groups)} are orphaned"
            )

        except Exception as e:
            logger.error(f"Error scanning orphaned security groups: {e}")

        return orphaned_security_groups

    def _get_packer_security_groups(self) -> list[str]:
        """Get all security groups with packer in name or description."""
        packer_security_groups = []

        try:
            paginator = self.ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    # Skip default security groups
                    if sg.get("GroupName") == "default":
                        continue

                    group_name = sg.get("GroupName", "").lower()
                    description = sg.get("Description", "").lower()

                    # Check if packer is in name or description
                    if (
                        self.PACKER_SG_PATTERN in group_name
                        or self.PACKER_SG_PATTERN in description
                    ):
                        packer_security_groups.append(sg["GroupId"])
        except Exception as e:
            logger.error(f"Error getting packer security groups: {e}")

        return packer_security_groups

    def _get_security_groups_in_use(self) -> set[str]:
        """Get security groups currently attached to instances or network interfaces."""
        in_use_security_groups = set()

        try:
            # Check instances (all states except terminated)
            paginator = self.ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[
                    {
                        "Name": "instance-state-name",
                        "Values": [
                            "pending",
                            "running",
                            "stopping",
                            "stopped",
                            "shutting-down",
                        ],
                    }
                ]
            ):
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        for sg in instance.get("SecurityGroups", []):
                            in_use_security_groups.add(sg["GroupId"])

            # Check network interfaces
            ni_paginator = self.ec2.get_paginator("describe_network_interfaces")
            for page in ni_paginator.paginate():
                for ni in page.get("NetworkInterfaces", []):
                    for sg in ni.get("Groups", []):
                        in_use_security_groups.add(sg["GroupId"])

        except Exception as e:
            logger.error(f"Error getting security groups in use: {e}")

        return in_use_security_groups

    def scan_orphaned_iam_roles(self) -> list[str]:
        """
        Identify IAM roles starting with 'packer_' not in any active instance profile.

        This implements Requirement 10.3: scan for IAM roles with names starting
        with `packer_` that are not attached to any EC2 instance profiles in use.

        Returns:
            List of orphaned IAM role names
        """
        if not self.iam:
            logger.warning("IAM client not available, skipping IAM role scan")
            return []

        orphaned_iam_roles = []

        try:
            # Get all IAM roles starting with packer_
            packer_roles = self._get_packer_iam_roles()

            if not packer_roles:
                logger.debug("No packer_* IAM roles found")
                return []

            # Get roles currently in use by instance profiles attached to instances
            in_use_roles = self._get_iam_roles_in_use()

            # Find orphaned roles (not in use)
            for role_name in packer_roles:
                if role_name not in in_use_roles:
                    orphaned_iam_roles.append(role_name)
                    logger.debug(f"Found orphaned IAM role: {role_name}")

            logger.info(
                f"Scanned {len(packer_roles)} packer_* IAM roles, "
                f"{len(orphaned_iam_roles)} are orphaned"
            )

        except Exception as e:
            logger.error(f"Error scanning orphaned IAM roles: {e}")

        return orphaned_iam_roles

    def _get_packer_iam_roles(self) -> list[str]:
        """Get all IAM roles starting with packer_ or packer- prefix that meet age threshold.

        SAFETY: Only returns roles that are older than max_resource_age_hours to prevent
        race conditions with active Packer builds that are still provisioning.
        """
        packer_roles: list[str] = []
        cutoff_time = datetime.now(UTC) - timedelta(hours=self.max_resource_age_hours)

        if self.iam is None:
            return packer_roles

        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name: str = role.get("RoleName", "")
                    # Skip the reaper's own role
                    if role_name.startswith(self.REAPER_RESOURCE_PREFIX):
                        continue
                    # Check for both packer_ and packer- prefixes
                    if any(
                        role_name.startswith(prefix) for prefix in self.PACKER_IAM_ROLE_PATTERNS
                    ):
                        # SAFETY: Check role age before considering for cleanup
                        # CreateDate is already a datetime object from boto3
                        create_date = role.get("CreateDate")
                        if create_date and create_date > cutoff_time:
                            logger.debug(
                                f"Skipping IAM role {role_name}: too young "
                                f"(created {create_date}, cutoff {cutoff_time})"
                            )
                            continue
                        packer_roles.append(role_name)
        except Exception as e:
            logger.error(f"Error getting packer IAM roles: {e}")

        return packer_roles

    def _get_iam_roles_in_use(self) -> set[str]:
        """Get IAM roles currently in use by instance profiles attached to instances."""
        in_use_roles = set()

        try:
            # Get all instance profiles attached to running/pending instances
            instance_profile_arns = set()

            paginator = self.ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "pending"]}]
            ):
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        iam_profile = instance.get("IamInstanceProfile")
                        if iam_profile:
                            instance_profile_arns.add(iam_profile.get("Arn", ""))

            # Get roles from those instance profiles
            if instance_profile_arns and self.iam is not None:
                iam_paginator = self.iam.get_paginator("list_instance_profiles")
                for page in iam_paginator.paginate():
                    for profile in page.get("InstanceProfiles", []):
                        if profile.get("Arn") in instance_profile_arns:
                            for role in profile.get("Roles", []):
                                in_use_roles.add(role["RoleName"])

        except Exception as e:
            logger.error(f"Error getting IAM roles in use: {e}")

        return in_use_roles

    def cleanup_orphaned_resources(self, orphaned: OrphanedResources) -> OrphanCleanupResult:
        """
        Delete orphaned resources after confirming no dependencies exist.

        This implements Requirements 10.4, 10.5, 10.6, 10.7, 10.8:
        - Delete key pairs after confirming no instance references (10.4)
        - Delete security groups after confirming no dependencies (10.5)
        - Delete IAM roles with policy detachment before deletion (10.6)
        - Execute as Phase 2 after primary cleanup (10.7)
        - Respect dry-run mode (10.8)

        Args:
            orphaned: OrphanedResources to clean up

        Returns:
            OrphanCleanupResult with details of operations performed
        """
        result = OrphanCleanupResult(dry_run=self.dry_run)

        if orphaned.is_empty():
            logger.info("No orphaned resources to clean up")
            return result

        logger.info(f"Starting orphaned resource cleanup for {orphaned.total_count()} resources")

        # Delete orphaned key pairs (Requirement 10.4)
        if orphaned.orphaned_key_pairs:
            self._cleanup_orphaned_key_pairs(orphaned.orphaned_key_pairs, result)

        # Delete orphaned security groups (Requirement 10.5)
        if orphaned.orphaned_security_groups:
            self._cleanup_orphaned_security_groups(orphaned.orphaned_security_groups, result)

        # Delete orphaned IAM roles (Requirement 10.6)
        if orphaned.orphaned_iam_roles and self.iam:
            self._cleanup_orphaned_iam_roles(orphaned.orphaned_iam_roles, result)

        logger.info(
            f"Orphaned resource cleanup complete: {result.total_cleaned()} cleaned, "
            f"{len(result.deferred_resources)} deferred, {len(result.errors)} errors"
        )

        return result

    def _cleanup_orphaned_key_pairs(
        self, key_pairs: list[str], result: OrphanCleanupResult
    ) -> None:
        """Delete orphaned key pairs after confirming no instance references."""
        logger.info(f"Cleaning up {len(key_pairs)} orphaned key pairs")

        for key_name in key_pairs:
            try:
                # Re-verify no instances are using this key pair
                if self._is_key_pair_in_use(key_name):
                    logger.info(f"Key pair {key_name} is now in use, deferring")
                    result.deferred_resources.append(f"key_pair:{key_name}")
                    continue

                if self.dry_run:
                    logger.info(f"[DRY RUN] Would delete orphaned key pair: {key_name}")
                    result.deleted_key_pairs.append(key_name)
                else:
                    logger.info(f"Deleting orphaned key pair: {key_name}")
                    self.ec2.delete_key_pair(KeyName=key_name)
                    result.deleted_key_pairs.append(key_name)

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "InvalidKeyPair.NotFound":
                    logger.info(f"Key pair {key_name} already deleted")
                    result.deleted_key_pairs.append(key_name)
                else:
                    logger.error(f"Error deleting key pair {key_name}: {e}")
                    result.errors[f"key_pair:{key_name}"] = str(e)
            except Exception as e:
                logger.error(f"Error deleting key pair {key_name}: {e}")
                result.errors[f"key_pair:{key_name}"] = str(e)

    def _is_key_pair_in_use(self, key_name: str) -> bool:
        """Check if a key pair is currently in use by any running/pending instance."""
        try:
            response = self.ec2.describe_instances(
                Filters=[
                    {"Name": "key-name", "Values": [key_name]},
                    {"Name": "instance-state-name", "Values": ["running", "pending"]},
                ]
            )
            for reservation in response.get("Reservations", []):
                if reservation.get("Instances"):
                    return True
        except Exception as e:
            logger.warning(f"Error checking key pair usage for {key_name}: {e}")
        return False

    def _cleanup_orphaned_security_groups(
        self, security_groups: list[str], result: OrphanCleanupResult
    ) -> None:
        """Delete orphaned security groups after confirming no dependencies."""
        logger.info(f"Cleaning up {len(security_groups)} orphaned security groups")

        for sg_id in security_groups:
            try:
                # Re-verify no dependencies exist
                if self._is_security_group_in_use(sg_id):
                    logger.info(f"Security group {sg_id} is now in use, deferring")
                    result.deferred_resources.append(f"security_group:{sg_id}")
                    continue

                if self.dry_run:
                    logger.info(f"[DRY RUN] Would delete orphaned security group: {sg_id}")
                    result.deleted_security_groups.append(sg_id)
                else:
                    logger.info(f"Deleting orphaned security group: {sg_id}")
                    self.ec2.delete_security_group(GroupId=sg_id)
                    result.deleted_security_groups.append(sg_id)

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "InvalidGroup.NotFound":
                    logger.info(f"Security group {sg_id} already deleted")
                    result.deleted_security_groups.append(sg_id)
                elif error_code == "DependencyViolation":
                    logger.info(f"Security group {sg_id} has dependencies, deferring")
                    result.deferred_resources.append(f"security_group:{sg_id}")
                else:
                    logger.error(f"Error deleting security group {sg_id}: {e}")
                    result.errors[f"security_group:{sg_id}"] = str(e)
            except Exception as e:
                logger.error(f"Error deleting security group {sg_id}: {e}")
                result.errors[f"security_group:{sg_id}"] = str(e)

    def _is_security_group_in_use(self, sg_id: str) -> bool:
        """Check if a security group is currently in use."""
        try:
            # Check instances
            response = self.ec2.describe_instances(
                Filters=[
                    {"Name": "instance.group-id", "Values": [sg_id]},
                    {
                        "Name": "instance-state-name",
                        "Values": [
                            "pending",
                            "running",
                            "stopping",
                            "stopped",
                            "shutting-down",
                        ],
                    },
                ]
            )
            for reservation in response.get("Reservations", []):
                if reservation.get("Instances"):
                    return True

            # Check network interfaces
            ni_response = self.ec2.describe_network_interfaces(
                Filters=[{"Name": "group-id", "Values": [sg_id]}]
            )
            if ni_response.get("NetworkInterfaces"):
                return True

        except Exception as e:
            logger.warning(f"Error checking security group usage for {sg_id}: {e}")
        return False

    def _cleanup_orphaned_iam_roles(
        self, iam_roles: list[str], result: OrphanCleanupResult
    ) -> None:
        """Delete orphaned IAM roles with policy detachment before deletion."""
        logger.info(f"Cleaning up {len(iam_roles)} orphaned IAM roles")

        for role_name in iam_roles:
            try:
                # Re-verify role is not in use
                if self._is_iam_role_in_use(role_name):
                    logger.info(f"IAM role {role_name} is now in use, deferring")
                    result.deferred_resources.append(f"iam_role:{role_name}")
                    continue

                if self.dry_run:
                    logger.info(f"[DRY RUN] Would delete orphaned IAM role: {role_name}")
                    result.deleted_iam_roles.append(role_name)
                else:
                    # Delete the role (with policy detachment)
                    self._delete_iam_role(role_name)
                    result.deleted_iam_roles.append(role_name)

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "NoSuchEntity":
                    logger.info(f"IAM role {role_name} already deleted")
                    result.deleted_iam_roles.append(role_name)
                elif error_code == "DeleteConflict":
                    logger.info(f"IAM role {role_name} has dependencies, deferring")
                    result.deferred_resources.append(f"iam_role:{role_name}")
                else:
                    logger.error(f"Error deleting IAM role {role_name}: {e}")
                    result.errors[f"iam_role:{role_name}"] = str(e)
            except Exception as e:
                logger.error(f"Error deleting IAM role {role_name}: {e}")
                result.errors[f"iam_role:{role_name}"] = str(e)

    def _is_iam_role_in_use(self, role_name: str) -> bool:
        """Check if an IAM role is currently in use by any instance profile attached to instances."""
        if self.iam is None:
            return False

        try:
            # Get instance profiles for this role
            response = self.iam.list_instance_profiles_for_role(RoleName=role_name)
            instance_profiles = response.get("InstanceProfiles", [])

            if not instance_profiles:
                return False

            # Check if any of these instance profiles are attached to running instances
            profile_arns = {p["Arn"] for p in instance_profiles}

            paginator = self.ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "pending"]}]
            ):
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        iam_profile = instance.get("IamInstanceProfile")
                        if iam_profile and iam_profile.get("Arn") in profile_arns:
                            return True

        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return False
            logger.warning(f"Error checking IAM role usage for {role_name}: {e}")
        except Exception as e:
            logger.warning(f"Error checking IAM role usage for {role_name}: {e}")
        return False

    def _delete_iam_role(self, role_name: str) -> None:
        """Delete an IAM role with proper cleanup sequence.

        This implements Requirement 10.6: detach all policies and delete the role
        after confirming no instance profiles reference them.
        """
        if self.iam is None:
            logger.warning(f"IAM client not available, cannot delete role {role_name}")
            return

        logger.info(f"Deleting orphaned IAM role: {role_name}")

        # Step 1: Remove role from all instance profiles
        try:
            response = self.iam.list_instance_profiles_for_role(RoleName=role_name)
            for profile in response.get("InstanceProfiles", []):
                profile_name = profile["InstanceProfileName"]
                logger.info(f"Removing role {role_name} from instance profile {profile_name}")
                self.iam.remove_role_from_instance_profile(
                    InstanceProfileName=profile_name, RoleName=role_name
                )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

        # Step 2: Detach all managed policies
        try:
            response = self.iam.list_attached_role_policies(RoleName=role_name)
            for policy in response.get("AttachedPolicies", []):
                policy_arn = policy["PolicyArn"]
                logger.info(f"Detaching policy {policy_arn} from role {role_name}")
                self.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

        # Step 3: Delete all inline policies
        try:
            response = self.iam.list_role_policies(RoleName=role_name)
            for policy_name in response.get("PolicyNames", []):
                logger.info(f"Deleting inline policy {policy_name} from role {role_name}")
                self.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

        # Step 4: Delete the role
        logger.info(f"Deleting IAM role: {role_name}")
        self.iam.delete_role(RoleName=role_name)
