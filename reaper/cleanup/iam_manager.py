"""IAM resource management for instance profiles cleanup.

This module provides IAM instance profile management functionality for the
Packer Resource Reaper. It handles instance profile scanning for `packer_*`
pattern, deletion with role detachment, and handling orphaned instance profiles
from failed Packer builds as per Requirements 2.2, 2.4, 2.8, 7.1, 7.2.
"""

import logging
from typing import Any, List, Optional

from botocore.exceptions import ClientError

from reaper.models import PackerInstanceProfile, ResourceType

logger = logging.getLogger(__name__)


class IAMManager:
    """Manages IAM instance profile cleanup operations.

    Handles:
    - Instance profile scanning for `packer_*` pattern (Requirement 7.2)
    - Instance profile deletion with role detachment (Requirement 2.4)
    - Handling orphaned instance profiles from failed Packer builds (Requirement 2.8)
    - IAM roles with permissions restricted to necessary actions (Requirement 7.1)
    """

    # Pattern for Packer-generated instance profiles
    PACKER_PATTERN = "packer_"

    def __init__(self, iam_client: Any, dry_run: bool = False):
        """
        Initialize IAM manager.

        Args:
            iam_client: Boto3 IAM client
            dry_run: If True, simulate operations without executing
        """
        self.iam = iam_client
        self.dry_run = dry_run

    def scan_instance_profiles(
        self, account_id: str, region: str, pattern: Optional[str] = None
    ) -> List[PackerInstanceProfile]:
        """
        Scan IAM instance profiles matching the packer pattern.

        This scans for instance profiles with names starting with `packer_`
        to identify orphaned profiles from failed Packer builds (Requirement 7.2).

        Args:
            account_id: AWS account ID
            region: AWS region
            pattern: Optional pattern to match (defaults to PACKER_PATTERN)

        Returns:
            List of PackerInstanceProfile objects matching the pattern
        """
        pattern = pattern or self.PACKER_PATTERN
        instance_profiles = []

        try:
            paginator = self.iam.get_paginator("list_instance_profiles")

            for page in paginator.paginate():
                for profile in page.get("InstanceProfiles", []):
                    profile_name = profile["InstanceProfileName"]

                    # Only include profiles matching the packer pattern
                    if not profile_name.startswith(pattern):
                        continue

                    # Extract role names from the profile
                    roles = [role["RoleName"] for role in profile.get("Roles", [])]

                    instance_profiles.append(
                        PackerInstanceProfile(
                            resource_id=profile["InstanceProfileId"],
                            resource_type=ResourceType.INSTANCE_PROFILE,
                            creation_time=profile["CreateDate"],
                            tags={},  # IAM instance profiles don't have tags directly
                            region=region,
                            account_id=account_id,
                            instance_profile_name=profile_name,
                            instance_profile_id=profile["InstanceProfileId"],
                            arn=profile["Arn"],
                            path=profile.get("Path", "/"),
                            roles=roles,
                        )
                    )
        except Exception as e:
            logger.error(f"Error scanning instance profiles: {e}")

        logger.info(
            f"Scanned {len(instance_profiles)} instance profiles matching '{pattern}'"
        )
        return instance_profiles

    def get_instance_profile_by_name(
        self, profile_name: str, account_id: str, region: str
    ) -> Optional[PackerInstanceProfile]:
        """
        Get an instance profile by its name.

        Args:
            profile_name: Instance profile name
            account_id: AWS account ID
            region: AWS region

        Returns:
            PackerInstanceProfile object or None if not found
        """
        if not profile_name:
            return None

        try:
            response = self.iam.get_instance_profile(InstanceProfileName=profile_name)
            profile = response.get("InstanceProfile")

            if profile:
                roles = [role["RoleName"] for role in profile.get("Roles", [])]

                return PackerInstanceProfile(
                    resource_id=profile["InstanceProfileId"],
                    resource_type=ResourceType.INSTANCE_PROFILE,
                    creation_time=profile["CreateDate"],
                    tags={},
                    region=region,
                    account_id=account_id,
                    instance_profile_name=profile["InstanceProfileName"],
                    instance_profile_id=profile["InstanceProfileId"],
                    arn=profile["Arn"],
                    path=profile.get("Path", "/"),
                    roles=roles,
                )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchEntity":
                logger.debug(f"Instance profile {profile_name} not found")
            else:
                logger.error(f"Error getting instance profile {profile_name}: {e}")
        except Exception as e:
            logger.error(f"Error getting instance profile {profile_name}: {e}")

        return None

    def delete_instance_profiles(
        self, instance_profiles: List[PackerInstanceProfile]
    ) -> tuple[List[str], List[str], dict]:
        """
        Delete IAM instance profiles with role detachment.

        This implements Requirement 2.4: delete instance profiles after
        instance termination, with proper role detachment.

        Args:
            instance_profiles: List of instance profiles to delete

        Returns:
            Tuple of (deleted_names, deferred_names, errors)
        """
        deleted = []
        deferred = []
        errors = {}

        for profile in instance_profiles:
            try:
                result = self._delete_instance_profile(profile)
                if result == "deleted":
                    deleted.append(profile.instance_profile_name)
                elif result == "deferred":
                    deferred.append(profile.instance_profile_name)
            except Exception as e:
                logger.error(
                    f"Error deleting instance profile "
                    f"{profile.instance_profile_name}: {e}"
                )
                errors[profile.instance_profile_name] = str(e)

        return deleted, deferred, errors

    def _delete_instance_profile(self, profile: PackerInstanceProfile) -> str:
        """
        Delete a single instance profile with role detachment.

        This handles the proper cleanup sequence:
        1. Remove all roles from the instance profile
        2. Delete the instance profile

        Returns:
            "deleted" if successful, "deferred" if has dependencies
        """
        profile_name = profile.instance_profile_name

        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete instance profile {profile_name}")
            if profile.roles:
                logger.info(f"[DRY RUN] Would first detach roles: {profile.roles}")
            return "deleted"

        try:
            # Step 1: Remove all roles from the instance profile
            for role_name in profile.roles:
                logger.info(
                    f"Removing role {role_name} from instance profile {profile_name}"
                )
                self.iam.remove_role_from_instance_profile(
                    InstanceProfileName=profile_name,
                    RoleName=role_name,
                )

            # Step 2: Delete the instance profile
            logger.info(f"Deleting instance profile {profile_name}")
            self.iam.delete_instance_profile(InstanceProfileName=profile_name)
            return "deleted"

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "DeleteConflict":
                logger.info(
                    f"Instance profile {profile_name} has dependencies, deferring"
                )
                return "deferred"
            elif error_code == "NoSuchEntity":
                logger.info(f"Instance profile {profile_name} already deleted")
                return "deleted"
            raise

    def matches_packer_pattern(self, profile_name: str) -> bool:
        """
        Check if an instance profile name matches the Packer pattern.

        This implements Requirement 7.2: only operate on resources that
        match the configured filters.

        Args:
            profile_name: Instance profile name to check

        Returns:
            True if the name starts with 'packer_', False otherwise
        """
        if not profile_name:
            return False
        return profile_name.startswith(self.PACKER_PATTERN)
