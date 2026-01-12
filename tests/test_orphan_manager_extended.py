"""Extended tests for orphan manager to increase coverage.

Tests for error handling paths and edge cases.
"""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from reaper.cleanup.orphan_manager import (
    OrphanedResources,
    OrphanManager,
)


class TestOrphanManagerErrorHandling:
    """Tests for error handling in OrphanManager."""

    def test_cleanup_key_pair_generic_error(self):
        """Test cleaning up key pair with generic error."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.delete_key_pair.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}},
            "DeleteKeyPair",
        )
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_key_pairs) == 0
        assert "key_pair:packer_key" in result.errors

    def test_cleanup_key_pair_non_client_error(self):
        """Test cleaning up key pair with non-ClientError exception."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.delete_key_pair.side_effect = Exception("Unexpected error")
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_key_pairs) == 0
        assert "key_pair:packer_key" in result.errors

    def test_cleanup_security_group_generic_error(self):
        """Test cleaning up security group with generic error."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
        mock_ec2.delete_security_group.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}},
            "DeleteSecurityGroup",
        )
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_security_groups=["sg-001"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_security_groups) == 0
        assert "security_group:sg-001" in result.errors

    def test_cleanup_security_group_non_client_error(self):
        """Test cleaning up security group with non-ClientError exception."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
        mock_ec2.delete_security_group.side_effect = Exception("Unexpected error")
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_security_groups=["sg-001"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_security_groups) == 0
        assert "security_group:sg-001" in result.errors

    def test_cleanup_iam_role_generic_error(self):
        """Test cleaning up IAM role with generic error."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}},
            "ListAttachedRolePolicies",
        )
        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_iam_roles) == 0
        assert "iam_role:packer_role" in result.errors

    def test_cleanup_iam_role_no_such_entity(self):
        """Test cleaning up IAM role that doesn't exist."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}
        mock_iam.delete_role.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Role not found"}},
            "DeleteRole",
        )
        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        # Role already deleted is still counted as deleted
        assert len(result.deleted_iam_roles) == 1

    def test_cleanup_iam_role_delete_conflict(self):
        """Test cleaning up IAM role with delete conflict."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}
        mock_iam.delete_role.side_effect = ClientError(
            {"Error": {"Code": "DeleteConflict", "Message": "Role has dependencies"}},
            "DeleteRole",
        )
        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_iam_roles) == 0
        assert len(result.deferred_resources) == 1

    def test_cleanup_iam_role_non_client_error(self):
        """Test cleaning up IAM role with non-ClientError exception."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}
        mock_iam.delete_role.side_effect = Exception("Unexpected error")
        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_iam_roles) == 0
        assert "iam_role:packer_role" in result.errors


class TestOrphanManagerDeferredResources:
    """Tests for deferred resource handling."""

    def test_cleanup_key_pair_deferred_when_in_use(self):
        """Test key pair is deferred when it becomes in use."""
        mock_ec2 = MagicMock()
        # Key pair is now in use
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-001"}]}]
        }
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_key_pairs) == 0
        assert "key_pair:packer_key" in result.deferred_resources

    def test_cleanup_security_group_deferred_when_in_use(self):
        """Test security group is deferred when it becomes in use."""
        mock_ec2 = MagicMock()
        # Security group is now in use by instance
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-001"}]}]
        }
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_security_groups=["sg-001"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_security_groups) == 0
        assert "security_group:sg-001" in result.deferred_resources

    def test_cleanup_iam_role_deferred_when_in_use(self):
        """Test IAM role is deferred when it becomes in use."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Role is now in use
        mock_iam.list_instance_profiles_for_role.return_value = {
            "InstanceProfiles": [{"Arn": "arn:aws:iam::123456789012:instance-profile/test"}]
        }
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "IamInstanceProfile": {
                                    "Arn": "arn:aws:iam::123456789012:instance-profile/test"
                                }
                            }
                        ]
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_iam_roles) == 0
        assert "iam_role:packer_role" in result.deferred_resources


class TestOrphanManagerScanErrorHandling:
    """Tests for scan error handling."""

    def test_scan_orphaned_iam_roles_handles_exception(self):
        """Test scanning IAM roles handles exceptions."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_iam.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager.scan_orphaned_iam_roles()

        assert len(result) == 0

    def test_get_iam_roles_in_use_handles_exception(self):
        """Test getting IAM roles in use handles exceptions."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._get_iam_roles_in_use()

        assert len(result) == 0

    def test_get_security_groups_in_use_handles_exception(self):
        """Test getting security groups in use handles exceptions."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        result = manager._get_security_groups_in_use()

        assert len(result) == 0

    def test_is_key_pair_in_use_handles_exception(self):
        """Test checking key pair in use handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = Exception("API error")

        manager = OrphanManager(mock_ec2)
        result = manager._is_key_pair_in_use("packer_key")

        assert result is False

    def test_is_security_group_in_use_handles_exception(self):
        """Test checking security group in use handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = Exception("API error")

        manager = OrphanManager(mock_ec2)
        result = manager._is_security_group_in_use("sg-001")

        assert result is False

    def test_is_iam_role_in_use_handles_no_such_entity(self):
        """Test checking IAM role in use handles NoSuchEntity."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_iam.list_instance_profiles_for_role.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Role not found"}},
            "ListInstanceProfilesForRole",
        )

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._is_iam_role_in_use("packer_role")

        assert result is False

    def test_is_iam_role_in_use_handles_generic_exception(self):
        """Test checking IAM role in use handles generic exceptions."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_iam.list_instance_profiles_for_role.side_effect = Exception("API error")

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._is_iam_role_in_use("packer_role")

        assert result is False


class TestOrphanManagerDeleteIAMRoleErrorHandling:
    """Tests for _delete_iam_role error handling."""

    def test_delete_iam_role_handles_no_such_entity_on_profiles(self):
        """Test deleting IAM role handles NoSuchEntity on instance profiles."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Role not found"}},
            "ListInstanceProfilesForRole",
        )
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        manager._delete_iam_role("packer_role")

        mock_iam.delete_role.assert_called_once()

    def test_delete_iam_role_handles_no_such_entity_on_policies(self):
        """Test deleting IAM role handles NoSuchEntity on attached policies."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Role not found"}},
            "ListAttachedRolePolicies",
        )
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        manager._delete_iam_role("packer_role")

        mock_iam.delete_role.assert_called_once()

    def test_delete_iam_role_handles_no_such_entity_on_inline_policies(self):
        """Test deleting IAM role handles NoSuchEntity on inline policies."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Role not found"}},
            "ListRolePolicies",
        )

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        manager._delete_iam_role("packer_role")

        mock_iam.delete_role.assert_called_once()

    def test_delete_iam_role_reraises_non_no_such_entity_error(self):
        """Test deleting IAM role re-raises non-NoSuchEntity errors."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "ListInstanceProfilesForRole",
        )

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        with pytest.raises(ClientError) as exc_info:
            manager._delete_iam_role("packer_role")

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"


class TestOrphanManagerGetPackerIAMRolesErrorHandling:
    """Tests for _get_packer_iam_roles error handling."""

    def test_get_packer_iam_roles_handles_exception(self):
        """Test getting packer IAM roles handles exceptions."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_iam.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._get_packer_iam_roles()

        assert len(result) == 0
