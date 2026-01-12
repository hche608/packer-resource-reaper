"""Tests for orphan manager functionality.

Tests for orphaned resource detection and cleanup.
"""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from reaper.cleanup.orphan_manager import (
    OrphanCleanupResult,
    OrphanedResources,
    OrphanManager,
)


class TestOrphanedResources:
    """Tests for OrphanedResources dataclass."""

    def test_is_empty_true(self):
        """Test is_empty returns True when no resources."""
        orphaned = OrphanedResources()

        assert orphaned.is_empty() is True

    def test_is_empty_false_key_pairs(self):
        """Test is_empty returns False when key pairs exist."""
        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key"])

        assert orphaned.is_empty() is False

    def test_is_empty_false_security_groups(self):
        """Test is_empty returns False when security groups exist."""
        orphaned = OrphanedResources(orphaned_security_groups=["sg-001"])

        assert orphaned.is_empty() is False

    def test_is_empty_false_iam_roles(self):
        """Test is_empty returns False when IAM roles exist."""
        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        assert orphaned.is_empty() is False

    def test_total_count(self):
        """Test total_count returns correct count."""
        orphaned = OrphanedResources(
            orphaned_key_pairs=["key1", "key2"],
            orphaned_security_groups=["sg-001"],
            orphaned_iam_roles=["role1", "role2", "role3"],
        )

        assert orphaned.total_count() == 6


class TestOrphanCleanupResult:
    """Tests for OrphanCleanupResult dataclass."""

    def test_total_cleaned(self):
        """Test total_cleaned returns correct count."""
        result = OrphanCleanupResult(
            deleted_key_pairs=["key1", "key2"],
            deleted_security_groups=["sg-001"],
            deleted_iam_roles=["role1"],
        )

        assert result.total_cleaned() == 4

    def test_total_cleaned_empty(self):
        """Test total_cleaned returns 0 when empty."""
        result = OrphanCleanupResult()

        assert result.total_cleaned() == 0


class TestOrphanManagerScanOrphanedKeyPairs:
    """Tests for scan_orphaned_key_pairs method."""

    def test_scan_finds_orphaned_key_pairs(self):
        """Test scanning finds orphaned packer key pairs."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {"KeyName": "packer_key_1"},
                {"KeyName": "packer_key_2"},
                {"KeyName": "production_key"},
            ]
        }
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Reservations": []}]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        orphaned = manager.scan_orphaned_key_pairs()

        assert len(orphaned) == 2
        assert "packer_key_1" in orphaned
        assert "packer_key_2" in orphaned

    def test_scan_excludes_key_pairs_in_use(self):
        """Test scanning excludes key pairs used by instances."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {"KeyName": "packer_key_1"},
                {"KeyName": "packer_key_2"},
            ]
        }
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {"Instances": [{"KeyName": "packer_key_1", "State": {"Name": "running"}}]}
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        orphaned = manager.scan_orphaned_key_pairs()

        assert len(orphaned) == 1
        assert "packer_key_2" in orphaned

    def test_scan_handles_exception(self):
        """Test scanning handles exceptions gracefully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = Exception("API error")

        manager = OrphanManager(mock_ec2)
        orphaned = manager.scan_orphaned_key_pairs()

        assert len(orphaned) == 0


class TestOrphanManagerScanOrphanedSecurityGroups:
    """Tests for scan_orphaned_security_groups method."""

    def test_scan_finds_orphaned_security_groups(self):
        """Test scanning finds orphaned packer security groups."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {"GroupId": "sg-001", "GroupName": "packer_sg_1", "Description": ""},
                    {"GroupId": "sg-002", "GroupName": "packer_sg_2", "Description": ""},
                    {"GroupId": "sg-003", "GroupName": "production_sg", "Description": ""},
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        orphaned = manager.scan_orphaned_security_groups()

        assert len(orphaned) == 2

    def test_scan_excludes_default_security_groups(self):
        """Test scanning excludes default security groups."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {"GroupId": "sg-001", "GroupName": "default", "Description": ""},
                    {"GroupId": "sg-002", "GroupName": "packer_sg", "Description": ""},
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        orphaned = manager.scan_orphaned_security_groups()

        assert "sg-001" not in orphaned

    def test_scan_handles_exception(self):
        """Test scanning handles exceptions gracefully."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        orphaned = manager.scan_orphaned_security_groups()

        assert len(orphaned) == 0


class TestOrphanManagerScanOrphanedIAMRoles:
    """Tests for scan_orphaned_iam_roles method."""

    def test_scan_finds_orphaned_iam_roles(self):
        """Test scanning finds orphaned packer IAM roles."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # IAM paginator for roles
        mock_iam_paginator = MagicMock()
        mock_iam_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "packer_role_1"},
                    {"RoleName": "packer-role-2"},
                    {"RoleName": "production_role"},
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_iam_paginator

        # EC2 paginator for instances
        mock_ec2_paginator = MagicMock()
        mock_ec2_paginator.paginate.return_value = [{"Reservations": []}]
        mock_ec2.get_paginator.return_value = mock_ec2_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        orphaned = manager.scan_orphaned_iam_roles()

        assert len(orphaned) == 2
        assert "packer_role_1" in orphaned
        assert "packer-role-2" in orphaned

    def test_scan_excludes_reaper_role(self):
        """Test scanning excludes the reaper's own role."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam_paginator = MagicMock()
        mock_iam_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "packer-resource-reaper-role"},
                    {"RoleName": "packer_role_1"},
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_iam_paginator

        mock_ec2_paginator = MagicMock()
        mock_ec2_paginator.paginate.return_value = [{"Reservations": []}]
        mock_ec2.get_paginator.return_value = mock_ec2_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        orphaned = manager.scan_orphaned_iam_roles()

        assert "packer-resource-reaper-role" not in orphaned
        assert "packer_role_1" in orphaned

    def test_scan_without_iam_client(self):
        """Test scanning without IAM client returns empty list."""
        mock_ec2 = MagicMock()

        manager = OrphanManager(mock_ec2, iam_client=None)
        orphaned = manager.scan_orphaned_iam_roles()

        assert len(orphaned) == 0


class TestOrphanManagerScanOrphanedResources:
    """Tests for scan_orphaned_resources method."""

    def test_scan_all_resources(self):
        """Test scanning all orphaned resources."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": [{"KeyName": "packer_key"}]}
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Reservations": []},
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        orphaned = manager.scan_orphaned_resources()

        assert orphaned.total_count() >= 1


class TestOrphanManagerCleanupOrphanedResources:
    """Tests for cleanup_orphaned_resources method."""

    def test_cleanup_key_pairs_success(self):
        """Test cleaning up orphaned key pairs successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key_1", "packer_key_2"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_key_pairs) == 2
        assert mock_ec2.delete_key_pair.call_count == 2

    def test_cleanup_key_pairs_dry_run(self):
        """Test cleaning up key pairs in dry run mode."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        manager = OrphanManager(mock_ec2, dry_run=True)

        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert result.dry_run is True
        assert len(result.deleted_key_pairs) == 1
        mock_ec2.delete_key_pair.assert_not_called()

    def test_cleanup_security_groups_success(self):
        """Test cleaning up orphaned security groups successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_security_groups=["sg-001", "sg-002"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_security_groups) == 2

    def test_cleanup_security_groups_dependency_violation(self):
        """Test cleaning up security groups handles dependency violations."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
        mock_ec2.delete_security_group.side_effect = ClientError(
            {"Error": {"Code": "DependencyViolation", "Message": "Has dependencies"}},
            "DeleteSecurityGroup",
        )
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_security_groups=["sg-001"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_security_groups) == 0
        assert len(result.deferred_resources) == 1

    def test_cleanup_empty_orphaned_resources(self):
        """Test cleaning up empty orphaned resources."""
        mock_ec2 = MagicMock()
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources()

        result = manager.cleanup_orphaned_resources(orphaned)

        assert result.total_cleaned() == 0
        mock_ec2.delete_key_pair.assert_not_called()
        mock_ec2.delete_security_group.assert_not_called()

    def test_cleanup_key_pair_not_found(self):
        """Test cleaning up key pair that doesn't exist."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.delete_key_pair.side_effect = ClientError(
            {"Error": {"Code": "InvalidKeyPair.NotFound", "Message": "Not found"}},
            "DeleteKeyPair",
        )
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key"])

        result = manager.cleanup_orphaned_resources(orphaned)

        # Key pair already deleted is still counted as deleted
        assert len(result.deleted_key_pairs) == 1

    def test_cleanup_security_group_not_found(self):
        """Test cleaning up security group that doesn't exist."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
        mock_ec2.delete_security_group.side_effect = ClientError(
            {"Error": {"Code": "InvalidGroup.NotFound", "Message": "Not found"}},
            "DeleteSecurityGroup",
        )
        manager = OrphanManager(mock_ec2, dry_run=False)

        orphaned = OrphanedResources(orphaned_security_groups=["sg-001"])

        result = manager.cleanup_orphaned_resources(orphaned)

        # Security group already deleted is still counted as deleted
        assert len(result.deleted_security_groups) == 1


class TestOrphanManagerIsKeyPairInUse:
    """Tests for _is_key_pair_in_use method."""

    def test_key_pair_in_use(self):
        """Test detecting key pair in use."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-001"}]}]
        }

        manager = OrphanManager(mock_ec2)
        result = manager._is_key_pair_in_use("packer_key")

        assert result is True

    def test_key_pair_not_in_use(self):
        """Test detecting key pair not in use."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        manager = OrphanManager(mock_ec2)
        result = manager._is_key_pair_in_use("packer_key")

        assert result is False


class TestOrphanManagerIsSecurityGroupInUse:
    """Tests for _is_security_group_in_use method."""

    def test_security_group_in_use_by_instance(self):
        """Test detecting security group in use by instance."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-001"}]}]
        }

        manager = OrphanManager(mock_ec2)
        result = manager._is_security_group_in_use("sg-001")

        assert result is True

    def test_security_group_in_use_by_eni(self):
        """Test detecting security group in use by ENI."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {
            "NetworkInterfaces": [{"NetworkInterfaceId": "eni-001"}]
        }

        manager = OrphanManager(mock_ec2)
        result = manager._is_security_group_in_use("sg-001")

        assert result is True

    def test_security_group_not_in_use(self):
        """Test detecting security group not in use."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}

        manager = OrphanManager(mock_ec2)
        result = manager._is_security_group_in_use("sg-001")

        assert result is False


class TestOrphanManagerCleanupIAMRoles:
    """Tests for IAM role cleanup."""

    def test_cleanup_iam_roles_success(self):
        """Test cleaning up orphaned IAM roles successfully."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Role is not in use
        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_iam_roles) == 1
        mock_iam.delete_role.assert_called_once_with(RoleName="packer_role")

    def test_cleanup_iam_roles_dry_run(self):
        """Test cleaning up IAM roles in dry run mode."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=True)

        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert result.dry_run is True
        assert len(result.deleted_iam_roles) == 1
        mock_iam.delete_role.assert_not_called()

    def test_cleanup_iam_role_with_policies(self):
        """Test cleaning up IAM role with attached policies."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/TestPolicy"}]
        }
        mock_iam.list_role_policies.return_value = {"PolicyNames": ["InlinePolicy"]}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert len(result.deleted_iam_roles) == 1
        mock_iam.detach_role_policy.assert_called_once()
        mock_iam.delete_role_policy.assert_called_once()
        mock_iam.delete_role.assert_called_once()


class TestOrphanManagerGetPackerKeyPairs:
    """Tests for _get_packer_key_pairs method."""

    def test_get_packer_key_pairs_success(self):
        """Test getting packer key pairs successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {"KeyName": "packer_key_1"},
                {"KeyName": "packer_key_2"},
                {"KeyName": "production_key"},
            ]
        }

        manager = OrphanManager(mock_ec2)
        result = manager._get_packer_key_pairs()

        assert len(result) == 2
        assert "packer_key_1" in result
        assert "packer_key_2" in result

    def test_get_packer_key_pairs_empty(self):
        """Test getting packer key pairs when none exist."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": []}

        manager = OrphanManager(mock_ec2)
        result = manager._get_packer_key_pairs()

        assert len(result) == 0

    def test_get_packer_key_pairs_handles_exception(self):
        """Test getting packer key pairs handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = Exception("API error")

        manager = OrphanManager(mock_ec2)
        result = manager._get_packer_key_pairs()

        assert len(result) == 0


class TestOrphanManagerGetKeyPairsInUse:
    """Tests for _get_key_pairs_in_use method."""

    def test_get_key_pairs_in_use_success(self):
        """Test getting key pairs in use successfully."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {"Instances": [{"KeyName": "packer_key_1"}]},
                    {"Instances": [{"KeyName": "packer_key_2"}]},
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        result = manager._get_key_pairs_in_use()

        assert "packer_key_1" in result
        assert "packer_key_2" in result

    def test_get_key_pairs_in_use_handles_exception(self):
        """Test getting key pairs in use handles exceptions."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        result = manager._get_key_pairs_in_use()

        assert len(result) == 0


class TestOrphanManagerGetPackerSecurityGroups:
    """Tests for _get_packer_security_groups method."""

    def test_get_packer_security_groups_by_name(self):
        """Test getting packer security groups by name."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {"GroupId": "sg-001", "GroupName": "packer_sg", "Description": ""},
                    {"GroupId": "sg-002", "GroupName": "production_sg", "Description": ""},
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        result = manager._get_packer_security_groups()

        assert "sg-001" in result
        assert "sg-002" not in result

    def test_get_packer_security_groups_by_description(self):
        """Test getting packer security groups by description."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {"GroupId": "sg-001", "GroupName": "my_sg", "Description": "packer build sg"},
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        result = manager._get_packer_security_groups()

        assert "sg-001" in result

    def test_get_packer_security_groups_handles_exception(self):
        """Test getting packer security groups handles exceptions."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        result = manager._get_packer_security_groups()

        assert len(result) == 0


class TestOrphanManagerGetSecurityGroupsInUse:
    """Tests for _get_security_groups_in_use method."""

    def test_get_security_groups_in_use_by_instances(self):
        """Test getting security groups in use by instances."""
        mock_ec2 = MagicMock()

        # Instance paginator
        mock_instance_paginator = MagicMock()
        mock_instance_paginator.paginate.return_value = [
            {"Reservations": [{"Instances": [{"SecurityGroups": [{"GroupId": "sg-001"}]}]}]}
        ]

        # Network interface paginator
        mock_ni_paginator = MagicMock()
        mock_ni_paginator.paginate.return_value = [{"NetworkInterfaces": []}]

        def get_paginator(name):
            if name == "describe_instances":
                return mock_instance_paginator
            return mock_ni_paginator

        mock_ec2.get_paginator.side_effect = get_paginator

        manager = OrphanManager(mock_ec2)
        result = manager._get_security_groups_in_use()

        assert "sg-001" in result

    def test_get_security_groups_in_use_by_enis(self):
        """Test getting security groups in use by ENIs."""
        mock_ec2 = MagicMock()

        # Instance paginator
        mock_instance_paginator = MagicMock()
        mock_instance_paginator.paginate.return_value = [{"Reservations": []}]

        # Network interface paginator
        mock_ni_paginator = MagicMock()
        mock_ni_paginator.paginate.return_value = [
            {"NetworkInterfaces": [{"Groups": [{"GroupId": "sg-002"}]}]}
        ]

        def get_paginator(name):
            if name == "describe_instances":
                return mock_instance_paginator
            return mock_ni_paginator

        mock_ec2.get_paginator.side_effect = get_paginator

        manager = OrphanManager(mock_ec2)
        result = manager._get_security_groups_in_use()

        assert "sg-002" in result


class TestOrphanManagerGetPackerIAMRoles:
    """Tests for _get_packer_iam_roles method."""

    def test_get_packer_iam_roles_success(self):
        """Test getting packer IAM roles successfully."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "packer_role_1"},
                    {"RoleName": "packer-role-2"},
                    {"RoleName": "production_role"},
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._get_packer_iam_roles()

        assert "packer_role_1" in result
        assert "packer-role-2" in result
        assert "production_role" not in result

    def test_get_packer_iam_roles_excludes_reaper(self):
        """Test getting packer IAM roles excludes reaper role."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "packer-resource-reaper-role"},
                    {"RoleName": "packer_role_1"},
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._get_packer_iam_roles()

        assert "packer-resource-reaper-role" not in result
        assert "packer_role_1" in result


class TestOrphanManagerIsIAMRoleInUse:
    """Tests for _is_iam_role_in_use method."""

    def test_iam_role_in_use(self):
        """Test detecting IAM role in use."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

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

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._is_iam_role_in_use("packer_role")

        assert result is True

    def test_iam_role_not_in_use(self):
        """Test detecting IAM role not in use."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._is_iam_role_in_use("packer_role")

        assert result is False


class TestOrphanManagerDeleteIAMRole:
    """Tests for _delete_iam_role method."""

    def test_delete_iam_role_success(self):
        """Test deleting IAM role successfully."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        manager._delete_iam_role("packer_role")

        mock_iam.delete_role.assert_called_once_with(RoleName="packer_role")

    def test_delete_iam_role_with_policies(self):
        """Test deleting IAM role with attached policies."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/TestPolicy"}]
        }
        mock_iam.list_role_policies.return_value = {"PolicyNames": ["InlinePolicy"]}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        manager._delete_iam_role("packer_role")

        mock_iam.detach_role_policy.assert_called_once()
        mock_iam.delete_role_policy.assert_called_once()
        mock_iam.delete_role.assert_called_once()

    def test_delete_iam_role_with_instance_profile(self):
        """Test deleting IAM role attached to instance profile."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {
            "InstanceProfiles": [{"InstanceProfileName": "test_profile"}]
        }
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        manager._delete_iam_role("packer_role")

        mock_iam.remove_role_from_instance_profile.assert_called_once()
        mock_iam.delete_role.assert_called_once()
