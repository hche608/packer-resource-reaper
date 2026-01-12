"""Tests for network manager functionality.

Tests for security groups, key pairs, and EIP management.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from reaper.cleanup.network_manager import NetworkManager
from reaper.models import (
    PackerElasticIP,
    PackerKeyPair,
    PackerSecurityGroup,
    ResourceType,
)


def create_packer_security_group(
    group_id: str,
    group_name: str = "packer_sg",
    vpc_id: str = "vpc-12345678",
) -> PackerSecurityGroup:
    """Create a PackerSecurityGroup for testing."""
    return PackerSecurityGroup(
        resource_id=group_id,
        resource_type=ResourceType.SECURITY_GROUP,
        creation_time=datetime.now(UTC),
        tags={},
        region="us-east-1",
        account_id="123456789012",
        group_name=group_name,
        vpc_id=vpc_id,
        description="Packer security group",
    )


def create_packer_key_pair(
    key_name: str,
    key_id: str = "key-12345678",
) -> PackerKeyPair:
    """Create a PackerKeyPair for testing."""
    return PackerKeyPair(
        resource_id=key_id,
        resource_type=ResourceType.KEY_PAIR,
        creation_time=datetime.now(UTC),
        tags={},
        region="us-east-1",
        account_id="123456789012",
        key_name=key_name,
        key_fingerprint="ab:cd:ef:12:34:56",
    )


def create_packer_elastic_ip(
    allocation_id: str,
    public_ip: str = "1.2.3.4",
    association_id: str = None,
    instance_id: str = None,
) -> PackerElasticIP:
    """Create a PackerElasticIP for testing."""
    return PackerElasticIP(
        resource_id=allocation_id,
        resource_type=ResourceType.ELASTIC_IP,
        creation_time=datetime.now(UTC),
        tags={},
        region="us-east-1",
        account_id="123456789012",
        public_ip=public_ip,
        allocation_id=allocation_id,
        association_id=association_id,
        instance_id=instance_id,
    )


class TestNetworkManagerGetSecurityGroupsForInstance:
    """Tests for get_security_groups_for_instance method."""

    def test_get_security_groups_success(self):
        """Test getting security groups successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-001",
                    "GroupName": "packer_sg_1",
                    "VpcId": "vpc-12345678",
                    "Description": "Packer SG",
                    "Tags": [{"Key": "Name", "Value": "Packer"}],
                },
                {
                    "GroupId": "sg-002",
                    "GroupName": "packer_sg_2",
                    "VpcId": "vpc-12345678",
                    "Description": "Packer SG 2",
                    "Tags": [],
                },
            ]
        }

        manager = NetworkManager(mock_ec2)
        sgs = manager.get_security_groups_for_instance(
            ["sg-001", "sg-002"], "123456789012", "us-east-1"
        )

        assert len(sgs) == 2
        assert sgs[0].resource_id == "sg-001"
        assert sgs[1].resource_id == "sg-002"

    def test_get_security_groups_skips_default(self):
        """Test getting security groups skips default group."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-001",
                    "GroupName": "packer_sg",
                    "VpcId": "vpc-12345678",
                    "Description": "Packer SG",
                    "Tags": [],
                },
                {
                    "GroupId": "sg-default",
                    "GroupName": "default",
                    "VpcId": "vpc-12345678",
                    "Description": "Default SG",
                    "Tags": [],
                },
            ]
        }

        manager = NetworkManager(mock_ec2)
        sgs = manager.get_security_groups_for_instance(
            ["sg-001", "sg-default"], "123456789012", "us-east-1"
        )

        assert len(sgs) == 1
        assert sgs[0].group_name != "default"

    def test_get_security_groups_empty_list(self):
        """Test getting security groups with empty list."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2)

        sgs = manager.get_security_groups_for_instance([], "123456789012", "us-east-1")

        assert len(sgs) == 0
        mock_ec2.describe_security_groups.assert_not_called()

    def test_get_security_groups_handles_exception(self):
        """Test getting security groups handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.side_effect = Exception("API error")

        manager = NetworkManager(mock_ec2)
        sgs = manager.get_security_groups_for_instance(["sg-001"], "123456789012", "us-east-1")

        assert len(sgs) == 0


class TestNetworkManagerScanSecurityGroups:
    """Tests for scan_security_groups method."""

    def test_scan_security_groups_success(self):
        """Test scanning security groups successfully."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-001",
                        "GroupName": "packer_sg",
                        "VpcId": "vpc-12345678",
                        "Description": "Packer SG",
                        "Tags": [],
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = NetworkManager(mock_ec2)
        sgs = manager.scan_security_groups("123456789012", "us-east-1")

        assert len(sgs) == 1

    def test_scan_security_groups_with_filters(self):
        """Test scanning security groups with filters."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"SecurityGroups": []}]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = NetworkManager(mock_ec2)
        filters = [{"Name": "group-name", "Values": ["packer_*"]}]
        manager.scan_security_groups("123456789012", "us-east-1", filters=filters)

        mock_paginator.paginate.assert_called_with(Filters=filters)

    def test_scan_security_groups_handles_exception(self):
        """Test scanning security groups handles exceptions."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = NetworkManager(mock_ec2)
        sgs = manager.scan_security_groups("123456789012", "us-east-1")

        assert len(sgs) == 0


class TestNetworkManagerGetKeyPairByName:
    """Tests for get_key_pair_by_name method."""

    def test_get_key_pair_success(self):
        """Test getting key pair successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {
                    "KeyPairId": "key-001",
                    "KeyName": "packer_key",
                    "KeyFingerprint": "ab:cd:ef",
                    "CreateTime": datetime.now(UTC),
                    "Tags": [],
                }
            ]
        }

        manager = NetworkManager(mock_ec2)
        kp = manager.get_key_pair_by_name("packer_key", "123456789012", "us-east-1")

        assert kp is not None
        assert kp.key_name == "packer_key"

    def test_get_key_pair_not_found(self):
        """Test getting key pair that doesn't exist."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = ClientError(
            {"Error": {"Code": "InvalidKeyPair.NotFound", "Message": "Not found"}},
            "DescribeKeyPairs",
        )

        manager = NetworkManager(mock_ec2)
        kp = manager.get_key_pair_by_name("nonexistent", "123456789012", "us-east-1")

        assert kp is None

    def test_get_key_pair_empty_name(self):
        """Test getting key pair with empty name."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2)

        kp = manager.get_key_pair_by_name("", "123456789012", "us-east-1")

        assert kp is None
        mock_ec2.describe_key_pairs.assert_not_called()

    def test_get_key_pair_none_name(self):
        """Test getting key pair with None name."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2)

        kp = manager.get_key_pair_by_name(None, "123456789012", "us-east-1")

        assert kp is None

    def test_get_key_pair_other_error(self):
        """Test getting key pair handles other errors."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "DescribeKeyPairs",
        )

        manager = NetworkManager(mock_ec2)
        kp = manager.get_key_pair_by_name("test", "123456789012", "us-east-1")

        assert kp is None

    def test_get_key_pair_generic_exception(self):
        """Test getting key pair handles generic exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = Exception("Unexpected error")

        manager = NetworkManager(mock_ec2)
        kp = manager.get_key_pair_by_name("test", "123456789012", "us-east-1")

        assert kp is None


class TestNetworkManagerScanKeyPairs:
    """Tests for scan_key_pairs method."""

    def test_scan_key_pairs_success(self):
        """Test scanning key pairs successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {
                    "KeyPairId": "key-001",
                    "KeyName": "packer_key_1",
                    "KeyFingerprint": "ab:cd:ef",
                    "CreateTime": datetime.now(UTC),
                    "Tags": [],
                },
                {
                    "KeyPairId": "key-002",
                    "KeyName": "packer_key_2",
                    "KeyFingerprint": "12:34:56",
                    "Tags": [],
                },
            ]
        }

        manager = NetworkManager(mock_ec2)
        kps = manager.scan_key_pairs("123456789012", "us-east-1")

        assert len(kps) == 2

    def test_scan_key_pairs_handles_exception(self):
        """Test scanning key pairs handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = Exception("API error")

        manager = NetworkManager(mock_ec2)
        kps = manager.scan_key_pairs("123456789012", "us-east-1")

        assert len(kps) == 0


class TestNetworkManagerGetEIPsForInstance:
    """Tests for get_eips_for_instance method."""

    def test_get_eips_success(self):
        """Test getting EIPs successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_addresses.return_value = {
            "Addresses": [
                {
                    "AllocationId": "eipalloc-001",
                    "PublicIp": "1.2.3.4",
                    "AssociationId": "eipassoc-001",
                    "InstanceId": "i-001",
                    "Tags": [],
                }
            ]
        }

        manager = NetworkManager(mock_ec2)
        eips = manager.get_eips_for_instance("i-001", "123456789012", "us-east-1")

        assert len(eips) == 1
        assert eips[0].public_ip == "1.2.3.4"

    def test_get_eips_handles_exception(self):
        """Test getting EIPs handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_addresses.side_effect = Exception("API error")

        manager = NetworkManager(mock_ec2)
        eips = manager.get_eips_for_instance("i-001", "123456789012", "us-east-1")

        assert len(eips) == 0


class TestNetworkManagerScanElasticIPs:
    """Tests for scan_elastic_ips method."""

    def test_scan_elastic_ips_success(self):
        """Test scanning EIPs successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_addresses.return_value = {
            "Addresses": [
                {
                    "AllocationId": "eipalloc-001",
                    "PublicIp": "1.2.3.4",
                    "Tags": [],
                },
                {
                    "AllocationId": "eipalloc-002",
                    "PublicIp": "5.6.7.8",
                    "InstanceId": "i-001",
                    "AssociationId": "eipassoc-001",
                    "Tags": [],
                },
            ]
        }

        manager = NetworkManager(mock_ec2)
        eips = manager.scan_elastic_ips("123456789012", "us-east-1")

        assert len(eips) == 2

    def test_scan_elastic_ips_handles_exception(self):
        """Test scanning EIPs handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_addresses.side_effect = Exception("API error")

        manager = NetworkManager(mock_ec2)
        eips = manager.scan_elastic_ips("123456789012", "us-east-1")

        assert len(eips) == 0


class TestNetworkManagerDeleteSecurityGroups:
    """Tests for delete_security_groups method."""

    def test_delete_security_groups_success(self):
        """Test deleting security groups successfully."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2, dry_run=False)

        sgs = [
            create_packer_security_group("sg-001"),
            create_packer_security_group("sg-002"),
        ]

        deleted, deferred, errors = manager.delete_security_groups(sgs)

        assert len(deleted) == 2
        assert len(deferred) == 0
        assert len(errors) == 0

    def test_delete_security_groups_dry_run(self):
        """Test deleting security groups in dry run mode."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2, dry_run=True)

        sgs = [create_packer_security_group("sg-001")]

        deleted, deferred, errors = manager.delete_security_groups(sgs)

        assert len(deleted) == 1
        mock_ec2.delete_security_group.assert_not_called()

    def test_delete_security_groups_dependency_violation(self):
        """Test deleting security groups handles dependency violations."""
        mock_ec2 = MagicMock()
        mock_ec2.delete_security_group.side_effect = ClientError(
            {"Error": {"Code": "DependencyViolation", "Message": "Has dependencies"}},
            "DeleteSecurityGroup",
        )
        manager = NetworkManager(mock_ec2, dry_run=False)

        sgs = [create_packer_security_group("sg-001")]

        deleted, deferred, errors = manager.delete_security_groups(sgs)

        assert len(deleted) == 0
        assert len(deferred) == 1
        assert len(errors) == 0

    def test_delete_security_groups_other_error(self):
        """Test deleting security groups handles other errors."""
        mock_ec2 = MagicMock()
        mock_ec2.delete_security_group.side_effect = ClientError(
            {"Error": {"Code": "InvalidGroup.NotFound", "Message": "Not found"}},
            "DeleteSecurityGroup",
        )
        manager = NetworkManager(mock_ec2, dry_run=False)

        sgs = [create_packer_security_group("sg-001")]

        deleted, deferred, errors = manager.delete_security_groups(sgs)

        assert len(deleted) == 0
        assert len(deferred) == 0
        assert len(errors) == 1


class TestNetworkManagerDeleteKeyPairs:
    """Tests for delete_key_pairs method."""

    def test_delete_key_pairs_success(self):
        """Test deleting key pairs successfully."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2, dry_run=False)

        kps = [
            create_packer_key_pair("packer_key_1"),
            create_packer_key_pair("packer_key_2"),
        ]

        deleted, deferred, errors = manager.delete_key_pairs(kps)

        assert len(deleted) == 2
        assert len(deferred) == 0
        assert len(errors) == 0

    def test_delete_key_pairs_dry_run(self):
        """Test deleting key pairs in dry run mode."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2, dry_run=True)

        kps = [create_packer_key_pair("packer_key")]

        deleted, deferred, errors = manager.delete_key_pairs(kps)

        assert len(deleted) == 1
        mock_ec2.delete_key_pair.assert_not_called()

    def test_delete_key_pairs_error(self):
        """Test deleting key pairs handles errors."""
        mock_ec2 = MagicMock()
        mock_ec2.delete_key_pair.side_effect = Exception("API error")
        manager = NetworkManager(mock_ec2, dry_run=False)

        kps = [create_packer_key_pair("packer_key")]

        deleted, deferred, errors = manager.delete_key_pairs(kps)

        assert len(deleted) == 0
        assert len(errors) == 1


class TestNetworkManagerReleaseElasticIPs:
    """Tests for release_elastic_ips method."""

    def test_release_elastic_ips_success(self):
        """Test releasing EIPs successfully."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2, dry_run=False)

        eips = [
            create_packer_elastic_ip("eipalloc-001"),
            create_packer_elastic_ip("eipalloc-002"),
        ]

        released, deferred, errors = manager.release_elastic_ips(eips)

        assert len(released) == 2
        assert len(deferred) == 0
        assert len(errors) == 0

    def test_release_elastic_ips_dry_run(self):
        """Test releasing EIPs in dry run mode."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2, dry_run=True)

        eips = [create_packer_elastic_ip("eipalloc-001")]

        released, deferred, errors = manager.release_elastic_ips(eips)

        assert len(released) == 1
        mock_ec2.release_address.assert_not_called()

    def test_release_elastic_ips_associated(self):
        """Test releasing EIPs that are associated defers them."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2, dry_run=False)

        eips = [
            create_packer_elastic_ip(
                "eipalloc-001",
                association_id="eipassoc-001",
                instance_id="i-001",
            )
        ]

        released, deferred, errors = manager.release_elastic_ips(eips)

        assert len(released) == 0
        assert len(deferred) == 1
        mock_ec2.release_address.assert_not_called()

    def test_release_elastic_ips_error(self):
        """Test releasing EIPs handles errors."""
        mock_ec2 = MagicMock()
        mock_ec2.release_address.side_effect = Exception("API error")
        manager = NetworkManager(mock_ec2, dry_run=False)

        eips = [create_packer_elastic_ip("eipalloc-001")]

        released, deferred, errors = manager.release_elastic_ips(eips)

        assert len(released) == 0
        assert len(errors) == 1
