"""Comprehensive tests for Lambda handler module.

Tests for handler functions and helper utilities.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from reaper.filters.identity import IdentityFilter
from reaper.filters.temporal import TemporalFilter
from reaper.handler import (
    _fetch_elastic_ips,
    _fetch_key_pairs,
    _fetch_security_groups,
    _fetch_volumes,
    _log_filtered_resources,
    apply_two_criteria_filter,
    build_resource_collection,
    enforce_scope,
    scan_instances,
    validate_config_security,
)
from reaper.models import (
    PackerInstance,
    ResourceCollection,
    ResourceType,
)
from reaper.utils.config import ReaperConfig
from reaper.utils.security import ScopeEnforcer


def create_instance(
    instance_id: str,
    key_name: str = "packer_key",
    age_hours: float = 3.0,
) -> PackerInstance:
    """Create a PackerInstance for testing."""
    launch_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=launch_time,
        tags={"Name": "Test"},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state="running",
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name=key_name,
        launch_time=launch_time,
    )


class TestValidateConfigSecurity:
    """Tests for validate_config_security function."""

    def test_valid_config(self):
        """Test validation with valid config."""
        config = ReaperConfig(
            region="us-east-1",
            notification_topic_arn="arn:aws:sns:us-east-1:123456789012:topic",
        )
        errors = validate_config_security(config)
        assert len(errors) == 0

    def test_invalid_region(self):
        """Test validation with invalid region."""
        config = ReaperConfig(region="invalid-region")
        errors = validate_config_security(config)
        assert len(errors) > 0

    def test_invalid_sns_arn(self):
        """Test validation with invalid SNS ARN."""
        config = ReaperConfig(
            region="us-east-1",
            notification_topic_arn="invalid-arn",
        )
        errors = validate_config_security(config)
        assert len(errors) > 0

    def test_empty_sns_arn(self):
        """Test validation with empty SNS ARN is valid."""
        config = ReaperConfig(
            region="us-east-1",
            notification_topic_arn="",
        )
        errors = validate_config_security(config)
        assert len(errors) == 0


class TestApplyTwoCriteriaFilter:
    """Tests for apply_two_criteria_filter function."""

    def test_filter_matches_both_criteria(self):
        """Test filtering instances matching both criteria."""
        instances = [
            create_instance("i-001", key_name="packer_key", age_hours=3),
            create_instance("i-002", key_name="production_key", age_hours=3),
            create_instance("i-003", key_name="packer_key", age_hours=1),
        ]
        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        assert len(filtered) == 1
        assert filtered[0].resource_id == "i-001"

    def test_filter_no_matches(self):
        """Test filtering with no matches."""
        instances = [
            create_instance("i-001", key_name="production_key", age_hours=3),
            create_instance("i-002", key_name="packer_key", age_hours=1),
        ]
        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        assert len(filtered) == 0

    def test_filter_empty_list(self):
        """Test filtering empty list."""
        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered = apply_two_criteria_filter([], temporal_filter, identity_filter)

        assert len(filtered) == 0


class TestScanInstances:
    """Tests for scan_instances function."""

    def test_scan_instances_success(self):
        """Test scanning instances successfully."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-001",
                                "InstanceType": "t3.micro",
                                "State": {"Name": "running"},
                                "LaunchTime": datetime.now(UTC),
                                "VpcId": "vpc-12345678",
                                "SecurityGroups": [{"GroupId": "sg-001"}],
                                "KeyName": "packer_key",
                                "Tags": [{"Key": "Name", "Value": "Test"}],
                            }
                        ]
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        instances = scan_instances(mock_ec2, "123456789012", "us-east-1")

        assert len(instances) == 1
        assert instances[0].resource_id == "i-001"

    def test_scan_instances_skips_terminated(self):
        """Test scanning skips terminated instances."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-001",
                                "InstanceType": "t3.micro",
                                "State": {"Name": "terminated"},
                                "LaunchTime": datetime.now(UTC),
                            }
                        ]
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        instances = scan_instances(mock_ec2, "123456789012", "us-east-1")

        assert len(instances) == 0

    def test_scan_instances_handles_exception(self):
        """Test scanning handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.get_paginator.side_effect = Exception("API error")

        instances = scan_instances(mock_ec2, "123456789012", "us-east-1")

        assert len(instances) == 0


class TestBuildResourceCollection:
    """Tests for build_resource_collection function."""

    def test_build_empty_collection(self):
        """Test building collection with no instances."""
        mock_ec2 = MagicMock()
        resources = build_resource_collection([], mock_ec2, "123456789012", "us-east-1")
        assert resources.is_empty()

    def test_build_collection_with_instances(self):
        """Test building collection with instances."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.return_value = {"Volumes": []}
        mock_ec2.describe_addresses.return_value = {"Addresses": []}
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": []}

        instances = [create_instance("i-001")]
        resources = build_resource_collection(instances, mock_ec2, "123456789012", "us-east-1")

        assert len(resources.instances) == 1


class TestFetchSecurityGroups:
    """Tests for _fetch_security_groups function."""

    def test_fetch_empty_list(self):
        """Test fetching with empty list."""
        mock_ec2 = MagicMock()
        result = _fetch_security_groups(mock_ec2, [], "123456789012", "us-east-1")
        assert len(result) == 0

    def test_fetch_security_groups_success(self):
        """Test fetching security groups successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-001",
                    "GroupName": "packer_sg",
                    "VpcId": "vpc-12345678",
                    "Description": "Test SG",
                    "Tags": [],
                }
            ]
        }

        result = _fetch_security_groups(mock_ec2, ["sg-001"], "123456789012", "us-east-1")

        assert len(result) == 1
        assert result[0].resource_id == "sg-001"

    def test_fetch_security_groups_skips_default(self):
        """Test fetching skips default security group."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-001",
                    "GroupName": "default",
                    "VpcId": "vpc-12345678",
                    "Description": "Default SG",
                }
            ]
        }

        result = _fetch_security_groups(mock_ec2, ["sg-001"], "123456789012", "us-east-1")

        assert len(result) == 0

    def test_fetch_security_groups_handles_exception(self):
        """Test fetching handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.side_effect = Exception("API error")

        result = _fetch_security_groups(mock_ec2, ["sg-001"], "123456789012", "us-east-1")

        assert len(result) == 0


class TestFetchKeyPairs:
    """Tests for _fetch_key_pairs function."""

    def test_fetch_empty_list(self):
        """Test fetching with empty list."""
        mock_ec2 = MagicMock()
        result = _fetch_key_pairs(mock_ec2, [], "123456789012", "us-east-1")
        assert len(result) == 0

    def test_fetch_key_pairs_success(self):
        """Test fetching key pairs successfully."""
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

        result = _fetch_key_pairs(mock_ec2, ["packer_key"], "123456789012", "us-east-1")

        assert len(result) == 1
        assert result[0].key_name == "packer_key"

    def test_fetch_key_pairs_handles_exception(self):
        """Test fetching handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = Exception("API error")

        result = _fetch_key_pairs(mock_ec2, ["packer_key"], "123456789012", "us-east-1")

        assert len(result) == 0


class TestFetchVolumes:
    """Tests for _fetch_volumes function."""

    def test_fetch_empty_list(self):
        """Test fetching with empty list."""
        mock_ec2 = MagicMock()
        result = _fetch_volumes(mock_ec2, [], "123456789012", "us-east-1")
        assert len(result) == 0

    def test_fetch_volumes_success(self):
        """Test fetching volumes successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.return_value = {
            "Volumes": [
                {
                    "VolumeId": "vol-001",
                    "Size": 100,
                    "State": "available",
                    "CreateTime": datetime.now(UTC),
                    "Attachments": [],
                    "Tags": [],
                }
            ]
        }

        result = _fetch_volumes(mock_ec2, ["vol-001"], "123456789012", "us-east-1")

        assert len(result) == 1
        assert result[0].resource_id == "vol-001"

    def test_fetch_volumes_with_attachment(self):
        """Test fetching volumes with attachments."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.return_value = {
            "Volumes": [
                {
                    "VolumeId": "vol-001",
                    "Size": 100,
                    "State": "in-use",
                    "CreateTime": datetime.now(UTC),
                    "Attachments": [{"InstanceId": "i-001"}],
                    "Tags": [],
                }
            ]
        }

        result = _fetch_volumes(mock_ec2, ["vol-001"], "123456789012", "us-east-1")

        assert len(result) == 1
        assert result[0].attached_instance == "i-001"

    def test_fetch_volumes_handles_exception(self):
        """Test fetching handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.side_effect = Exception("API error")

        result = _fetch_volumes(mock_ec2, ["vol-001"], "123456789012", "us-east-1")

        assert len(result) == 0


class TestFetchElasticIPs:
    """Tests for _fetch_elastic_ips function."""

    def test_fetch_empty_list(self):
        """Test fetching with empty list."""
        mock_ec2 = MagicMock()
        result = _fetch_elastic_ips(mock_ec2, [], "123456789012", "us-east-1")
        assert len(result) == 0

    def test_fetch_elastic_ips_success(self):
        """Test fetching elastic IPs successfully."""
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

        result = _fetch_elastic_ips(mock_ec2, ["eipalloc-001"], "123456789012", "us-east-1")

        assert len(result) == 1
        assert result[0].public_ip == "1.2.3.4"

    def test_fetch_elastic_ips_handles_exception(self):
        """Test fetching handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_addresses.side_effect = Exception("API error")

        result = _fetch_elastic_ips(mock_ec2, ["eipalloc-001"], "123456789012", "us-east-1")

        assert len(result) == 0


class TestEnforceScope:
    """Tests for enforce_scope function."""

    def test_enforce_scope_all_in_scope(self):
        """Test enforcing scope with all resources in scope."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        resources = ResourceCollection(
            instances=[create_instance("i-001")],
        )

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.instances) == 1

    def test_enforce_scope_filters_out_of_scope(self):
        """Test enforcing scope filters out-of-scope resources."""
        enforcer = ScopeEnforcer(
            allowed_regions={"eu-west-1"},
            allowed_account_ids={"123456789012"},
        )
        resources = ResourceCollection(
            instances=[create_instance("i-001")],  # us-east-1
        )

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.instances) == 0


class TestLogFilteredResources:
    """Tests for _log_filtered_resources function."""

    @patch("reaper.handler.logger")
    def test_log_filtered_resources_with_instances(self, mock_logger):
        """Test logging filtered resources with instances."""
        resources = ResourceCollection(
            instances=[create_instance("i-001")],
        )
        _log_filtered_resources(resources)
        mock_logger.info.assert_called()

    @patch("reaper.handler.logger")
    def test_log_filtered_resources_empty(self, mock_logger):
        """Test logging filtered resources when empty."""
        resources = ResourceCollection()
        _log_filtered_resources(resources)
        mock_logger.info.assert_not_called()
