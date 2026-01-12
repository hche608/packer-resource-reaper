"""Tests for Lambda handler functionality.

Tests for the main Lambda entry point and helper functions.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from reaper.handler import (
    _fetch_elastic_ips,
    _fetch_key_pairs,
    _fetch_security_groups,
    _fetch_volumes,
    apply_two_criteria_filter,
    build_resource_collection,
    enforce_scope,
    lambda_handler,
    scan_instances,
    validate_config_security,
)
from reaper.models import (
    PackerInstance,
    PackerKeyPair,
    PackerSecurityGroup,
    ResourceCollection,
    ResourceType,
)
from reaper.utils.security import ScopeEnforcer


def create_packer_instance(
    instance_id: str,
    key_name: str = "packer_key",
    age_hours: float = 3.0,
    state: str = "running",
    region: str = "us-east-1",
    account_id: str = "123456789012",
) -> PackerInstance:
    """Create a PackerInstance for testing."""
    launch_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=launch_time,
        tags={"Name": "Packer Builder"},
        region=region,
        account_id=account_id,
        instance_type="t3.micro",
        state=state,
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name=key_name,
        launch_time=launch_time,
    )


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    @patch("reaper.handler.AWSClientManager")
    @patch("reaper.handler.execute_reaper")
    @patch("reaper.handler.ReaperConfig")
    def test_lambda_handler_success(self, mock_config_class, mock_execute, mock_client_manager):
        """Test successful Lambda execution."""
        mock_config = MagicMock()
        mock_config.validate.return_value = []
        mock_config.region = "us-east-1"
        mock_config.dry_run = True
        mock_config.max_instance_age_hours = 2
        mock_config.log_level = "INFO"
        mock_config.notification_topic_arn = None
        mock_config_class.from_environment.return_value = mock_config

        mock_manager = MagicMock()
        mock_manager.get_account_id.return_value = "123456789012"
        mock_client_manager.return_value = mock_manager

        mock_execute.return_value = {
            "dry_run": True,
            "resources_found": 5,
            "resources_cleaned": 3,
        }

        result = lambda_handler({}, None)

        assert result["statusCode"] == 200
        assert result["body"]["account_id"] == "123456789012"

    @patch("reaper.handler.ReaperConfig")
    def test_lambda_handler_config_validation_error(self, mock_config_class):
        """Test Lambda handler with config validation errors."""
        mock_config = MagicMock()
        mock_config.validate.return_value = ["Invalid region"]
        mock_config.log_level = "INFO"
        mock_config.dry_run = True
        mock_config.max_instance_age_hours = 2
        mock_config_class.from_environment.return_value = mock_config

        result = lambda_handler({}, None)

        assert result["statusCode"] == 400
        assert "errors" in result["body"]

    @patch("reaper.handler.AWSClientManager")
    @patch("reaper.handler.ReaperConfig")
    def test_lambda_handler_security_validation_error(self, mock_config_class, mock_client_manager):
        """Test Lambda handler with security validation errors."""
        mock_config = MagicMock()
        mock_config.validate.return_value = []
        mock_config.region = "invalid-region"
        mock_config.notification_topic_arn = None
        mock_config.log_level = "INFO"
        mock_config.dry_run = True
        mock_config.max_instance_age_hours = 2
        mock_config_class.from_environment.return_value = mock_config

        result = lambda_handler({}, None)

        assert result["statusCode"] == 400


class TestValidateConfigSecurity:
    """Tests for validate_config_security function."""

    def test_validate_config_security_valid(self):
        """Test security validation with valid config."""
        config = MagicMock()
        config.region = "us-east-1"
        config.notification_topic_arn = None

        errors = validate_config_security(config)

        assert len(errors) == 0

    def test_validate_config_security_invalid_region(self):
        """Test security validation with invalid region."""
        config = MagicMock()
        config.region = "invalid-region-123"
        config.notification_topic_arn = None

        errors = validate_config_security(config)

        assert len(errors) > 0

    def test_validate_config_security_invalid_arn(self):
        """Test security validation with invalid SNS ARN."""
        config = MagicMock()
        config.region = "us-east-1"
        config.notification_topic_arn = "invalid-arn"

        errors = validate_config_security(config)

        assert len(errors) > 0


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
                                "VpcId": "vpc-12345678",
                                "SecurityGroups": [{"GroupId": "sg-12345678"}],
                                "KeyName": "packer_key",
                                "LaunchTime": datetime.now(UTC),
                                "Tags": [{"Key": "Name", "Value": "Packer"}],
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
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        instances = scan_instances(mock_ec2, "123456789012", "us-east-1")

        assert len(instances) == 0


class TestApplyTwoCriteriaFilter:
    """Tests for apply_two_criteria_filter function."""

    def test_filter_matches_both_criteria(self):
        """Test filtering matches instances with both criteria."""
        from reaper.filters.identity import IdentityFilter
        from reaper.filters.temporal import TemporalFilter

        instances = [
            create_packer_instance("i-001", key_name="packer_key", age_hours=3.0),
            create_packer_instance("i-002", key_name="production_key", age_hours=3.0),
            create_packer_instance("i-003", key_name="packer_key", age_hours=0.5),
        ]

        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        assert len(filtered) == 1
        assert filtered[0].resource_id == "i-001"

    def test_filter_excludes_young_instances(self):
        """Test filtering excludes young instances."""
        from reaper.filters.identity import IdentityFilter
        from reaper.filters.temporal import TemporalFilter

        instances = [
            create_packer_instance("i-001", key_name="packer_key", age_hours=0.5),
        ]

        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        assert len(filtered) == 0

    def test_filter_excludes_non_packer_instances(self):
        """Test filtering excludes non-packer instances."""
        from reaper.filters.identity import IdentityFilter
        from reaper.filters.temporal import TemporalFilter

        instances = [
            create_packer_instance("i-001", key_name="production_key", age_hours=3.0),
        ]

        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        assert len(filtered) == 0


class TestBuildResourceCollection:
    """Tests for build_resource_collection function."""

    def test_build_resource_collection_success(self):
        """Test building resource collection successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.return_value = {"Volumes": [{"VolumeId": "vol-001"}]}
        mock_ec2.describe_addresses.return_value = {"Addresses": [{"AllocationId": "eipalloc-001"}]}
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-12345678",
                    "GroupName": "packer_sg",
                    "VpcId": "vpc-12345678",
                    "Description": "Packer SG",
                    "Tags": [],
                }
            ]
        }
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

        instances = [create_packer_instance("i-001")]

        resources = build_resource_collection(instances, mock_ec2, "123456789012", "us-east-1")

        assert len(resources.instances) == 1
        assert len(resources.security_groups) == 1
        assert len(resources.key_pairs) == 1

    def test_build_resource_collection_handles_volume_error(self):
        """Test building resource collection handles volume errors."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.side_effect = Exception("API error")
        mock_ec2.describe_addresses.return_value = {"Addresses": []}
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": []}

        instances = [create_packer_instance("i-001")]

        resources = build_resource_collection(instances, mock_ec2, "123456789012", "us-east-1")

        assert len(resources.instances) == 1
        assert len(resources.volumes) == 0


class TestFetchSecurityGroups:
    """Tests for _fetch_security_groups function."""

    def test_fetch_security_groups_success(self):
        """Test fetching security groups successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
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

        sgs = _fetch_security_groups(mock_ec2, ["sg-001"], "123456789012", "us-east-1")

        assert len(sgs) == 1

    def test_fetch_security_groups_empty_list(self):
        """Test fetching security groups with empty list."""
        mock_ec2 = MagicMock()

        sgs = _fetch_security_groups(mock_ec2, [], "123456789012", "us-east-1")

        assert len(sgs) == 0
        mock_ec2.describe_security_groups.assert_not_called()

    def test_fetch_security_groups_skips_default(self):
        """Test fetching security groups skips default."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-default",
                    "GroupName": "default",
                    "VpcId": "vpc-12345678",
                    "Description": "Default SG",
                    "Tags": [],
                }
            ]
        }

        sgs = _fetch_security_groups(mock_ec2, ["sg-default"], "123456789012", "us-east-1")

        assert len(sgs) == 0


class TestFetchKeyPairs:
    """Tests for _fetch_key_pairs function."""

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

        kps = _fetch_key_pairs(mock_ec2, ["packer_key"], "123456789012", "us-east-1")

        assert len(kps) == 1

    def test_fetch_key_pairs_empty_list(self):
        """Test fetching key pairs with empty list."""
        mock_ec2 = MagicMock()

        kps = _fetch_key_pairs(mock_ec2, [], "123456789012", "us-east-1")

        assert len(kps) == 0
        mock_ec2.describe_key_pairs.assert_not_called()


class TestFetchVolumes:
    """Tests for _fetch_volumes function."""

    def test_fetch_volumes_success(self):
        """Test fetching volumes successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.return_value = {
            "Volumes": [
                {
                    "VolumeId": "vol-001",
                    "Size": 8,
                    "State": "available",
                    "CreateTime": datetime.now(UTC),
                    "Attachments": [],
                    "Tags": [],
                }
            ]
        }

        volumes = _fetch_volumes(mock_ec2, ["vol-001"], "123456789012", "us-east-1")

        assert len(volumes) == 1

    def test_fetch_volumes_empty_list(self):
        """Test fetching volumes with empty list."""
        mock_ec2 = MagicMock()

        volumes = _fetch_volumes(mock_ec2, [], "123456789012", "us-east-1")

        assert len(volumes) == 0
        mock_ec2.describe_volumes.assert_not_called()


class TestFetchElasticIPs:
    """Tests for _fetch_elastic_ips function."""

    def test_fetch_elastic_ips_success(self):
        """Test fetching EIPs successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_addresses.return_value = {
            "Addresses": [
                {
                    "AllocationId": "eipalloc-001",
                    "PublicIp": "1.2.3.4",
                    "Tags": [],
                }
            ]
        }

        eips = _fetch_elastic_ips(mock_ec2, ["eipalloc-001"], "123456789012", "us-east-1")

        assert len(eips) == 1

    def test_fetch_elastic_ips_empty_list(self):
        """Test fetching EIPs with empty list."""
        mock_ec2 = MagicMock()

        eips = _fetch_elastic_ips(mock_ec2, [], "123456789012", "us-east-1")

        assert len(eips) == 0
        mock_ec2.describe_addresses.assert_not_called()


class TestEnforceScope:
    """Tests for enforce_scope function."""

    def test_enforce_scope_filters_by_account(self):
        """Test scope enforcement filters by account."""
        scope_enforcer = ScopeEnforcer(
            allowed_account_ids={"123456789012"},
            allowed_regions={"us-east-1"},
        )

        resources = ResourceCollection(
            instances=[
                create_packer_instance("i-001", account_id="123456789012"),
                create_packer_instance("i-002", account_id="999999999999"),
            ]
        )

        filtered = enforce_scope(resources, scope_enforcer)

        assert len(filtered.instances) == 1
        assert filtered.instances[0].resource_id == "i-001"

    def test_enforce_scope_filters_by_region(self):
        """Test scope enforcement filters by region."""
        scope_enforcer = ScopeEnforcer(
            allowed_account_ids={"123456789012"},
            allowed_regions={"us-east-1"},
        )

        resources = ResourceCollection(
            instances=[
                create_packer_instance("i-001", region="us-east-1"),
                create_packer_instance("i-002", region="eu-west-1"),
            ]
        )

        filtered = enforce_scope(resources, scope_enforcer)

        assert len(filtered.instances) == 1
        assert filtered.instances[0].resource_id == "i-001"

    def test_enforce_scope_filters_all_resource_types(self):
        """Test scope enforcement filters all resource types."""
        scope_enforcer = ScopeEnforcer(
            allowed_account_ids={"123456789012"},
            allowed_regions={"us-east-1"},
        )

        resources = ResourceCollection(
            instances=[create_packer_instance("i-001")],
            security_groups=[
                PackerSecurityGroup(
                    resource_id="sg-001",
                    resource_type=ResourceType.SECURITY_GROUP,
                    creation_time=datetime.now(UTC),
                    tags={},
                    region="us-east-1",
                    account_id="123456789012",
                    group_name="packer_sg",
                    vpc_id="vpc-12345678",
                    description="Packer SG",
                )
            ],
            key_pairs=[
                PackerKeyPair(
                    resource_id="key-001",
                    resource_type=ResourceType.KEY_PAIR,
                    creation_time=datetime.now(UTC),
                    tags={},
                    region="us-east-1",
                    account_id="123456789012",
                    key_name="packer_key",
                    key_fingerprint="ab:cd:ef",
                )
            ],
        )

        filtered = enforce_scope(resources, scope_enforcer)

        assert len(filtered.instances) == 1
        assert len(filtered.security_groups) == 1
        assert len(filtered.key_pairs) == 1
