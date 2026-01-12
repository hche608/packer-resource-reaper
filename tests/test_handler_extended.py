"""Extended tests for Lambda handler module to increase coverage.

Tests for execute_reaper, enforce_scope, and lambda_handler functions.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from reaper.handler import (
    enforce_scope,
    execute_reaper,
    lambda_handler,
)
from reaper.models import (
    PackerElasticIP,
    PackerInstance,
    PackerInstanceProfile,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerSnapshot,
    PackerVolume,
    ResourceCollection,
    ResourceType,
)
from reaper.utils.config import ReaperConfig
from reaper.utils.security import ScopeEnforcer


def create_instance(
    instance_id: str,
    key_name: str = "packer_key",
    age_hours: float = 3.0,
    region: str = "us-east-1",
    account_id: str = "123456789012",
) -> PackerInstance:
    """Create a PackerInstance for testing."""
    launch_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=launch_time,
        tags={"Name": "Test"},
        region=region,
        account_id=account_id,
        instance_type="t3.micro",
        state="running",
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name=key_name,
        launch_time=launch_time,
    )


class TestLambdaHandlerExtended:
    """Extended tests for lambda_handler function."""

    @patch("reaper.handler.AWSClientManager")
    @patch("reaper.handler.execute_reaper")
    def test_lambda_handler_success(self, mock_execute, mock_client_manager):
        """Test lambda_handler executes successfully."""
        mock_client = MagicMock()
        mock_client.get_account_id.return_value = "123456789012"
        mock_client_manager.return_value = mock_client
        mock_execute.return_value = {
            "dry_run": True,
            "resources_found": 0,
            "resources_cleaned": 0,
            "resources_deferred": 0,
            "errors": 0,
        }

        with patch.dict(
            "os.environ",
            {
                "AWS_REGION": "us-east-1",
                "DRY_RUN": "true",
                "MAX_INSTANCE_AGE_HOURS": "2",
            },
        ):
            result = lambda_handler({}, None)

        assert result["statusCode"] == 200
        assert result["body"]["account_id"] == "123456789012"

    @patch("reaper.handler.AWSClientManager")
    def test_lambda_handler_invalid_account_id(self, mock_client_manager):
        """Test lambda_handler with invalid account ID."""
        mock_client = MagicMock()
        mock_client.get_account_id.return_value = "invalid"
        mock_client_manager.return_value = mock_client

        with patch.dict(
            "os.environ",
            {
                "AWS_REGION": "us-east-1",
                "DRY_RUN": "true",
            },
        ):
            result = lambda_handler({}, None)

        assert result["statusCode"] == 400


class TestExecuteReaper:
    """Tests for execute_reaper function."""

    @patch("reaper.handler.SNSNotifier")
    @patch("reaper.handler.CleanupEngine")
    @patch("reaper.handler.scan_instances")
    def test_execute_reaper_dry_run_with_notification(
        self, mock_scan, mock_engine_class, mock_notifier_class
    ):
        """Test execute_reaper in dry run mode with SNS notification."""
        mock_scan.return_value = []
        mock_engine = MagicMock()
        mock_engine.cleanup_resources.return_value = MagicMock(
            total_cleaned=lambda: 0,
            deferred_resources=[],
            errors={},
        )
        mock_engine.get_last_orphan_cleanup_result.return_value = None
        mock_engine_class.return_value = mock_engine

        mock_notifier = MagicMock()
        mock_notifier_class.return_value = mock_notifier

        config = ReaperConfig(
            region="us-east-1",
            dry_run=True,
            notification_topic_arn="arn:aws:sns:us-east-1:123456789012:topic",
        )
        mock_client_manager = MagicMock()
        mock_client_manager.ec2 = MagicMock()
        mock_client_manager.sns = MagicMock()
        mock_client_manager.iam = MagicMock()

        result = execute_reaper(config, mock_client_manager, "123456789012")

        assert result["dry_run"] is True
        mock_notifier.send_dry_run_report.assert_called_once()

    @patch("reaper.handler.SNSNotifier")
    @patch("reaper.handler.CleanupEngine")
    @patch("reaper.handler.scan_instances")
    def test_execute_reaper_live_with_notification(
        self, mock_scan, mock_engine_class, mock_notifier_class
    ):
        """Test execute_reaper in live mode with SNS notification."""
        mock_scan.return_value = []
        mock_engine = MagicMock()
        mock_engine.cleanup_resources.return_value = MagicMock(
            total_cleaned=lambda: 0,
            deferred_resources=[],
            errors={},
        )
        mock_engine.get_last_orphan_cleanup_result.return_value = None
        mock_engine_class.return_value = mock_engine

        mock_notifier = MagicMock()
        mock_notifier_class.return_value = mock_notifier

        config = ReaperConfig(
            region="us-east-1",
            dry_run=False,
            notification_topic_arn="arn:aws:sns:us-east-1:123456789012:topic",
        )
        mock_client_manager = MagicMock()
        mock_client_manager.ec2 = MagicMock()
        mock_client_manager.sns = MagicMock()
        mock_client_manager.iam = MagicMock()

        result = execute_reaper(config, mock_client_manager, "123456789012")

        assert result["dry_run"] is False
        mock_notifier.send_cleanup_notification.assert_called_once()

    @patch("reaper.handler.CleanupEngine")
    @patch("reaper.handler.scan_instances")
    def test_execute_reaper_no_notification_topic(self, mock_scan, mock_engine_class):
        """Test execute_reaper without SNS notification topic."""
        mock_scan.return_value = []
        mock_engine = MagicMock()
        mock_engine.cleanup_resources.return_value = MagicMock(
            total_cleaned=lambda: 0,
            deferred_resources=[],
            errors={},
        )
        mock_engine.get_last_orphan_cleanup_result.return_value = None
        mock_engine_class.return_value = mock_engine

        config = ReaperConfig(
            region="us-east-1",
            dry_run=True,
            notification_topic_arn="",
        )
        mock_client_manager = MagicMock()
        mock_client_manager.ec2 = MagicMock()

        result = execute_reaper(config, mock_client_manager, "123456789012")

        assert result["dry_run"] is True

    @patch("reaper.handler.CleanupEngine")
    @patch("reaper.handler.build_resource_collection")
    @patch("reaper.handler.apply_two_criteria_filter")
    @patch("reaper.handler.scan_instances")
    def test_execute_reaper_with_matching_instances(
        self, mock_scan, mock_filter, mock_build, mock_engine_class
    ):
        """Test execute_reaper with instances matching criteria."""
        instance = create_instance("i-001")
        mock_scan.return_value = [instance]
        mock_filter.return_value = [instance]
        mock_build.return_value = ResourceCollection(instances=[instance])

        mock_engine = MagicMock()
        mock_engine.cleanup_resources.return_value = MagicMock(
            total_cleaned=lambda: 1,
            deferred_resources=[],
            errors={},
        )
        mock_engine.get_last_orphan_cleanup_result.return_value = None
        mock_engine_class.return_value = mock_engine

        config = ReaperConfig(region="us-east-1", dry_run=True)
        mock_client_manager = MagicMock()
        mock_client_manager.ec2 = MagicMock()

        result = execute_reaper(config, mock_client_manager, "123456789012")

        assert result["resources_found"] == 1


class TestEnforceScopeExtended:
    """Extended tests for enforce_scope function."""

    def test_enforce_scope_filters_security_groups(self):
        """Test enforcing scope filters security groups."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        sg = PackerSecurityGroup(
            resource_id="sg-001",
            resource_type=ResourceType.SECURITY_GROUP,
            creation_time=datetime.now(UTC),
            tags={},
            region="eu-west-1",  # Out of scope
            account_id="123456789012",
            group_name="test-sg",
            vpc_id="vpc-123",
            description="Test",
        )
        resources = ResourceCollection(security_groups=[sg])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.security_groups) == 0

    def test_enforce_scope_filters_key_pairs(self):
        """Test enforcing scope filters key pairs."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        kp = PackerKeyPair(
            resource_id="key-001",
            resource_type=ResourceType.KEY_PAIR,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="999999999999",  # Out of scope
            key_name="packer_key",
            key_fingerprint="ab:cd:ef",
        )
        resources = ResourceCollection(key_pairs=[kp])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.key_pairs) == 0

    def test_enforce_scope_filters_volumes(self):
        """Test enforcing scope filters volumes."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        vol = PackerVolume(
            resource_id="vol-001",
            resource_type=ResourceType.VOLUME,
            creation_time=datetime.now(UTC),
            tags={},
            region="ap-southeast-1",  # Out of scope
            account_id="123456789012",
            size=100,
            state="available",
            attached_instance=None,
            snapshot_id=None,
        )
        resources = ResourceCollection(volumes=[vol])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.volumes) == 0

    def test_enforce_scope_filters_snapshots(self):
        """Test enforcing scope filters snapshots."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        snap = PackerSnapshot(
            resource_id="snap-001",
            resource_type=ResourceType.SNAPSHOT,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-west-2",  # Out of scope
            account_id="123456789012",
            volume_id="vol-001",
            state="completed",
            progress="100%",
            owner_id="123456789012",
        )
        resources = ResourceCollection(snapshots=[snap])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.snapshots) == 0

    def test_enforce_scope_filters_elastic_ips(self):
        """Test enforcing scope filters elastic IPs."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        eip = PackerElasticIP(
            resource_id="eipalloc-001",
            resource_type=ResourceType.ELASTIC_IP,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="888888888888",  # Out of scope
            public_ip="1.2.3.4",
            allocation_id="eipalloc-001",
            association_id=None,
            instance_id=None,
        )
        resources = ResourceCollection(elastic_ips=[eip])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.elastic_ips) == 0

    def test_enforce_scope_filters_instance_profiles(self):
        """Test enforcing scope filters instance profiles."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        profile = PackerInstanceProfile(
            resource_id="profile-001",
            resource_type=ResourceType.INSTANCE_PROFILE,
            creation_time=datetime.now(UTC),
            tags={},
            region="eu-central-1",  # Out of scope
            account_id="123456789012",
            instance_profile_name="test-profile",
            instance_profile_id="AIPA123456789",
            arn="arn:aws:iam::123456789012:instance-profile/test",
            path="/",
        )
        resources = ResourceCollection(instance_profiles=[profile])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.instance_profiles) == 0

    def test_enforce_scope_keeps_in_scope_resources(self):
        """Test enforcing scope keeps in-scope resources."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        sg = PackerSecurityGroup(
            resource_id="sg-001",
            resource_type=ResourceType.SECURITY_GROUP,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            group_name="test-sg",
            vpc_id="vpc-123",
            description="Test",
        )
        kp = PackerKeyPair(
            resource_id="key-001",
            resource_type=ResourceType.KEY_PAIR,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            key_name="packer_key",
            key_fingerprint="ab:cd:ef",
        )
        resources = ResourceCollection(security_groups=[sg], key_pairs=[kp])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.security_groups) == 1
        assert len(filtered.key_pairs) == 1
