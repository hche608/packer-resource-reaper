"""Extended tests for SNS notifier to increase coverage.

Tests for orphaned resource sections and edge cases.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

from reaper.cleanup.orphan_manager import OrphanCleanupResult
from reaper.models import (
    CleanupResult,
    PackerElasticIP,
    PackerInstance,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerSnapshot,
    PackerVolume,
    ResourceCollection,
    ResourceType,
)
from reaper.notifications.sns_notifier import SNSNotifier


def create_instance(instance_id: str) -> PackerInstance:
    """Create a PackerInstance for testing."""
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=datetime.now(UTC),
        tags={"Name": "Test"},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state="running",
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name="packer_key",
        launch_time=datetime.now(UTC),
    )


class TestSNSNotifierOrphanedResources:
    """Tests for orphaned resource notification sections."""

    def test_build_message_with_orphan_result(self):
        """Test building message with orphan cleanup result."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        result = CleanupResult(
            terminated_instances=["i-001"],
            deleted_security_groups=["sg-001"],
            deleted_key_pairs=["packer_key"],
            released_elastic_ips=[],
            deleted_volumes=[],
            deleted_snapshots=[],
            deferred_resources=[],
            errors={},
            dry_run=False,
        )
        resources = ResourceCollection(instances=[create_instance("i-001")])
        orphan_result = OrphanCleanupResult(
            deleted_key_pairs=["packer_orphan_key"],
            deleted_security_groups=["sg-orphan"],
            deleted_iam_roles=["packer_orphan_role"],
        )

        message = notifier._build_message(result, resources, "123456789012", orphan_result)

        assert "ORPHANED PACKER RESOURCES CLEANED" in message
        assert "packer_orphan_key" in message
        assert "sg-orphan" in message
        assert "packer_orphan_role" in message

    def test_build_message_without_orphan_result(self):
        """Test building message without orphan cleanup result."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        result = CleanupResult(
            terminated_instances=["i-001"],
            deleted_security_groups=[],
            deleted_key_pairs=[],
            released_elastic_ips=[],
            deleted_volumes=[],
            deleted_snapshots=[],
            deferred_resources=[],
            errors={},
            dry_run=False,
        )
        resources = ResourceCollection(instances=[create_instance("i-001")])

        message = notifier._build_message(result, resources, "123456789012", None)

        assert "ORPHANED PACKER RESOURCES CLEANED" not in message

    def test_build_message_with_empty_orphan_result(self):
        """Test building message with empty orphan cleanup result."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        result = CleanupResult(
            terminated_instances=[],
            deleted_security_groups=[],
            deleted_key_pairs=[],
            released_elastic_ips=[],
            deleted_volumes=[],
            deleted_snapshots=[],
            deferred_resources=[],
            errors={},
            dry_run=False,
        )
        resources = ResourceCollection()
        orphan_result = OrphanCleanupResult()  # Empty

        message = notifier._build_message(result, resources, "123456789012", orphan_result)

        assert "ORPHANED PACKER RESOURCES CLEANED" not in message

    def test_build_dry_run_message_with_orphan_result(self):
        """Test building dry run message with orphan cleanup result."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        resources = ResourceCollection(instances=[create_instance("i-001")])
        orphan_result = OrphanCleanupResult(
            deleted_key_pairs=["packer_orphan_key"],
            deleted_security_groups=["sg-orphan"],
            deleted_iam_roles=["packer_orphan_role"],
        )

        message = notifier._build_dry_run_message(resources, "123456789012", orphan_result)

        assert "PHASE 2: ORPHANED PACKER RESOURCE CLEANUP" in message
        assert "ORPHANED KEY PAIRS TO DELETE" in message
        assert "packer_orphan_key" in message
        assert "ORPHANED SECURITY GROUPS TO DELETE" in message
        assert "sg-orphan" in message
        assert "ORPHANED IAM ROLES TO DELETE" in message
        assert "packer_orphan_role" in message

    def test_build_dry_run_message_without_orphan_result(self):
        """Test building dry run message without orphan cleanup result."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        resources = ResourceCollection(instances=[create_instance("i-001")])

        message = notifier._build_dry_run_message(resources, "123456789012", None)

        assert "PHASE 2: ORPHANED PACKER RESOURCE CLEANUP" not in message

    def test_build_dry_run_message_with_empty_orphan_result(self):
        """Test building dry run message with empty orphan cleanup result."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        resources = ResourceCollection()
        orphan_result = OrphanCleanupResult()  # Empty

        message = notifier._build_dry_run_message(resources, "123456789012", orphan_result)

        assert "PHASE 2: ORPHANED PACKER RESOURCE CLEANUP" not in message


class TestSNSNotifierDryRunMessage:
    """Tests for dry run message building with all resource types."""

    def test_build_dry_run_message_with_all_resources(self):
        """Test building dry run message with all resource types."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        resources = ResourceCollection(
            instances=[create_instance("i-001")],
            security_groups=[
                PackerSecurityGroup(
                    resource_id="sg-001",
                    resource_type=ResourceType.SECURITY_GROUP,
                    creation_time=datetime.now(UTC),
                    tags={},
                    region="us-east-1",
                    account_id="123456789012",
                    group_name="packer_sg",
                    vpc_id="vpc-123",
                    description="Test",
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
            volumes=[
                PackerVolume(
                    resource_id="vol-001",
                    resource_type=ResourceType.VOLUME,
                    creation_time=datetime.now(UTC),
                    tags={},
                    region="us-east-1",
                    account_id="123456789012",
                    size=100,
                    state="available",
                    attached_instance=None,
                    snapshot_id=None,
                )
            ],
            snapshots=[
                PackerSnapshot(
                    resource_id="snap-001",
                    resource_type=ResourceType.SNAPSHOT,
                    creation_time=datetime.now(UTC),
                    tags={},
                    region="us-east-1",
                    account_id="123456789012",
                    volume_id="vol-001",
                    state="completed",
                    progress="100%",
                    owner_id="123456789012",
                )
            ],
            elastic_ips=[
                PackerElasticIP(
                    resource_id="eipalloc-001",
                    resource_type=ResourceType.ELASTIC_IP,
                    creation_time=datetime.now(UTC),
                    tags={},
                    region="us-east-1",
                    account_id="123456789012",
                    public_ip="1.2.3.4",
                    allocation_id="eipalloc-001",
                    association_id=None,
                    instance_id=None,
                )
            ],
        )

        message = notifier._build_dry_run_message(resources, "123456789012", None)

        assert "INSTANCES TO TERMINATE" in message
        assert "i-001" in message
        assert "SECURITY GROUPS TO DELETE" in message
        assert "sg-001" in message
        assert "KEY PAIRS TO DELETE" in message
        assert "packer_key" in message
        assert "VOLUMES TO DELETE" in message
        assert "vol-001" in message
        assert "SNAPSHOTS TO DELETE" in message
        assert "snap-001" in message
        assert "ELASTIC IPS TO RELEASE" in message
        assert "eipalloc-001" in message


class TestSNSNotifierBuildMessageDetails:
    """Tests for detailed message building."""

    def test_build_message_with_deferred_resources(self):
        """Test building message with deferred resources."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        result = CleanupResult(
            terminated_instances=[],
            deleted_security_groups=[],
            deleted_key_pairs=[],
            released_elastic_ips=[],
            deleted_volumes=[],
            deleted_snapshots=[],
            deferred_resources=["sg-deferred", "key-deferred"],
            errors={},
            dry_run=False,
        )
        resources = ResourceCollection()

        message = notifier._build_message(result, resources, "123456789012", None)

        assert "DEFERRED RESOURCES" in message
        assert "sg-deferred" in message
        assert "key-deferred" in message

    def test_build_message_with_errors(self):
        """Test building message with errors."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        result = CleanupResult(
            terminated_instances=[],
            deleted_security_groups=[],
            deleted_key_pairs=[],
            released_elastic_ips=[],
            deleted_volumes=[],
            deleted_snapshots=[],
            deferred_resources=[],
            errors={"sg-001": "DependencyViolation", "vol-001": "VolumeInUse"},
            dry_run=False,
        )
        resources = ResourceCollection()

        message = notifier._build_message(result, resources, "123456789012", None)

        assert "ERRORS" in message
        assert "sg-001" in message
        assert "vol-001" in message

    def test_build_message_with_all_deleted_resources(self):
        """Test building message with all deleted resource types."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        result = CleanupResult(
            terminated_instances=["i-001"],
            deleted_security_groups=["sg-001"],
            deleted_key_pairs=["packer_key"],
            released_elastic_ips=["eipalloc-001"],
            deleted_volumes=["vol-001"],
            deleted_snapshots=["snap-001"],
            deferred_resources=[],
            errors={},
            dry_run=False,
        )
        resources = ResourceCollection(instances=[create_instance("i-001")])

        message = notifier._build_message(result, resources, "123456789012", None)

        assert "TERMINATED INSTANCES" in message
        assert "DELETED SECURITY GROUPS" in message
        assert "DELETED KEY PAIRS" in message
        assert "RELEASED ELASTIC IPS" in message
        assert "DELETED VOLUMES" in message
        assert "DELETED SNAPSHOTS" in message


class TestSNSNotifierSendMethods:
    """Tests for send methods."""

    def test_send_cleanup_notification_no_topic(self):
        """Test send_cleanup_notification with no topic ARN."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "", "us-east-1")

        result = CleanupResult(
            terminated_instances=[],
            deleted_security_groups=[],
            deleted_key_pairs=[],
            released_elastic_ips=[],
            deleted_volumes=[],
            deleted_snapshots=[],
            deferred_resources=[],
            errors={},
            dry_run=False,
        )
        resources = ResourceCollection()

        success = notifier.send_cleanup_notification(result, resources, "123456789012")

        assert success is False
        mock_sns.publish.assert_not_called()

    def test_send_dry_run_report_no_topic(self):
        """Test send_dry_run_report with no topic ARN."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(mock_sns, "", "us-east-1")

        resources = ResourceCollection()

        success = notifier.send_dry_run_report(resources, "123456789012")

        assert success is False
        mock_sns.publish.assert_not_called()

    def test_send_cleanup_notification_exception(self):
        """Test send_cleanup_notification handles exceptions."""
        mock_sns = MagicMock()
        mock_sns.publish.side_effect = Exception("SNS error")
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        result = CleanupResult(
            terminated_instances=[],
            deleted_security_groups=[],
            deleted_key_pairs=[],
            released_elastic_ips=[],
            deleted_volumes=[],
            deleted_snapshots=[],
            deferred_resources=[],
            errors={},
            dry_run=False,
        )
        resources = ResourceCollection()

        success = notifier.send_cleanup_notification(result, resources, "123456789012")

        assert success is False

    def test_send_dry_run_report_exception(self):
        """Test send_dry_run_report handles exceptions."""
        mock_sns = MagicMock()
        mock_sns.publish.side_effect = Exception("SNS error")
        notifier = SNSNotifier(mock_sns, "arn:aws:sns:us-east-1:123456789012:topic", "us-east-1")

        resources = ResourceCollection()

        success = notifier.send_dry_run_report(resources, "123456789012")

        assert success is False
