"""Tests for SNS notifier functionality.

Tests for notification sending and formatting.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from reaper.models import (
    CleanupResult,
    PackerInstance,
    PackerSecurityGroup,
    ResourceCollection,
    ResourceType,
)
from reaper.notifications.sns_notifier import SNSNotifier


def create_packer_instance(
    instance_id: str,
    state: str = "running",
    age_hours: float = 3.0,
) -> PackerInstance:
    """Create a PackerInstance for testing."""
    launch_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=launch_time,
        tags={"Name": "Packer Builder"},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state=state,
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name="packer_key",
        launch_time=launch_time,
    )


def create_packer_security_group(
    group_id: str,
    group_name: str = "packer_sg",
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
        vpc_id="vpc-12345678",
        description="Packer SG",
    )


class TestSNSNotifierInit:
    """Tests for SNSNotifier initialization."""

    def test_init_with_topic_arn(self):
        """Test initialization with topic ARN."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        assert notifier.topic_arn == "arn:aws:sns:us-east-1:123456789012:test-topic"
        assert notifier.region == "us-east-1"

    def test_init_without_topic_arn(self):
        """Test initialization without topic ARN."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="",
            region="us-east-1",
        )

        assert notifier.topic_arn == ""


class TestSNSNotifierSendCleanupNotification:
    """Tests for send_cleanup_notification method."""

    def test_send_cleanup_notification_success(self):
        """Test sending cleanup notification successfully."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        result = CleanupResult(
            terminated_instances=["i-001", "i-002"],
            deleted_security_groups=["sg-001"],
            deleted_key_pairs=["packer_key"],
        )
        resources = ResourceCollection(
            instances=[create_packer_instance("i-001"), create_packer_instance("i-002")],
            security_groups=[create_packer_security_group("sg-001")],
        )

        success = notifier.send_cleanup_notification(result, resources, "123456789012")

        assert success is True
        mock_sns.publish.assert_called_once()

    def test_send_cleanup_notification_no_topic(self):
        """Test sending notification without topic ARN."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="",
            region="us-east-1",
        )

        result = CleanupResult()
        resources = ResourceCollection()

        success = notifier.send_cleanup_notification(result, resources, "123456789012")

        assert success is False
        mock_sns.publish.assert_not_called()

    def test_send_cleanup_notification_error(self):
        """Test sending notification handles errors."""
        mock_sns = MagicMock()
        mock_sns.publish.side_effect = ClientError(
            {"Error": {"Code": "InvalidParameter", "Message": "Invalid"}},
            "Publish",
        )
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        result = CleanupResult()
        resources = ResourceCollection()

        success = notifier.send_cleanup_notification(result, resources, "123456789012")

        assert success is False


class TestSNSNotifierSendDryRunReport:
    """Tests for send_dry_run_report method."""

    def test_send_dry_run_report_success(self):
        """Test sending dry run report successfully."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        resources = ResourceCollection(
            instances=[create_packer_instance("i-001")],
            security_groups=[create_packer_security_group("sg-001")],
        )

        success = notifier.send_dry_run_report(resources, "123456789012")

        assert success is True
        mock_sns.publish.assert_called_once()
        call_args = mock_sns.publish.call_args
        assert "[DRY RUN]" in call_args.kwargs["Subject"]

    def test_send_dry_run_report_no_topic(self):
        """Test sending dry run report without topic ARN."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="",
            region="us-east-1",
        )

        resources = ResourceCollection()

        success = notifier.send_dry_run_report(resources, "123456789012")

        assert success is False

    def test_send_dry_run_report_error(self):
        """Test sending dry run report handles errors."""
        mock_sns = MagicMock()
        mock_sns.publish.side_effect = Exception("API error")
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        resources = ResourceCollection()

        success = notifier.send_dry_run_report(resources, "123456789012")

        assert success is False


class TestSNSNotifierBuildSubject:
    """Tests for _build_subject method."""

    def test_build_subject_dry_run(self):
        """Test building subject for dry run."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        result = CleanupResult(dry_run=True)
        subject = notifier._build_subject(result)

        assert "[DRY RUN]" in subject

    def test_build_subject_with_errors(self):
        """Test building subject with errors."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        result = CleanupResult(
            terminated_instances=["i-001"],
            errors={"i-002": "Failed to terminate"},
        )
        subject = notifier._build_subject(result)

        assert "1 errors" in subject

    def test_build_subject_no_errors(self):
        """Test building subject without errors."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        result = CleanupResult(
            terminated_instances=["i-001", "i-002"],
        )
        subject = notifier._build_subject(result)

        assert "Cleaned 2 resources" in subject


class TestSNSNotifierBuildMessage:
    """Tests for _build_message method."""

    def test_build_message_includes_instance_details(self):
        """Test building message includes instance details."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        result = CleanupResult(
            terminated_instances=["i-001"],
            deleted_security_groups=["sg-001"],
        )
        resources = ResourceCollection(
            instances=[create_packer_instance("i-001")],
        )

        message = notifier._build_message(result, resources, "123456789012")

        assert "i-001" in message
        assert "sg-001" in message
        assert "123456789012" in message
        assert "t3.micro" in message  # Instance type

    def test_build_message_includes_orphan_results(self):
        """Test building message includes orphan cleanup results."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        result = CleanupResult()
        resources = ResourceCollection()

        # Create mock orphan result
        orphan_result = MagicMock()
        orphan_result.deleted_key_pairs = ["packer_orphan_key"]
        orphan_result.deleted_security_groups = ["sg-orphan"]
        orphan_result.deleted_iam_roles = []

        message = notifier._build_message(result, resources, "123456789012", orphan_result)

        assert "packer_orphan_key" in message
        assert "sg-orphan" in message


class TestSNSNotifierBuildDryRunMessage:
    """Tests for _build_dry_run_message method."""

    def test_build_dry_run_message(self):
        """Test building dry run message."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        resources = ResourceCollection(
            instances=[create_packer_instance("i-001")],
        )

        message = notifier._build_dry_run_message(resources, "123456789012")

        assert "WOULD be cleaned up" in message
        assert "i-001" in message
        assert "DRY RUN" in message

    def test_build_dry_run_message_with_orphans(self):
        """Test building dry run message with orphan results."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        resources = ResourceCollection()

        orphan_result = MagicMock()
        orphan_result.deleted_key_pairs = ["packer_orphan_key"]
        orphan_result.deleted_security_groups = []
        orphan_result.deleted_iam_roles = []
        orphan_result.total_cleaned.return_value = 1

        message = notifier._build_dry_run_message(resources, "123456789012", orphan_result)

        assert "packer_orphan_key" in message


class TestSNSNotifierGetInstanceLink:
    """Tests for _get_instance_link method."""

    def test_get_instance_link(self):
        """Test generating instance console link."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        link = notifier._get_instance_link("i-001")

        assert "i-001" in link
        assert "us-east-1" in link
        assert "console.aws.amazon.com" in link


class TestSNSNotifierAddResourceSection:
    """Tests for _add_resource_section method."""

    def test_add_resource_section_with_resources(self):
        """Test adding resource section with resources."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        lines = []
        notifier._add_resource_section(lines, "TEST SECTION", ["resource-1", "resource-2"])

        assert "TEST SECTION" in lines
        assert "  - resource-1" in lines
        assert "  - resource-2" in lines

    def test_add_resource_section_empty(self):
        """Test adding resource section with no resources."""
        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        lines = []
        notifier._add_resource_section(lines, "TEST SECTION", [])

        assert len(lines) == 0
