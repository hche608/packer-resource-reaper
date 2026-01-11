"""Property-based tests for comprehensive logging and notification.

Feature: packer-resource-reaper, Property 7: Comprehensive Logging and Notification
Validates: Requirements 4.2, 4.3, 4.4

This module tests that:
- All scanned resources and actions are logged to CloudWatch (Requirement 4.2)
- SNS notifications include instance ID, type, termination reason, and deleted resources (Requirement 4.3)
- SNS notifications are sent when cleanup actions are performed (Requirement 4.4)
"""

from datetime import datetime, timezone
from typing import List
from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

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
from reaper.notifications.sns_notifier import DEFAULT_TERMINATION_REASON, SNSNotifier
from reaper.utils.logging import (
    ActionType,
    LogLevel,
    ReaperLogger,
)


# Helper functions to create test resources
def create_instance(
    instance_id: str,
    instance_type: str = "t3.micro",
    state: str = "running",
    name: str = "Packer Builder",
) -> PackerInstance:
    """Helper to create a PackerInstance for testing."""
    now = datetime.now(timezone.utc)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=now,
        tags={"Name": name},
        region="us-east-1",
        account_id="123456789012",
        instance_type=instance_type,
        state=state,
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name="packer_key",
        launch_time=now,
    )


def create_security_group(
    group_id: str,
    group_name: str = "packer_sg",
) -> PackerSecurityGroup:
    """Helper to create a PackerSecurityGroup for testing."""
    now = datetime.now(timezone.utc)
    return PackerSecurityGroup(
        resource_id=group_id,
        resource_type=ResourceType.SECURITY_GROUP,
        creation_time=now,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        group_name=group_name,
        vpc_id="vpc-12345678",
        description="Packer security group",
    )


def create_key_pair(
    key_name: str,
    key_id: str = "key-test123",
) -> PackerKeyPair:
    """Helper to create a PackerKeyPair for testing."""
    now = datetime.now(timezone.utc)
    return PackerKeyPair(
        resource_id=key_id,
        resource_type=ResourceType.KEY_PAIR,
        creation_time=now,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        key_name=key_name,
        key_fingerprint="ab:cd:ef:12:34:56",
    )


def create_volume(
    volume_id: str,
    size: int = 8,
    state: str = "available",
) -> PackerVolume:
    """Helper to create a PackerVolume for testing."""
    now = datetime.now(timezone.utc)
    return PackerVolume(
        resource_id=volume_id,
        resource_type=ResourceType.VOLUME,
        creation_time=now,
        tags={"Name": "Packer Volume"},
        region="us-east-1",
        account_id="123456789012",
        size=size,
        state=state,
        attached_instance=None,
        snapshot_id=None,
    )


def create_snapshot(
    snapshot_id: str,
    state: str = "completed",
) -> PackerSnapshot:
    """Helper to create a PackerSnapshot for testing."""
    now = datetime.now(timezone.utc)
    return PackerSnapshot(
        resource_id=snapshot_id,
        resource_type=ResourceType.SNAPSHOT,
        creation_time=now,
        tags={"Name": "Packer Snapshot"},
        region="us-east-1",
        account_id="123456789012",
        volume_id="vol-12345678",
        state=state,
        progress="100%",
        owner_id="123456789012",
    )


def create_elastic_ip(
    allocation_id: str,
    public_ip: str = "1.2.3.4",
) -> PackerElasticIP:
    """Helper to create a PackerElasticIP for testing."""
    now = datetime.now(timezone.utc)
    return PackerElasticIP(
        resource_id=allocation_id,
        resource_type=ResourceType.ELASTIC_IP,
        creation_time=now,
        tags={"Name": "packer_eip"},
        region="us-east-1",
        account_id="123456789012",
        public_ip=public_ip,
        allocation_id=allocation_id,
        association_id=None,
        instance_id=None,
    )


def create_mock_sns_client() -> MagicMock:
    """Create a mock SNS client that tracks publish calls."""
    mock_client = MagicMock()
    mock_client.published_messages = []

    def track_publish(TopicArn, Subject, Message):
        mock_client.published_messages.append(
            {
                "TopicArn": TopicArn,
                "Subject": Subject,
                "Message": Message,
            }
        )
        return {"MessageId": "test-message-id"}

    mock_client.publish = MagicMock(side_effect=track_publish)
    return mock_client


# Hypothesis strategies
instance_id_strategy = st.text(
    alphabet=st.sampled_from("0123456789abcdef"),
    min_size=8,
    max_size=8,
).map(lambda s: f"i-{s}")

instance_type_strategy = st.sampled_from(
    ["t3.micro", "t3.small", "t3.medium", "m5.large", "c5.xlarge"]
)

num_instances_strategy = st.integers(min_value=0, max_value=5)
num_security_groups_strategy = st.integers(min_value=0, max_value=5)
num_key_pairs_strategy = st.integers(min_value=0, max_value=3)
num_volumes_strategy = st.integers(min_value=0, max_value=5)
num_snapshots_strategy = st.integers(min_value=0, max_value=5)
num_elastic_ips_strategy = st.integers(min_value=0, max_value=3)


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
    num_security_groups=num_security_groups_strategy,
    num_key_pairs=num_key_pairs_strategy,
    num_volumes=num_volumes_strategy,
    num_elastic_ips=num_elastic_ips_strategy,
)
def test_notification_includes_instance_ids(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
    num_volumes: int,
    num_elastic_ips: int,
):
    """
    Feature: packer-resource-reaper, Property 8: Comprehensive Logging and Notification

    For any cleanup operation, SNS notifications should include all instance IDs
    that were terminated.

    Validates: Requirements 3.5
    """
    # Create test resources
    instances = [
        create_instance(instance_id=f"i-{i:08x}") for i in range(num_instances)
    ]
    security_groups = [
        create_security_group(group_id=f"sg-{i:08x}")
        for i in range(num_security_groups)
    ]
    key_pairs = [
        create_key_pair(key_name=f"packer_key_{i}", key_id=f"key-{i:08x}")
        for i in range(num_key_pairs)
    ]
    volumes = [create_volume(volume_id=f"vol-{i:08x}") for i in range(num_volumes)]
    elastic_ips = [
        create_elastic_ip(allocation_id=f"eipalloc-{i:08x}", public_ip=f"1.2.3.{i}")
        for i in range(num_elastic_ips)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
        volumes=volumes,
        elastic_ips=elastic_ips,
    )

    # Create cleanup result with terminated instances
    result = CleanupResult(
        terminated_instances=[inst.resource_id for inst in instances],
        deleted_security_groups=[sg.resource_id for sg in security_groups],
        deleted_key_pairs=[kp.key_name for kp in key_pairs],
        deleted_volumes=[vol.resource_id for vol in volumes],
        released_elastic_ips=[eip.allocation_id for eip in elastic_ips],
        dry_run=False,
    )

    # Create notifier and send notification
    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        region="us-east-1",
    )

    notifier.send_cleanup_notification(result, resources, "123456789012")

    # Verify notification was sent
    assert len(mock_sns.published_messages) == 1, "Should send exactly one notification"

    message = mock_sns.published_messages[0]["Message"]

    # Verify all instance IDs are in the message
    for instance in instances:
        assert (
            instance.resource_id in message
        ), f"Instance ID {instance.resource_id} should be in notification message"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
)
def test_notification_includes_console_links(num_instances: int):
    """
    Feature: packer-resource-reaper, Property 8: Comprehensive Logging and Notification

    For any cleanup operation, SNS notifications should include direct AWS Console
    links to the resources being processed.

    Validates: Requirements 3.6
    """
    instances = [
        create_instance(instance_id=f"i-{i:08x}") for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    result = CleanupResult(
        terminated_instances=[inst.resource_id for inst in instances],
        dry_run=False,
    )

    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        region="us-east-1",
    )

    notifier.send_cleanup_notification(result, resources, "123456789012")

    assert len(mock_sns.published_messages) == 1
    message = mock_sns.published_messages[0]["Message"]

    # Verify console links are present for each instance
    for instance in instances:
        expected_link_part = f"InstanceDetails:instanceId={instance.resource_id}"
        assert (
            expected_link_part in message
        ), f"Console link for {instance.resource_id} should be in notification"
        # Also verify the base console URL is present
        assert (
            "console.aws.amazon.com" in message
        ), "AWS Console base URL should be in notification"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_instances_strategy,
    num_security_groups=st.integers(min_value=1, max_value=5),
    num_key_pairs=st.integers(min_value=1, max_value=3),
    num_volumes=st.integers(min_value=1, max_value=5),
    num_elastic_ips=st.integers(min_value=1, max_value=3),
)
def test_notification_includes_auxiliary_resources(
    num_instances: int,
    num_security_groups: int,
    num_key_pairs: int,
    num_volumes: int,
    num_elastic_ips: int,
):
    """
    Feature: packer-resource-reaper, Property 8: Comprehensive Logging and Notification

    For any cleanup operation, SNS notifications should include the list of
    deleted auxiliary resources (security groups, key pairs, volumes, EIPs).

    Validates: Requirements 3.5
    """
    instances = [
        create_instance(instance_id=f"i-{i:08x}") for i in range(num_instances)
    ]
    security_groups = [
        create_security_group(group_id=f"sg-{i:08x}")
        for i in range(num_security_groups)
    ]
    key_pairs = [
        create_key_pair(key_name=f"packer_key_{i}", key_id=f"key-{i:08x}")
        for i in range(num_key_pairs)
    ]
    volumes = [create_volume(volume_id=f"vol-{i:08x}") for i in range(num_volumes)]
    elastic_ips = [
        create_elastic_ip(allocation_id=f"eipalloc-{i:08x}", public_ip=f"1.2.3.{i}")
        for i in range(num_elastic_ips)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        key_pairs=key_pairs,
        volumes=volumes,
        elastic_ips=elastic_ips,
    )

    result = CleanupResult(
        terminated_instances=[inst.resource_id for inst in instances],
        deleted_security_groups=[sg.resource_id for sg in security_groups],
        deleted_key_pairs=[kp.key_name for kp in key_pairs],
        deleted_volumes=[vol.resource_id for vol in volumes],
        released_elastic_ips=[eip.allocation_id for eip in elastic_ips],
        dry_run=False,
    )

    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        region="us-east-1",
    )

    notifier.send_cleanup_notification(result, resources, "123456789012")

    assert len(mock_sns.published_messages) == 1
    message = mock_sns.published_messages[0]["Message"]

    # Verify all security groups are in the message
    for sg in security_groups:
        assert (
            sg.resource_id in message
        ), f"Security group {sg.resource_id} should be in notification"

    # Verify all key pairs are in the message
    for kp in key_pairs:
        assert (
            kp.key_name in message
        ), f"Key pair {kp.key_name} should be in notification"

    # Verify all volumes are in the message
    for vol in volumes:
        assert (
            vol.resource_id in message
        ), f"Volume {vol.resource_id} should be in notification"

    # Verify all elastic IPs are in the message
    for eip in elastic_ips:
        assert (
            eip.allocation_id in message
        ), f"Elastic IP {eip.allocation_id} should be in notification"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
    num_volumes=st.integers(min_value=1, max_value=5),
)
def test_dry_run_notification_includes_all_resources(
    num_instances: int,
    num_volumes: int,
):
    """
    Feature: packer-resource-reaper, Property 8: Comprehensive Logging and Notification

    For any dry-run execution, the simulation report should include all resources
    that would be cleaned up.

    Validates: Requirements 3.3, 3.5
    """
    instances = [
        create_instance(
            instance_id=f"i-{i:08x}",
            instance_type="t3.micro",
            name=f"Packer Builder {i}",
        )
        for i in range(num_instances)
    ]
    volumes = [
        create_volume(volume_id=f"vol-{i:08x}", size=8 + i) for i in range(num_volumes)
    ]

    resources = ResourceCollection(
        instances=instances,
        volumes=volumes,
    )

    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        region="us-east-1",
    )

    notifier.send_dry_run_report(resources, "123456789012")

    assert len(mock_sns.published_messages) == 1
    message = mock_sns.published_messages[0]["Message"]
    subject = mock_sns.published_messages[0]["Subject"]

    # Verify dry-run is indicated in subject
    assert "DRY RUN" in subject, "Subject should indicate dry-run mode"

    # Verify all instances are in the message
    for instance in instances:
        assert (
            instance.resource_id in message
        ), f"Instance {instance.resource_id} should be in dry-run report"
        assert (
            instance.instance_type in message
        ), f"Instance type {instance.instance_type} should be in dry-run report"

    # Verify all volumes are in the message
    for vol in volumes:
        assert (
            vol.resource_id in message
        ), f"Volume {vol.resource_id} should be in dry-run report"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
    num_errors=st.integers(min_value=1, max_value=3),
)
def test_notification_includes_errors(
    num_instances: int,
    num_errors: int,
):
    """
    Feature: packer-resource-reaper, Property 8: Comprehensive Logging and Notification

    For any cleanup operation with errors, SNS notifications should include
    error information for failed resources.

    Validates: Requirements 3.3
    """
    instances = [
        create_instance(instance_id=f"i-{i:08x}") for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    # Create errors for some resources
    errors = {
        f"i-error{i:04x}": "DependencyViolation: Resource has dependencies"
        for i in range(num_errors)
    }

    result = CleanupResult(
        terminated_instances=[inst.resource_id for inst in instances],
        errors=errors,
        dry_run=False,
    )

    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        region="us-east-1",
    )

    notifier.send_cleanup_notification(result, resources, "123456789012")

    assert len(mock_sns.published_messages) == 1
    message = mock_sns.published_messages[0]["Message"]
    subject = mock_sns.published_messages[0]["Subject"]

    # Verify errors are mentioned in subject
    assert "error" in subject.lower(), "Subject should mention errors"

    # Verify error details are in the message
    for resource_id, error_msg in errors.items():
        assert (
            resource_id in message
        ), f"Error resource {resource_id} should be in notification"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
    num_deferred=st.integers(min_value=1, max_value=3),
)
def test_notification_includes_deferred_resources(
    num_instances: int,
    num_deferred: int,
):
    """
    Feature: packer-resource-reaper, Property 8: Comprehensive Logging and Notification

    For any cleanup operation with deferred resources, SNS notifications should
    include information about resources deferred for later cleanup.

    Validates: Requirements 3.3
    """
    instances = [
        create_instance(instance_id=f"i-{i:08x}") for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    deferred = [f"sg-deferred{i:04x}" for i in range(num_deferred)]

    result = CleanupResult(
        terminated_instances=[inst.resource_id for inst in instances],
        deferred_resources=deferred,
        dry_run=False,
    )

    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        region="us-east-1",
    )

    notifier.send_cleanup_notification(result, resources, "123456789012")

    assert len(mock_sns.published_messages) == 1
    message = mock_sns.published_messages[0]["Message"]

    # Verify deferred resources are in the message
    for resource_id in deferred:
        assert (
            resource_id in message
        ), f"Deferred resource {resource_id} should be in notification"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
)
def test_notification_includes_account_and_region(num_instances: int):
    """
    Feature: packer-resource-reaper, Property 8: Comprehensive Logging and Notification

    For any cleanup operation, SNS notifications should include the AWS account ID
    and region for context.

    Validates: Requirements 3.3
    """
    instances = [
        create_instance(instance_id=f"i-{i:08x}") for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    result = CleanupResult(
        terminated_instances=[inst.resource_id for inst in instances],
        dry_run=False,
    )

    account_id = "123456789012"
    region = "us-west-2"

    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-west-2:123456789012:test-topic",
        region=region,
    )

    notifier.send_cleanup_notification(result, resources, account_id)

    assert len(mock_sns.published_messages) == 1
    message = mock_sns.published_messages[0]["Message"]

    # Verify account and region are in the message
    assert account_id in message, "Account ID should be in notification"
    assert region in message, "Region should be in notification"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=0, max_value=5),
    num_security_groups=st.integers(min_value=0, max_value=5),
    num_volumes=st.integers(min_value=0, max_value=5),
)
def test_notification_total_count_accurate(
    num_instances: int,
    num_security_groups: int,
    num_volumes: int,
):
    """
    Feature: packer-resource-reaper, Property 8: Comprehensive Logging and Notification

    For any cleanup operation, the notification should accurately report the
    total count of resources processed and cleaned.

    Validates: Requirements 3.3, 3.5
    """
    instances = [
        create_instance(instance_id=f"i-{i:08x}") for i in range(num_instances)
    ]
    security_groups = [
        create_security_group(group_id=f"sg-{i:08x}")
        for i in range(num_security_groups)
    ]
    volumes = [create_volume(volume_id=f"vol-{i:08x}") for i in range(num_volumes)]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
        volumes=volumes,
    )

    result = CleanupResult(
        terminated_instances=[inst.resource_id for inst in instances],
        deleted_security_groups=[sg.resource_id for sg in security_groups],
        deleted_volumes=[vol.resource_id for vol in volumes],
        dry_run=False,
    )

    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        region="us-east-1",
    )

    notifier.send_cleanup_notification(result, resources, "123456789012")

    # Skip assertion if no resources (no notification sent for empty results)
    if resources.total_count() == 0:
        return

    assert len(mock_sns.published_messages) == 1
    message = mock_sns.published_messages[0]["Message"]

    # Verify total counts are in the message
    total_processed = str(resources.total_count())
    total_cleaned = str(result.total_cleaned())

    assert (
        total_processed in message
    ), f"Total processed count ({total_processed}) should be in notification"
    assert (
        total_cleaned in message
    ), f"Total cleaned count ({total_cleaned}) should be in notification"


# Property tests for instance type and termination reason (Requirement 4.3)


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
    instance_types=st.lists(
        st.sampled_from(
            ["t3.micro", "t3.small", "m5.large", "c5.xlarge", "r5.2xlarge"]
        ),
        min_size=1,
        max_size=5,
    ),
)
def test_notification_includes_instance_type(
    num_instances: int,
    instance_types: List[str],
):
    """
    Feature: packer-resource-reaper, Property 7: Comprehensive Logging and Notification

    For any cleanup operation, SNS notifications should include the instance type
    for each terminated instance.

    Validates: Requirements 4.3
    """
    # Ensure we have enough instance types
    while len(instance_types) < num_instances:
        instance_types.append("t3.micro")

    instances = [
        create_instance(
            instance_id=f"i-{i:08x}",
            instance_type=instance_types[i],
        )
        for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    result = CleanupResult(
        terminated_instances=[inst.resource_id for inst in instances],
        dry_run=False,
    )

    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        region="us-east-1",
    )

    notifier.send_cleanup_notification(result, resources, "123456789012")

    assert len(mock_sns.published_messages) == 1
    message = mock_sns.published_messages[0]["Message"]

    # Verify all instance types are in the message (Requirement 4.3)
    for i, instance in enumerate(instances):
        assert (
            instance.instance_type in message
        ), f"Instance type {instance.instance_type} should be in notification"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
)
def test_notification_includes_termination_reason(num_instances: int):
    """
    Feature: packer-resource-reaper, Property 7: Comprehensive Logging and Notification

    For any cleanup operation, SNS notifications should include the termination
    reason for each terminated instance.

    Validates: Requirements 4.3
    """
    instances = [
        create_instance(instance_id=f"i-{i:08x}") for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    result = CleanupResult(
        terminated_instances=[inst.resource_id for inst in instances],
        dry_run=False,
    )

    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        region="us-east-1",
    )

    notifier.send_cleanup_notification(result, resources, "123456789012")

    assert len(mock_sns.published_messages) == 1
    message = mock_sns.published_messages[0]["Message"]

    # Verify termination reason is in the message (Requirement 4.3)
    assert (
        DEFAULT_TERMINATION_REASON in message
    ), f"Termination reason '{DEFAULT_TERMINATION_REASON}' should be in notification"


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=st.integers(min_value=1, max_value=5),
)
def test_dry_run_notification_includes_termination_reason(num_instances: int):
    """
    Feature: packer-resource-reaper, Property 7: Comprehensive Logging and Notification

    For any dry-run execution, the simulation report should include the termination
    reason for each instance that would be terminated.

    Validates: Requirements 4.3, 9.3
    """
    instances = [
        create_instance(instance_id=f"i-{i:08x}") for i in range(num_instances)
    ]

    resources = ResourceCollection(instances=instances)

    mock_sns = create_mock_sns_client()
    notifier = SNSNotifier(
        sns_client=mock_sns,
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        region="us-east-1",
    )

    notifier.send_dry_run_report(resources, "123456789012")

    assert len(mock_sns.published_messages) == 1
    message = mock_sns.published_messages[0]["Message"]

    # Verify termination reason is in the dry-run report
    assert (
        DEFAULT_TERMINATION_REASON in message
    ), f"Termination reason '{DEFAULT_TERMINATION_REASON}' should be in dry-run report"


# Property tests for CloudWatch logging (Requirement 4.2)


@settings(max_examples=100, deadline=10000)
@given(
    num_resources=st.integers(min_value=1, max_value=10),
)
def test_logger_records_all_scanned_resources(num_resources: int):
    """
    Feature: packer-resource-reaper, Property 7: Comprehensive Logging and Notification

    For any set of resources, the logger should record all scanned resources.

    Validates: Requirements 4.2
    """
    reaper_logger = ReaperLogger(
        account_id="123456789012",
        region="us-east-1",
        dry_run=False,
    )

    # Log scan start
    reaper_logger.log_scan_start("instance", num_resources)

    # Log each resource scanned
    for i in range(num_resources):
        reaper_logger.log_resource_scanned(
            resource_type="instance",
            resource_id=f"i-{i:08x}",
            details={"instance_type": "t3.micro"},
        )

    # Log scan complete
    reaper_logger.log_scan_complete("instance", num_resources, num_resources)

    # Verify all log entries were recorded
    entries = reaper_logger.get_log_entries()

    # Should have: 1 scan start + num_resources scanned + 1 scan complete
    expected_entries = 2 + num_resources
    assert (
        len(entries) == expected_entries
    ), f"Expected {expected_entries} log entries, got {len(entries)}"

    # Verify scan entries have correct action type
    scan_entries = [e for e in entries if e.action == ActionType.SCAN]
    assert len(scan_entries) == expected_entries, "All entries should be SCAN actions"


@settings(max_examples=100, deadline=10000)
@given(
    num_actions=st.integers(min_value=1, max_value=5),
)
def test_logger_records_all_cleanup_actions(num_actions: int):
    """
    Feature: packer-resource-reaper, Property 7: Comprehensive Logging and Notification

    For any cleanup operation, the logger should record all actions taken.

    Validates: Requirements 4.2
    """
    reaper_logger = ReaperLogger(
        account_id="123456789012",
        region="us-east-1",
        dry_run=False,
    )

    # Log cleanup actions
    for i in range(num_actions):
        resource_id = f"i-{i:08x}"
        reaper_logger.log_action_start(
            action=ActionType.TERMINATE,
            resource_type="instance",
            resource_id=resource_id,
        )
        reaper_logger.log_action_complete(
            action=ActionType.TERMINATE,
            resource_type="instance",
            resource_id=resource_id,
        )

    # Verify all log entries were recorded
    entries = reaper_logger.get_log_entries()

    # Should have: num_actions * 2 (start + complete for each)
    expected_entries = num_actions * 2
    assert (
        len(entries) == expected_entries
    ), f"Expected {expected_entries} log entries, got {len(entries)}"

    # Verify terminate entries have correct action type
    terminate_entries = [e for e in entries if e.action == ActionType.TERMINATE]
    assert (
        len(terminate_entries) == expected_entries
    ), "All entries should be TERMINATE actions"


@settings(max_examples=100, deadline=10000)
@given(
    num_errors=st.integers(min_value=1, max_value=5),
)
def test_logger_records_errors_with_details(num_errors: int):
    """
    Feature: packer-resource-reaper, Property 7: Comprehensive Logging and Notification

    For any cleanup operation with errors, the logger should record detailed
    error information.

    Validates: Requirements 4.2, 6.3
    """
    reaper_logger = ReaperLogger(
        account_id="123456789012",
        region="us-east-1",
        dry_run=False,
    )

    # Log errors
    for i in range(num_errors):
        resource_id = f"sg-{i:08x}"
        error = Exception("DependencyViolation: Resource has dependencies")
        reaper_logger.log_error(
            resource_type="security_group",
            resource_id=resource_id,
            error=error,
            action=ActionType.DELETE,
        )

    # Verify all error entries were recorded
    entries = reaper_logger.get_log_entries()

    assert (
        len(entries) == num_errors
    ), f"Expected {num_errors} error entries, got {len(entries)}"

    # Verify all entries are ERROR level
    for entry in entries:
        assert entry.level == LogLevel.ERROR, "Error entries should have ERROR level"
        assert entry.error_info is not None, "Error entries should have error_info"
        assert "error_type" in entry.error_info, "Error info should include error_type"


@settings(max_examples=100, deadline=10000)
@given(
    num_deferred=st.integers(min_value=1, max_value=5),
)
def test_logger_records_deferred_resources(num_deferred: int):
    """
    Feature: packer-resource-reaper, Property 7: Comprehensive Logging and Notification

    For any cleanup operation with deferred resources, the logger should record
    the deferral with reason.

    Validates: Requirements 4.2
    """
    reaper_logger = ReaperLogger(
        account_id="123456789012",
        region="us-east-1",
        dry_run=False,
    )

    # Log deferred resources
    for i in range(num_deferred):
        resource_id = f"sg-{i:08x}"
        reaper_logger.log_action_deferred(
            resource_type="security_group",
            resource_id=resource_id,
            reason="DependencyViolation - will retry in next execution",
        )

    # Verify all deferred entries were recorded
    entries = reaper_logger.get_log_entries()

    assert (
        len(entries) == num_deferred
    ), f"Expected {num_deferred} deferred entries, got {len(entries)}"

    # Verify all entries are DEFER action type
    for entry in entries:
        assert (
            entry.action == ActionType.DEFER
        ), "Deferred entries should have DEFER action type"
        assert (
            entry.level == LogLevel.WARNING
        ), "Deferred entries should have WARNING level"
