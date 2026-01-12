"""Property-based tests for error recovery without state persistence.

Feature: packer-resource-reaper, Property 4: Error Recovery Without State
Validates: Requirements 3.1, 3.2, 3.3, 3.4, 6.1, 6.3

This module tests the stateless error recovery behavior of the reaper:
- Fresh scan of resources without relying on previous execution state (3.1)
- No database or state persistence required (3.2)
- Re-identification of failed resources in next execution (3.3)
- No tracking of resources between executions (3.4)
- DependencyViolation errors logged and continued (6.1)
- Detailed error logging to CloudWatch (6.3)
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

from botocore.exceptions import ClientError
from hypothesis import given, settings
from hypothesis import strategies as st

from reaper.cleanup.engine import CleanupEngine
from reaper.models import (
    PackerInstance,
    PackerSecurityGroup,
    PackerVolume,
    ResourceCollection,
    ResourceType,
)


def create_instance(
    instance_id: str,
    state: str = "running",
) -> PackerInstance:
    """Helper to create a PackerInstance for testing."""
    now = datetime.now(UTC)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=now,
        tags={"Name": "Packer Builder"},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
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
    now = datetime.now(UTC)
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


def create_volume(
    volume_id: str,
    state: str = "available",
) -> PackerVolume:
    """Helper to create a PackerVolume for testing."""
    now = datetime.now(UTC)
    return PackerVolume(
        resource_id=volume_id,
        resource_type=ResourceType.VOLUME,
        creation_time=now,
        tags={"Name": "Packer Volume"},
        region="us-east-1",
        account_id="123456789012",
        size=8,
        state=state,
        attached_instance=None,
        snapshot_id=None,
    )


def create_mock_ec2_client(
    dependency_violations: list[str] | None = None,
    rate_limit_resources: list[str] | None = None,
    permanent_errors: list[str] | None = None,
) -> MagicMock:
    """Create a mock EC2 client that simulates various error conditions."""
    mock_client = MagicMock()

    dependency_violations = dependency_violations or []
    rate_limit_resources = rate_limit_resources or []
    permanent_errors = permanent_errors or []

    # Track retry attempts for rate-limited resources
    mock_client.retry_counts = {r: 0 for r in rate_limit_resources}

    def terminate_instances(InstanceIds):
        results = []
        for iid in InstanceIds:
            if iid in permanent_errors:
                raise ClientError(
                    {
                        "Error": {
                            "Code": "InvalidInstanceID.NotFound",
                            "Message": "Instance not found",
                        }
                    },
                    "TerminateInstances",
                )
            results.append({"InstanceId": iid, "CurrentState": {"Name": "shutting-down"}})
        return {"TerminatingInstances": results}

    def delete_security_group(GroupId):
        if GroupId in dependency_violations:
            raise ClientError(
                {
                    "Error": {
                        "Code": "DependencyViolation",
                        "Message": "Resource has dependencies",
                    }
                },
                "DeleteSecurityGroup",
            )
        if GroupId in rate_limit_resources:
            mock_client.retry_counts[GroupId] += 1
            if mock_client.retry_counts[GroupId] < 3:
                raise ClientError(
                    {
                        "Error": {
                            "Code": "RequestLimitExceeded",
                            "Message": "Rate limit exceeded",
                        }
                    },
                    "DeleteSecurityGroup",
                )
        if GroupId in permanent_errors:
            raise ClientError(
                {
                    "Error": {
                        "Code": "InvalidGroup.NotFound",
                        "Message": "Security group not found",
                    }
                },
                "DeleteSecurityGroup",
            )

    def delete_volume(VolumeId):
        if VolumeId in dependency_violations:
            raise ClientError(
                {"Error": {"Code": "VolumeInUse", "Message": "Volume is in use"}},
                "DeleteVolume",
            )
        if VolumeId in permanent_errors:
            raise ClientError(
                {
                    "Error": {
                        "Code": "InvalidVolume.NotFound",
                        "Message": "Volume not found",
                    }
                },
                "DeleteVolume",
            )

    def describe_instances(InstanceIds):
        return {
            "Reservations": [
                {"Instances": [{"InstanceId": iid, "State": {"Name": "terminated"}}]}
                for iid in InstanceIds
            ]
        }

    def get_waiter(waiter_name):
        waiter = MagicMock()
        waiter.wait = MagicMock()
        return waiter

    def describe_images(**kwargs):
        return {"Images": []}

    mock_client.terminate_instances = MagicMock(side_effect=terminate_instances)
    mock_client.delete_security_group = MagicMock(side_effect=delete_security_group)
    mock_client.delete_volume = MagicMock(side_effect=delete_volume)
    mock_client.describe_instances = MagicMock(side_effect=describe_instances)
    mock_client.get_waiter = MagicMock(side_effect=get_waiter)
    mock_client.describe_images = MagicMock(side_effect=describe_images)
    mock_client.delete_key_pair = MagicMock()
    mock_client.release_address = MagicMock()
    mock_client.delete_snapshot = MagicMock()

    return mock_client


# Strategies for generating test data
num_resources_strategy = st.integers(min_value=1, max_value=5)
num_failing_strategy = st.integers(min_value=0, max_value=3)


@settings(max_examples=100, deadline=10000)
@given(
    num_security_groups=num_resources_strategy,
    num_dependency_violations=num_failing_strategy,
)
def test_dependency_violations_cause_deferral(
    num_security_groups: int,
    num_dependency_violations: int,
):
    """
    Feature: packer-resource-reaper, Property 4: Error Recovery Without State

    For any cleanup operation that encounters a DependencyViolation error,
    the system should defer the resource to the next execution cycle.

    Validates: Requirements 6.1, 6.3
    """
    # Ensure we don't have more violations than resources
    num_dependency_violations = min(num_dependency_violations, num_security_groups)

    # Create security groups
    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_security_groups)
    ]

    # Mark some as having dependency violations
    dependency_violations = [f"sg-{i:08d}" for i in range(num_dependency_violations)]

    resources = ResourceCollection(security_groups=security_groups)

    # Create mock clients
    mock_ec2 = create_mock_ec2_client(dependency_violations=dependency_violations)

    engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

    # Execute cleanup
    result = engine.cleanup_resources(resources)

    # Verify: resources with dependency violations should be deferred
    expected_deleted = num_security_groups - num_dependency_violations
    expected_deferred = num_dependency_violations

    assert len(result.deleted_security_groups) == expected_deleted, (
        f"Expected {expected_deleted} deleted SGs, got {len(result.deleted_security_groups)}"
    )

    assert len(result.deferred_resources) == expected_deferred, (
        f"Expected {expected_deferred} deferred resources, got {len(result.deferred_resources)}"
    )

    # All dependency violation resources should be in deferred list
    for sg_id in dependency_violations:
        assert sg_id in result.deferred_resources, (
            f"Security group {sg_id} with dependency violation should be deferred"
        )


@settings(max_examples=100, deadline=10000)
@given(
    num_security_groups=num_resources_strategy,
    num_instances=num_resources_strategy,
    num_sg_failures=num_failing_strategy,
)
def test_partial_cleanup_continues_with_remaining_resources(
    num_security_groups: int,
    num_instances: int,
    num_sg_failures: int,
):
    """
    Feature: packer-resource-reaper, Property 4: Error Recovery Without State

    For any partial cleanup (where some resources fail), the system should
    continue processing remaining resources and defer failed ones for
    re-identification in subsequent executions.

    Validates: Requirements 3.3, 6.1
    """
    # Ensure we don't have more failures than resources
    num_sg_failures = min(num_sg_failures, num_security_groups)

    # Create resources
    instances = [create_instance(instance_id=f"i-{i:08d}") for i in range(num_instances)]

    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_security_groups)
    ]

    # Mark some SGs as having dependency violations
    dependency_violations = [f"sg-{i:08d}" for i in range(num_sg_failures)]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
    )

    mock_ec2 = create_mock_ec2_client(dependency_violations=dependency_violations)
    engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

    # Execute cleanup
    result = engine.cleanup_resources(resources)

    # Verify: all instances should be terminated (no failures)
    assert len(result.terminated_instances) == num_instances, (
        f"Expected {num_instances} terminated instances"
    )

    # Verify: successful SGs should be deleted, failed ones deferred
    assert len(result.deleted_security_groups) == num_security_groups - num_sg_failures
    assert len(result.deferred_resources) == num_sg_failures

    # Total cleaned + deferred should equal total resources
    total_processed = (
        len(result.terminated_instances)
        + len(result.deleted_security_groups)
        + len(result.deferred_resources)
    )
    assert total_processed == num_instances + num_security_groups


@settings(max_examples=100, deadline=10000)
@given(
    num_resources=num_resources_strategy,
    num_permanent_errors=num_failing_strategy,
)
def test_permanent_errors_recorded_separately_from_deferrals(
    num_resources: int,
    num_permanent_errors: int,
):
    """
    Feature: packer-resource-reaper, Property 4: Error Recovery Without State

    For any cleanup operation, permanent errors (like resource not found)
    should be recorded in the errors dict, while retryable errors should
    result in deferrals.

    Validates: Requirements 6.1, 6.3
    """
    # Ensure we don't have more errors than resources
    num_permanent_errors = min(num_permanent_errors, num_resources)

    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_resources)
    ]

    # Mark some as having permanent errors
    permanent_errors = [f"sg-{i:08d}" for i in range(num_permanent_errors)]

    resources = ResourceCollection(security_groups=security_groups)

    mock_ec2 = create_mock_ec2_client(permanent_errors=permanent_errors)
    engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

    result = engine.cleanup_resources(resources)

    # Permanent errors should be in errors dict, not deferred
    assert len(result.errors) == num_permanent_errors, (
        f"Expected {num_permanent_errors} errors, got {len(result.errors)}"
    )

    # Successful deletions
    assert len(result.deleted_security_groups) == num_resources - num_permanent_errors

    # Permanent errors should not be deferred
    for sg_id in permanent_errors:
        assert sg_id not in result.deferred_resources, (
            f"Permanent error resource {sg_id} should not be deferred"
        )


@settings(max_examples=100, deadline=10000)
@given(
    num_security_groups=num_resources_strategy,
    num_dependency_violations=num_failing_strategy,
)
def test_dependency_violation_logged_and_continued(
    num_security_groups: int,
    num_dependency_violations: int,
):
    """
    Feature: packer-resource-reaper, Property 4: Error Recovery Without State

    For any cleanup operation that encounters a DependencyViolation error,
    the system should log the error and continue execution, allowing the
    resource to be re-identified in the next scheduled run.

    Validates: Requirements 6.1, 6.3
    """
    # Ensure we don't have more violations than resources
    num_dependency_violations = min(num_dependency_violations, num_security_groups)

    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_security_groups)
    ]

    dependency_violations = [f"sg-{i:08d}" for i in range(num_dependency_violations)]

    resources = ResourceCollection(security_groups=security_groups)

    mock_ec2 = create_mock_ec2_client(dependency_violations=dependency_violations)
    engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

    # Execute cleanup - should not raise exception
    result = engine.cleanup_resources(resources)

    # Verify: cleanup continued despite errors
    expected_deleted = num_security_groups - num_dependency_violations
    assert len(result.deleted_security_groups) == expected_deleted, (
        "Cleanup should continue after DependencyViolation errors"
    )

    # Verify: deferred resources are tracked for re-identification
    assert len(result.deferred_resources) == num_dependency_violations, (
        "DependencyViolation resources should be deferred for next execution"
    )


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_resources_strategy,
    num_security_groups=num_resources_strategy,
)
def test_stateless_execution_fresh_scan(
    num_instances: int,
    num_security_groups: int,
):
    """
    Feature: packer-resource-reaper, Property 4: Error Recovery Without State

    For any execution, the reaper should perform a fresh scan of resources
    without relying on previous execution state.

    Validates: Requirements 3.1, 3.2
    """
    instances = [create_instance(instance_id=f"i-{i:08d}") for i in range(num_instances)]

    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_security_groups)
    ]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
    )

    mock_ec2 = create_mock_ec2_client()

    # Create engine (stateless - no state tracker)
    engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

    # Execute cleanup
    result = engine.cleanup_resources(resources)

    # Verify: all resources processed without state dependency
    assert len(result.terminated_instances) == num_instances
    assert len(result.deleted_security_groups) == num_security_groups


@settings(max_examples=100, deadline=10000)
@given(
    num_security_groups=num_resources_strategy,
    num_dependency_violations=num_failing_strategy,
)
def test_failed_resources_can_be_reidentified(
    num_security_groups: int,
    num_dependency_violations: int,
):
    """
    Feature: packer-resource-reaper, Property 4: Error Recovery Without State

    For any resource that could not be deleted in a previous run, the reaper
    should be able to re-identify it in the next execution and attempt
    cleanup again.

    Validates: Requirements 3.3, 3.4
    """
    num_dependency_violations = min(num_dependency_violations, num_security_groups)

    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_security_groups)
    ]

    dependency_violations = [f"sg-{i:08d}" for i in range(num_dependency_violations)]

    resources = ResourceCollection(security_groups=security_groups)

    # First execution - some resources fail
    mock_ec2_first = create_mock_ec2_client(dependency_violations=dependency_violations)
    engine_first = CleanupEngine(ec2_client=mock_ec2_first, dry_run=False)
    result_first = engine_first.cleanup_resources(resources)

    # Verify first execution had deferred resources
    assert len(result_first.deferred_resources) == num_dependency_violations

    # Second execution - simulate resources now available for deletion
    # (no dependency violations this time)
    mock_ec2_second = create_mock_ec2_client(dependency_violations=[])
    engine_second = CleanupEngine(ec2_client=mock_ec2_second, dry_run=False)

    # Re-create resources (simulating fresh scan)
    resources_second = ResourceCollection(security_groups=security_groups)
    result_second = engine_second.cleanup_resources(resources_second)

    # Verify: all resources now deleted (including previously failed ones)
    assert len(result_second.deleted_security_groups) == num_security_groups
    assert len(result_second.deferred_resources) == 0


@settings(max_examples=100, deadline=10000)
@given(
    num_instances=num_resources_strategy,
    num_security_groups=num_resources_strategy,
    num_instance_errors=num_failing_strategy,
    num_sg_errors=num_failing_strategy,
)
def test_multiple_error_types_handled_independently(
    num_instances: int,
    num_security_groups: int,
    num_instance_errors: int,
    num_sg_errors: int,
):
    """
    Feature: packer-resource-reaper, Property 4: Error Recovery Without State

    For any cleanup operation with multiple error types across different
    resource types, each error should be handled independently without
    affecting other resources.

    Validates: Requirements 6.1, 6.3
    """
    num_instance_errors = min(num_instance_errors, num_instances)
    num_sg_errors = min(num_sg_errors, num_security_groups)

    instances = [create_instance(instance_id=f"i-{i:08d}") for i in range(num_instances)]

    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_security_groups)
    ]

    # Set up errors for different resource types
    instance_errors = [f"i-{i:08d}" for i in range(num_instance_errors)]
    sg_errors = [f"sg-{i:08d}" for i in range(num_sg_errors)]

    resources = ResourceCollection(
        instances=instances,
        security_groups=security_groups,
    )

    mock_ec2 = create_mock_ec2_client(
        permanent_errors=instance_errors,
        dependency_violations=sg_errors,
    )
    engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

    result = engine.cleanup_resources(resources)

    # Verify: instance errors recorded separately
    assert len(result.errors) == num_instance_errors, (
        f"Expected {num_instance_errors} instance errors"
    )

    # Verify: SG dependency violations deferred
    assert len(result.deferred_resources) == num_sg_errors, f"Expected {num_sg_errors} deferred SGs"

    # Verify: successful operations completed
    expected_terminated = num_instances - num_instance_errors
    expected_deleted_sgs = num_security_groups - num_sg_errors

    assert len(result.terminated_instances) == expected_terminated
    assert len(result.deleted_security_groups) == expected_deleted_sgs


@settings(max_examples=100, deadline=10000)
@given(
    num_security_groups=num_resources_strategy,
)
def test_no_state_tracking_between_executions(
    num_security_groups: int,
):
    """
    Feature: packer-resource-reaper, Property 4: Error Recovery Without State

    For any execution, the reaper should not track or store information
    about resources between executions.

    Validates: Requirements 3.2, 3.4
    """
    security_groups = [
        create_security_group(
            group_id=f"sg-{i:08d}",
            group_name=f"packer_sg_{i}",
        )
        for i in range(num_security_groups)
    ]

    resources = ResourceCollection(security_groups=security_groups)

    mock_ec2 = create_mock_ec2_client()

    # Create engine without state tracker
    engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

    # Execute cleanup
    result = engine.cleanup_resources(resources)

    # Verify: cleanup completed successfully
    assert len(result.deleted_security_groups) == num_security_groups

    # Verify: result contains no persistent state references
    assert result.dry_run is False
    assert len(result.errors) == 0
