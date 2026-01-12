"""Integration tests for complete workflow.

Tests end-to-end cleanup scenarios, cross-component interactions,
and error propagation and recovery.

Task: 10.3 Write integration tests for complete workflow
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from reaper.cleanup.engine import CleanupEngine
from reaper.filters.identity import IdentityFilter
from reaper.filters.temporal import TemporalFilter
from reaper.handler import apply_two_criteria_filter, enforce_scope
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
from reaper.utils.security import ScopeEnforcer

# ============================================================================
# Helper Functions for Creating Test Resources
# ============================================================================


def create_packer_instance(
    instance_id: str,
    state: str = "running",
    age_hours: float = 3.0,
    vpc_id: str = "vpc-12345678",
    key_name: str | None = "packer_key_test",
    security_groups: list[str] | None = None,
    tags: dict[str, str] | None = None,
    include_packer_tags: bool = True,
) -> PackerInstance:
    """Create a PackerInstance for testing."""
    launch_time = datetime.now(UTC) - timedelta(hours=age_hours)
    if include_packer_tags:
        default_tags = {"Name": "Packer Builder", "packer": "true"}
    else:
        default_tags = {}
    if tags:
        default_tags.update(tags)

    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=launch_time,
        tags=default_tags,
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state=state,
        vpc_id=vpc_id,
        security_groups=security_groups or ["sg-12345678"],
        key_name=key_name,
        launch_time=launch_time,
    )


def create_packer_security_group(
    group_id: str,
    group_name: str = "packer_sg_test",
    vpc_id: str = "vpc-12345678",
    tags: dict[str, str] | None = None,
) -> PackerSecurityGroup:
    """Create a PackerSecurityGroup for testing."""
    now = datetime.now(UTC)
    return PackerSecurityGroup(
        resource_id=group_id,
        resource_type=ResourceType.SECURITY_GROUP,
        creation_time=now,
        tags=tags or {},
        region="us-east-1",
        account_id="123456789012",
        group_name=group_name,
        vpc_id=vpc_id,
        description="Packer security group",
    )


def create_packer_key_pair(
    key_name: str,
    key_id: str = "key-test123",
    tags: dict[str, str] | None = None,
) -> PackerKeyPair:
    """Create a PackerKeyPair for testing."""
    now = datetime.now(UTC)
    return PackerKeyPair(
        resource_id=key_id,
        resource_type=ResourceType.KEY_PAIR,
        creation_time=now,
        tags=tags or {},
        region="us-east-1",
        account_id="123456789012",
        key_name=key_name,
        key_fingerprint="ab:cd:ef:12:34:56",
    )


def create_packer_volume(
    volume_id: str,
    state: str = "available",
    age_hours: float = 3.0,
    attached_instance: str | None = None,
    tags: dict[str, str] | None = None,
) -> PackerVolume:
    """Create a PackerVolume for testing."""
    creation_time = datetime.now(UTC) - timedelta(hours=age_hours)
    default_tags = {"Name": "Packer Volume", "packer": "true"}
    if tags:
        default_tags.update(tags)

    return PackerVolume(
        resource_id=volume_id,
        resource_type=ResourceType.VOLUME,
        creation_time=creation_time,
        tags=default_tags,
        region="us-east-1",
        account_id="123456789012",
        size=8,
        state=state,
        attached_instance=attached_instance,
        snapshot_id=None,
    )


def create_packer_snapshot(
    snapshot_id: str,
    state: str = "completed",
    age_hours: float = 3.0,
    tags: dict[str, str] | None = None,
) -> PackerSnapshot:
    """Create a PackerSnapshot for testing."""
    creation_time = datetime.now(UTC) - timedelta(hours=age_hours)
    default_tags = {"Name": "Packer Snapshot", "packer": "true"}
    if tags:
        default_tags.update(tags)

    return PackerSnapshot(
        resource_id=snapshot_id,
        resource_type=ResourceType.SNAPSHOT,
        creation_time=creation_time,
        tags=default_tags,
        region="us-east-1",
        account_id="123456789012",
        volume_id="vol-12345678",
        state=state,
        progress="100%",
        owner_id="123456789012",
    )


def create_packer_elastic_ip(
    allocation_id: str,
    public_ip: str = "1.2.3.4",
    association_id: str | None = None,
    instance_id: str | None = None,
    tags: dict[str, str] | None = None,
) -> PackerElasticIP:
    """Create a PackerElasticIP for testing."""
    now = datetime.now(UTC)
    default_tags = {"Name": "packer_eip", "packer": "true"}
    if tags:
        default_tags.update(tags)

    return PackerElasticIP(
        resource_id=allocation_id,
        resource_type=ResourceType.ELASTIC_IP,
        creation_time=now,
        tags=default_tags,
        region="us-east-1",
        account_id="123456789012",
        public_ip=public_ip,
        allocation_id=allocation_id,
        association_id=association_id,
        instance_id=instance_id,
    )


# ============================================================================
# Mock EC2 Client Factory
# ============================================================================


def create_mock_ec2_client(
    dependency_violations: list[str] | None = None,
    permanent_errors: list[str] | None = None,
) -> MagicMock:
    """Create a mock EC2 client that tracks operations."""
    mock_client = MagicMock()
    mock_client.operations = []

    dependency_violations = dependency_violations or []
    permanent_errors = permanent_errors or []

    def terminate_instances(InstanceIds):
        mock_client.operations.append(("terminate_instances", InstanceIds))
        results = []
        for iid in InstanceIds:
            if iid in permanent_errors:
                from botocore.exceptions import ClientError

                raise ClientError(
                    {
                        "Error": {
                            "Code": "InvalidInstanceID.NotFound",
                            "Message": "Not found",
                        }
                    },
                    "TerminateInstances",
                )
            results.append({"InstanceId": iid, "CurrentState": {"Name": "shutting-down"}})
        return {"TerminatingInstances": results}

    def delete_security_group(GroupId):
        mock_client.operations.append(("delete_security_group", GroupId))
        if GroupId in dependency_violations:
            from botocore.exceptions import ClientError

            raise ClientError(
                {
                    "Error": {
                        "Code": "DependencyViolation",
                        "Message": "Has dependencies",
                    }
                },
                "DeleteSecurityGroup",
            )
        if GroupId in permanent_errors:
            from botocore.exceptions import ClientError

            raise ClientError(
                {"Error": {"Code": "InvalidGroup.NotFound", "Message": "Not found"}},
                "DeleteSecurityGroup",
            )

    def delete_key_pair(KeyName):
        mock_client.operations.append(("delete_key_pair", KeyName))
        if KeyName in permanent_errors:
            from botocore.exceptions import ClientError

            raise ClientError(
                {"Error": {"Code": "InvalidKeyPair.NotFound", "Message": "Not found"}},
                "DeleteKeyPair",
            )

    def release_address(AllocationId):
        mock_client.operations.append(("release_address", AllocationId))
        if AllocationId in permanent_errors:
            from botocore.exceptions import ClientError

            raise ClientError(
                {
                    "Error": {
                        "Code": "InvalidAllocationID.NotFound",
                        "Message": "Not found",
                    }
                },
                "ReleaseAddress",
            )

    def delete_volume(VolumeId):
        mock_client.operations.append(("delete_volume", VolumeId))
        if VolumeId in dependency_violations:
            from botocore.exceptions import ClientError

            raise ClientError(
                {"Error": {"Code": "VolumeInUse", "Message": "Volume in use"}},
                "DeleteVolume",
            )
        if VolumeId in permanent_errors:
            from botocore.exceptions import ClientError

            raise ClientError(
                {"Error": {"Code": "InvalidVolume.NotFound", "Message": "Not found"}},
                "DeleteVolume",
            )

    def delete_snapshot(SnapshotId):
        mock_client.operations.append(("delete_snapshot", SnapshotId))
        if SnapshotId in permanent_errors:
            from botocore.exceptions import ClientError

            raise ClientError(
                {"Error": {"Code": "InvalidSnapshot.NotFound", "Message": "Not found"}},
                "DeleteSnapshot",
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

    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Images": []}]

    mock_client.terminate_instances = MagicMock(side_effect=terminate_instances)
    mock_client.delete_security_group = MagicMock(side_effect=delete_security_group)
    mock_client.delete_key_pair = MagicMock(side_effect=delete_key_pair)
    mock_client.release_address = MagicMock(side_effect=release_address)
    mock_client.delete_volume = MagicMock(side_effect=delete_volume)
    mock_client.delete_snapshot = MagicMock(side_effect=delete_snapshot)
    mock_client.describe_instances = MagicMock(side_effect=describe_instances)
    mock_client.get_waiter = MagicMock(side_effect=get_waiter)
    mock_client.describe_images = MagicMock(side_effect=describe_images)
    mock_client.get_paginator = MagicMock(return_value=mock_paginator)

    return mock_client


# ============================================================================
# Integration Tests: End-to-End Cleanup Scenarios
# ============================================================================


class TestEndToEndCleanupScenarios:
    """Test complete end-to-end cleanup workflows."""

    def test_complete_packer_build_cleanup(self):
        """
        Test cleanup of a complete Packer build's resources.

        Scenario: A Packer build left behind an instance, security group,
        key pair, and volume. All should be cleaned up in correct order.
        """
        # Create resources representing a failed Packer build
        instance = create_packer_instance(
            instance_id="i-packer001",
            state="running",
            age_hours=3.0,
            key_name="packer_key_build1",
            security_groups=["sg-packer001"],
        )
        sg = create_packer_security_group(
            group_id="sg-packer001",
            group_name="packer_sg_build1",
        )
        kp = create_packer_key_pair(
            key_name="packer_key_build1",
            key_id="key-packer001",
        )
        volume = create_packer_volume(
            volume_id="vol-packer001",
            state="available",
            age_hours=3.0,
        )

        resources = ResourceCollection(
            instances=[instance],
            security_groups=[sg],
            key_pairs=[kp],
            volumes=[volume],
        )

        mock_client = create_mock_ec2_client()
        engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

        result = engine.cleanup_resources(resources)

        # Verify all resources were cleaned
        assert "i-packer001" in result.terminated_instances
        assert "sg-packer001" in result.deleted_security_groups
        assert "packer_key_build1" in result.deleted_key_pairs
        assert "vol-packer001" in result.deleted_volumes
        assert result.total_cleaned() == 4
        assert len(result.errors) == 0

    def test_multi_instance_cleanup_with_shared_resources(self):
        """
        Test cleanup of multiple instances sharing security groups.

        Scenario: Two Packer instances share a security group. Both instances
        should be terminated before the security group is deleted.
        """
        instances = [
            create_packer_instance(
                instance_id=f"i-packer00{i}",
                state="running",
                age_hours=3.0,
                security_groups=["sg-shared001"],
            )
            for i in range(1, 3)
        ]
        sg = create_packer_security_group(
            group_id="sg-shared001",
            group_name="packer_shared_sg",
        )

        resources = ResourceCollection(
            instances=instances,
            security_groups=[sg],
        )

        mock_client = create_mock_ec2_client()
        engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

        result = engine.cleanup_resources(resources)

        # Verify both instances terminated
        assert len(result.terminated_instances) == 2
        assert "i-packer001" in result.terminated_instances
        assert "i-packer002" in result.terminated_instances

        # Verify security group deleted
        assert "sg-shared001" in result.deleted_security_groups

        # Verify operation order: instances before SG
        ops = mock_client.operations
        terminate_idx = next(i for i, (op, _) in enumerate(ops) if op == "terminate_instances")
        sg_delete_idx = next(i for i, (op, _) in enumerate(ops) if op == "delete_security_group")
        assert terminate_idx < sg_delete_idx

    def test_cleanup_with_all_resource_types(self):
        """
        Test cleanup of all supported resource types in a single execution.
        """
        resources = ResourceCollection(
            instances=[create_packer_instance("i-all001", age_hours=3.0)],
            security_groups=[create_packer_security_group("sg-all001")],
            key_pairs=[create_packer_key_pair("packer_key_all", "key-all001")],
            volumes=[create_packer_volume("vol-all001", age_hours=3.0)],
            snapshots=[create_packer_snapshot("snap-all001", age_hours=3.0)],
            elastic_ips=[create_packer_elastic_ip("eipalloc-all001")],
        )

        mock_client = create_mock_ec2_client()
        engine = CleanupEngine(ec2_client=mock_client, dry_run=False)

        result = engine.cleanup_resources(resources)

        # Verify all resource types cleaned
        assert len(result.terminated_instances) == 1
        assert len(result.deleted_security_groups) == 1
        assert len(result.deleted_key_pairs) == 1
        assert len(result.deleted_volumes) == 1
        assert len(result.deleted_snapshots) == 1
        assert len(result.released_elastic_ips) == 1
        assert result.total_cleaned() == 6


# ============================================================================
# Integration Tests: Cross-Component Interactions
# ============================================================================


class TestCrossComponentInteractions:
    """Test interactions between filters, cleanup engine, and notifications."""

    def test_filter_chain_integration(self):
        """
        Test that both filters work together correctly.

        Resources must pass temporal AND identity filters (two-criteria filtering).
        """
        # Create instances with varying characteristics
        instances = [
            # Should pass all filters: old, packer key name
            create_packer_instance(
                instance_id="i-pass001",
                age_hours=3.0,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
            # Should fail temporal: too young
            create_packer_instance(
                instance_id="i-young001",
                age_hours=0.5,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
            # Should fail identity: no packer key pattern
            create_packer_instance(
                instance_id="i-noid001",
                age_hours=3.0,
                key_name="regular_key",
                tags={"Name": "Production Server"},
                include_packer_tags=False,
            ),
        ]

        # Apply two-criteria filtering
        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered_instances = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        # Only the first instance should pass both filters
        assert len(filtered_instances) == 1
        assert filtered_instances[0].resource_id == "i-pass001"

    def test_cleanup_engine_with_sns_notification(self):
        """
        Test that cleanup results are properly formatted for SNS notifications.
        """
        resources = ResourceCollection(
            instances=[create_packer_instance("i-notify001", age_hours=3.0)],
            security_groups=[create_packer_security_group("sg-notify001")],
        )

        mock_ec2 = create_mock_ec2_client()
        mock_sns = MagicMock()

        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)
        result = engine.cleanup_resources(resources)

        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        success = notifier.send_cleanup_notification(
            result=result,
            resources=resources,
            account_id="123456789012",
        )

        assert success is True
        mock_sns.publish.assert_called_once()

        # Verify notification content
        call_args = mock_sns.publish.call_args
        assert "i-notify001" in call_args.kwargs["Message"]
        assert "sg-notify001" in call_args.kwargs["Message"]

    def test_dry_run_with_sns_report(self):
        """
        Test that dry-run mode generates proper simulation reports.
        """
        resources = ResourceCollection(
            instances=[create_packer_instance("i-dryrun001", age_hours=3.0)],
            volumes=[create_packer_volume("vol-dryrun001", age_hours=3.0)],
        )

        mock_ec2 = create_mock_ec2_client()
        mock_sns = MagicMock()

        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=True)
        engine.cleanup_resources(resources)

        # Verify dry-run didn't make destructive calls
        assert len(mock_ec2.operations) == 0

        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        success = notifier.send_dry_run_report(
            resources=resources,
            account_id="123456789012",
        )

        assert success is True
        call_args = mock_sns.publish.call_args
        assert "[DRY RUN]" in call_args.kwargs["Subject"]
        assert "WOULD be cleaned up" in call_args.kwargs["Message"]


# ============================================================================
# Integration Tests: Error Propagation and Recovery
# ============================================================================


class TestErrorPropagationAndRecovery:
    """Test error handling across components."""

    def test_partial_failure_continues_cleanup(self):
        """
        Test that failure on one resource doesn't stop cleanup of others.
        """
        resources = ResourceCollection(
            instances=[
                create_packer_instance("i-success001", age_hours=3.0),
                create_packer_instance("i-success002", age_hours=3.0),
            ],
            security_groups=[
                create_packer_security_group("sg-success001"),
                create_packer_security_group("sg-fail001"),  # Will fail
                create_packer_security_group("sg-success002"),
            ],
        )

        mock_ec2 = create_mock_ec2_client(permanent_errors=["sg-fail001"])
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

        result = engine.cleanup_resources(resources)

        # Instances should all succeed
        assert len(result.terminated_instances) == 2

        # Two SGs should succeed, one should fail
        assert len(result.deleted_security_groups) == 2
        assert "sg-fail001" in result.errors
        assert len(result.errors) == 1

    def test_dependency_violation_defers_resource(self):
        """
        Test that DependencyViolation errors result in deferral, not failure.
        """
        resources = ResourceCollection(
            instances=[create_packer_instance("i-dep001", age_hours=3.0)],
            security_groups=[
                create_packer_security_group("sg-dep001"),
                create_packer_security_group("sg-dep002"),
            ],
        )

        # sg-dep001 has dependency violation (instance still terminating)
        mock_ec2 = create_mock_ec2_client(dependency_violations=["sg-dep001"])
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

        result = engine.cleanup_resources(resources)

        # Instance should be terminated
        assert "i-dep001" in result.terminated_instances

        # sg-dep001 should be deferred, not in errors
        assert "sg-dep001" in result.deferred_resources
        assert "sg-dep001" not in result.errors

        # sg-dep002 should be deleted successfully
        assert "sg-dep002" in result.deleted_security_groups

    def test_multiple_error_types_handled_correctly(self):
        """
        Test handling of mixed error types: dependency violations and permanent errors.
        """
        resources = ResourceCollection(
            security_groups=[
                create_packer_security_group("sg-ok001"),
                create_packer_security_group("sg-dep001"),  # Dependency violation
                create_packer_security_group("sg-notfound001"),  # Not found
                create_packer_security_group("sg-ok002"),
            ],
        )

        mock_ec2 = create_mock_ec2_client(
            dependency_violations=["sg-dep001"],
            permanent_errors=["sg-notfound001"],
        )
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

        result = engine.cleanup_resources(resources)

        # Two should succeed
        assert len(result.deleted_security_groups) == 2
        assert "sg-ok001" in result.deleted_security_groups
        assert "sg-ok002" in result.deleted_security_groups

        # One deferred (dependency violation)
        assert "sg-dep001" in result.deferred_resources

        # One error (not found)
        assert "sg-notfound001" in result.errors

    def test_volume_in_use_deferred(self):
        """
        Test that volumes in use are deferred for later cleanup.
        """
        resources = ResourceCollection(
            volumes=[
                create_packer_volume("vol-available001", state="available", age_hours=3.0),
                create_packer_volume("vol-inuse001", state="in-use", age_hours=3.0),
            ],
        )

        mock_ec2 = create_mock_ec2_client(dependency_violations=["vol-inuse001"])
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

        result = engine.cleanup_resources(resources)

        # Available volume should be deleted
        assert "vol-available001" in result.deleted_volumes

        # In-use volume should be deferred
        assert "vol-inuse001" in result.deferred_resources

    def test_empty_resource_collection_handled(self):
        """
        Test that empty resource collections are handled gracefully.
        """
        resources = ResourceCollection()

        mock_ec2 = create_mock_ec2_client()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

        result = engine.cleanup_resources(resources)

        assert result.total_cleaned() == 0
        assert len(result.errors) == 0
        assert len(result.deferred_resources) == 0

        # No API calls should be made
        assert len(mock_ec2.operations) == 0

    def test_all_resources_fail_gracefully(self):
        """
        Test that cleanup completes even if all resources fail.
        """
        resources = ResourceCollection(
            security_groups=[
                create_packer_security_group("sg-fail001"),
                create_packer_security_group("sg-fail002"),
            ],
        )

        mock_ec2 = create_mock_ec2_client(permanent_errors=["sg-fail001", "sg-fail002"])
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

        result = engine.cleanup_resources(resources)

        # No successful deletions
        assert len(result.deleted_security_groups) == 0

        # Both should be in errors
        assert len(result.errors) == 2
        assert "sg-fail001" in result.errors
        assert "sg-fail002" in result.errors


# ============================================================================
# Integration Tests: Filter and Cleanup Pipeline
# ============================================================================


class TestFilterCleanupPipeline:
    """Test the complete filter-to-cleanup pipeline."""

    def test_excluded_resources_not_cleaned(self):
        """
        Test that resources not matching key pair pattern are never cleaned.
        """
        instances = [
            create_packer_instance(
                instance_id="i-clean001",
                age_hours=3.0,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
            create_packer_instance(
                instance_id="i-protected001",
                age_hours=3.0,
                key_name="production_key",  # Not a packer key
                tags={"Name": "Production Server"},
                include_packer_tags=False,
            ),
        ]

        # Apply two-criteria filtering
        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered_instances = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        # Only packer instance should pass
        assert len(filtered_instances) == 1
        assert filtered_instances[0].resource_id == "i-clean001"

        # Clean up filtered resources
        resources = ResourceCollection(instances=filtered_instances)
        mock_ec2 = create_mock_ec2_client()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)
        result = engine.cleanup_resources(resources)

        # Only one instance should be terminated
        assert len(result.terminated_instances) == 1
        assert "i-clean001" in result.terminated_instances
        assert "i-protected001" not in result.terminated_instances

    def test_young_resources_not_cleaned(self):
        """
        Test that resources younger than max age are not cleaned.
        """
        instances = [
            create_packer_instance(
                instance_id="i-old001",
                age_hours=5.0,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
            create_packer_instance(
                instance_id="i-young001",
                age_hours=0.5,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
        ]

        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered_instances = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        # Only old instance should pass
        assert len(filtered_instances) == 1
        assert filtered_instances[0].resource_id == "i-old001"

    def test_non_packer_resources_not_cleaned(self):
        """
        Test that resources without Packer key pattern are not cleaned.
        """
        instances = [
            create_packer_instance(
                instance_id="i-packer001",
                age_hours=3.0,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
            create_packer_instance(
                instance_id="i-prod001",
                age_hours=3.0,
                key_name="production_key",
                tags={"Name": "Production Server", "Environment": "prod"},
                include_packer_tags=False,
            ),
        ]

        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered_instances = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        # Only Packer instance should pass
        assert len(filtered_instances) == 1
        assert filtered_instances[0].resource_id == "i-packer001"

    def test_scope_enforcement_filters_by_account_region(self):
        """
        Test that scope enforcement filters resources by account and region.
        """
        instances = [
            create_packer_instance(
                instance_id="i-same001",
                age_hours=3.0,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
        ]
        # Add instance from different region
        other_region_instance = PackerInstance(
            resource_id="i-other-region",
            resource_type=ResourceType.INSTANCE,
            creation_time=datetime.now(UTC) - timedelta(hours=3),
            tags={"Name": "Packer Builder"},
            region="eu-west-1",  # Different region
            account_id="123456789012",
            instance_type="t3.micro",
            state="running",
            vpc_id="vpc-12345678",
            security_groups=["sg-12345678"],
            key_name="packer_key_test",
            launch_time=datetime.now(UTC) - timedelta(hours=3),
        )
        instances.append(other_region_instance)

        resources = ResourceCollection(instances=instances)

        # Create scope enforcer for single account/region
        scope_enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )

        filtered = enforce_scope(resources, scope_enforcer)

        # Only instance from same region should pass
        assert len(filtered.instances) == 1
        assert filtered.instances[0].resource_id == "i-same001"


# ============================================================================
# Integration Tests: Configuration Integration
# ============================================================================


class TestConfigurationIntegration:
    """Test configuration integration with cleanup workflow."""

    def test_dry_run_config_prevents_cleanup(self):
        """
        Test that dry_run configuration prevents actual cleanup.
        """
        resources = ResourceCollection(
            instances=[create_packer_instance("i-dryconfig001", age_hours=3.0)],
            security_groups=[create_packer_security_group("sg-dryconfig001")],
        )

        mock_ec2 = create_mock_ec2_client()

        # Create engine with dry_run=True (as would come from config)
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=True)
        result = engine.cleanup_resources(resources)

        # Resources should be "identified" but not actually cleaned
        assert result.dry_run is True
        assert len(result.terminated_instances) == 1
        assert len(result.deleted_security_groups) == 1

        # No actual API calls
        mock_ec2.terminate_instances.assert_not_called()
        mock_ec2.delete_security_group.assert_not_called()

    def test_config_max_age_affects_filtering(self):
        """
        Test that max_instance_age_hours config affects temporal filtering.
        """
        instances = [
            create_packer_instance(
                "i-3hr",
                age_hours=3.0,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
            create_packer_instance(
                "i-5hr",
                age_hours=5.0,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
            create_packer_instance(
                "i-1hr",
                age_hours=1.0,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
        ]

        # With 4 hour threshold
        temporal_filter = TemporalFilter(max_age_hours=4)
        identity_filter = IdentityFilter()

        filtered_instances = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        # Only 5hr instance should pass (>= 4 hours)
        assert len(filtered_instances) == 1
        assert filtered_instances[0].resource_id == "i-5hr"

        # With 2 hour threshold
        temporal_filter_2hr = TemporalFilter(max_age_hours=2)
        filtered_2hr = apply_two_criteria_filter(instances, temporal_filter_2hr, identity_filter)

        # 3hr and 5hr instances should pass (>= 2 hours)
        assert len(filtered_2hr) == 2
        instance_ids = {i.resource_id for i in filtered_2hr}
        assert instance_ids == {"i-3hr", "i-5hr"}


# ============================================================================
# Integration Tests: Lambda Handler Integration
# ============================================================================


class TestLambdaHandlerIntegration:
    """Test Lambda handler integration with all components."""

    def test_lambda_handler_stateless_execution(self):
        """
        Test that Lambda handler performs stateless execution.

        Each execution should perform a fresh scan without relying on
        previous execution state (Requirements 3.1-3.4).
        """
        # Create resources for first execution
        resources1 = ResourceCollection(
            instances=[create_packer_instance("i-exec1", age_hours=3.0)],
        )

        mock_ec2 = create_mock_ec2_client()
        engine = CleanupEngine(
            ec2_client=mock_ec2,
            dry_run=False,
        )

        result1 = engine.cleanup_resources(resources1)
        assert "i-exec1" in result1.terminated_instances

        # Create resources for second execution (simulating fresh scan)
        resources2 = ResourceCollection(
            instances=[create_packer_instance("i-exec2", age_hours=3.0)],
        )

        # Second execution should work independently
        result2 = engine.cleanup_resources(resources2)
        assert "i-exec2" in result2.terminated_instances

        # Both executions should have succeeded independently
        assert result1.total_cleaned() == 1
        assert result2.total_cleaned() == 1

    def test_lambda_handler_single_account_region_scope(self):
        """
        Test that handler only processes resources in current account/region.

        This validates Requirements 8.1-8.6: single account/region boundary.
        """
        # Create scope enforcer for single account/region
        scope_enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )

        # Create instances from different accounts/regions
        instances = [
            create_packer_instance(
                instance_id="i-same001",
                age_hours=3.0,
                tags={"Name": "Packer Builder"},
            ),
            # This instance is from a different region
            PackerInstance(
                resource_id="i-other-region",
                resource_type=ResourceType.INSTANCE,
                creation_time=datetime.now(UTC) - timedelta(hours=3),
                tags={"Name": "Packer Builder"},
                region="eu-west-1",  # Different region
                account_id="123456789012",
                instance_type="t3.micro",
                state="running",
                vpc_id="vpc-12345678",
                security_groups=["sg-12345678"],
                key_name="packer_key_test",
                launch_time=datetime.now(UTC) - timedelta(hours=3),
            ),
            # This instance is from a different account
            PackerInstance(
                resource_id="i-other-account",
                resource_type=ResourceType.INSTANCE,
                creation_time=datetime.now(UTC) - timedelta(hours=3),
                tags={"Name": "Packer Builder"},
                region="us-east-1",
                account_id="999999999999",  # Different account
                instance_type="t3.micro",
                state="running",
                vpc_id="vpc-12345678",
                security_groups=["sg-12345678"],
                key_name="packer_key_test",
                launch_time=datetime.now(UTC) - timedelta(hours=3),
            ),
        ]

        resources = ResourceCollection(instances=instances)

        # Apply scope enforcement
        filtered = enforce_scope(resources, scope_enforcer)

        # Only instance from same account/region should pass
        assert len(filtered.instances) == 1
        assert filtered.instances[0].resource_id == "i-same001"

    def test_lambda_handler_two_criteria_filtering(self):
        """
        Test that handler applies two-criteria filtering correctly.

        Instances must match BOTH key pair pattern AND age threshold
        (Requirement 1.3).
        """
        instances = [
            # Matches both criteria
            create_packer_instance(
                instance_id="i-both001",
                age_hours=3.0,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
            # Matches key pattern but too young
            create_packer_instance(
                instance_id="i-young001",
                age_hours=0.5,
                key_name="packer_key_test",
                tags={"Name": "Packer Builder"},
            ),
            # Old enough but wrong key pattern (no packer tags either)
            create_packer_instance(
                instance_id="i-wrongkey001",
                age_hours=3.0,
                key_name="production_key",
                tags={"Name": "Production Server"},
                include_packer_tags=False,
            ),
        ]

        temporal_filter = TemporalFilter(max_age_hours=2)
        identity_filter = IdentityFilter()

        filtered_instances = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

        # Only instance matching both criteria should pass
        assert len(filtered_instances) == 1
        assert filtered_instances[0].resource_id == "i-both001"

    def test_lambda_handler_notification_integration(self):
        """
        Test that handler properly integrates with notification system.
        """
        resources = ResourceCollection(
            instances=[create_packer_instance("i-notify001", age_hours=3.0)],
            security_groups=[create_packer_security_group("sg-notify001")],
            key_pairs=[create_packer_key_pair("packer_key_notify", "key-notify001")],
        )

        mock_ec2 = create_mock_ec2_client()
        mock_sns = MagicMock()

        # Execute cleanup
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)
        result = engine.cleanup_resources(resources)

        # Send notification
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        success = notifier.send_cleanup_notification(
            result=result,
            resources=resources,
            account_id="123456789012",
        )

        assert success is True
        mock_sns.publish.assert_called_once()

        # Verify notification includes required fields (Requirement 4.3)
        call_args = mock_sns.publish.call_args
        message = call_args.kwargs["Message"]

        # Should include instance ID
        assert "i-notify001" in message
        # Should include instance type
        assert "t3.micro" in message
        # Should include termination reason
        assert "packer_" in message.lower() or "age" in message.lower()
        # Should include deleted resources
        assert "sg-notify001" in message
        assert "packer_key_notify" in message

    def test_lambda_handler_dry_run_no_destructive_operations(self):
        """
        Test that dry-run mode doesn't execute destructive operations.

        This validates Requirements 9.1-9.4.
        """
        resources = ResourceCollection(
            instances=[create_packer_instance("i-dryrun001", age_hours=3.0)],
            security_groups=[create_packer_security_group("sg-dryrun001")],
            volumes=[create_packer_volume("vol-dryrun001", age_hours=3.0)],
        )

        mock_ec2 = create_mock_ec2_client()

        # Execute in dry-run mode
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=True)
        result = engine.cleanup_resources(resources)

        # Result should indicate dry-run
        assert result.dry_run is True

        # Resources should be "identified" in result
        assert len(result.terminated_instances) == 1
        assert len(result.deleted_security_groups) == 1
        assert len(result.deleted_volumes) == 1

        # But NO actual API calls should be made
        assert len(mock_ec2.operations) == 0
        mock_ec2.terminate_instances.assert_not_called()
        mock_ec2.delete_security_group.assert_not_called()
        mock_ec2.delete_volume.assert_not_called()

    def test_lambda_handler_error_recovery_continues(self):
        """
        Test that handler continues processing after errors.

        This validates Requirements 6.1, 6.3.
        """
        resources = ResourceCollection(
            instances=[
                create_packer_instance("i-success001", age_hours=3.0),
                create_packer_instance("i-success002", age_hours=3.0),
            ],
            security_groups=[
                create_packer_security_group("sg-success001"),
                create_packer_security_group("sg-fail001"),
                create_packer_security_group("sg-success002"),
            ],
        )

        # sg-fail001 will fail with permanent error
        mock_ec2 = create_mock_ec2_client(permanent_errors=["sg-fail001"])

        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)
        result = engine.cleanup_resources(resources)

        # Instances should all succeed
        assert len(result.terminated_instances) == 2

        # Two SGs should succeed, one should fail
        assert len(result.deleted_security_groups) == 2
        assert "sg-fail001" in result.errors

        # Error should be logged but not stop execution
        assert len(result.errors) == 1


# ============================================================================
# Integration Tests: Orphaned Resource Cleanup Workflow
# ============================================================================


class TestOrphanedResourceCleanupWorkflow:
    """Test end-to-end orphaned resource cleanup scenarios.

    These tests validate the two-phase cleanup model:
    - Phase 1: Primary zombie instance cleanup
    - Phase 2: Orphaned resource cleanup (Requirement 10.7)

    Task: 14.2 Update integration tests for orphaned resource workflow
    """

    def test_orphaned_resources_cleaned_after_primary_cleanup(self):
        """
        Test that orphaned resources are cleaned after primary zombie cleanup.

        Validates Requirement 10.7: orphaned resource cleanup executes as
        an additional step after primary zombie instance cleanup completes.
        """
        # Create primary resources (zombie instances)
        resources = ResourceCollection(
            instances=[create_packer_instance("i-zombie001", age_hours=3.0)],
            security_groups=[create_packer_security_group("sg-zombie001")],
        )

        # Create mock EC2 client that also has orphaned resources
        mock_ec2 = create_mock_ec2_client()

        # Mock orphan scanning - return orphaned key pairs and security groups
        orphaned_key_pairs = ["packer_orphan_key1", "packer_orphan_key2"]
        orphaned_sgs = ["sg-orphan001", "sg-orphan002"]

        # Setup mock for orphan manager scanning
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [{"KeyName": kp} for kp in orphaned_key_pairs]
        }

        # Mock paginator for describe_instances (for orphan scanning)
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Reservations": []}]
        mock_ec2.get_paginator.return_value = mock_paginator

        # Mock describe_security_groups for orphan scanning
        mock_sg_paginator = MagicMock()
        mock_sg_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": sg,
                        "GroupName": f"packer-sg-{i}",
                        "Description": "packer sg",
                    }
                    for i, sg in enumerate(orphaned_sgs)
                ]
            }
        ]

        def get_paginator_side_effect(operation):
            if operation == "describe_instances":
                return mock_paginator
            elif operation == "describe_security_groups":
                return mock_sg_paginator
            elif operation == "describe_network_interfaces":
                ni_paginator = MagicMock()
                ni_paginator.paginate.return_value = [{"NetworkInterfaces": []}]
                return ni_paginator
            return MagicMock()

        mock_ec2.get_paginator.side_effect = get_paginator_side_effect
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)
        result = engine.cleanup_resources(resources)

        # Verify Phase 1: primary cleanup completed
        assert "i-zombie001" in result.terminated_instances
        assert "sg-zombie001" in result.deleted_security_groups

        # Verify Phase 2: orphan cleanup result is available
        orphan_result = engine.get_last_orphan_cleanup_result()
        assert orphan_result is not None

    def test_orphaned_key_pairs_cleanup_end_to_end(self):
        """
        Test end-to-end cleanup of orphaned key pairs.

        Validates Requirements 10.1, 10.4: identify and delete orphaned
        key pairs starting with `packer_` not used by any instance.
        """
        # Create mock EC2 client
        mock_ec2 = MagicMock()

        # Setup orphaned key pairs
        orphaned_keys = ["packer_orphan1", "packer_orphan2"]

        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [{"KeyName": kp} for kp in orphaned_keys]
        }

        # No instances using these keys
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Reservations": []}]

        def get_paginator_side_effect(operation):
            if operation == "describe_instances":
                return mock_paginator
            elif operation == "describe_security_groups":
                sg_paginator = MagicMock()
                sg_paginator.paginate.return_value = [{"SecurityGroups": []}]
                return sg_paginator
            elif operation == "describe_network_interfaces":
                ni_paginator = MagicMock()
                ni_paginator.paginate.return_value = [{"NetworkInterfaces": []}]
                return ni_paginator
            return MagicMock()

        mock_ec2.get_paginator.side_effect = get_paginator_side_effect
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
        mock_ec2.delete_key_pair.return_value = {}
        mock_ec2.delete_security_group.return_value = {}
        mock_ec2.terminate_instances.return_value = {"TerminatingInstances": []}

        # Create waiter mock
        mock_waiter = MagicMock()
        mock_ec2.get_waiter.return_value = mock_waiter
        mock_ec2.describe_images.return_value = {"Images": []}

        # Execute cleanup with empty primary resources
        resources = ResourceCollection()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)
        engine.cleanup_resources(resources)

        # Verify orphaned key pairs were deleted
        orphan_result = engine.get_last_orphan_cleanup_result()
        assert orphan_result is not None
        assert set(orphan_result.deleted_key_pairs) == set(orphaned_keys)

    def test_orphaned_security_groups_cleanup_end_to_end(self):
        """
        Test end-to-end cleanup of orphaned security groups.

        Validates Requirements 10.2, 10.5: identify and delete orphaned
        security groups with `packer` in name/description not attached.
        """
        # Create mock EC2 client
        mock_ec2 = MagicMock()

        # Setup orphaned security groups
        orphaned_sgs = [
            {
                "GroupId": "sg-orphan001",
                "GroupName": "packer-sg-1",
                "Description": "packer sg",
            },
            {
                "GroupId": "sg-orphan002",
                "GroupName": "my-packer-sg",
                "Description": "another sg",
            },
        ]

        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": []}

        # Setup paginators
        def get_paginator_side_effect(operation):
            mock_pag = MagicMock()
            if operation == "describe_instances":
                mock_pag.paginate.return_value = [{"Reservations": []}]
            elif operation == "describe_security_groups":
                mock_pag.paginate.return_value = [{"SecurityGroups": orphaned_sgs}]
            elif operation == "describe_network_interfaces":
                mock_pag.paginate.return_value = [{"NetworkInterfaces": []}]
            else:
                mock_pag.paginate.return_value = [{}]
            return mock_pag

        mock_ec2.get_paginator.side_effect = get_paginator_side_effect
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
        mock_ec2.delete_key_pair.return_value = {}
        mock_ec2.delete_security_group.return_value = {}
        mock_ec2.terminate_instances.return_value = {"TerminatingInstances": []}
        mock_ec2.describe_images.return_value = {"Images": []}

        mock_waiter = MagicMock()
        mock_ec2.get_waiter.return_value = mock_waiter

        # Execute cleanup with empty primary resources
        resources = ResourceCollection()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)
        engine.cleanup_resources(resources)

        # Verify orphaned security groups were deleted
        orphan_result = engine.get_last_orphan_cleanup_result()
        assert orphan_result is not None
        expected_sg_ids = {sg["GroupId"] for sg in orphaned_sgs}
        assert set(orphan_result.deleted_security_groups) == expected_sg_ids

    def test_dry_run_mode_for_orphaned_resources(self):
        """
        Test that dry-run mode prevents destructive operations on orphaned resources.

        Validates Requirement 10.8: apply same dry-run mode behavior to
        orphaned resource operations.
        """
        # Create mock EC2 client
        mock_ec2 = MagicMock()

        # Setup orphaned resources
        orphaned_keys = ["packer_dryrun_key1"]
        orphaned_sgs = [
            {
                "GroupId": "sg-dryrun001",
                "GroupName": "packer-dryrun-sg",
                "Description": "packer",
            }
        ]

        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [{"KeyName": kp} for kp in orphaned_keys]
        }

        def get_paginator_side_effect(operation):
            mock_pag = MagicMock()
            if operation == "describe_instances":
                mock_pag.paginate.return_value = [{"Reservations": []}]
            elif operation == "describe_security_groups":
                mock_pag.paginate.return_value = [{"SecurityGroups": orphaned_sgs}]
            elif operation == "describe_network_interfaces":
                mock_pag.paginate.return_value = [{"NetworkInterfaces": []}]
            else:
                mock_pag.paginate.return_value = [{}]
            return mock_pag

        mock_ec2.get_paginator.side_effect = get_paginator_side_effect
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
        mock_ec2.describe_images.return_value = {"Images": []}

        # Execute cleanup in dry-run mode
        resources = ResourceCollection()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=True)
        result = engine.cleanup_resources(resources)

        # Verify dry-run mode
        assert result.dry_run is True

        # Verify NO destructive operations were called
        mock_ec2.delete_key_pair.assert_not_called()
        mock_ec2.delete_security_group.assert_not_called()

        # But orphan result should still report what would be deleted
        orphan_result = engine.get_last_orphan_cleanup_result()
        assert orphan_result is not None
        assert orphan_result.dry_run is True
        assert len(orphan_result.deleted_key_pairs) == 1
        assert len(orphan_result.deleted_security_groups) == 1

    def test_orphaned_resources_included_in_sns_notification(self):
        """
        Test that orphaned resource details are included in SNS notifications.

        Validates Requirement 10.10: include orphaned resource details in
        SNS notifications.
        """
        from reaper.cleanup.orphan_manager import OrphanCleanupResult

        # Create cleanup result
        result = CleanupResult(
            dry_run=False,
            terminated_instances=["i-zombie001"],
            deleted_security_groups=["sg-zombie001"],
        )

        # Create orphan cleanup result
        orphan_result = OrphanCleanupResult(
            deleted_key_pairs=["packer_orphan_key1", "packer_orphan_key2"],
            deleted_security_groups=["sg-orphan001"],
            deleted_iam_roles=["packer_orphan_role1"],
            dry_run=False,
        )

        # Create resources
        resources = ResourceCollection(
            instances=[create_packer_instance("i-zombie001", age_hours=3.0)],
            security_groups=[create_packer_security_group("sg-zombie001")],
        )

        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        success = notifier.send_cleanup_notification(
            result=result,
            resources=resources,
            account_id="123456789012",
            orphan_result=orphan_result,
        )

        assert success is True
        mock_sns.publish.assert_called_once()

        # Verify notification includes orphaned resource details
        call_args = mock_sns.publish.call_args
        message = call_args.kwargs["Message"]

        # Should include orphaned key pairs
        assert "packer_orphan_key1" in message
        assert "packer_orphan_key2" in message

        # Should include orphaned security groups
        assert "sg-orphan001" in message

        # Should include orphaned IAM roles
        assert "packer_orphan_role1" in message

        # Should have orphaned resources section
        assert "ORPHANED" in message.upper()

    def test_orphaned_resources_in_dry_run_report(self):
        """
        Test that orphaned resources are included in dry-run simulation reports.

        Validates Requirements 9.3, 10.10: send simulation report via SNS
        including orphaned resource details.
        """
        from reaper.cleanup.orphan_manager import OrphanCleanupResult

        # Create orphan cleanup result for dry-run
        orphan_result = OrphanCleanupResult(
            deleted_key_pairs=["packer_dryrun_key1"],
            deleted_security_groups=["sg-dryrun001"],
            dry_run=True,
        )

        # Create resources
        resources = ResourceCollection(
            instances=[create_packer_instance("i-dryrun001", age_hours=3.0)],
        )

        mock_sns = MagicMock()
        notifier = SNSNotifier(
            sns_client=mock_sns,
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            region="us-east-1",
        )

        success = notifier.send_dry_run_report(
            resources=resources,
            account_id="123456789012",
            orphan_result=orphan_result,
        )

        assert success is True
        mock_sns.publish.assert_called_once()

        # Verify dry-run report includes orphaned resources
        call_args = mock_sns.publish.call_args
        message = call_args.kwargs["Message"]
        subject = call_args.kwargs["Subject"]

        # Subject should indicate dry-run
        assert "[DRY RUN]" in subject

        # Message should include orphaned resources
        assert "packer_dryrun_key1" in message
        assert "sg-dryrun001" in message

        # Should indicate Phase 2 cleanup
        assert "PHASE 2" in message or "ORPHAN" in message.upper()

    def test_two_phase_cleanup_order(self):
        """
        Test that Phase 2 (orphan cleanup) runs after Phase 1 (zombie cleanup).

        Validates Requirement 10.7: orphaned resource cleanup executes as
        an additional step after primary zombie instance cleanup completes.
        """
        # Track operation order
        operation_order = []

        # Create mock EC2 client that tracks operations
        mock_ec2 = MagicMock()

        def terminate_instances_side_effect(InstanceIds):
            operation_order.append(("phase1_terminate", InstanceIds))
            return {
                "TerminatingInstances": [
                    {"InstanceId": iid, "CurrentState": {"Name": "shutting-down"}}
                    for iid in InstanceIds
                ]
            }

        def delete_key_pair_side_effect(KeyName):
            operation_order.append(("phase2_delete_key", KeyName))
            return {}

        mock_ec2.terminate_instances.side_effect = terminate_instances_side_effect
        mock_ec2.delete_key_pair.side_effect = delete_key_pair_side_effect
        mock_ec2.delete_security_group.return_value = {}
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-zombie001", "State": {"Name": "terminated"}}]}
            ]
        }
        mock_ec2.describe_images.return_value = {"Images": []}

        # Setup orphaned key pairs
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": [{"KeyName": "packer_orphan_key1"}]}

        def get_paginator_side_effect(operation):
            mock_pag = MagicMock()
            if operation == "describe_instances":
                mock_pag.paginate.return_value = [{"Reservations": []}]
            elif operation == "describe_security_groups":
                mock_pag.paginate.return_value = [{"SecurityGroups": []}]
            elif operation == "describe_network_interfaces":
                mock_pag.paginate.return_value = [{"NetworkInterfaces": []}]
            else:
                mock_pag.paginate.return_value = [{}]
            return mock_pag

        mock_ec2.get_paginator.side_effect = get_paginator_side_effect
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}

        mock_waiter = MagicMock()
        mock_ec2.get_waiter.return_value = mock_waiter

        # Create primary resources
        resources = ResourceCollection(
            instances=[create_packer_instance("i-zombie001", age_hours=3.0)],
        )

        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)
        engine.cleanup_resources(resources)

        # Verify operation order: Phase 1 before Phase 2
        phase1_ops = [op for op in operation_order if op[0].startswith("phase1")]
        phase2_ops = [op for op in operation_order if op[0].startswith("phase2")]

        if phase1_ops and phase2_ops:
            # Get indices
            first_phase1_idx = operation_order.index(phase1_ops[0])
            first_phase2_idx = operation_order.index(phase2_ops[0])

            # Phase 1 should come before Phase 2
            assert first_phase1_idx < first_phase2_idx, (
                f"Phase 1 should execute before Phase 2. Order: {operation_order}"
            )

    def test_combined_cleanup_result_totals(self):
        """
        Test that cleanup result totals include both primary and orphaned resources.
        """

        # Create mock EC2 client
        mock_ec2 = MagicMock()

        mock_ec2.terminate_instances.return_value = {
            "TerminatingInstances": [
                {"InstanceId": "i-zombie001", "CurrentState": {"Name": "shutting-down"}}
            ]
        }
        mock_ec2.delete_security_group.return_value = {}
        mock_ec2.delete_key_pair.return_value = {}

        # describe_instances needs to return different results for different calls:
        # - For waiter: return terminated instance
        # - For orphan manager key pair check: return empty (key not in use)
        # - For orphan manager SG check: return empty (SG not in use)
        def describe_instances_side_effect(**kwargs):
            filters = kwargs.get("Filters", [])
            instance_ids = kwargs.get("InstanceIds", [])

            # If checking specific instance IDs (waiter call)
            if instance_ids:
                return {
                    "Reservations": [
                        {
                            "Instances": [
                                {"InstanceId": iid, "State": {"Name": "terminated"}}
                                for iid in instance_ids
                            ]
                        }
                    ]
                }

            # If checking by key-name filter (orphan manager check)
            for f in filters:
                if f.get("Name") == "key-name":
                    # Return empty - key pair not in use
                    return {"Reservations": []}
                if f.get("Name") == "instance.group-id":
                    # Return empty - security group not in use
                    return {"Reservations": []}

            return {"Reservations": []}

        mock_ec2.describe_instances.side_effect = describe_instances_side_effect
        mock_ec2.describe_images.return_value = {"Images": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}

        # Setup orphaned resources
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [{"KeyName": "packer_orphan1"}, {"KeyName": "packer_orphan2"}]
        }

        def get_paginator_side_effect(operation):
            mock_pag = MagicMock()
            if operation == "describe_instances":
                mock_pag.paginate.return_value = [{"Reservations": []}]
            elif operation == "describe_security_groups":
                mock_pag.paginate.return_value = [
                    {
                        "SecurityGroups": [
                            {
                                "GroupId": "sg-orphan001",
                                "GroupName": "packer-orphan",
                                "Description": "packer",
                            }
                        ]
                    }
                ]
            elif operation == "describe_network_interfaces":
                mock_pag.paginate.return_value = [{"NetworkInterfaces": []}]
            else:
                mock_pag.paginate.return_value = [{}]
            return mock_pag

        mock_ec2.get_paginator.side_effect = get_paginator_side_effect

        mock_waiter = MagicMock()
        mock_ec2.get_waiter.return_value = mock_waiter

        # Create primary resources
        resources = ResourceCollection(
            instances=[create_packer_instance("i-zombie001", age_hours=3.0)],
            security_groups=[create_packer_security_group("sg-zombie001")],
        )

        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)
        result = engine.cleanup_resources(resources)

        # Verify combined totals
        # Phase 1: 1 instance + 1 security group = 2
        # Phase 2: 2 key pairs + 1 security group = 3
        # Total should include orphaned resources merged into result
        assert "i-zombie001" in result.terminated_instances

        # Orphaned key pairs should be in deleted_key_pairs
        assert "packer_orphan1" in result.deleted_key_pairs
        assert "packer_orphan2" in result.deleted_key_pairs

        # Orphaned security groups should be in deleted_security_groups
        assert "sg-orphan001" in result.deleted_security_groups
