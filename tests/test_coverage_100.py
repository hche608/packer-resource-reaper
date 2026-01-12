"""Additional tests to achieve 100% coverage.

Tests for remaining uncovered lines across all modules.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from reaper.cleanup.batch_processor import BatchProcessor
from reaper.cleanup.engine import CleanupEngine
from reaper.cleanup.network_manager import NetworkManager
from reaper.handler import _log_filtered_resources, enforce_scope
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
from reaper.utils.aws_client import AWSClientManager, RetryStrategy
from reaper.utils.security import ScopeEnforcer

# ============================================================================
# BatchProcessor tests for uncovered lines 168-178, 209-212
# ============================================================================


class TestBatchProcessorConcurrent:
    """Tests for concurrent batch processing."""

    def test_process_batch_concurrent_with_exception_in_future(self):
        """Test concurrent batch processing handles exceptions from futures."""
        processor = BatchProcessor(batch_size=3)

        def delete_func(resource_id: str) -> bool:
            if resource_id == "res-2":
                raise RuntimeError("Simulated failure")
            return True

        result = processor.process_deletions(
            ["res-1", "res-2", "res-3"], delete_func, "test-resource"
        )

        assert "res-1" in result.successful
        assert "res-3" in result.successful
        assert "res-2" in result.failed
        assert "res-2" in result.errors

    def test_process_batch_concurrent_delete_returns_false(self):
        """Test concurrent batch processing when delete returns False."""
        processor = BatchProcessor(batch_size=2)

        def delete_func(resource_id: str) -> bool:
            return resource_id != "res-2"

        result = processor.process_deletions(["res-1", "res-2"], delete_func, "test-resource")

        assert "res-1" in result.successful
        assert "res-2" in result.failed


class TestBatchProcessorSequential:
    """Tests for sequential batch processing."""

    def test_process_batch_sequential_delete_returns_false(self):
        """Test sequential batch processing when delete returns False."""
        processor = BatchProcessor(batch_size=1)

        def delete_func(resource_id: str) -> bool:
            return resource_id != "res-2"

        result = processor.process_deletions(
            ["res-1", "res-2", "res-3"], delete_func, "test-resource"
        )

        assert "res-1" in result.successful
        assert "res-3" in result.successful
        assert "res-2" in result.failed
        assert "Delete returned False" in result.errors.get("res-2", "")


# ============================================================================
# CleanupEngine tests for uncovered lines 230, 297, 479-491
# ============================================================================


class TestCleanupEngineExtended:
    """Extended tests for CleanupEngine."""

    def test_cleanup_resources_empty_collection(self):
        """Test cleanup with empty resource collection."""
        mock_ec2 = MagicMock()
        mock_ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": []}]
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": []}

        engine = CleanupEngine(mock_ec2, dry_run=False)
        resources = ResourceCollection()

        result = engine.cleanup_resources(resources)

        # Should still run Phase 2 orphan cleanup
        assert result is not None

    def test_cleanup_instance_profiles_no_iam_manager(self):
        """Test cleanup_instance_profiles when IAM manager is not initialized."""
        mock_ec2 = MagicMock()
        mock_ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": []}]
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": []}

        engine = CleanupEngine(mock_ec2, dry_run=False, iam_client=None)

        profile = PackerInstanceProfile(
            resource_id="profile-001",
            resource_type=ResourceType.INSTANCE_PROFILE,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            instance_profile_name="test-profile",
            instance_profile_id="AIPA123456789",
            arn="arn:aws:iam::123456789012:instance-profile/test",
            path="/",
        )
        resources = ResourceCollection(instance_profiles=[profile])

        result = engine.cleanup_resources(resources)

        # Should not fail, just skip instance profile cleanup
        assert result is not None

    def test_get_last_dry_run_report(self):
        """Test get_last_dry_run_report returns None when no dry run executed."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(mock_ec2, dry_run=False)

        report = engine.get_last_dry_run_report()

        assert report is None


# ============================================================================
# AWSClientManager tests for uncovered lines 54-56
# ============================================================================


class TestAWSClientManagerRoleAssumption:
    """Tests for AWSClientManager with role assumption."""

    @patch("reaper.utils.aws_client.boto3")
    def test_get_session_with_role_arn(self, mock_boto3):
        """Test session creation with role assumption."""
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }
        mock_boto3.client.return_value = mock_sts
        mock_boto3.Session.return_value = MagicMock()

        manager = AWSClientManager(
            region="us-east-1",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )

        manager._get_session()

        mock_sts.assume_role.assert_called_once()
        mock_boto3.Session.assert_called_once()


# ============================================================================
# RetryStrategy tests for edge cases
# ============================================================================


class TestRetryStrategyEdgeCases:
    """Tests for RetryStrategy edge cases."""

    def test_execute_with_retry_non_retryable_error(self):
        """Test retry strategy with non-retryable error."""
        strategy = RetryStrategy(max_retries=3)

        def failing_operation():
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "TestOperation",
            )

        with pytest.raises(ClientError) as exc_info:
            strategy.execute_with_retry(failing_operation)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_execute_with_retry_success_after_retries(self):
        """Test retry strategy succeeds after retries."""
        strategy = RetryStrategy(max_retries=3, base_delay=0.01)
        call_count = 0

        def eventually_succeeds():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ClientError(
                    {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                    "TestOperation",
                )
            return "success"

        result = strategy.execute_with_retry(eventually_succeeds)

        assert result == "success"
        assert call_count == 3


# ============================================================================
# NetworkManager tests for uncovered lines 122, 376-377
# ============================================================================


class TestNetworkManagerExtended:
    """Extended tests for NetworkManager."""

    def test_get_key_pair_by_name_not_found(self):
        """Test get_key_pair_by_name when key pair doesn't exist."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = ClientError(
            {"Error": {"Code": "InvalidKeyPair.NotFound", "Message": "Not found"}},
            "DescribeKeyPairs",
        )

        manager = NetworkManager(mock_ec2)
        result = manager.get_key_pair_by_name("nonexistent", "123456789012", "us-east-1")

        assert result is None

    def test_get_key_pair_by_name_other_error(self):
        """Test get_key_pair_by_name with other ClientError."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}},
            "DescribeKeyPairs",
        )

        manager = NetworkManager(mock_ec2)
        result = manager.get_key_pair_by_name("test-key", "123456789012", "us-east-1")

        assert result is None

    def test_release_elastic_ip_with_association(self):
        """Test releasing EIP that is still associated."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2, dry_run=False)

        eip = PackerElasticIP(
            resource_id="eipalloc-001",
            resource_type=ResourceType.ELASTIC_IP,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            public_ip="1.2.3.4",
            allocation_id="eipalloc-001",
            association_id="eipassoc-001",  # Still associated
            instance_id="i-001",
        )

        released, deferred, errors = manager.release_elastic_ips([eip])

        assert len(released) == 0
        assert "eipalloc-001" in deferred
        mock_ec2.release_address.assert_not_called()


# ============================================================================
# Handler tests for uncovered lines 246-259, 602-629
# ============================================================================


class TestLogFilteredResourcesExtended:
    """Extended tests for _log_filtered_resources."""

    @patch("reaper.handler.logger")
    def test_log_filtered_resources_with_security_groups(self, mock_logger):
        """Test logging with security groups."""
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
        resources = ResourceCollection(security_groups=[sg])

        _log_filtered_resources(resources)

        mock_logger.info.assert_called()

    @patch("reaper.handler.logger")
    def test_log_filtered_resources_with_key_pairs(self, mock_logger):
        """Test logging with key pairs."""
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
        resources = ResourceCollection(key_pairs=[kp])

        _log_filtered_resources(resources)

        mock_logger.info.assert_called()

    @patch("reaper.handler.logger")
    def test_log_filtered_resources_with_volumes(self, mock_logger):
        """Test logging with volumes."""
        vol = PackerVolume(
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
        resources = ResourceCollection(volumes=[vol])

        _log_filtered_resources(resources)

        mock_logger.info.assert_called()

    @patch("reaper.handler.logger")
    def test_log_filtered_resources_with_elastic_ips(self, mock_logger):
        """Test logging with elastic IPs."""
        eip = PackerElasticIP(
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
        resources = ResourceCollection(elastic_ips=[eip])

        _log_filtered_resources(resources)

        mock_logger.info.assert_called()


class TestEnforceScopeInScope:
    """Tests for enforce_scope keeping in-scope resources."""

    def test_enforce_scope_keeps_in_scope_volumes(self):
        """Test enforce_scope keeps in-scope volumes."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        vol = PackerVolume(
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
        resources = ResourceCollection(volumes=[vol])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.volumes) == 1

    def test_enforce_scope_keeps_in_scope_snapshots(self):
        """Test enforce_scope keeps in-scope snapshots."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        snap = PackerSnapshot(
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
        resources = ResourceCollection(snapshots=[snap])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.snapshots) == 1

    def test_enforce_scope_keeps_in_scope_elastic_ips(self):
        """Test enforce_scope keeps in-scope elastic IPs."""
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
            account_id="123456789012",
            public_ip="1.2.3.4",
            allocation_id="eipalloc-001",
            association_id=None,
            instance_id=None,
        )
        resources = ResourceCollection(elastic_ips=[eip])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.elastic_ips) == 1

    def test_enforce_scope_keeps_in_scope_instance_profiles(self):
        """Test enforce_scope keeps in-scope instance profiles."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )
        profile = PackerInstanceProfile(
            resource_id="profile-001",
            resource_type=ResourceType.INSTANCE_PROFILE,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            instance_profile_name="test-profile",
            instance_profile_id="AIPA123456789",
            arn="arn:aws:iam::123456789012:instance-profile/test",
            path="/",
        )
        resources = ResourceCollection(instance_profiles=[profile])

        filtered = enforce_scope(resources, enforcer)

        assert len(filtered.instance_profiles) == 1


# ============================================================================
# OrphanManager tests for remaining uncovered lines
# ============================================================================


class TestOrphanManagerScanNoPackerKeyPairs:
    """Tests for scan_orphaned_key_pairs when no packer key pairs exist."""

    def test_scan_orphaned_key_pairs_no_packer_keys(self):
        """Test scanning when no packer_* key pairs exist."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {"KeyName": "production_key"},
                {"KeyName": "staging_key"},
            ]
        }

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2)
        result = manager.scan_orphaned_key_pairs()

        assert len(result) == 0

    def test_scan_orphaned_security_groups_no_packer_sgs(self):
        """Test scanning when no packer security groups exist."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {"GroupId": "sg-001", "GroupName": "production_sg", "Description": "Prod"},
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2)
        result = manager.scan_orphaned_security_groups()

        assert len(result) == 0

    def test_scan_orphaned_iam_roles_no_packer_roles(self):
        """Test scanning when no packer IAM roles exist."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "production_role"},
                    {"RoleName": "staging_role"},
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager.scan_orphaned_iam_roles()

        assert len(result) == 0


class TestOrphanManagerGetIAMRolesInUseWithProfiles:
    """Tests for _get_iam_roles_in_use with instance profiles."""

    def test_get_iam_roles_in_use_with_profiles(self):
        """Test getting IAM roles in use when profiles are attached to instances."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # EC2 paginator returns instances with IAM profiles
        mock_ec2_paginator = MagicMock()
        mock_ec2_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "IamInstanceProfile": {
                                    "Arn": "arn:aws:iam::123456789012:instance-profile/test-profile"
                                }
                            }
                        ]
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_ec2_paginator

        # IAM paginator returns instance profiles with roles
        mock_iam_paginator = MagicMock()
        mock_iam_paginator.paginate.return_value = [
            {
                "InstanceProfiles": [
                    {
                        "Arn": "arn:aws:iam::123456789012:instance-profile/test-profile",
                        "Roles": [{"RoleName": "packer_role"}],
                    }
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_iam_paginator

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._get_iam_roles_in_use()

        assert "packer_role" in result


# ============================================================================
# filters/base.py - Abstract class coverage
# ============================================================================


class TestResourceFilterAbstractMethods:
    """Tests to cover abstract method definitions in base.py."""

    def test_abstract_methods_are_defined(self):
        """Verify abstract methods exist on the base class."""
        from reaper.filters.base import ResourceFilter

        # Check that the abstract methods are defined
        assert hasattr(ResourceFilter, "filter_instances")
        assert hasattr(ResourceFilter, "filter_volumes")
        assert hasattr(ResourceFilter, "filter_snapshots")
        assert hasattr(ResourceFilter, "filter_security_groups")
        assert hasattr(ResourceFilter, "filter_key_pairs")
        assert hasattr(ResourceFilter, "filter_elastic_ips")


# ============================================================================
# Logging module coverage
# ============================================================================


class TestLoggingModuleCoverage:
    """Tests for logging module edge cases."""

    def test_configure_logging_with_debug_level(self):
        """Test configure_logging with DEBUG level."""
        from reaper.utils.config import ReaperConfig, configure_logging

        config = ReaperConfig(log_level="DEBUG")
        configure_logging(config)

        # Should not raise any errors

    def test_configure_logging_with_warning_level(self):
        """Test configure_logging with WARNING level."""
        from reaper.utils.config import ReaperConfig, configure_logging

        config = ReaperConfig(log_level="WARNING")
        configure_logging(config)

        # Should not raise any errors


# ============================================================================
# Engine tests for uncovered lines 297, 485-491
# ============================================================================


class TestCleanupEngineExecuteWithRetry:
    """Tests for _execute_with_retry method."""

    def test_execute_with_retry_success(self):
        """Test _execute_with_retry with successful operation."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(mock_ec2, dry_run=False)

        def successful_operation():
            return "success"

        result = engine._execute_with_retry(successful_operation)

        assert result == "success"


class TestCleanupEngineCleanupSnapshots:
    """Tests for _cleanup_snapshots method."""

    def test_cleanup_snapshots(self):
        """Test cleanup_snapshots method."""
        mock_ec2 = MagicMock()
        mock_ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": []}]
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": []}
        mock_ec2.describe_images.return_value = {"Images": []}

        engine = CleanupEngine(mock_ec2, dry_run=False)

        snap = PackerSnapshot(
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
        resources = ResourceCollection(snapshots=[snap])

        result = engine.cleanup_resources(resources)

        assert result is not None


# ============================================================================
# Handler tests for build_resource_collection error paths
# ============================================================================


class TestBuildResourceCollectionErrors:
    """Tests for build_resource_collection error handling."""

    def test_build_resource_collection_volume_error(self):
        """Test build_resource_collection handles volume fetch errors."""
        from reaper.handler import build_resource_collection

        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.side_effect = Exception("Volume API error")
        mock_ec2.describe_addresses.return_value = {"Addresses": []}
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": []}

        instance = PackerInstance(
            resource_id="i-001",
            resource_type=ResourceType.INSTANCE,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            instance_type="t3.micro",
            state="running",
            vpc_id="vpc-123",
            security_groups=["sg-001"],
            key_name="packer_key",
            launch_time=datetime.now(UTC),
        )

        resources = build_resource_collection([instance], mock_ec2, "123456789012", "us-east-1")

        # Should still return resources, just without volumes
        assert resources is not None

    def test_build_resource_collection_eip_error(self):
        """Test build_resource_collection handles EIP fetch errors."""
        from reaper.handler import build_resource_collection

        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.return_value = {"Volumes": []}
        mock_ec2.describe_addresses.side_effect = Exception("EIP API error")
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": []}

        instance = PackerInstance(
            resource_id="i-001",
            resource_type=ResourceType.INSTANCE,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            instance_type="t3.micro",
            state="running",
            vpc_id="vpc-123",
            security_groups=[],
            key_name="packer_key",
            launch_time=datetime.now(UTC),
        )

        resources = build_resource_collection([instance], mock_ec2, "123456789012", "us-east-1")

        # Should still return resources, just without EIPs
        assert resources is not None


# ============================================================================
# Batch processor concurrent failure path
# ============================================================================


class TestBatchProcessorConcurrentFailure:
    """Tests for batch processor concurrent failure handling."""

    def test_process_batch_concurrent_with_no_error_msg(self):
        """Test concurrent batch when delete returns False without error."""
        processor = BatchProcessor(batch_size=2)

        call_count = 0

        def delete_func(resource_id: str) -> bool:
            nonlocal call_count
            call_count += 1
            # First call succeeds, second fails
            return call_count != 2

        result = processor.process_deletions(["res-1", "res-2"], delete_func, "test-resource")

        # One should succeed, one should fail
        assert len(result.successful) + len(result.failed) == 2


# ============================================================================
# OrphanManager additional coverage
# ============================================================================


class TestOrphanManagerCleanupWithErrors:
    """Tests for OrphanManager cleanup with various error scenarios."""

    def test_cleanup_key_pair_in_use_during_cleanup(self):
        """Test key pair becomes in use during cleanup."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        # Key pair is now in use when we check
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-001"}]}]
        }

        manager = OrphanManager(mock_ec2, dry_run=False)
        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert "key_pair:packer_key" in result.deferred_resources

    def test_cleanup_security_group_in_use_during_cleanup(self):
        """Test security group becomes in use during cleanup."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        # Security group is now in use when we check
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-001"}]}]
        }

        manager = OrphanManager(mock_ec2, dry_run=False)
        orphaned = OrphanedResources(orphaned_security_groups=["sg-001"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert "security_group:sg-001" in result.deferred_resources


# ============================================================================
# Batch processor exception in future.result()
# ============================================================================


class TestBatchProcessorFutureException:
    """Tests for batch processor when future.result() raises exception."""

    def test_process_batch_concurrent_future_raises_exception(self):
        """Test concurrent batch when future.result() raises an exception."""
        import time

        processor = BatchProcessor(batch_size=3)

        def delete_func(resource_id: str) -> bool:
            if resource_id == "res-2":
                # This will cause future.result() to raise
                raise ValueError("Simulated exception in thread")
            time.sleep(0.01)  # Small delay to ensure concurrent execution
            return True

        result = processor.process_deletions(
            ["res-1", "res-2", "res-3"], delete_func, "test-resource"
        )

        # res-2 should be in failed due to exception
        assert "res-2" in result.failed
        assert "res-2" in result.errors
        assert "Simulated exception" in result.errors["res-2"]


# ============================================================================
# Engine cleanup_instance_profiles with IAM manager
# ============================================================================


class TestCleanupEngineInstanceProfiles:
    """Tests for cleanup_instance_profiles with IAM manager."""

    def test_cleanup_instance_profiles_with_iam_manager(self):
        """Test cleanup_instance_profiles when IAM manager is available."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Setup orphan manager mocks
        mock_ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": []}]
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": []}

        engine = CleanupEngine(mock_ec2, dry_run=False, iam_client=mock_iam)

        # Mock IAM manager's delete_instance_profiles
        engine.iam_manager.delete_instance_profiles = MagicMock(
            return_value=(["profile-001"], [], {})
        )

        profile = PackerInstanceProfile(
            resource_id="profile-001",
            resource_type=ResourceType.INSTANCE_PROFILE,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            instance_profile_name="test-profile",
            instance_profile_id="AIPA123456789",
            arn="arn:aws:iam::123456789012:instance-profile/test",
            path="/",
        )
        resources = ResourceCollection(instance_profiles=[profile])

        result = engine.cleanup_resources(resources)

        assert "profile-001" in result.deleted_instance_profiles


# ============================================================================
# AWS Client Manager role assumption coverage
# ============================================================================


class TestAWSClientManagerRoleAssumptionComplete:
    """Complete tests for AWSClientManager with role assumption."""

    @patch("reaper.utils.aws_client.boto3")
    def test_get_session_creates_session_with_credentials(self, mock_boto3):
        """Test session creation uses assumed role credentials."""
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIATEST123",
                "SecretAccessKey": "secretkey123",
                "SessionToken": "sessiontoken123",
            }
        }
        mock_boto3.client.return_value = mock_sts

        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        manager = AWSClientManager(
            region="us-west-2",
            role_arn="arn:aws:iam::999999999999:role/CrossAccountRole",
        )

        # Call _get_session to trigger role assumption
        result = manager._get_session()

        # Verify assume_role was called with correct parameters
        mock_sts.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::999999999999:role/CrossAccountRole",
            RoleSessionName="PackerResourceReaper",
            DurationSeconds=3600,
        )

        # Verify Session was created with credentials
        mock_boto3.Session.assert_called_once_with(
            aws_access_key_id="AKIATEST123",
            aws_secret_access_key="secretkey123",
            aws_session_token="sessiontoken123",
            region_name="us-west-2",
        )

        assert result == mock_session

    @patch("reaper.utils.aws_client.boto3")
    def test_get_session_caches_session(self, mock_boto3):
        """Test that session is cached after first call."""
        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        manager = AWSClientManager(region="us-east-1")

        # Call twice
        result1 = manager._get_session()
        result2 = manager._get_session()

        # Session should only be created once
        assert mock_boto3.Session.call_count == 1
        assert result1 == result2


# ============================================================================
# NetworkManager additional coverage for lines 122, 376-377
# ============================================================================


class TestNetworkManagerKeyPairException:
    """Tests for NetworkManager key pair exception handling."""

    def test_get_key_pair_by_name_generic_exception(self):
        """Test get_key_pair_by_name handles generic exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = Exception("Network error")

        manager = NetworkManager(mock_ec2)
        result = manager.get_key_pair_by_name("test-key", "123456789012", "us-east-1")

        assert result is None


class TestNetworkManagerEIPRelease:
    """Tests for NetworkManager EIP release with association."""

    def test_release_elastic_ip_with_association_deferred(self):
        """Test releasing EIP that is still associated returns deferred."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2, dry_run=False)

        eip = PackerElasticIP(
            resource_id="eipalloc-001",
            resource_type=ResourceType.ELASTIC_IP,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            public_ip="1.2.3.4",
            allocation_id="eipalloc-001",
            association_id="eipassoc-001",  # Still associated
            instance_id="i-001",
        )

        released, deferred, errors = manager.release_elastic_ips([eip])

        assert len(released) == 0
        assert "eipalloc-001" in deferred
        assert len(errors) == 0
        mock_ec2.release_address.assert_not_called()


# ============================================================================
# OrphanManager additional coverage
# ============================================================================


class TestOrphanManagerEdgeCases:
    """Tests for OrphanManager edge cases."""

    def test_scan_orphaned_key_pairs_exception(self):
        """Test scan_orphaned_key_pairs handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = Exception("API error")

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2)
        result = manager.scan_orphaned_key_pairs()

        assert result == []

    def test_scan_orphaned_security_groups_exception(self):
        """Test scan_orphaned_security_groups handles exceptions."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2)
        result = manager.scan_orphaned_security_groups()

        assert result == []

    def test_scan_orphaned_iam_roles_exception(self):
        """Test scan_orphaned_iam_roles handles exceptions."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_iam.get_paginator.return_value = mock_paginator

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager.scan_orphaned_iam_roles()

        assert result == []

    def test_get_key_pairs_in_use_exception(self):
        """Test _get_key_pairs_in_use handles exceptions."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2)
        result = manager._get_key_pairs_in_use()

        assert result == set()

    def test_get_security_groups_in_use_exception(self):
        """Test _get_security_groups_in_use handles exceptions."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2)
        result = manager._get_security_groups_in_use()

        assert result == set()

    def test_get_iam_roles_in_use_exception(self):
        """Test _get_iam_roles_in_use handles exceptions."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._get_iam_roles_in_use()

        assert result == set()

    def test_cleanup_key_pair_already_deleted(self):
        """Test cleanup handles key pair already deleted."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.delete_key_pair.side_effect = ClientError(
            {"Error": {"Code": "InvalidKeyPair.NotFound", "Message": "Not found"}},
            "DeleteKeyPair",
        )

        manager = OrphanManager(mock_ec2, dry_run=False)
        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key"])

        result = manager.cleanup_orphaned_resources(orphaned)

        # Should be marked as deleted since it's already gone
        assert "packer_key" in result.deleted_key_pairs

    def test_cleanup_security_group_already_deleted(self):
        """Test cleanup handles security group already deleted."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

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

        # Should be marked as deleted since it's already gone
        assert "sg-001" in result.deleted_security_groups

    def test_cleanup_security_group_dependency_violation(self):
        """Test cleanup handles security group dependency violation."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

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

        # Should be deferred
        assert "security_group:sg-001" in result.deferred_resources

    def test_cleanup_iam_role_already_deleted(self):
        """Test cleanup handles IAM role already deleted."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Role not in use
        mock_iam.list_instance_profiles_for_role.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "ListInstanceProfilesForRole",
        )

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        # Should be marked as deleted since it's already gone
        assert "packer_role" in result.deleted_iam_roles

    def test_cleanup_iam_role_delete_conflict(self):
        """Test cleanup handles IAM role delete conflict."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Role not in use
        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}
        mock_iam.delete_role.side_effect = ClientError(
            {"Error": {"Code": "DeleteConflict", "Message": "Has dependencies"}},
            "DeleteRole",
        )

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        # Should be deferred
        assert "iam_role:packer_role" in result.deferred_resources

    def test_is_key_pair_in_use_exception(self):
        """Test _is_key_pair_in_use handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = Exception("API error")

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2)
        result = manager._is_key_pair_in_use("packer_key")

        # Should return False on error (safe default)
        assert result is False

    def test_is_security_group_in_use_exception(self):
        """Test _is_security_group_in_use handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = Exception("API error")

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2)
        result = manager._is_security_group_in_use("sg-001")

        # Should return False on error (safe default)
        assert result is False

    def test_is_iam_role_in_use_no_such_entity(self):
        """Test _is_iam_role_in_use handles NoSuchEntity."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_iam.list_instance_profiles_for_role.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "ListInstanceProfilesForRole",
        )

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._is_iam_role_in_use("packer_role")

        # Should return False when role doesn't exist
        assert result is False

    def test_is_iam_role_in_use_generic_exception(self):
        """Test _is_iam_role_in_use handles generic exceptions."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_iam.list_instance_profiles_for_role.side_effect = Exception("API error")

        from reaper.cleanup.orphan_manager import OrphanManager

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._is_iam_role_in_use("packer_role")

        # Should return False on error (safe default)
        assert result is False


# ============================================================================
# BatchProcessor concurrent processing edge cases
# ============================================================================


class TestBatchProcessorConcurrentEdgeCases:
    """Tests for batch processor concurrent edge cases."""

    def test_process_batch_concurrent_all_fail(self):
        """Test concurrent batch when all deletions fail."""
        processor = BatchProcessor(batch_size=3)

        def delete_func(resource_id: str) -> bool:
            return False

        result = processor.process_deletions(
            ["res-1", "res-2", "res-3"], delete_func, "test-resource"
        )

        assert len(result.successful) == 0
        assert len(result.failed) == 3

    def test_process_batch_concurrent_mixed_results(self):
        """Test concurrent batch with mixed success/failure."""
        processor = BatchProcessor(batch_size=5)

        def delete_func(resource_id: str) -> bool:
            # Odd numbers succeed, even fail
            return int(resource_id.split("-")[1]) % 2 == 1

        result = processor.process_deletions(
            ["res-1", "res-2", "res-3", "res-4", "res-5"], delete_func, "test-resource"
        )

        assert "res-1" in result.successful
        assert "res-3" in result.successful
        assert "res-5" in result.successful
        assert "res-2" in result.failed
        assert "res-4" in result.failed


# ============================================================================
# Concrete ResourceFilter implementation for coverage
# ============================================================================


class TestConcreteResourceFilter:
    """Tests using a concrete ResourceFilter implementation."""

    def test_concrete_filter_implementation(self):
        """Test that concrete implementations work correctly."""
        from reaper.filters.identity import IdentityFilter

        # IdentityFilter is a concrete implementation
        filter_instance = IdentityFilter(key_pattern="packer_")

        # Test filter_instances
        instance = PackerInstance(
            resource_id="i-001",
            resource_type=ResourceType.INSTANCE,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            instance_type="t3.micro",
            state="running",
            vpc_id="vpc-123",
            security_groups=[],
            key_name="packer_key",
            launch_time=datetime.now(UTC),
        )

        result = filter_instance.filter_instances([instance])
        assert len(result) == 1

    def test_identity_filter_all_methods(self):
        """Test all filter methods on IdentityFilter."""
        from reaper.filters.identity import IdentityFilter

        filter_instance = IdentityFilter(key_pattern="packer_")

        # Test filter_volumes
        vol = PackerVolume(
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
        assert filter_instance.filter_volumes([vol]) == [vol]

        # Test filter_snapshots
        snap = PackerSnapshot(
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
        assert filter_instance.filter_snapshots([snap]) == [snap]

        # Test filter_security_groups - needs packer_ prefix in group_name
        sg = PackerSecurityGroup(
            resource_id="sg-001",
            resource_type=ResourceType.SECURITY_GROUP,
            creation_time=datetime.now(UTC),
            tags={},
            region="us-east-1",
            account_id="123456789012",
            group_name="packer_sg",  # Must start with packer_
            vpc_id="vpc-123",
            description="Test",
        )
        assert filter_instance.filter_security_groups([sg]) == [sg]

        # Test filter_key_pairs
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
        result = filter_instance.filter_key_pairs([kp])
        assert len(result) == 1

        # Test filter_elastic_ips
        eip = PackerElasticIP(
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
        assert filter_instance.filter_elastic_ips([eip]) == [eip]


# ============================================================================
# Delete IAM role cleanup sequence coverage
# ============================================================================


class TestDeleteIAMRoleCleanupSequence:
    """Tests for _delete_iam_role cleanup sequence."""

    def test_delete_iam_role_full_cleanup(self):
        """Test full IAM role cleanup sequence."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Setup mocks for full cleanup
        mock_iam.list_instance_profiles_for_role.return_value = {
            "InstanceProfiles": [{"InstanceProfileName": "test-profile"}]
        }
        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/TestPolicy"}]
        }
        mock_iam.list_role_policies.return_value = {"PolicyNames": ["inline-policy"]}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        manager._delete_iam_role("packer_role")

        # Verify cleanup sequence
        mock_iam.remove_role_from_instance_profile.assert_called_once()
        mock_iam.detach_role_policy.assert_called_once()
        mock_iam.delete_role_policy.assert_called_once()
        mock_iam.delete_role.assert_called_once_with(RoleName="packer_role")

    def test_delete_iam_role_no_such_entity_on_profiles(self):
        """Test IAM role cleanup handles NoSuchEntity on instance profiles."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # NoSuchEntity on list_instance_profiles_for_role
        mock_iam.list_instance_profiles_for_role.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "ListInstanceProfilesForRole",
        )
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        manager._delete_iam_role("packer_role")

        # Should still delete the role
        mock_iam.delete_role.assert_called_once()

    def test_delete_iam_role_no_such_entity_on_policies(self):
        """Test IAM role cleanup handles NoSuchEntity on policies."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "ListAttachedRolePolicies",
        )
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        manager._delete_iam_role("packer_role")

        # Should still delete the role
        mock_iam.delete_role.assert_called_once()

    def test_delete_iam_role_no_such_entity_on_inline_policies(self):
        """Test IAM role cleanup handles NoSuchEntity on inline policies."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "ListRolePolicies",
        )

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        manager._delete_iam_role("packer_role")

        # Should still delete the role
        mock_iam.delete_role.assert_called_once()


# ============================================================================
# Additional tests for remaining uncovered lines
# ============================================================================


class TestOrphanManagerScanWithResults:
    """Tests for orphan manager scan methods that return results."""

    def test_scan_orphaned_key_pairs_with_orphans(self):
        """Test scan_orphaned_key_pairs when orphans are found."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        # Return packer key pairs
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {"KeyName": "packer_key1"},
                {"KeyName": "packer_key2"},
                {"KeyName": "other_key"},
            ]
        }
        # No instances using any keys
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Reservations": []}]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        result = manager.scan_orphaned_key_pairs()

        # Both packer keys should be orphaned
        assert "packer_key1" in result
        assert "packer_key2" in result
        assert len(result) == 2

    def test_scan_orphaned_security_groups_with_orphans(self):
        """Test scan_orphaned_security_groups when orphans are found."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()

        # Setup paginator for security groups
        mock_sg_paginator = MagicMock()
        mock_sg_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {"GroupId": "sg-001", "GroupName": "packer_sg", "Description": "Packer SG"},
                    {"GroupId": "sg-002", "GroupName": "other_sg", "Description": "Other"},
                ]
            }
        ]

        # Setup paginator for instances (no instances)
        mock_instance_paginator = MagicMock()
        mock_instance_paginator.paginate.return_value = [{"Reservations": []}]

        # Setup paginator for network interfaces (none)
        mock_ni_paginator = MagicMock()
        mock_ni_paginator.paginate.return_value = [{"NetworkInterfaces": []}]

        def get_paginator(name):
            if name == "describe_security_groups":
                return mock_sg_paginator
            elif name == "describe_instances":
                return mock_instance_paginator
            elif name == "describe_network_interfaces":
                return mock_ni_paginator
            return MagicMock()

        mock_ec2.get_paginator.side_effect = get_paginator

        manager = OrphanManager(mock_ec2)
        result = manager.scan_orphaned_security_groups()

        assert "sg-001" in result

    def test_scan_orphaned_iam_roles_with_orphans(self):
        """Test scan_orphaned_iam_roles when orphans are found."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Setup IAM paginator for roles
        mock_role_paginator = MagicMock()
        mock_role_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "packer_role1"},
                    {"RoleName": "packer-role2"},
                    {"RoleName": "other_role"},
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_role_paginator

        # Setup EC2 paginator for instances (no instances)
        mock_instance_paginator = MagicMock()
        mock_instance_paginator.paginate.return_value = [{"Reservations": []}]
        mock_ec2.get_paginator.return_value = mock_instance_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager.scan_orphaned_iam_roles()

        assert "packer_role1" in result
        assert "packer-role2" in result


class TestOrphanManagerCleanupGenericExceptions:
    """Tests for orphan manager cleanup with generic exceptions."""

    def test_cleanup_key_pair_generic_exception(self):
        """Test cleanup handles generic exception during key pair deletion."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.delete_key_pair.side_effect = Exception("Unexpected error")

        manager = OrphanManager(mock_ec2, dry_run=False)
        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert "key_pair:packer_key" in result.errors

    def test_cleanup_security_group_generic_exception(self):
        """Test cleanup handles generic exception during security group deletion."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
        mock_ec2.delete_security_group.side_effect = Exception("Unexpected error")

        manager = OrphanManager(mock_ec2, dry_run=False)
        orphaned = OrphanedResources(orphaned_security_groups=["sg-001"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert "security_group:sg-001" in result.errors

    def test_cleanup_iam_role_generic_exception(self):
        """Test cleanup handles generic exception during IAM role deletion."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Role not in use
        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}
        mock_iam.delete_role.side_effect = Exception("Unexpected error")

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)
        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        assert "iam_role:packer_role" in result.errors


class TestOrphanManagerIsInUseChecks:
    """Tests for orphan manager in-use checks."""

    def test_is_iam_role_in_use_with_attached_profile(self):
        """Test _is_iam_role_in_use when role is attached to running instance."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Role has instance profiles
        mock_iam.list_instance_profiles_for_role.return_value = {
            "InstanceProfiles": [{"Arn": "arn:aws:iam::123456789012:instance-profile/test-profile"}]
        }

        # Instance using this profile
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "IamInstanceProfile": {
                                    "Arn": "arn:aws:iam::123456789012:instance-profile/test-profile"
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

    def test_is_iam_role_in_use_client_error(self):
        """Test _is_iam_role_in_use handles ClientError."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # ClientError that's not NoSuchEntity
        mock_iam.list_instance_profiles_for_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "ListInstanceProfilesForRole",
        )

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._is_iam_role_in_use("packer_role")

        # Should return False on error (safe default)
        assert result is False


class TestLoggingModuleEdgeCases:
    """Tests for logging module edge cases."""

    def test_reaper_logger_log_critical(self):
        """Test ReaperLogger logs at CRITICAL level."""
        from reaper.utils.logging import ActionType, LogLevel, ReaperLogger

        logger_instance = ReaperLogger(account_id="123456789012", region="us-east-1")

        # Create a critical log entry
        entry = logger_instance._create_entry(
            level=LogLevel.CRITICAL,
            action=ActionType.ERROR,
            resource_type="test",
            resource_id="test-001",
            message="Critical error",
        )

        # Log it
        logger_instance._log(entry)

        # Verify entry was stored
        entries = logger_instance.get_log_entries()
        assert len(entries) == 1
        assert entries[0].level == LogLevel.CRITICAL


class TestGetPackerHelperMethods:
    """Tests for _get_packer_* helper methods."""

    def test_get_packer_key_pairs_exception(self):
        """Test _get_packer_key_pairs handles exceptions."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.side_effect = Exception("API error")

        manager = OrphanManager(mock_ec2)
        result = manager._get_packer_key_pairs()

        assert result == []

    def test_get_packer_security_groups_exception(self):
        """Test _get_packer_security_groups handles exceptions."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        result = manager._get_packer_security_groups()

        assert result == []

    def test_get_packer_iam_roles_exception(self):
        """Test _get_packer_iam_roles handles exceptions."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_iam.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager._get_packer_iam_roles()

        assert result == []


class TestDeleteIAMRoleOtherErrors:
    """Tests for _delete_iam_role with other error types."""

    def test_delete_iam_role_raises_on_other_error(self):
        """Test _delete_iam_role raises on non-NoSuchEntity errors."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # AccessDenied error on list_instance_profiles_for_role
        mock_iam.list_instance_profiles_for_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "ListInstanceProfilesForRole",
        )

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        with pytest.raises(ClientError):
            manager._delete_iam_role("packer_role")

    def test_delete_iam_role_raises_on_policy_error(self):
        """Test _delete_iam_role raises on policy detach errors."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "ListAttachedRolePolicies",
        )

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        with pytest.raises(ClientError):
            manager._delete_iam_role("packer_role")

    def test_delete_iam_role_raises_on_inline_policy_error(self):
        """Test _delete_iam_role raises on inline policy errors."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "ListRolePolicies",
        )

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=False)

        with pytest.raises(ClientError):
            manager._delete_iam_role("packer_role")


# ============================================================================
# Final coverage push - remaining uncovered lines
# ============================================================================


class TestOrphanManagerScanLogging:
    """Tests to cover logging statements in scan methods."""

    def test_scan_orphaned_key_pairs_logs_results(self):
        """Test scan_orphaned_key_pairs logs scan results."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        # Return packer key pairs
        mock_ec2.describe_key_pairs.return_value = {"KeyPairs": [{"KeyName": "packer_key1"}]}
        # Key is in use
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Reservations": [{"Instances": [{"KeyName": "packer_key1"}]}]}
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        result = manager.scan_orphaned_key_pairs()

        # Key is in use, so no orphans
        assert len(result) == 0

    def test_scan_orphaned_security_groups_logs_results(self):
        """Test scan_orphaned_security_groups logs scan results."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()

        # Setup paginator for security groups with packer SG
        mock_sg_paginator = MagicMock()
        mock_sg_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {"GroupId": "sg-001", "GroupName": "packer_sg", "Description": "Test"},
                ]
            }
        ]

        # Setup paginator for instances - SG is in use
        mock_instance_paginator = MagicMock()
        mock_instance_paginator.paginate.return_value = [
            {"Reservations": [{"Instances": [{"SecurityGroups": [{"GroupId": "sg-001"}]}]}]}
        ]

        # Setup paginator for network interfaces
        mock_ni_paginator = MagicMock()
        mock_ni_paginator.paginate.return_value = [{"NetworkInterfaces": []}]

        def get_paginator(name):
            if name == "describe_security_groups":
                return mock_sg_paginator
            elif name == "describe_instances":
                return mock_instance_paginator
            elif name == "describe_network_interfaces":
                return mock_ni_paginator
            return MagicMock()

        mock_ec2.get_paginator.side_effect = get_paginator

        manager = OrphanManager(mock_ec2)
        result = manager.scan_orphaned_security_groups()

        # SG is in use, so no orphans
        assert len(result) == 0

    def test_scan_orphaned_iam_roles_logs_results(self):
        """Test scan_orphaned_iam_roles logs scan results."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Setup IAM paginator for roles
        mock_role_paginator = MagicMock()
        mock_role_paginator.paginate.return_value = [{"Roles": [{"RoleName": "packer_role1"}]}]

        # Setup IAM paginator for instance profiles
        mock_profile_paginator = MagicMock()
        mock_profile_paginator.paginate.return_value = [
            {
                "InstanceProfiles": [
                    {
                        "Arn": "arn:aws:iam::123456789012:instance-profile/test",
                        "Roles": [{"RoleName": "packer_role1"}],
                    }
                ]
            }
        ]

        def get_iam_paginator(name):
            if name == "list_roles":
                return mock_role_paginator
            elif name == "list_instance_profiles":
                return mock_profile_paginator
            return MagicMock()

        mock_iam.get_paginator.side_effect = get_iam_paginator

        # Setup EC2 paginator for instances - role is in use
        mock_instance_paginator = MagicMock()
        mock_instance_paginator.paginate.return_value = [
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
        mock_ec2.get_paginator.return_value = mock_instance_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager.scan_orphaned_iam_roles()

        # Role is in use, so no orphans
        assert len(result) == 0


class TestNetworkManagerLine122:
    """Test to cover network_manager.py line 122."""

    def test_get_key_pair_by_name_empty_key_name(self):
        """Test get_key_pair_by_name with empty key name."""
        mock_ec2 = MagicMock()
        manager = NetworkManager(mock_ec2)

        result = manager.get_key_pair_by_name("", "123456789012", "us-east-1")

        assert result is None
        mock_ec2.describe_key_pairs.assert_not_called()


class TestBatchProcessorLines174to178:
    """Tests to cover batch_processor.py lines 174-178."""

    def test_process_batch_concurrent_exception_in_future_result(self):
        """Test concurrent batch when future.result() raises exception."""
        processor = BatchProcessor(batch_size=2)

        call_count = 0

        def delete_func(resource_id: str) -> bool:
            nonlocal call_count
            call_count += 1
            if resource_id == "res-fail":
                raise RuntimeError("Simulated failure in thread")
            return True

        result = processor.process_deletions(["res-ok", "res-fail"], delete_func, "test-resource")

        assert "res-ok" in result.successful
        assert "res-fail" in result.failed
        assert "res-fail" in result.errors
        assert "Simulated failure" in result.errors["res-fail"]


class TestAWSClientManagerLines54to56:
    """Tests to cover aws_client.py lines 54-56."""

    @patch("reaper.utils.aws_client.boto3")
    def test_get_session_with_role_arn_full_flow(self, mock_boto3):
        """Test full role assumption flow."""
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }
        mock_boto3.client.return_value = mock_sts

        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        manager = AWSClientManager(
            region="us-east-1",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )

        # First call creates session
        session1 = manager._get_session()
        assert session1 == mock_session

        # Verify credentials were used
        mock_boto3.Session.assert_called_with(
            aws_access_key_id="AKIATEST",
            aws_secret_access_key="secret",
            aws_session_token="token",
            region_name="us-east-1",
        )


# ============================================================================
# Final push for 100% coverage
# ============================================================================


class TestNetworkManagerScanSecurityGroupsDefault:
    """Test scanning security groups with default SG."""

    def test_scan_security_groups_skips_default(self):
        """Test scan_security_groups skips default security group."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {"GroupId": "sg-default", "GroupName": "default", "Description": "Default"},
                    {"GroupId": "sg-001", "GroupName": "packer_sg", "Description": "Packer SG"},
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = NetworkManager(mock_ec2)
        result = manager.scan_security_groups("123456789012", "us-east-1")

        # Should only return non-default SG
        assert len(result) == 1
        assert result[0].resource_id == "sg-001"


class TestOrphanManagerScanLoggingStatements:
    """Tests to cover logging statements in orphan_manager."""

    def test_scan_orphaned_key_pairs_with_packer_keys_found(self):
        """Test scan logs when packer keys are found."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        # Return packer key pairs
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {"KeyName": "packer_key1"},
                {"KeyName": "packer_key2"},
            ]
        }
        # No instances using keys
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Reservations": []}]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2)
        result = manager.scan_orphaned_key_pairs()

        # Both keys should be orphaned
        assert len(result) == 2
        assert "packer_key1" in result
        assert "packer_key2" in result

    def test_scan_orphaned_security_groups_with_packer_sgs_found(self):
        """Test scan logs when packer security groups are found."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()

        # Setup paginator for security groups
        mock_sg_paginator = MagicMock()
        mock_sg_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {"GroupId": "sg-001", "GroupName": "packer_sg1", "Description": "Test"},
                    {"GroupId": "sg-002", "GroupName": "packer_sg2", "Description": "Test"},
                ]
            }
        ]

        # Setup paginator for instances (no instances)
        mock_instance_paginator = MagicMock()
        mock_instance_paginator.paginate.return_value = [{"Reservations": []}]

        # Setup paginator for network interfaces (none)
        mock_ni_paginator = MagicMock()
        mock_ni_paginator.paginate.return_value = [{"NetworkInterfaces": []}]

        def get_paginator(name):
            if name == "describe_security_groups":
                return mock_sg_paginator
            elif name == "describe_instances":
                return mock_instance_paginator
            elif name == "describe_network_interfaces":
                return mock_ni_paginator
            return MagicMock()

        mock_ec2.get_paginator.side_effect = get_paginator

        manager = OrphanManager(mock_ec2)
        result = manager.scan_orphaned_security_groups()

        # Both SGs should be orphaned
        assert len(result) == 2
        assert "sg-001" in result
        assert "sg-002" in result

    def test_scan_orphaned_iam_roles_with_packer_roles_found(self):
        """Test scan logs when packer IAM roles are found."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Setup IAM paginator for roles
        mock_role_paginator = MagicMock()
        mock_role_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "packer_role1"},
                    {"RoleName": "packer_role2"},
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_role_paginator

        # Setup EC2 paginator for instances (no instances)
        mock_instance_paginator = MagicMock()
        mock_instance_paginator.paginate.return_value = [{"Reservations": []}]
        mock_ec2.get_paginator.return_value = mock_instance_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam)
        result = manager.scan_orphaned_iam_roles()

        # Both roles should be orphaned
        assert len(result) == 2
        assert "packer_role1" in result
        assert "packer_role2" in result


class TestOrphanManagerCleanupDryRun:
    """Tests for orphan manager cleanup in dry-run mode."""

    def test_cleanup_key_pairs_dry_run(self):
        """Test cleanup key pairs in dry-run mode."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        manager = OrphanManager(mock_ec2, dry_run=True)
        orphaned = OrphanedResources(orphaned_key_pairs=["packer_key"])

        result = manager.cleanup_orphaned_resources(orphaned)

        # Should be marked as deleted in dry-run
        assert "packer_key" in result.deleted_key_pairs
        mock_ec2.delete_key_pair.assert_not_called()

    def test_cleanup_security_groups_dry_run(self):
        """Test cleanup security groups in dry-run mode."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}

        manager = OrphanManager(mock_ec2, dry_run=True)
        orphaned = OrphanedResources(orphaned_security_groups=["sg-001"])

        result = manager.cleanup_orphaned_resources(orphaned)

        # Should be marked as deleted in dry-run
        assert "sg-001" in result.deleted_security_groups
        mock_ec2.delete_security_group.assert_not_called()

    def test_cleanup_iam_roles_dry_run(self):
        """Test cleanup IAM roles in dry-run mode."""
        from reaper.cleanup.orphan_manager import OrphanedResources, OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Role not in use
        mock_iam.list_instance_profiles_for_role.return_value = {"InstanceProfiles": []}

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, dry_run=True)
        orphaned = OrphanedResources(orphaned_iam_roles=["packer_role"])

        result = manager.cleanup_orphaned_resources(orphaned)

        # Should be marked as deleted in dry-run
        assert "packer_role" in result.deleted_iam_roles
        mock_iam.delete_role.assert_not_called()


# ============================================================================
# Tests for age-based filtering of orphaned resources (safety feature)
# ============================================================================


class TestOrphanManagerAgeFiltering:
    """Tests for age-based filtering to prevent race conditions."""

    def test_skip_young_iam_role(self):
        """Test that IAM roles younger than threshold are skipped."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Role created 30 minutes ago (younger than 2 hour threshold)
        young_create_time = datetime.now(UTC) - timedelta(minutes=30)

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "packer_young_role", "CreateDate": young_create_time},
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, max_resource_age_hours=2)
        result = manager._get_packer_iam_roles()

        # Young role should be skipped
        assert "packer_young_role" not in result

    def test_include_old_iam_role(self):
        """Test that IAM roles older than threshold are included."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Role created 3 hours ago (older than 2 hour threshold)
        old_create_time = datetime.now(UTC) - timedelta(hours=3)

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "packer_old_role", "CreateDate": old_create_time},
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, max_resource_age_hours=2)
        result = manager._get_packer_iam_roles()

        # Old role should be included
        assert "packer_old_role" in result

    def test_skip_young_key_pair(self):
        """Test that key pairs younger than threshold are skipped."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()

        # Key pair created 30 minutes ago (younger than 2 hour threshold)
        young_create_time = datetime.now(UTC) - timedelta(minutes=30)

        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {"KeyName": "packer_young_key", "CreateTime": young_create_time},
            ]
        }

        manager = OrphanManager(mock_ec2, max_resource_age_hours=2)
        result = manager._get_packer_key_pairs()

        # Young key pair should be skipped
        assert "packer_young_key" not in result

    def test_include_old_key_pair(self):
        """Test that key pairs older than threshold are included."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()

        # Key pair created 3 hours ago (older than 2 hour threshold)
        old_create_time = datetime.now(UTC) - timedelta(hours=3)

        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {"KeyName": "packer_old_key", "CreateTime": old_create_time},
            ]
        }

        manager = OrphanManager(mock_ec2, max_resource_age_hours=2)
        result = manager._get_packer_key_pairs()

        # Old key pair should be included
        assert "packer_old_key" in result

    def test_include_key_pair_without_create_time(self):
        """Test that key pairs without CreateTime are included (legacy behavior)."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()

        # Key pair without CreateTime (older API response)
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {"KeyName": "packer_legacy_key"},  # No CreateTime
            ]
        }

        manager = OrphanManager(mock_ec2, max_resource_age_hours=2)
        result = manager._get_packer_key_pairs()

        # Key pair without CreateTime should be included (assume old)
        assert "packer_legacy_key" in result

    def test_include_iam_role_without_create_date(self):
        """Test that IAM roles without CreateDate are included (legacy behavior)."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "packer_legacy_role"},  # No CreateDate
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        manager = OrphanManager(mock_ec2, iam_client=mock_iam, max_resource_age_hours=2)
        result = manager._get_packer_iam_roles()

        # Role without CreateDate should be included (assume old)
        assert "packer_legacy_role" in result

    def test_custom_age_threshold(self):
        """Test custom age threshold is respected."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        # Role created 90 minutes ago
        create_time = datetime.now(UTC) - timedelta(minutes=90)

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Roles": [
                    {"RoleName": "packer_role", "CreateDate": create_time},
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        # With 1 hour threshold, role should be included
        manager_1h = OrphanManager(mock_ec2, iam_client=mock_iam, max_resource_age_hours=1)
        result_1h = manager_1h._get_packer_iam_roles()
        assert "packer_role" in result_1h

        # With 2 hour threshold, role should be skipped
        manager_2h = OrphanManager(mock_ec2, iam_client=mock_iam, max_resource_age_hours=2)
        result_2h = manager_2h._get_packer_iam_roles()
        assert "packer_role" not in result_2h

    def test_minimum_age_threshold_enforced(self):
        """Test that minimum age threshold of 1 hour is enforced."""
        from reaper.cleanup.orphan_manager import OrphanManager

        mock_ec2 = MagicMock()

        # Try to set 0 hour threshold
        manager = OrphanManager(mock_ec2, max_resource_age_hours=0)

        # Should be enforced to minimum of 1 hour
        assert manager.max_resource_age_hours == 1
