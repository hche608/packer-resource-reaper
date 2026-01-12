"""Tests for cleanup engine module.

Tests for CleanupEngine orchestration.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from reaper.cleanup.engine import AssociatedResources, CleanupEngine
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


def create_instance(
    instance_id: str,
    state: str = "running",
    key_name: str = "packer_key",
) -> PackerInstance:
    """Create a PackerInstance for testing."""
    launch_time = datetime.now(UTC) - timedelta(hours=3)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=launch_time,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state=state,
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name=key_name,
        launch_time=launch_time,
    )


def create_security_group(sg_id: str) -> PackerSecurityGroup:
    """Create a PackerSecurityGroup for testing."""
    return PackerSecurityGroup(
        resource_id=sg_id,
        resource_type=ResourceType.SECURITY_GROUP,
        creation_time=datetime.now(UTC),
        tags={},
        region="us-east-1",
        account_id="123456789012",
        group_name="packer_sg",
        vpc_id="vpc-12345678",
        description="Test SG",
    )


def create_key_pair(key_name: str) -> PackerKeyPair:
    """Create a PackerKeyPair for testing."""
    return PackerKeyPair(
        resource_id=f"key-{key_name}",
        resource_type=ResourceType.KEY_PAIR,
        creation_time=datetime.now(UTC),
        tags={},
        region="us-east-1",
        account_id="123456789012",
        key_name=key_name,
        key_fingerprint="ab:cd:ef",
    )


def create_volume(volume_id: str) -> PackerVolume:
    """Create a PackerVolume for testing."""
    return PackerVolume(
        resource_id=volume_id,
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


def create_snapshot(snapshot_id: str) -> PackerSnapshot:
    """Create a PackerSnapshot for testing."""
    return PackerSnapshot(
        resource_id=snapshot_id,
        resource_type=ResourceType.SNAPSHOT,
        creation_time=datetime.now(UTC),
        tags={},
        region="us-east-1",
        account_id="123456789012",
        volume_id="vol-12345678",
        state="completed",
        progress="100%",
        owner_id="123456789012",
    )


def create_elastic_ip(allocation_id: str) -> PackerElasticIP:
    """Create a PackerElasticIP for testing."""
    return PackerElasticIP(
        resource_id=allocation_id,
        resource_type=ResourceType.ELASTIC_IP,
        creation_time=datetime.now(UTC),
        tags={},
        region="us-east-1",
        account_id="123456789012",
        public_ip="1.2.3.4",
        allocation_id=allocation_id,
        association_id=None,
        instance_id=None,
    )


def create_instance_profile(profile_name: str) -> PackerInstanceProfile:
    """Create a PackerInstanceProfile for testing."""
    return PackerInstanceProfile(
        resource_id=f"profile-{profile_name}",
        resource_type=ResourceType.INSTANCE_PROFILE,
        creation_time=datetime.now(UTC),
        tags={},
        region="us-east-1",
        account_id="123456789012",
        instance_profile_id=f"AIPA{profile_name.upper()}",
        instance_profile_name=profile_name,
        arn=f"arn:aws:iam::123456789012:instance-profile/{profile_name}",
        path="/",
        roles=["packer_role"],
    )


class TestAssociatedResources:
    """Tests for AssociatedResources dataclass."""

    def test_default_values(self):
        """Test default values."""
        associated = AssociatedResources(instance_id="i-001")
        assert associated.instance_id == "i-001"
        assert associated.security_group_ids == []
        assert associated.key_pair_name is None
        assert associated.volume_ids == []
        assert associated.eip_allocation_ids == []

    def test_with_values(self):
        """Test with populated values."""
        associated = AssociatedResources(
            instance_id="i-001",
            security_group_ids=["sg-001", "sg-002"],
            key_pair_name="packer_key",
            volume_ids=["vol-001"],
            eip_allocation_ids=["eipalloc-001"],
        )
        assert len(associated.security_group_ids) == 2
        assert associated.key_pair_name == "packer_key"


class TestCleanupEngineInit:
    """Tests for CleanupEngine initialization."""

    def test_init_defaults(self):
        """Test initialization with defaults."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2)
        assert engine.dry_run is False
        assert engine.batch_delete_size == 1

    def test_init_dry_run(self):
        """Test initialization with dry_run=True."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=True)
        assert engine.dry_run is True

    def test_init_with_iam_client(self):
        """Test initialization with IAM client."""
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, iam_client=mock_iam)
        assert engine.iam_manager is not None

    def test_init_without_iam_client(self):
        """Test initialization without IAM client."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, iam_client=None)
        assert engine.iam_manager is None

    def test_init_batch_size(self):
        """Test initialization with batch size."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, batch_delete_size=5)
        assert engine.batch_delete_size == 5

    def test_init_batch_size_minimum(self):
        """Test batch size is at least 1."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, batch_delete_size=0)
        assert engine.batch_delete_size == 1


class TestCleanupEngineCleanupResources:
    """Tests for CleanupEngine.cleanup_resources."""

    def test_cleanup_empty_resources(self):
        """Test cleanup with empty resources."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2)

        # Mock orphan manager
        engine.orphan_manager.scan_orphaned_resources = MagicMock(
            return_value=MagicMock(is_empty=lambda: True, total_count=lambda: 0)
        )
        engine.orphan_manager.cleanup_orphaned_resources = MagicMock(
            return_value=MagicMock(
                deleted_key_pairs=[],
                deleted_security_groups=[],
                deleted_iam_roles=[],
                deferred_resources=[],
                errors={},
            )
        )

        resources = ResourceCollection()
        result = engine.cleanup_resources(resources)
        assert result.total_cleaned() == 0

    def test_cleanup_dry_run(self):
        """Test cleanup in dry-run mode."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=True)

        # Mock orphan manager
        engine.orphan_manager.scan_orphaned_resources = MagicMock(
            return_value=MagicMock(is_empty=lambda: True, total_count=lambda: 0)
        )
        engine.orphan_manager.cleanup_orphaned_resources = MagicMock(
            return_value=MagicMock(
                deleted_key_pairs=[],
                deleted_security_groups=[],
                deleted_iam_roles=[],
                deferred_resources=[],
                errors={},
            )
        )

        resources = ResourceCollection(instances=[create_instance("i-001")])
        result = engine.cleanup_resources(resources)
        assert result.dry_run is True
        assert len(result.terminated_instances) == 1

    def test_cleanup_with_instances(self):
        """Test cleanup with instances."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

        # Mock managers
        engine.ec2_manager.terminate_instances = MagicMock(return_value=(["i-001"], [], {}))
        engine.ec2_manager.wait_for_termination = MagicMock()
        engine.orphan_manager.scan_orphaned_resources = MagicMock(
            return_value=MagicMock(is_empty=lambda: True, total_count=lambda: 0)
        )
        engine.orphan_manager.cleanup_orphaned_resources = MagicMock(
            return_value=MagicMock(
                deleted_key_pairs=[],
                deleted_security_groups=[],
                deleted_iam_roles=[],
                deferred_resources=[],
                errors={},
            )
        )

        resources = ResourceCollection(instances=[create_instance("i-001")])
        result = engine.cleanup_resources(resources)
        assert "i-001" in result.terminated_instances

    def test_cleanup_defers_shutting_down_instances(self):
        """Test cleanup defers shutting-down instances."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

        # Mock managers
        engine.ec2_manager.terminate_instances = MagicMock(return_value=([], [], {}))
        engine.orphan_manager.scan_orphaned_resources = MagicMock(
            return_value=MagicMock(is_empty=lambda: True, total_count=lambda: 0)
        )
        engine.orphan_manager.cleanup_orphaned_resources = MagicMock(
            return_value=MagicMock(
                deleted_key_pairs=[],
                deleted_security_groups=[],
                deleted_iam_roles=[],
                deferred_resources=[],
                errors={},
            )
        )

        resources = ResourceCollection(instances=[create_instance("i-001", state="shutting-down")])
        result = engine.cleanup_resources(resources)
        assert "i-001" in result.deferred_resources

    def test_cleanup_skips_terminated_instances(self):
        """Test cleanup skips already terminated instances."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=False)

        # Mock managers
        engine.ec2_manager.terminate_instances = MagicMock(return_value=([], [], {}))
        engine.orphan_manager.scan_orphaned_resources = MagicMock(
            return_value=MagicMock(is_empty=lambda: True, total_count=lambda: 0)
        )
        engine.orphan_manager.cleanup_orphaned_resources = MagicMock(
            return_value=MagicMock(
                deleted_key_pairs=[],
                deleted_security_groups=[],
                deleted_iam_roles=[],
                deferred_resources=[],
                errors={},
            )
        )

        resources = ResourceCollection(instances=[create_instance("i-001", state="terminated")])
        result = engine.cleanup_resources(resources)
        assert "i-001" in result.terminated_instances


class TestCleanupEngineShouldDeferInstance:
    """Tests for _should_defer_instance method."""

    def test_should_defer_shutting_down(self):
        """Test should defer shutting-down instance."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2)
        instance = create_instance("i-001", state="shutting-down")
        assert engine._should_defer_instance(instance) is True

    def test_should_not_defer_running(self):
        """Test should not defer running instance."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2)
        instance = create_instance("i-001", state="running")
        assert engine._should_defer_instance(instance) is False

    def test_should_not_defer_stopped(self):
        """Test should not defer stopped instance."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2)
        instance = create_instance("i-001", state="stopped")
        assert engine._should_defer_instance(instance) is False


class TestCleanupEngineCollectAssociatedResources:
    """Tests for collect_associated_resources method."""

    def test_collect_associated_resources(self):
        """Test collecting associated resources."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2)

        # Mock EC2 manager
        engine.ec2_manager.get_associated_resources = MagicMock(
            return_value={
                "volume_ids": ["vol-001"],
                "eip_allocation_ids": ["eipalloc-001"],
            }
        )

        instance = create_instance("i-001")
        associated = engine.collect_associated_resources(instance)

        assert associated.instance_id == "i-001"
        assert "sg-12345678" in associated.security_group_ids
        assert associated.key_pair_name == "packer_key"
        assert "vol-001" in associated.volume_ids
        assert "eipalloc-001" in associated.eip_allocation_ids


class TestCleanupEngineGetLastOrphanCleanupResult:
    """Tests for get_last_orphan_cleanup_result method."""

    def test_get_last_orphan_cleanup_result_none(self):
        """Test returns None when no cleanup has been done."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2)
        assert engine.get_last_orphan_cleanup_result() is None

    def test_get_last_orphan_cleanup_result_after_cleanup(self):
        """Test returns result after cleanup."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=True)

        # Mock orphan manager
        mock_orphan_result = MagicMock(
            deleted_key_pairs=["packer_key"],
            deleted_security_groups=[],
            deleted_iam_roles=[],
            deferred_resources=[],
            errors={},
        )
        engine.orphan_manager.scan_orphaned_resources = MagicMock(
            return_value=MagicMock(is_empty=lambda: True, total_count=lambda: 0)
        )
        engine.orphan_manager.cleanup_orphaned_resources = MagicMock(
            return_value=mock_orphan_result
        )

        resources = ResourceCollection()
        engine.cleanup_resources(resources)

        result = engine.get_last_orphan_cleanup_result()
        assert result is not None


class TestCleanupEngineGetLastDryRunReport:
    """Tests for get_last_dry_run_report method."""

    def test_get_last_dry_run_report_none(self):
        """Test returns None when no dry run has been done."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2)
        assert engine.get_last_dry_run_report() is None

    def test_get_last_dry_run_report_after_dry_run(self):
        """Test returns report after dry run."""
        mock_ec2 = MagicMock()
        engine = CleanupEngine(ec2_client=mock_ec2, dry_run=True)

        # Mock orphan manager
        engine.orphan_manager.scan_orphaned_resources = MagicMock(
            return_value=MagicMock(is_empty=lambda: True, total_count=lambda: 0)
        )
        engine.orphan_manager.cleanup_orphaned_resources = MagicMock(
            return_value=MagicMock(
                deleted_key_pairs=[],
                deleted_security_groups=[],
                deleted_iam_roles=[],
                deferred_resources=[],
                errors={},
            )
        )

        resources = ResourceCollection(instances=[create_instance("i-001")])
        engine.cleanup_resources(resources)

        report = engine.get_last_dry_run_report()
        assert report is not None
