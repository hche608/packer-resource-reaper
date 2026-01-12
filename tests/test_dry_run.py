"""Tests for dry-run execution module.

Tests for DryRunExecutor and DryRunReport.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from reaper.cleanup.dry_run import (
    DryRunExecutor,
    DryRunReport,
    is_dry_run_enabled,
    log_dry_run_planned_action,
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


def create_instance(instance_id: str, age_hours: float = 3.0) -> PackerInstance:
    """Create a PackerInstance for testing."""
    launch_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=launch_time,
        tags={"Name": "Test Instance"},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state="running",
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name="packer_key",
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
        key_fingerprint="ab:cd:ef:12:34:56",
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
        attached_instance="i-12345678",
        snapshot_id="snap-12345678",
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
        association_id="eipassoc-12345678",
        instance_id="i-12345678",
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


class TestDryRunReport:
    """Tests for DryRunReport dataclass."""

    def test_default_values(self):
        """Test default values."""
        report = DryRunReport()
        assert report.account_id == ""
        assert report.region == ""
        assert report.instances_to_terminate == []
        assert report.security_groups_to_delete == []

    def test_total_resources_empty(self):
        """Test total_resources returns 0 when empty."""
        report = DryRunReport()
        assert report.total_resources() == 0

    def test_total_resources_with_data(self):
        """Test total_resources returns correct count."""
        report = DryRunReport(
            instances_to_terminate=[{"instance_id": "i-001"}],
            security_groups_to_delete=[{"group_id": "sg-001"}],
            key_pairs_to_delete=[{"key_name": "packer_key"}],
            volumes_to_delete=[{"volume_id": "vol-001"}],
            snapshots_to_delete=[{"snapshot_id": "snap-001"}],
            elastic_ips_to_release=[{"allocation_id": "eipalloc-001"}],
            instance_profiles_to_delete=[{"profile_name": "packer_profile"}],
        )
        assert report.total_resources() == 7

    def test_to_dict(self):
        """Test to_dict serialization."""
        report = DryRunReport(
            account_id="123456789012",
            region="us-east-1",
            instances_to_terminate=[{"instance_id": "i-001"}],
        )
        result = report.to_dict()
        assert result["account_id"] == "123456789012"
        assert result["region"] == "us-east-1"
        assert result["total_resources"] == 1
        assert len(result["instances_to_terminate"]) == 1


class TestDryRunExecutor:
    """Tests for DryRunExecutor class."""

    def test_init(self):
        """Test initialization."""
        executor = DryRunExecutor(account_id="123456789012", region="us-east-1")
        assert executor.account_id == "123456789012"
        assert executor.region == "us-east-1"

    def test_execute_dry_run_empty_resources(self):
        """Test dry run with empty resources."""
        executor = DryRunExecutor()
        resources = ResourceCollection()
        result, report = executor.execute_dry_run(resources)
        assert result.dry_run is True
        assert report.total_resources() == 0

    def test_execute_dry_run_with_instances(self):
        """Test dry run with instances."""
        executor = DryRunExecutor(account_id="123456789012", region="us-east-1")
        resources = ResourceCollection(
            instances=[create_instance("i-001"), create_instance("i-002")]
        )
        result, report = executor.execute_dry_run(resources)
        assert result.dry_run is True
        assert len(result.terminated_instances) == 2
        assert len(report.instances_to_terminate) == 2

    def test_execute_dry_run_with_security_groups(self):
        """Test dry run with security groups."""
        executor = DryRunExecutor()
        resources = ResourceCollection(security_groups=[create_security_group("sg-001")])
        result, report = executor.execute_dry_run(resources)
        assert len(result.deleted_security_groups) == 1
        assert len(report.security_groups_to_delete) == 1

    def test_execute_dry_run_with_key_pairs(self):
        """Test dry run with key pairs."""
        executor = DryRunExecutor()
        resources = ResourceCollection(key_pairs=[create_key_pair("packer_key1")])
        result, report = executor.execute_dry_run(resources)
        assert len(result.deleted_key_pairs) == 1
        assert len(report.key_pairs_to_delete) == 1

    def test_execute_dry_run_with_volumes(self):
        """Test dry run with volumes."""
        executor = DryRunExecutor()
        resources = ResourceCollection(volumes=[create_volume("vol-001")])
        result, report = executor.execute_dry_run(resources)
        assert len(result.deleted_volumes) == 1
        assert len(report.volumes_to_delete) == 1

    def test_execute_dry_run_with_snapshots(self):
        """Test dry run with snapshots."""
        executor = DryRunExecutor()
        resources = ResourceCollection(snapshots=[create_snapshot("snap-001")])
        result, report = executor.execute_dry_run(resources)
        assert len(result.deleted_snapshots) == 1
        assert len(report.snapshots_to_delete) == 1

    def test_execute_dry_run_with_elastic_ips(self):
        """Test dry run with elastic IPs."""
        executor = DryRunExecutor()
        resources = ResourceCollection(elastic_ips=[create_elastic_ip("eipalloc-001")])
        result, report = executor.execute_dry_run(resources)
        assert len(result.released_elastic_ips) == 1
        assert len(report.elastic_ips_to_release) == 1

    def test_execute_dry_run_with_instance_profiles(self):
        """Test dry run with instance profiles."""
        executor = DryRunExecutor()
        resources = ResourceCollection(
            instance_profiles=[create_instance_profile("packer_profile")]
        )
        result, report = executor.execute_dry_run(resources)
        assert len(result.deleted_instance_profiles) == 1
        assert len(report.instance_profiles_to_delete) == 1

    def test_execute_dry_run_all_resources(self):
        """Test dry run with all resource types."""
        executor = DryRunExecutor(account_id="123456789012", region="us-east-1")
        resources = ResourceCollection(
            instances=[create_instance("i-001")],
            security_groups=[create_security_group("sg-001")],
            key_pairs=[create_key_pair("packer_key")],
            volumes=[create_volume("vol-001")],
            snapshots=[create_snapshot("snap-001")],
            elastic_ips=[create_elastic_ip("eipalloc-001")],
            instance_profiles=[create_instance_profile("packer_profile")],
        )
        result, report = executor.execute_dry_run(resources)
        assert result.dry_run is True
        assert report.total_resources() == 7
        assert report.account_id == "123456789012"
        assert report.region == "us-east-1"


class TestIsDryRunEnabled:
    """Tests for is_dry_run_enabled function."""

    def test_dry_run_enabled(self):
        """Test when dry_run is True."""
        config = MagicMock()
        config.dry_run = True
        assert is_dry_run_enabled(config) is True

    def test_dry_run_disabled(self):
        """Test when dry_run is False."""
        config = MagicMock()
        config.dry_run = False
        assert is_dry_run_enabled(config) is False

    def test_dry_run_missing_attribute(self):
        """Test when dry_run attribute is missing."""
        config = MagicMock(spec=[])
        assert is_dry_run_enabled(config) is False


class TestLogDryRunPlannedAction:
    """Tests for log_dry_run_planned_action function."""

    @patch("reaper.cleanup.dry_run.logger")
    def test_log_basic_action(self, mock_logger):
        """Test logging basic action."""
        log_dry_run_planned_action("terminate", "instance", "i-001")
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "terminate" in call_args
        assert "instance" in call_args
        assert "i-001" in call_args

    @patch("reaper.cleanup.dry_run.logger")
    def test_log_action_with_details(self, mock_logger):
        """Test logging action with details."""
        log_dry_run_planned_action(
            "terminate",
            "instance",
            "i-001",
            details={"type": "t3.micro", "state": "running"},
        )
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "t3.micro" in call_args
        assert "running" in call_args

    @patch("reaper.cleanup.dry_run.logger")
    def test_log_action_with_none_details(self, mock_logger):
        """Test logging action with None values in details."""
        log_dry_run_planned_action(
            "delete",
            "volume",
            "vol-001",
            details={"attached": None, "size": 100},
        )
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "size=100" in call_args
        assert "attached" not in call_args
