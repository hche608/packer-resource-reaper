"""Comprehensive tests for filter modules.

Tests for base, identity, and temporal filters.
"""

from datetime import UTC, datetime, timedelta

import pytest

from reaper.filters.base import ResourceFilter
from reaper.filters.identity import IdentityFilter
from reaper.filters.temporal import TemporalFilter
from reaper.models import (
    PackerElasticIP,
    PackerInstance,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerSnapshot,
    PackerVolume,
    ResourceType,
)


def create_instance(
    instance_id: str,
    key_name: str = "packer_key",
    age_hours: float = 3.0,
) -> PackerInstance:
    """Create a PackerInstance for testing."""
    launch_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=launch_time,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state="running",
        vpc_id="vpc-12345678",
        security_groups=["sg-12345678"],
        key_name=key_name,
        launch_time=launch_time,
    )


def create_volume(volume_id: str, age_hours: float = 3.0) -> PackerVolume:
    """Create a PackerVolume for testing."""
    creation_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerVolume(
        resource_id=volume_id,
        resource_type=ResourceType.VOLUME,
        creation_time=creation_time,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        size=100,
        state="available",
        attached_instance=None,
        snapshot_id=None,
    )


def create_snapshot(snapshot_id: str, age_hours: float = 3.0) -> PackerSnapshot:
    """Create a PackerSnapshot for testing."""
    creation_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerSnapshot(
        resource_id=snapshot_id,
        resource_type=ResourceType.SNAPSHOT,
        creation_time=creation_time,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        volume_id="vol-12345678",
        state="completed",
        progress="100%",
        owner_id="123456789012",
    )


def create_security_group(
    sg_id: str, group_name: str = "packer_sg", age_hours: float = 3.0
) -> PackerSecurityGroup:
    """Create a PackerSecurityGroup for testing."""
    creation_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerSecurityGroup(
        resource_id=sg_id,
        resource_type=ResourceType.SECURITY_GROUP,
        creation_time=creation_time,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        group_name=group_name,
        vpc_id="vpc-12345678",
        description="Test SG",
    )


def create_key_pair(key_name: str, age_hours: float = 3.0) -> PackerKeyPair:
    """Create a PackerKeyPair for testing."""
    creation_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerKeyPair(
        resource_id=f"key-{key_name}",
        resource_type=ResourceType.KEY_PAIR,
        creation_time=creation_time,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        key_name=key_name,
        key_fingerprint="ab:cd:ef:12:34:56",
    )


def create_elastic_ip(allocation_id: str, age_hours: float = 3.0) -> PackerElasticIP:
    """Create a PackerElasticIP for testing."""
    creation_time = datetime.now(UTC) - timedelta(hours=age_hours)
    return PackerElasticIP(
        resource_id=allocation_id,
        resource_type=ResourceType.ELASTIC_IP,
        creation_time=creation_time,
        tags={},
        region="us-east-1",
        account_id="123456789012",
        public_ip="1.2.3.4",
        allocation_id=allocation_id,
        association_id=None,
        instance_id=None,
    )


class TestTemporalFilter:
    """Tests for TemporalFilter class."""

    def test_init_default(self):
        """Test default initialization."""
        filter = TemporalFilter()
        assert filter.max_age_hours == 2

    def test_init_custom_age(self):
        """Test initialization with custom age."""
        filter = TemporalFilter(max_age_hours=5)
        assert filter.max_age_hours == 5

    def test_init_invalid_age_zero(self):
        """Test initialization with zero age raises error."""
        with pytest.raises(ValueError, match="positive integer"):
            TemporalFilter(max_age_hours=0)

    def test_init_invalid_age_negative(self):
        """Test initialization with negative age raises error."""
        with pytest.raises(ValueError, match="positive integer"):
            TemporalFilter(max_age_hours=-1)

    def test_get_age_hours(self):
        """Test calculating age in hours."""
        filter = TemporalFilter()
        creation_time = datetime.now(UTC) - timedelta(hours=5)
        age = filter.get_age_hours(creation_time)
        assert 4.9 < age < 5.1

    def test_get_age_hours_naive_datetime(self):
        """Test calculating age with naive datetime."""
        filter = TemporalFilter()
        # Use utcnow() for naive datetime to avoid timezone issues
        creation_time = datetime.utcnow() - timedelta(hours=3)
        age = filter.get_age_hours(creation_time)
        assert 2.9 < age < 3.1

    def test_exceeds_age_threshold_true(self):
        """Test exceeds_age_threshold returns True for old resources."""
        filter = TemporalFilter(max_age_hours=2)
        creation_time = datetime.now(UTC) - timedelta(hours=3)
        assert filter.exceeds_age_threshold(creation_time) is True

    def test_exceeds_age_threshold_false(self):
        """Test exceeds_age_threshold returns False for young resources."""
        filter = TemporalFilter(max_age_hours=2)
        creation_time = datetime.now(UTC) - timedelta(hours=1)
        assert filter.exceeds_age_threshold(creation_time) is False

    def test_exceeds_age_threshold_exact(self):
        """Test exceeds_age_threshold at exact threshold."""
        filter = TemporalFilter(max_age_hours=2)
        creation_time = datetime.now(UTC) - timedelta(hours=2)
        assert filter.exceeds_age_threshold(creation_time) is True

    def test_filter_instances(self):
        """Test filtering instances by age."""
        filter = TemporalFilter(max_age_hours=2)
        instances = [
            create_instance("i-001", age_hours=3),
            create_instance("i-002", age_hours=1),
            create_instance("i-003", age_hours=5),
        ]
        filtered = filter.filter_instances(instances)
        assert len(filtered) == 2
        assert filtered[0].resource_id == "i-001"
        assert filtered[1].resource_id == "i-003"

    def test_filter_volumes(self):
        """Test filtering volumes by age."""
        filter = TemporalFilter(max_age_hours=2)
        volumes = [
            create_volume("vol-001", age_hours=3),
            create_volume("vol-002", age_hours=1),
        ]
        filtered = filter.filter_volumes(volumes)
        assert len(filtered) == 1
        assert filtered[0].resource_id == "vol-001"

    def test_filter_snapshots(self):
        """Test filtering snapshots by age."""
        filter = TemporalFilter(max_age_hours=2)
        snapshots = [
            create_snapshot("snap-001", age_hours=3),
            create_snapshot("snap-002", age_hours=1),
        ]
        filtered = filter.filter_snapshots(snapshots)
        assert len(filtered) == 1
        assert filtered[0].resource_id == "snap-001"

    def test_filter_security_groups(self):
        """Test filtering security groups by age."""
        filter = TemporalFilter(max_age_hours=2)
        sgs = [
            create_security_group("sg-001", age_hours=3),
            create_security_group("sg-002", age_hours=1),
        ]
        filtered = filter.filter_security_groups(sgs)
        assert len(filtered) == 1
        assert filtered[0].resource_id == "sg-001"

    def test_filter_key_pairs(self):
        """Test filtering key pairs by age."""
        filter = TemporalFilter(max_age_hours=2)
        kps = [
            create_key_pair("packer_key1", age_hours=3),
            create_key_pair("packer_key2", age_hours=1),
        ]
        filtered = filter.filter_key_pairs(kps)
        assert len(filtered) == 1
        assert filtered[0].key_name == "packer_key1"

    def test_filter_elastic_ips(self):
        """Test filtering elastic IPs by age."""
        filter = TemporalFilter(max_age_hours=2)
        eips = [
            create_elastic_ip("eipalloc-001", age_hours=3),
            create_elastic_ip("eipalloc-002", age_hours=1),
        ]
        filtered = filter.filter_elastic_ips(eips)
        assert len(filtered) == 1
        assert filtered[0].allocation_id == "eipalloc-001"


class TestIdentityFilter:
    """Tests for IdentityFilter class."""

    def test_init_default(self):
        """Test default initialization."""
        filter = IdentityFilter()
        assert filter.key_pattern == "packer_"

    def test_init_custom_pattern(self):
        """Test initialization with custom pattern."""
        filter = IdentityFilter(key_pattern="custom_")
        assert filter.key_pattern == "custom_"

    def test_matches_key_pattern_true(self):
        """Test matches_key_pattern returns True for matching key."""
        filter = IdentityFilter()
        assert filter.matches_key_pattern("packer_12345678") is True

    def test_matches_key_pattern_false(self):
        """Test matches_key_pattern returns False for non-matching key."""
        filter = IdentityFilter()
        assert filter.matches_key_pattern("production_key") is False

    def test_matches_key_pattern_empty(self):
        """Test matches_key_pattern returns False for empty key."""
        filter = IdentityFilter()
        assert filter.matches_key_pattern("") is False

    def test_matches_key_pattern_none(self):
        """Test matches_key_pattern returns False for None key."""
        filter = IdentityFilter()
        assert filter.matches_key_pattern(None) is False

    def test_filter_instances(self):
        """Test filtering instances by key pattern."""
        filter = IdentityFilter()
        instances = [
            create_instance("i-001", key_name="packer_key1"),
            create_instance("i-002", key_name="production_key"),
            create_instance("i-003", key_name="packer_key2"),
        ]
        filtered = filter.filter_instances(instances)
        assert len(filtered) == 2
        assert filtered[0].resource_id == "i-001"
        assert filtered[1].resource_id == "i-003"

    def test_filter_instances_no_key(self):
        """Test filtering instances without key name."""
        filter = IdentityFilter()
        instances = [
            create_instance("i-001", key_name=None),
        ]
        filtered = filter.filter_instances(instances)
        assert len(filtered) == 0

    def test_filter_volumes_passthrough(self):
        """Test volumes pass through identity filter."""
        filter = IdentityFilter()
        volumes = [create_volume("vol-001"), create_volume("vol-002")]
        filtered = filter.filter_volumes(volumes)
        assert len(filtered) == 2

    def test_filter_snapshots_passthrough(self):
        """Test snapshots pass through identity filter."""
        filter = IdentityFilter()
        snapshots = [create_snapshot("snap-001"), create_snapshot("snap-002")]
        filtered = filter.filter_snapshots(snapshots)
        assert len(filtered) == 2

    def test_filter_security_groups(self):
        """Test filtering security groups by name pattern."""
        filter = IdentityFilter()
        sgs = [
            create_security_group("sg-001", group_name="packer_sg1"),
            create_security_group("sg-002", group_name="production_sg"),
            create_security_group("sg-003", group_name="packer_sg2"),
        ]
        filtered = filter.filter_security_groups(sgs)
        assert len(filtered) == 2

    def test_filter_key_pairs(self):
        """Test filtering key pairs by name pattern."""
        filter = IdentityFilter()
        kps = [
            create_key_pair("packer_key1"),
            create_key_pair("production_key"),
            create_key_pair("packer_key2"),
        ]
        filtered = filter.filter_key_pairs(kps)
        assert len(filtered) == 2

    def test_filter_elastic_ips_passthrough(self):
        """Test elastic IPs pass through identity filter."""
        filter = IdentityFilter()
        eips = [create_elastic_ip("eipalloc-001"), create_elastic_ip("eipalloc-002")]
        filtered = filter.filter_elastic_ips(eips)
        assert len(filtered) == 2

    def test_custom_pattern(self):
        """Test filtering with custom pattern."""
        filter = IdentityFilter(key_pattern="custom_")
        instances = [
            create_instance("i-001", key_name="custom_key1"),
            create_instance("i-002", key_name="packer_key"),
        ]
        filtered = filter.filter_instances(instances)
        assert len(filtered) == 1
        assert filtered[0].resource_id == "i-001"


class TestResourceFilterAbstract:
    """Tests for ResourceFilter abstract base class."""

    def test_cannot_instantiate_abstract(self):
        """Test that ResourceFilter cannot be instantiated directly."""
        with pytest.raises(TypeError):
            ResourceFilter()

    def test_concrete_implementation(self):
        """Test that concrete implementations work."""
        # TemporalFilter and IdentityFilter are concrete implementations
        temporal = TemporalFilter()
        identity = IdentityFilter()
        assert isinstance(temporal, ResourceFilter)
        assert isinstance(identity, ResourceFilter)
