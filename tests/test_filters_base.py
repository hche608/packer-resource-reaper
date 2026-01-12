"""Tests for base filter interface.

Tests for the abstract ResourceFilter base class.
"""

from datetime import UTC, datetime

import pytest

from reaper.filters.base import ResourceFilter
from reaper.models import (
    PackerElasticIP,
    PackerInstance,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerSnapshot,
    PackerVolume,
    ResourceType,
)


class ConcreteFilter(ResourceFilter):
    """Concrete implementation of ResourceFilter for testing."""

    def filter_instances(self, instances: list[PackerInstance]) -> list[PackerInstance]:
        """Return all instances."""
        return instances

    def filter_volumes(self, volumes: list[PackerVolume]) -> list[PackerVolume]:
        """Return all volumes."""
        return volumes

    def filter_snapshots(self, snapshots: list[PackerSnapshot]) -> list[PackerSnapshot]:
        """Return all snapshots."""
        return snapshots

    def filter_security_groups(
        self, security_groups: list[PackerSecurityGroup]
    ) -> list[PackerSecurityGroup]:
        """Return all security groups."""
        return security_groups

    def filter_key_pairs(self, key_pairs: list[PackerKeyPair]) -> list[PackerKeyPair]:
        """Return all key pairs."""
        return key_pairs

    def filter_elastic_ips(self, elastic_ips: list[PackerElasticIP]) -> list[PackerElasticIP]:
        """Return all elastic IPs."""
        return elastic_ips


class TestResourceFilterInterface:
    """Tests for ResourceFilter abstract interface."""

    def test_filter_instances(self):
        """Test filter_instances method."""
        filter_impl = ConcreteFilter()
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
            key_name="test",
            launch_time=datetime.now(UTC),
        )

        result = filter_impl.filter_instances([instance])

        assert len(result) == 1
        assert result[0].resource_id == "i-001"

    def test_filter_volumes(self):
        """Test filter_volumes method."""
        filter_impl = ConcreteFilter()
        volume = PackerVolume(
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

        result = filter_impl.filter_volumes([volume])

        assert len(result) == 1
        assert result[0].resource_id == "vol-001"

    def test_filter_snapshots(self):
        """Test filter_snapshots method."""
        filter_impl = ConcreteFilter()
        snapshot = PackerSnapshot(
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

        result = filter_impl.filter_snapshots([snapshot])

        assert len(result) == 1
        assert result[0].resource_id == "snap-001"

    def test_filter_security_groups(self):
        """Test filter_security_groups method."""
        filter_impl = ConcreteFilter()
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

        result = filter_impl.filter_security_groups([sg])

        assert len(result) == 1
        assert result[0].resource_id == "sg-001"

    def test_filter_key_pairs(self):
        """Test filter_key_pairs method."""
        filter_impl = ConcreteFilter()
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

        result = filter_impl.filter_key_pairs([kp])

        assert len(result) == 1
        assert result[0].key_name == "packer_key"

    def test_filter_elastic_ips(self):
        """Test filter_elastic_ips method."""
        filter_impl = ConcreteFilter()
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

        result = filter_impl.filter_elastic_ips([eip])

        assert len(result) == 1
        assert result[0].public_ip == "1.2.3.4"

    def test_filter_empty_lists(self):
        """Test filtering empty lists."""
        filter_impl = ConcreteFilter()

        assert filter_impl.filter_instances([]) == []
        assert filter_impl.filter_volumes([]) == []
        assert filter_impl.filter_snapshots([]) == []
        assert filter_impl.filter_security_groups([]) == []
        assert filter_impl.filter_key_pairs([]) == []
        assert filter_impl.filter_elastic_ips([]) == []


class TestResourceFilterAbstract:
    """Tests to verify ResourceFilter is abstract."""

    def test_cannot_instantiate_abstract_class(self):
        """Test that ResourceFilter cannot be instantiated directly."""
        with pytest.raises(TypeError):
            ResourceFilter()  # type: ignore
