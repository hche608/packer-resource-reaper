"""Base filter interface for resource filtering."""

from abc import ABC, abstractmethod

from reaper.models import (
    PackerElasticIP,
    PackerInstance,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerSnapshot,
    PackerVolume,
)


class ResourceFilter(ABC):
    """Abstract base class for resource filters."""

    @abstractmethod
    def filter_instances(self, instances: list[PackerInstance]) -> list[PackerInstance]:
        """Filter EC2 instances based on specific criteria."""
        raise NotImplementedError

    @abstractmethod
    def filter_volumes(self, volumes: list[PackerVolume]) -> list[PackerVolume]:
        """Filter EBS volumes based on specific criteria."""
        raise NotImplementedError

    @abstractmethod
    def filter_snapshots(self, snapshots: list[PackerSnapshot]) -> list[PackerSnapshot]:
        """Filter EBS snapshots based on specific criteria."""
        raise NotImplementedError

    @abstractmethod
    def filter_security_groups(
        self, security_groups: list[PackerSecurityGroup]
    ) -> list[PackerSecurityGroup]:
        """Filter security groups based on specific criteria."""
        raise NotImplementedError

    @abstractmethod
    def filter_key_pairs(self, key_pairs: list[PackerKeyPair]) -> list[PackerKeyPair]:
        """Filter key pairs based on specific criteria."""
        raise NotImplementedError

    @abstractmethod
    def filter_elastic_ips(self, elastic_ips: list[PackerElasticIP]) -> list[PackerElasticIP]:
        """Filter elastic IPs based on specific criteria."""
        raise NotImplementedError
