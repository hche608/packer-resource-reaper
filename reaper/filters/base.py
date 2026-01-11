"""Base filter interface for resource filtering."""

from abc import ABC, abstractmethod
from typing import List

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
    def filter_instances(self, instances: List[PackerInstance]) -> List[PackerInstance]:
        """Filter EC2 instances based on specific criteria."""
        pass

    @abstractmethod
    def filter_volumes(self, volumes: List[PackerVolume]) -> List[PackerVolume]:
        """Filter EBS volumes based on specific criteria."""
        pass

    @abstractmethod
    def filter_snapshots(self, snapshots: List[PackerSnapshot]) -> List[PackerSnapshot]:
        """Filter EBS snapshots based on specific criteria."""
        pass

    @abstractmethod
    def filter_security_groups(
        self, security_groups: List[PackerSecurityGroup]
    ) -> List[PackerSecurityGroup]:
        """Filter security groups based on specific criteria."""
        pass

    @abstractmethod
    def filter_key_pairs(self, key_pairs: List[PackerKeyPair]) -> List[PackerKeyPair]:
        """Filter key pairs based on specific criteria."""
        pass

    @abstractmethod
    def filter_elastic_ips(
        self, elastic_ips: List[PackerElasticIP]
    ) -> List[PackerElasticIP]:
        """Filter elastic IPs based on specific criteria."""
        pass
