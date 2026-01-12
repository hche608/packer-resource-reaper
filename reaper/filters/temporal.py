"""Temporal filter for age-based resource identification.

This module provides age-based filtering for Packer-related resources
using the MaxInstanceAge threshold as per Requirement 1.1.

The filter identifies instances that exceed the configured MaxInstanceAge
threshold based on their launch time.
"""

from datetime import UTC, datetime

from reaper.filters.base import ResourceFilter
from reaper.models import (
    PackerElasticIP,
    PackerInstance,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerSnapshot,
    PackerVolume,
)


class TemporalFilter(ResourceFilter):
    """Filter resources based on age threshold.

    This implements Requirement 1.1: mark instances as cleanup candidates
    when they exceed the configured MaxInstanceAge threshold.
    """

    def __init__(self, max_age_hours: int = 2):
        """
        Initialize temporal filter.

        Args:
            max_age_hours: Maximum age in hours before resource is considered
                          for cleanup (must be positive integer)
        """
        if max_age_hours <= 0:
            raise ValueError("max_age_hours must be a positive integer")
        self.max_age_hours = max_age_hours

    def get_age_hours(self, creation_time: datetime) -> float:
        """
        Calculate age in hours from creation time.

        Args:
            creation_time: The datetime when the resource was created

        Returns:
            Age in hours as a float
        """
        now = datetime.now(UTC)
        if creation_time.tzinfo is None:
            creation_time = creation_time.replace(tzinfo=UTC)
        delta = now - creation_time
        return delta.total_seconds() / 3600

    def exceeds_age_threshold(self, creation_time: datetime) -> bool:
        """
        Check if resource has exceeded the age threshold.

        This implements Requirement 1.1: identify resources that exceed
        the MaxInstanceAge threshold.

        Args:
            creation_time: The datetime when the resource was created

        Returns:
            True if age exceeds threshold, False otherwise
        """
        age_hours = self.get_age_hours(creation_time)
        return age_hours >= self.max_age_hours

    def filter_instances(self, instances: list[PackerInstance]) -> list[PackerInstance]:
        """
        Filter instances that exceed age threshold.

        Uses launch_time to determine instance age.
        """
        return [
            instance for instance in instances if self.exceeds_age_threshold(instance.launch_time)
        ]

    def filter_volumes(self, volumes: list[PackerVolume]) -> list[PackerVolume]:
        """Filter volumes that exceed age threshold."""
        return [volume for volume in volumes if self.exceeds_age_threshold(volume.creation_time)]

    def filter_snapshots(self, snapshots: list[PackerSnapshot]) -> list[PackerSnapshot]:
        """Filter snapshots that exceed age threshold."""
        return [
            snapshot for snapshot in snapshots if self.exceeds_age_threshold(snapshot.creation_time)
        ]

    def filter_security_groups(
        self, security_groups: list[PackerSecurityGroup]
    ) -> list[PackerSecurityGroup]:
        """Filter security groups that exceed age threshold."""
        return [sg for sg in security_groups if self.exceeds_age_threshold(sg.creation_time)]

    def filter_key_pairs(self, key_pairs: list[PackerKeyPair]) -> list[PackerKeyPair]:
        """Filter key pairs that exceed age threshold."""
        return [kp for kp in key_pairs if self.exceeds_age_threshold(kp.creation_time)]

    def filter_elastic_ips(self, elastic_ips: list[PackerElasticIP]) -> list[PackerElasticIP]:
        """Filter elastic IPs that exceed age threshold."""
        return [eip for eip in elastic_ips if self.exceeds_age_threshold(eip.creation_time)]
