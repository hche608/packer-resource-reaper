"""Data models for AWS Packer Resource Reaper."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class ResourceType(Enum):
    """Types of AWS resources managed by the reaper."""

    INSTANCE = "instance"
    VOLUME = "volume"
    SNAPSHOT = "snapshot"
    SECURITY_GROUP = "security_group"
    KEY_PAIR = "key_pair"
    ELASTIC_IP = "elastic_ip"
    INSTANCE_PROFILE = "instance_profile"


@dataclass
class PackerResource:
    """Base class for all Packer-related resources."""

    resource_id: str
    resource_type: ResourceType
    creation_time: datetime
    tags: Dict[str, str]
    region: str
    account_id: str


@dataclass
class PackerInstance(PackerResource):
    """EC2 Instance with Packer metadata."""

    instance_type: str
    state: str
    vpc_id: str
    security_groups: List[str]
    key_name: Optional[str]
    launch_time: datetime

    def __post_init__(self):
        self.resource_type = ResourceType.INSTANCE


@dataclass
class PackerVolume(PackerResource):
    """EBS Volume with Packer metadata."""

    size: int
    state: str
    attached_instance: Optional[str]
    snapshot_id: Optional[str]

    def __post_init__(self):
        self.resource_type = ResourceType.VOLUME


@dataclass
class PackerSnapshot(PackerResource):
    """EBS Snapshot with Packer metadata."""

    volume_id: str
    state: str
    progress: str
    owner_id: str

    def __post_init__(self):
        self.resource_type = ResourceType.SNAPSHOT


@dataclass
class PackerSecurityGroup(PackerResource):
    """Security Group with Packer metadata."""

    group_name: str
    vpc_id: str
    description: str

    def __post_init__(self):
        self.resource_type = ResourceType.SECURITY_GROUP


@dataclass
class PackerKeyPair(PackerResource):
    """Key Pair with Packer metadata."""

    key_name: str
    key_fingerprint: str

    def __post_init__(self):
        self.resource_type = ResourceType.KEY_PAIR


@dataclass
class PackerElasticIP(PackerResource):
    """Elastic IP with Packer metadata."""

    public_ip: str
    allocation_id: str
    association_id: Optional[str]
    instance_id: Optional[str]

    def __post_init__(self):
        self.resource_type = ResourceType.ELASTIC_IP


@dataclass
class PackerInstanceProfile(PackerResource):
    """IAM Instance Profile with Packer metadata."""

    instance_profile_name: str
    instance_profile_id: str
    arn: str
    path: str
    roles: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.resource_type = ResourceType.INSTANCE_PROFILE


@dataclass
class ResourceCollection:
    """Collection of resources identified for cleanup."""

    instances: List[PackerInstance] = field(default_factory=list)
    volumes: List[PackerVolume] = field(default_factory=list)
    snapshots: List[PackerSnapshot] = field(default_factory=list)
    security_groups: List[PackerSecurityGroup] = field(default_factory=list)
    key_pairs: List[PackerKeyPair] = field(default_factory=list)
    elastic_ips: List[PackerElasticIP] = field(default_factory=list)
    instance_profiles: List["PackerInstanceProfile"] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Check if the collection has no resources."""
        return (
            len(self.instances) == 0
            and len(self.volumes) == 0
            and len(self.snapshots) == 0
            and len(self.security_groups) == 0
            and len(self.key_pairs) == 0
            and len(self.elastic_ips) == 0
            and len(self.instance_profiles) == 0
        )

    def total_count(self) -> int:
        """Get total number of resources in the collection."""
        return (
            len(self.instances)
            + len(self.volumes)
            + len(self.snapshots)
            + len(self.security_groups)
            + len(self.key_pairs)
            + len(self.elastic_ips)
            + len(self.instance_profiles)
        )


@dataclass
class CleanupResult:
    """Result of cleanup operations."""

    terminated_instances: List[str] = field(default_factory=list)
    deleted_volumes: List[str] = field(default_factory=list)
    deleted_snapshots: List[str] = field(default_factory=list)
    deleted_security_groups: List[str] = field(default_factory=list)
    deleted_key_pairs: List[str] = field(default_factory=list)
    released_elastic_ips: List[str] = field(default_factory=list)
    deleted_instance_profiles: List[str] = field(default_factory=list)
    deferred_resources: List[str] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)
    dry_run: bool = False

    def total_cleaned(self) -> int:
        """Get total number of resources cleaned up."""
        return (
            len(self.terminated_instances)
            + len(self.deleted_volumes)
            + len(self.deleted_snapshots)
            + len(self.deleted_security_groups)
            + len(self.deleted_key_pairs)
            + len(self.released_elastic_ips)
            + len(self.deleted_instance_profiles)
        )
