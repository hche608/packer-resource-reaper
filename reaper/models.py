"""Data models for AWS Packer Resource Reaper."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


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
    tags: dict[str, str]
    region: str
    account_id: str


@dataclass
class PackerInstance(PackerResource):
    """EC2 Instance with Packer metadata."""

    instance_type: str
    state: str
    vpc_id: str
    security_groups: list[str]
    key_name: str | None
    launch_time: datetime

    def __post_init__(self) -> None:
        self.resource_type = ResourceType.INSTANCE


@dataclass
class PackerVolume(PackerResource):
    """EBS Volume with Packer metadata."""

    size: int
    state: str
    attached_instance: str | None
    snapshot_id: str | None

    def __post_init__(self) -> None:
        self.resource_type = ResourceType.VOLUME


@dataclass
class PackerSnapshot(PackerResource):
    """EBS Snapshot with Packer metadata."""

    volume_id: str
    state: str
    progress: str
    owner_id: str

    def __post_init__(self) -> None:
        self.resource_type = ResourceType.SNAPSHOT


@dataclass
class PackerSecurityGroup(PackerResource):
    """Security Group with Packer metadata."""

    group_name: str
    vpc_id: str
    description: str

    def __post_init__(self) -> None:
        self.resource_type = ResourceType.SECURITY_GROUP


@dataclass
class PackerKeyPair(PackerResource):
    """Key Pair with Packer metadata."""

    key_name: str
    key_fingerprint: str

    def __post_init__(self) -> None:
        self.resource_type = ResourceType.KEY_PAIR


@dataclass
class PackerElasticIP(PackerResource):
    """Elastic IP with Packer metadata."""

    public_ip: str
    allocation_id: str
    association_id: str | None
    instance_id: str | None

    def __post_init__(self) -> None:
        self.resource_type = ResourceType.ELASTIC_IP


@dataclass
class PackerInstanceProfile(PackerResource):
    """IAM Instance Profile with Packer metadata."""

    instance_profile_name: str
    instance_profile_id: str
    arn: str
    path: str
    roles: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.resource_type = ResourceType.INSTANCE_PROFILE


@dataclass
class ResourceCollection:
    """Collection of resources identified for cleanup."""

    instances: list[PackerInstance] = field(default_factory=list)
    volumes: list[PackerVolume] = field(default_factory=list)
    snapshots: list[PackerSnapshot] = field(default_factory=list)
    security_groups: list[PackerSecurityGroup] = field(default_factory=list)
    key_pairs: list[PackerKeyPair] = field(default_factory=list)
    elastic_ips: list[PackerElasticIP] = field(default_factory=list)
    instance_profiles: list["PackerInstanceProfile"] = field(default_factory=list)

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

    terminated_instances: list[str] = field(default_factory=list)
    deleted_volumes: list[str] = field(default_factory=list)
    deleted_snapshots: list[str] = field(default_factory=list)
    deleted_security_groups: list[str] = field(default_factory=list)
    deleted_key_pairs: list[str] = field(default_factory=list)
    released_elastic_ips: list[str] = field(default_factory=list)
    deleted_instance_profiles: list[str] = field(default_factory=list)
    deferred_resources: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
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
