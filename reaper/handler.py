"""Lambda handler for AWS Packer Resource Reaper.

This module implements the main Lambda entry point that orchestrates all components
for the Packer Resource Reaper. It follows a stateless execution model where each
invocation performs a fresh scan of resources.

Key Design Principles:
- Single Account/Region Scope: Operates strictly within the deployed AWS account
  and region using default Lambda execution environment credentials (Requirements 8.1-8.6)
- Stateless Execution: Each execution performs a fresh scan without relying on
  previous execution state (Requirements 3.1-3.4)
- Two-Criteria Filtering: Instances must match both key pair pattern (packer_*)
  AND age threshold to be selected for cleanup (Requirements 1.1-1.3)

Requirements Implemented:
- 1.1-1.3: Two-criteria filtering (key pair pattern + age threshold)
- 3.1-3.4: Stateless execution with fresh scan each run
- 5.4: Lambda entry point with default credentials
- 8.1-8.6: Single account/region boundary enforcement
"""

import logging
from datetime import UTC, datetime
from typing import Any

from reaper.cleanup.engine import CleanupEngine
from reaper.filters.identity import IdentityFilter
from reaper.filters.temporal import TemporalFilter
from reaper.models import (
    PackerElasticIP,
    PackerInstance,
    PackerKeyPair,
    PackerSecurityGroup,
    PackerVolume,
    ResourceCollection,
    ResourceType,
)
from reaper.notifications.sns_notifier import SNSNotifier
from reaper.utils.aws_client import AWSClientManager
from reaper.utils.config import ReaperConfig, configure_logging
from reaper.utils.security import (
    InputValidator,
    LogSanitizer,
    ScopeEnforcer,
)

# Configure logging - will be reconfigured with proper level in handler
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Lambda entry point for Packer Resource Reaper.

    This function orchestrates all components to identify and clean up
    zombie Packer resources. It operates strictly within the current
    AWS account and region using default Lambda execution environment
    credentials (Requirements 5.4, 8.5).

    The execution is completely stateless - each invocation performs
    a fresh scan of resources without relying on previous execution
    state (Requirements 3.1-3.4).

    Args:
        event: Lambda event (from EventBridge scheduler)
        context: Lambda context object

    Returns:
        Execution result summary with status code and details
    """
    # Load and validate configuration from environment variables
    config = ReaperConfig.from_environment(validate=False)

    # Configure logging based on LOG_LEVEL (Requirements 11.1, 11.2, 11.5)
    configure_logging(config)

    logger.info("Starting Packer Resource Reaper execution")
    logger.debug(
        f"Configuration: max_age={config.max_instance_age_hours}h, "
        f"dry_run={config.dry_run}, log_level={config.log_level}"
    )

    errors = config.validate()
    if errors:
        logger.error(f"Configuration errors: {LogSanitizer.sanitize(str(errors))}")
        return {"statusCode": 400, "body": {"errors": errors}}

    # Validate configuration inputs for security
    security_errors = validate_config_security(config)
    if security_errors:
        logger.error(f"Security validation errors: {LogSanitizer.sanitize(str(security_errors))}")
        return {"statusCode": 400, "body": {"errors": security_errors}}

    # Initialize AWS client manager using default Lambda credentials
    # This ensures single account/region scope (Requirements 8.5, 8.6)
    client_manager = AWSClientManager(region=config.region)
    account_id = client_manager.get_account_id()

    # Validate account ID format
    account_validation = InputValidator.validate_account_id(account_id)
    if not account_validation.is_valid:
        logger.error(f"Invalid account ID: {account_validation.errors}")
        return {"statusCode": 400, "body": {"errors": account_validation.errors}}

    logger.info(f"Executing reaper for account {account_id} in region {config.region}")

    # Execute reaper for the current account only (no cross-account support)
    # This implements Requirements 8.1-8.4
    result = execute_reaper(config, client_manager, account_id)

    return {
        "statusCode": 200,
        "body": {
            "account_id": account_id,
            "region": config.region,
            "result": result,
        },
    }


def validate_config_security(config: ReaperConfig) -> list[str]:
    """
    Validate configuration for security concerns.

    Args:
        config: Reaper configuration

    Returns:
        List of security validation errors
    """
    errors = []

    # Validate region
    region_result = InputValidator.validate_region(config.region)
    if not region_result.is_valid:
        errors.extend(region_result.errors)

    # Validate SNS topic ARN if provided
    if config.notification_topic_arn:
        arn_result = InputValidator.validate_arn(config.notification_topic_arn)
        if not arn_result.is_valid:
            errors.extend(arn_result.errors)

    return errors


def execute_reaper(
    config: ReaperConfig,
    client_manager: AWSClientManager,
    account_id: str,
) -> dict[str, Any]:
    """
    Execute reaper for the current account.

    This function implements the core reaper workflow:
    1. Scan all instances in the account/region
    2. Apply two-criteria filtering (key pair pattern + age threshold)
    3. Collect associated resources for matching instances
    4. Execute cleanup in dependency-aware order
    5. Send notifications via SNS

    The execution is stateless - each run performs a fresh scan
    (Requirements 3.1-3.4).

    Args:
        config: Reaper configuration
        client_manager: AWS client manager
        account_id: AWS account ID

    Returns:
        Execution result summary
    """
    logger.info(f"Executing reaper for account {account_id}")

    # Initialize filters for two-criteria selection (Requirements 1.1, 1.2, 1.3)
    temporal_filter = TemporalFilter(max_age_hours=config.max_instance_age_hours)
    identity_filter = IdentityFilter(key_pattern=config.key_pair_pattern)

    # Scan instances - fresh scan each execution (Requirement 3.1)
    instances = scan_instances(client_manager.ec2, account_id, config.region)

    # Apply two-criteria filtering (Requirement 1.3)
    # Instances must match BOTH key pair pattern AND age threshold
    filtered_instances = apply_two_criteria_filter(instances, temporal_filter, identity_filter)

    logger.info(f"Found {len(filtered_instances)} instances matching cleanup criteria")

    # Build resource collection with associated resources
    resources = build_resource_collection(
        filtered_instances, client_manager.ec2, account_id, config.region
    )

    # Log resource IDs for audit trail (Requirement 4.2)
    _log_filtered_resources(resources)

    # Initialize cleanup engine
    # Note: No state tracker - system is completely stateless (Requirements 3.2, 3.4)
    cleanup_engine = CleanupEngine(
        ec2_client=client_manager.ec2,
        dry_run=config.dry_run,
        account_id=account_id,
        region=config.region,
        iam_client=client_manager.iam if hasattr(client_manager, "iam") else None,
    )

    # Execute cleanup in dependency-aware order
    result = cleanup_engine.cleanup_resources(resources)

    # Get orphan cleanup result for notifications (Requirement 10.10)
    orphan_result = cleanup_engine.get_last_orphan_cleanup_result()

    # Send notifications (Requirement 4.4, 10.10)
    if config.notification_topic_arn:
        notifier = SNSNotifier(
            sns_client=client_manager.sns,
            topic_arn=config.notification_topic_arn,
            region=config.region,
        )

        if config.dry_run:
            notifier.send_dry_run_report(resources, account_id, orphan_result)
        else:
            notifier.send_cleanup_notification(result, resources, account_id, orphan_result)

    return {
        "dry_run": config.dry_run,
        "resources_found": resources.total_count(),
        "resources_cleaned": result.total_cleaned(),
        "resources_deferred": len(result.deferred_resources),
        "errors": len(result.errors),
    }


def _log_filtered_resources(resources: ResourceCollection) -> None:
    """
    Log filtered resources for audit trail.

    This implements Requirement 4.2: log all scanned resources and actions.
    """
    if resources.instances:
        instance_ids = [i.resource_id for i in resources.instances]
        logger.info(f"Instances to process: {instance_ids}")

    if resources.security_groups:
        sg_ids = [sg.resource_id for sg in resources.security_groups]
        logger.info(f"Security groups to process: {sg_ids}")

    if resources.key_pairs:
        kp_names = [kp.key_name for kp in resources.key_pairs]
        logger.info(f"Key pairs to process: {kp_names}")

    if resources.volumes:
        vol_ids = [v.resource_id for v in resources.volumes]
        logger.info(f"Volumes to process: {vol_ids}")

    if resources.elastic_ips:
        eip_ids = [eip.allocation_id for eip in resources.elastic_ips]
        logger.info(f"Elastic IPs to process: {eip_ids}")


def scan_instances(ec2: Any, account_id: str, region: str) -> list[PackerInstance]:
    """
    Scan EC2 instances in the account.

    This implements Requirement 3.1: perform a fresh scan of resources
    without relying on previous execution state.
    """
    instances = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    # Skip terminated instances
                    state = instance["State"]["Name"]
                    if state == "terminated":
                        continue

                    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}

                    instances.append(
                        PackerInstance(
                            resource_id=instance["InstanceId"],
                            resource_type=ResourceType.INSTANCE,
                            creation_time=instance["LaunchTime"],
                            tags=tags,
                            region=region,
                            account_id=account_id,
                            instance_type=instance["InstanceType"],
                            state=state,
                            vpc_id=instance.get("VpcId", ""),
                            security_groups=[
                                sg["GroupId"] for sg in instance.get("SecurityGroups", [])
                            ],
                            key_name=instance.get("KeyName"),
                            launch_time=instance["LaunchTime"],
                        )
                    )
    except Exception as e:
        logger.error(f"Error scanning instances: {LogSanitizer.sanitize(str(e))}")

    logger.info(f"Scanned {len(instances)} instances")
    return instances


def apply_two_criteria_filter(
    instances: list[PackerInstance],
    temporal_filter: TemporalFilter,
    identity_filter: IdentityFilter,
) -> list[PackerInstance]:
    """
    Apply two-criteria filtering to instances.

    This implements Requirement 1.3: only target instances that match BOTH
    criteria (key pair pattern AND age threshold).

    Args:
        instances: List of instances to filter
        temporal_filter: Age-based filter (Requirement 1.1)
        identity_filter: Key pair pattern filter (Requirement 1.2)

    Returns:
        List of instances matching both criteria
    """
    # Get instances matching age threshold
    temporal_matches = set(i.resource_id for i in temporal_filter.filter_instances(instances))

    # Get instances matching key pair pattern
    identity_matches = set(i.resource_id for i in identity_filter.filter_instances(instances))

    # Return instances matching BOTH criteria
    matching_ids = temporal_matches & identity_matches
    filtered = [i for i in instances if i.resource_id in matching_ids]

    logger.info(
        f"Two-criteria filter: {len(temporal_matches)} age matches, "
        f"{len(identity_matches)} key pattern matches, "
        f"{len(filtered)} matching both"
    )

    return filtered


def build_resource_collection(
    instances: list[PackerInstance],
    ec2: Any,
    account_id: str,
    region: str,
) -> ResourceCollection:
    """
    Build resource collection with associated resources for cleanup.

    This implements Requirement 2.2: collect directly associated resources
    (key pair, security group, attached EBS volumes, associated EIP)
    before termination.

    Args:
        instances: List of filtered instances
        ec2: EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        ResourceCollection with instances and their associated resources
    """
    resources = ResourceCollection()
    resources.instances = instances

    # Collect associated resources for each instance
    collected_sg_ids = set()
    collected_key_names = set()
    collected_volume_ids = set()
    collected_eip_ids = set()

    for instance in instances:
        # Collect security groups
        for sg_id in instance.security_groups:
            collected_sg_ids.add(sg_id)

        # Collect key pair
        if instance.key_name:
            collected_key_names.add(instance.key_name)

        # Collect attached volumes
        try:
            response = ec2.describe_volumes(
                Filters=[{"Name": "attachment.instance-id", "Values": [instance.resource_id]}]
            )
            for volume in response.get("Volumes", []):
                collected_volume_ids.add(volume["VolumeId"])
        except Exception as e:
            logger.warning(f"Error getting volumes for {instance.resource_id}: {e}")

        # Collect associated EIPs
        try:
            response = ec2.describe_addresses(
                Filters=[{"Name": "instance-id", "Values": [instance.resource_id]}]
            )
            for address in response.get("Addresses", []):
                if address.get("AllocationId"):
                    collected_eip_ids.add(address["AllocationId"])
        except Exception as e:
            logger.warning(f"Error getting EIPs for {instance.resource_id}: {e}")

    # Fetch full details for collected resources
    resources.security_groups = _fetch_security_groups(
        ec2, list(collected_sg_ids), account_id, region
    )
    resources.key_pairs = _fetch_key_pairs(ec2, list(collected_key_names), account_id, region)
    resources.volumes = _fetch_volumes(ec2, list(collected_volume_ids), account_id, region)
    resources.elastic_ips = _fetch_elastic_ips(ec2, list(collected_eip_ids), account_id, region)

    return resources


def _fetch_security_groups(
    ec2: Any, sg_ids: list[str], account_id: str, region: str
) -> list[PackerSecurityGroup]:
    """Fetch security group details."""
    if not sg_ids:
        return []

    security_groups = []
    try:
        response = ec2.describe_security_groups(GroupIds=sg_ids)
        for sg in response.get("SecurityGroups", []):
            # Skip default security groups
            if sg["GroupName"] == "default":
                continue

            tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
            security_groups.append(
                PackerSecurityGroup(
                    resource_id=sg["GroupId"],
                    resource_type=ResourceType.SECURITY_GROUP,
                    creation_time=datetime.now(UTC),
                    tags=tags,
                    region=region,
                    account_id=account_id,
                    group_name=sg["GroupName"],
                    vpc_id=sg.get("VpcId", ""),
                    description=sg.get("Description", ""),
                )
            )
    except Exception as e:
        logger.warning(f"Error fetching security groups: {e}")

    return security_groups


def _fetch_key_pairs(
    ec2: Any, key_names: list[str], account_id: str, region: str
) -> list[PackerKeyPair]:
    """Fetch key pair details."""
    if not key_names:
        return []

    key_pairs = []
    try:
        response = ec2.describe_key_pairs(KeyNames=key_names)
        for kp in response.get("KeyPairs", []):
            tags = {t["Key"]: t["Value"] for t in kp.get("Tags", [])}
            creation_time = kp.get("CreateTime", datetime.now(UTC))
            key_pairs.append(
                PackerKeyPair(
                    resource_id=kp.get("KeyPairId", kp["KeyName"]),
                    resource_type=ResourceType.KEY_PAIR,
                    creation_time=creation_time,
                    tags=tags,
                    region=region,
                    account_id=account_id,
                    key_name=kp["KeyName"],
                    key_fingerprint=kp.get("KeyFingerprint", ""),
                )
            )
    except Exception as e:
        logger.warning(f"Error fetching key pairs: {e}")

    return key_pairs


def _fetch_volumes(
    ec2: Any, volume_ids: list[str], account_id: str, region: str
) -> list[PackerVolume]:
    """Fetch volume details."""
    if not volume_ids:
        return []

    volumes = []
    try:
        response = ec2.describe_volumes(VolumeIds=volume_ids)
        for volume in response.get("Volumes", []):
            tags = {t["Key"]: t["Value"] for t in volume.get("Tags", [])}
            attachments = volume.get("Attachments", [])
            attached_instance = attachments[0]["InstanceId"] if attachments else None
            volumes.append(
                PackerVolume(
                    resource_id=volume["VolumeId"],
                    resource_type=ResourceType.VOLUME,
                    creation_time=volume["CreateTime"],
                    tags=tags,
                    region=region,
                    account_id=account_id,
                    size=volume["Size"],
                    state=volume["State"],
                    attached_instance=attached_instance,
                    snapshot_id=volume.get("SnapshotId"),
                )
            )
    except Exception as e:
        logger.warning(f"Error fetching volumes: {e}")

    return volumes


def _fetch_elastic_ips(
    ec2: Any, allocation_ids: list[str], account_id: str, region: str
) -> list[PackerElasticIP]:
    """Fetch elastic IP details."""
    if not allocation_ids:
        return []

    elastic_ips = []
    try:
        response = ec2.describe_addresses(AllocationIds=allocation_ids)
        for address in response.get("Addresses", []):
            tags = {t["Key"]: t["Value"] for t in address.get("Tags", [])}
            elastic_ips.append(
                PackerElasticIP(
                    resource_id=address.get("AllocationId", address["PublicIp"]),
                    resource_type=ResourceType.ELASTIC_IP,
                    creation_time=datetime.now(UTC),
                    tags=tags,
                    region=region,
                    account_id=account_id,
                    public_ip=address["PublicIp"],
                    allocation_id=address.get("AllocationId", ""),
                    association_id=address.get("AssociationId"),
                    instance_id=address.get("InstanceId"),
                )
            )
    except Exception as e:
        logger.warning(f"Error fetching elastic IPs: {e}")

    return elastic_ips


def enforce_scope(
    resources: ResourceCollection,
    scope_enforcer: ScopeEnforcer,
) -> ResourceCollection:
    """
    Filter resources to only include those within the allowed scope.

    This implements Requirements 8.1-8.6: single account/region boundary
    enforcement. Resources from other accounts or regions are filtered out.

    Args:
        resources: Collection of resources to filter
        scope_enforcer: ScopeEnforcer configured with allowed account/region

    Returns:
        ResourceCollection containing only in-scope resources
    """
    filtered = ResourceCollection()

    # Filter instances
    for instance in resources.instances:
        in_scope, _ = scope_enforcer.is_resource_in_scope(
            region=instance.region,
            account_id=instance.account_id,
        )
        if in_scope:
            filtered.instances.append(instance)

    # Filter security groups
    for sg in resources.security_groups:
        in_scope, _ = scope_enforcer.is_resource_in_scope(
            region=sg.region,
            account_id=sg.account_id,
        )
        if in_scope:
            filtered.security_groups.append(sg)

    # Filter key pairs
    for kp in resources.key_pairs:
        in_scope, _ = scope_enforcer.is_resource_in_scope(
            region=kp.region,
            account_id=kp.account_id,
        )
        if in_scope:
            filtered.key_pairs.append(kp)

    # Filter volumes
    for volume in resources.volumes:
        in_scope, _ = scope_enforcer.is_resource_in_scope(
            region=volume.region,
            account_id=volume.account_id,
        )
        if in_scope:
            filtered.volumes.append(volume)

    # Filter snapshots
    for snapshot in resources.snapshots:
        in_scope, _ = scope_enforcer.is_resource_in_scope(
            region=snapshot.region,
            account_id=snapshot.account_id,
        )
        if in_scope:
            filtered.snapshots.append(snapshot)

    # Filter elastic IPs
    for eip in resources.elastic_ips:
        in_scope, _ = scope_enforcer.is_resource_in_scope(
            region=eip.region,
            account_id=eip.account_id,
        )
        if in_scope:
            filtered.elastic_ips.append(eip)

    # Filter instance profiles
    for profile in resources.instance_profiles:
        in_scope, _ = scope_enforcer.is_resource_in_scope(
            region=profile.region,
            account_id=profile.account_id,
        )
        if in_scope:
            filtered.instance_profiles.append(profile)

    return filtered
