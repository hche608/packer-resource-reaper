"""Network resource management for security groups, key pairs, and EIPs.

This module provides network resource management functionality for the
Packer Resource Reaper. It handles security group cleanup with dependency
checking, key pair removal, and EIP release operations as per
Requirements 2.4, 2.6, 2.8.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from reaper.models import (
    PackerElasticIP,
    PackerKeyPair,
    PackerSecurityGroup,
    ResourceType,
)

logger = logging.getLogger(__name__)


class NetworkManager:
    """Manages network resource cleanup operations.

    Handles:
    - Security group cleanup with dependency checking (Requirement 2.4, 2.6)
    - Key pair removal functionality (Requirement 2.4)
    - EIP release operations (Requirement 2.4)
    - Only deletes resources directly associated with terminated instances (Requirement 2.8)
    """

    def __init__(self, ec2_client: Any, dry_run: bool = False):
        """
        Initialize network manager.

        Args:
            ec2_client: Boto3 EC2 client
            dry_run: If True, simulate operations without executing
        """
        self.ec2 = ec2_client
        self.dry_run = dry_run

    def get_security_groups_for_instance(
        self, security_group_ids: List[str], account_id: str, region: str
    ) -> List[PackerSecurityGroup]:
        """
        Get security groups by their IDs.

        This retrieves security groups that are directly associated with
        an instance for cleanup after termination (Requirement 2.8).

        Args:
            security_group_ids: List of security group IDs
            account_id: AWS account ID
            region: AWS region

        Returns:
            List of PackerSecurityGroup objects
        """
        if not security_group_ids:
            return []

        security_groups = []
        try:
            response = self.ec2.describe_security_groups(GroupIds=security_group_ids)
            for sg in response.get("SecurityGroups", []):
                # Skip default security groups
                if sg["GroupName"] == "default":
                    continue

                tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}

                security_groups.append(
                    PackerSecurityGroup(
                        resource_id=sg["GroupId"],
                        resource_type=ResourceType.SECURITY_GROUP,
                        creation_time=datetime.now(timezone.utc),
                        tags=tags,
                        region=region,
                        account_id=account_id,
                        group_name=sg["GroupName"],
                        vpc_id=sg.get("VpcId", ""),
                        description=sg.get("Description", ""),
                    )
                )
        except Exception as e:
            logger.error(f"Error getting security groups: {e}")

        return security_groups

    def scan_security_groups(
        self,
        account_id: str,
        region: str,
        filters: Optional[List[Dict[str, Any]]] = None,
    ) -> List[PackerSecurityGroup]:
        """
        Scan all security groups in the account.

        Args:
            account_id: AWS account ID
            region: AWS region
            filters: Optional list of EC2 filters

        Returns:
            List of PackerSecurityGroup objects
        """
        security_groups = []
        try:
            paginator = self.ec2.get_paginator("describe_security_groups")
            paginate_kwargs = {}
            if filters:
                paginate_kwargs["Filters"] = filters

            for page in paginator.paginate(**paginate_kwargs):
                for sg in page.get("SecurityGroups", []):
                    # Skip default security groups
                    if sg["GroupName"] == "default":
                        continue

                    tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}

                    security_groups.append(
                        PackerSecurityGroup(
                            resource_id=sg["GroupId"],
                            resource_type=ResourceType.SECURITY_GROUP,
                            creation_time=datetime.now(timezone.utc),
                            tags=tags,
                            region=region,
                            account_id=account_id,
                            group_name=sg["GroupName"],
                            vpc_id=sg.get("VpcId", ""),
                            description=sg.get("Description", ""),
                        )
                    )
        except Exception as e:
            logger.error(f"Error scanning security groups: {e}")

        logger.info(f"Scanned {len(security_groups)} security groups")
        return security_groups

    def get_key_pair_by_name(
        self, key_name: str, account_id: str, region: str
    ) -> Optional[PackerKeyPair]:
        """
        Get a key pair by its name.

        Args:
            key_name: Key pair name
            account_id: AWS account ID
            region: AWS region

        Returns:
            PackerKeyPair object or None if not found
        """
        if not key_name:
            return None

        try:
            response = self.ec2.describe_key_pairs(KeyNames=[key_name])
            key_pairs = response.get("KeyPairs", [])
            if key_pairs:
                kp = key_pairs[0]
                tags = {t["Key"]: t["Value"] for t in kp.get("Tags", [])}
                creation_time = kp.get("CreateTime", datetime.now(timezone.utc))

                return PackerKeyPair(
                    resource_id=kp.get("KeyPairId", kp["KeyName"]),
                    resource_type=ResourceType.KEY_PAIR,
                    creation_time=creation_time,
                    tags=tags,
                    region=region,
                    account_id=account_id,
                    key_name=kp["KeyName"],
                    key_fingerprint=kp.get("KeyFingerprint", ""),
                )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "InvalidKeyPair.NotFound":
                logger.debug(f"Key pair {key_name} not found")
            else:
                logger.error(f"Error getting key pair {key_name}: {e}")
        except Exception as e:
            logger.error(f"Error getting key pair {key_name}: {e}")

        return None

    def scan_key_pairs(self, account_id: str, region: str) -> List[PackerKeyPair]:
        """
        Scan all key pairs in the account.

        Args:
            account_id: AWS account ID
            region: AWS region

        Returns:
            List of PackerKeyPair objects
        """
        key_pairs = []
        try:
            response = self.ec2.describe_key_pairs()
            for kp in response.get("KeyPairs", []):
                tags = {t["Key"]: t["Value"] for t in kp.get("Tags", [])}
                creation_time = kp.get("CreateTime", datetime.now(timezone.utc))

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
            logger.error(f"Error scanning key pairs: {e}")

        logger.info(f"Scanned {len(key_pairs)} key pairs")
        return key_pairs

    def get_eips_for_instance(
        self, instance_id: str, account_id: str, region: str
    ) -> List[PackerElasticIP]:
        """
        Get Elastic IPs associated with a specific instance.

        Args:
            instance_id: EC2 instance ID
            account_id: AWS account ID
            region: AWS region

        Returns:
            List of PackerElasticIP objects
        """
        elastic_ips = []
        try:
            response = self.ec2.describe_addresses(
                Filters=[{"Name": "instance-id", "Values": [instance_id]}]
            )
            for address in response.get("Addresses", []):
                tags = {t["Key"]: t["Value"] for t in address.get("Tags", [])}

                elastic_ips.append(
                    PackerElasticIP(
                        resource_id=address.get("AllocationId", address["PublicIp"]),
                        resource_type=ResourceType.ELASTIC_IP,
                        creation_time=datetime.now(timezone.utc),
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
            logger.error(f"Error getting EIPs for instance {instance_id}: {e}")

        return elastic_ips

    def scan_elastic_ips(self, account_id: str, region: str) -> List[PackerElasticIP]:
        """
        Scan all Elastic IPs in the account.

        Args:
            account_id: AWS account ID
            region: AWS region

        Returns:
            List of PackerElasticIP objects
        """
        elastic_ips = []
        try:
            response = self.ec2.describe_addresses()
            for address in response.get("Addresses", []):
                tags = {t["Key"]: t["Value"] for t in address.get("Tags", [])}

                elastic_ips.append(
                    PackerElasticIP(
                        resource_id=address.get("AllocationId", address["PublicIp"]),
                        resource_type=ResourceType.ELASTIC_IP,
                        creation_time=datetime.now(timezone.utc),
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
            logger.error(f"Error scanning elastic IPs: {e}")

        logger.info(f"Scanned {len(elastic_ips)} elastic IPs")
        return elastic_ips

    def delete_security_groups(
        self, security_groups: List[PackerSecurityGroup]
    ) -> tuple[List[str], List[str], dict]:
        """
        Delete security groups.

        Args:
            security_groups: List of security groups to delete

        Returns:
            Tuple of (deleted_ids, deferred_ids, errors)
        """
        deleted = []
        deferred = []
        errors = {}

        for sg in security_groups:
            try:
                result = self._delete_security_group(sg)
                if result == "deleted":
                    deleted.append(sg.resource_id)
                elif result == "deferred":
                    deferred.append(sg.resource_id)
            except Exception as e:
                logger.error(f"Error deleting security group {sg.resource_id}: {e}")
                errors[sg.resource_id] = str(e)

        return deleted, deferred, errors

    def _delete_security_group(self, sg: PackerSecurityGroup) -> str:
        """
        Delete a single security group.

        Returns:
            "deleted" if successful, "deferred" if has dependencies
        """
        sg_id = sg.resource_id

        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete security group {sg_id}")
            return "deleted"

        try:
            logger.info(f"Deleting security group {sg_id} ({sg.group_name})")
            self.ec2.delete_security_group(GroupId=sg_id)
            return "deleted"
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "DependencyViolation":
                logger.info(f"Security group {sg_id} has dependencies, deferring")
                return "deferred"
            raise

    def delete_key_pairs(
        self, key_pairs: List[PackerKeyPair]
    ) -> tuple[List[str], List[str], dict]:
        """
        Delete key pairs.

        Args:
            key_pairs: List of key pairs to delete

        Returns:
            Tuple of (deleted_ids, deferred_ids, errors)
        """
        deleted = []
        deferred = []
        errors = {}

        for kp in key_pairs:
            try:
                result = self._delete_key_pair(kp)
                if result == "deleted":
                    deleted.append(kp.key_name)
                elif result == "deferred":
                    deferred.append(kp.key_name)
            except Exception as e:
                logger.error(f"Error deleting key pair {kp.key_name}: {e}")
                errors[kp.key_name] = str(e)

        return deleted, deferred, errors

    def _delete_key_pair(self, kp: PackerKeyPair) -> str:
        """
        Delete a single key pair.

        Returns:
            "deleted" if successful
        """
        key_name = kp.key_name

        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete key pair {key_name}")
            return "deleted"

        logger.info(f"Deleting key pair {key_name}")
        self.ec2.delete_key_pair(KeyName=key_name)
        return "deleted"

    def release_elastic_ips(
        self, elastic_ips: List[PackerElasticIP]
    ) -> tuple[List[str], List[str], dict]:
        """
        Release elastic IPs.

        Args:
            elastic_ips: List of elastic IPs to release

        Returns:
            Tuple of (released_ids, deferred_ids, errors)
        """
        released = []
        deferred = []
        errors = {}

        for eip in elastic_ips:
            try:
                result = self._release_elastic_ip(eip)
                if result == "released":
                    released.append(eip.allocation_id)
                elif result == "deferred":
                    deferred.append(eip.allocation_id)
            except Exception as e:
                logger.error(f"Error releasing EIP {eip.allocation_id}: {e}")
                errors[eip.allocation_id] = str(e)

        return released, deferred, errors

    def _release_elastic_ip(self, eip: PackerElasticIP) -> str:
        """
        Release a single elastic IP.

        Returns:
            "released" if successful, "deferred" if associated
        """
        allocation_id = eip.allocation_id

        # Check if EIP is associated with an instance
        if eip.association_id:
            logger.info(
                f"EIP {allocation_id} associated with {eip.instance_id}, deferring"
            )
            return "deferred"

        if self.dry_run:
            logger.info(f"[DRY RUN] Would release EIP {allocation_id}")
            return "released"

        logger.info(f"Releasing EIP {allocation_id} ({eip.public_ip})")
        self.ec2.release_address(AllocationId=allocation_id)
        return "released"
