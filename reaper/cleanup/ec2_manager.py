"""EC2 instance management for cleanup operations.

This module provides EC2 instance scanning and termination functionality
for the Packer Resource Reaper. It handles various instance states including
hung and rebooting instances as per Requirements 2.1, 2.3, 2.5, 6.4.
"""

import logging
from typing import Any, Dict, List, Optional

from reaper.models import PackerInstance, ResourceType

logger = logging.getLogger(__name__)


class EC2Manager:
    """Manages EC2 instance scanning and termination operations.

    Handles:
    - Instance scanning with boto3 EC2 client (Requirement 2.1)
    - Instance termination with state verification (Requirement 2.3, 2.5)
    - Various instance states including hung and rebooting (Requirement 6.4)
    """

    # Instance states that indicate termination is in progress or complete
    TERMINAL_STATES = {"shutting-down", "terminated"}

    # Instance states that should be attempted for termination
    # Includes "rebooting" to handle hung instances (Requirement 6.4)
    TERMINABLE_STATES = {"pending", "running", "stopping", "stopped", "rebooting"}

    # All valid EC2 instance states
    ALL_STATES = TERMINAL_STATES | TERMINABLE_STATES

    def __init__(self, ec2_client: Any, dry_run: bool = False):
        """
        Initialize EC2 manager.

        Args:
            ec2_client: Boto3 EC2 client
            dry_run: If True, simulate operations without executing
        """
        self.ec2 = ec2_client
        self.dry_run = dry_run

    def scan_instances(
        self,
        account_id: str,
        region: str,
        filters: Optional[List[Dict[str, Any]]] = None,
    ) -> List[PackerInstance]:
        """
        Scan EC2 instances in the account.

        Args:
            account_id: AWS account ID
            region: AWS region
            filters: Optional list of EC2 filters

        Returns:
            List of PackerInstance objects
        """
        instances = []
        try:
            paginator = self.ec2.get_paginator("describe_instances")
            paginate_kwargs = {}
            if filters:
                paginate_kwargs["Filters"] = filters

            for page in paginator.paginate(**paginate_kwargs):
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
                                    sg["GroupId"]
                                    for sg in instance.get("SecurityGroups", [])
                                ],
                                key_name=instance.get("KeyName"),
                                launch_time=instance["LaunchTime"],
                            )
                        )
        except Exception as e:
            logger.error(f"Error scanning instances: {e}")

        logger.info(f"Scanned {len(instances)} instances")
        return instances

    def get_instance_details(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific instance.

        Args:
            instance_id: EC2 instance ID

        Returns:
            Instance details dict or None if not found
        """
        try:
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            reservations = response.get("Reservations", [])
            if reservations and reservations[0].get("Instances"):
                return reservations[0]["Instances"][0]
        except Exception as e:
            logger.error(f"Error getting details for instance {instance_id}: {e}")
        return None

    def get_associated_resources(self, instance: PackerInstance) -> Dict[str, Any]:
        """
        Get resources directly associated with an instance.

        This collects security groups, key pairs, volumes, and EIPs
        that are directly associated with the instance for cleanup
        after termination (Requirement 2.2).

        Args:
            instance: PackerInstance to get associated resources for

        Returns:
            Dict with associated resource IDs
        """
        associated = {
            "security_group_ids": list(instance.security_groups),
            "key_pair_name": instance.key_name,
            "volume_ids": [],
            "eip_allocation_ids": [],
        }

        # Get attached volumes
        try:
            response = self.ec2.describe_volumes(
                Filters=[
                    {"Name": "attachment.instance-id", "Values": [instance.resource_id]}
                ]
            )
            for volume in response.get("Volumes", []):
                associated["volume_ids"].append(volume["VolumeId"])
        except Exception as e:
            logger.warning(f"Error getting volumes for {instance.resource_id}: {e}")

        # Get associated EIPs
        try:
            response = self.ec2.describe_addresses(
                Filters=[{"Name": "instance-id", "Values": [instance.resource_id]}]
            )
            for address in response.get("Addresses", []):
                if address.get("AllocationId"):
                    associated["eip_allocation_ids"].append(address["AllocationId"])
        except Exception as e:
            logger.warning(f"Error getting EIPs for {instance.resource_id}: {e}")

        return associated

    def terminate_instances(
        self, instances: List[PackerInstance]
    ) -> tuple[List[str], List[str], dict]:
        """
        Terminate EC2 instances.

        Args:
            instances: List of instances to terminate

        Returns:
            Tuple of (terminated_ids, deferred_ids, errors)
        """
        terminated = []
        deferred = []
        errors = {}

        for instance in instances:
            try:
                result = self._terminate_instance(instance)
                if result == "terminated":
                    terminated.append(instance.resource_id)
                elif result == "deferred":
                    deferred.append(instance.resource_id)
            except Exception as e:
                logger.error(f"Error terminating instance {instance.resource_id}: {e}")
                errors[instance.resource_id] = str(e)

        return terminated, deferred, errors

    def _terminate_instance(self, instance: PackerInstance) -> str:
        """
        Terminate a single instance.

        Returns:
            "terminated" if successful, "deferred" if in transitional state
        """
        instance_id = instance.resource_id
        current_state = instance.state.lower()

        # Already terminated or terminating
        if current_state in self.TERMINAL_STATES:
            logger.info(f"Instance {instance_id} already in state: {current_state}")
            return "terminated" if current_state == "terminated" else "deferred"

        # Attempt termination for terminable states
        if current_state in self.TERMINABLE_STATES:
            if self.dry_run:
                logger.info(f"[DRY RUN] Would terminate instance {instance_id}")
                return "terminated"

            logger.info(f"Terminating instance {instance_id} (state: {current_state})")
            self.ec2.terminate_instances(InstanceIds=[instance_id])
            return "terminated"

        # Unknown state - log and defer
        logger.warning(f"Instance {instance_id} in unexpected state: {current_state}")
        return "deferred"

    def get_instance_state(self, instance_id: str) -> Optional[str]:
        """Get current state of an instance."""
        try:
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            reservations = response.get("Reservations", [])
            if reservations and reservations[0].get("Instances"):
                return reservations[0]["Instances"][0]["State"]["Name"]
        except Exception as e:
            logger.error(f"Error getting state for instance {instance_id}: {e}")
        return None

    def wait_for_termination(
        self, instance_ids: List[str], timeout_seconds: int = 300
    ) -> dict:
        """
        Wait for instances to reach terminated state.

        Args:
            instance_ids: List of instance IDs to wait for
            timeout_seconds: Maximum time to wait

        Returns:
            Dict mapping instance_id to final state
        """
        if self.dry_run or not instance_ids:
            return {iid: "terminated" for iid in instance_ids}

        try:
            waiter = self.ec2.get_waiter("instance_terminated")
            waiter.wait(
                InstanceIds=instance_ids,
                WaiterConfig={"Delay": 15, "MaxAttempts": timeout_seconds // 15},
            )
            return {iid: "terminated" for iid in instance_ids}
        except Exception as e:
            logger.warning(f"Timeout waiting for instance termination: {e}")
            # Return current states
            result = {}
            for iid in instance_ids:
                state = self.get_instance_state(iid)
                result[iid] = state or "unknown"
            return result
