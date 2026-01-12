"""Tests for EC2 manager functionality.

Tests for instance scanning, termination, and associated resource collection.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

from reaper.cleanup.ec2_manager import EC2Manager
from reaper.models import PackerInstance, ResourceType


def create_packer_instance(
    instance_id: str,
    state: str = "running",
    key_name: str = "packer_key",
    vpc_id: str = "vpc-12345678",
    security_groups: list = None,
) -> PackerInstance:
    """Create a PackerInstance for testing."""
    return PackerInstance(
        resource_id=instance_id,
        resource_type=ResourceType.INSTANCE,
        creation_time=datetime.now(UTC),
        tags={"Name": "Packer Builder"},
        region="us-east-1",
        account_id="123456789012",
        instance_type="t3.micro",
        state=state,
        vpc_id=vpc_id,
        security_groups=security_groups or ["sg-12345678"],
        key_name=key_name,
        launch_time=datetime.now(UTC),
    )


def create_mock_instance_data(
    instance_id: str,
    state: str = "running",
    key_name: str = "packer_key",
) -> dict:
    """Create mock EC2 instance data."""
    return {
        "InstanceId": instance_id,
        "InstanceType": "t3.micro",
        "State": {"Name": state},
        "VpcId": "vpc-12345678",
        "SecurityGroups": [{"GroupId": "sg-12345678", "GroupName": "packer_sg"}],
        "KeyName": key_name,
        "LaunchTime": datetime.now(UTC),
        "Tags": [{"Key": "Name", "Value": "Packer Builder"}],
    }


class TestEC2ManagerScanInstances:
    """Tests for scan_instances method."""

    def test_scan_instances_success(self):
        """Test scanning instances successfully."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            create_mock_instance_data("i-001", "running"),
                            create_mock_instance_data("i-002", "stopped"),
                        ]
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = EC2Manager(mock_ec2)
        instances = manager.scan_instances("123456789012", "us-east-1")

        assert len(instances) == 2
        assert instances[0].resource_id == "i-001"
        assert instances[1].resource_id == "i-002"

    def test_scan_instances_skips_terminated(self):
        """Test scanning skips terminated instances."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            create_mock_instance_data("i-001", "running"),
                            create_mock_instance_data("i-002", "terminated"),
                        ]
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = EC2Manager(mock_ec2)
        instances = manager.scan_instances("123456789012", "us-east-1")

        assert len(instances) == 1
        assert instances[0].resource_id == "i-001"

    def test_scan_instances_with_filters(self):
        """Test scanning with filters."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Reservations": []}]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = EC2Manager(mock_ec2)
        filters = [{"Name": "instance-state-name", "Values": ["running"]}]
        manager.scan_instances("123456789012", "us-east-1", filters=filters)

        mock_paginator.paginate.assert_called_with(Filters=filters)

    def test_scan_instances_handles_exception(self):
        """Test scanning handles exceptions gracefully."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = EC2Manager(mock_ec2)
        instances = manager.scan_instances("123456789012", "us-east-1")

        assert len(instances) == 0

    def test_scan_instances_handles_missing_optional_fields(self):
        """Test scanning handles instances with missing optional fields."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-001",
                                "InstanceType": "t3.micro",
                                "State": {"Name": "running"},
                                "LaunchTime": datetime.now(UTC),
                                # Missing VpcId, SecurityGroups, KeyName, Tags
                            }
                        ]
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        manager = EC2Manager(mock_ec2)
        instances = manager.scan_instances("123456789012", "us-east-1")

        assert len(instances) == 1
        assert instances[0].vpc_id == ""
        assert instances[0].security_groups == []
        assert instances[0].key_name is None


class TestEC2ManagerGetInstanceDetails:
    """Tests for get_instance_details method."""

    def test_get_instance_details_success(self):
        """Test getting instance details successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [create_mock_instance_data("i-001")]}]
        }

        manager = EC2Manager(mock_ec2)
        details = manager.get_instance_details("i-001")

        assert details is not None
        assert details["InstanceId"] == "i-001"

    def test_get_instance_details_not_found(self):
        """Test getting details for non-existent instance."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        manager = EC2Manager(mock_ec2)
        details = manager.get_instance_details("i-nonexistent")

        assert details is None

    def test_get_instance_details_exception(self):
        """Test getting details handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = Exception("API error")

        manager = EC2Manager(mock_ec2)
        details = manager.get_instance_details("i-001")

        assert details is None


class TestEC2ManagerGetAssociatedResources:
    """Tests for get_associated_resources method."""

    def test_get_associated_resources_success(self):
        """Test getting associated resources successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.return_value = {
            "Volumes": [{"VolumeId": "vol-001"}, {"VolumeId": "vol-002"}]
        }
        mock_ec2.describe_addresses.return_value = {"Addresses": [{"AllocationId": "eipalloc-001"}]}

        manager = EC2Manager(mock_ec2)
        instance = create_packer_instance("i-001", security_groups=["sg-001", "sg-002"])
        associated = manager.get_associated_resources(instance)

        assert associated["security_group_ids"] == ["sg-001", "sg-002"]
        assert associated["key_pair_name"] == "packer_key"
        assert associated["volume_ids"] == ["vol-001", "vol-002"]
        assert associated["eip_allocation_ids"] == ["eipalloc-001"]

    def test_get_associated_resources_handles_volume_error(self):
        """Test getting associated resources handles volume errors."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.side_effect = Exception("API error")
        mock_ec2.describe_addresses.return_value = {"Addresses": []}

        manager = EC2Manager(mock_ec2)
        instance = create_packer_instance("i-001")
        associated = manager.get_associated_resources(instance)

        assert associated["volume_ids"] == []

    def test_get_associated_resources_handles_eip_error(self):
        """Test getting associated resources handles EIP errors."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_volumes.return_value = {"Volumes": []}
        mock_ec2.describe_addresses.side_effect = Exception("API error")

        manager = EC2Manager(mock_ec2)
        instance = create_packer_instance("i-001")
        associated = manager.get_associated_resources(instance)

        assert associated["eip_allocation_ids"] == []


class TestEC2ManagerTerminateInstances:
    """Tests for terminate_instances method."""

    def test_terminate_instances_success(self):
        """Test terminating instances successfully."""
        mock_ec2 = MagicMock()
        manager = EC2Manager(mock_ec2, dry_run=False)

        instances = [
            create_packer_instance("i-001", state="running"),
            create_packer_instance("i-002", state="stopped"),
        ]

        terminated, deferred, errors = manager.terminate_instances(instances)

        assert len(terminated) == 2
        assert len(deferred) == 0
        assert len(errors) == 0

    def test_terminate_instances_dry_run(self):
        """Test terminating instances in dry run mode."""
        mock_ec2 = MagicMock()
        manager = EC2Manager(mock_ec2, dry_run=True)

        instances = [create_packer_instance("i-001", state="running")]

        terminated, deferred, errors = manager.terminate_instances(instances)

        assert len(terminated) == 1
        mock_ec2.terminate_instances.assert_not_called()

    def test_terminate_instances_already_terminated(self):
        """Test terminating already terminated instances."""
        mock_ec2 = MagicMock()
        manager = EC2Manager(mock_ec2, dry_run=False)

        instances = [create_packer_instance("i-001", state="terminated")]

        terminated, deferred, errors = manager.terminate_instances(instances)

        assert len(terminated) == 1
        mock_ec2.terminate_instances.assert_not_called()

    def test_terminate_instances_shutting_down(self):
        """Test terminating instances that are shutting down."""
        mock_ec2 = MagicMock()
        manager = EC2Manager(mock_ec2, dry_run=False)

        instances = [create_packer_instance("i-001", state="shutting-down")]

        terminated, deferred, errors = manager.terminate_instances(instances)

        assert len(terminated) == 0
        assert len(deferred) == 1

    def test_terminate_instances_unknown_state(self):
        """Test terminating instances in unknown state."""
        mock_ec2 = MagicMock()
        manager = EC2Manager(mock_ec2, dry_run=False)

        instances = [create_packer_instance("i-001", state="unknown-state")]

        terminated, deferred, errors = manager.terminate_instances(instances)

        assert len(terminated) == 0
        assert len(deferred) == 1

    def test_terminate_instances_error(self):
        """Test terminating instances handles errors."""
        mock_ec2 = MagicMock()
        mock_ec2.terminate_instances.side_effect = Exception("API error")
        manager = EC2Manager(mock_ec2, dry_run=False)

        instances = [create_packer_instance("i-001", state="running")]

        terminated, deferred, errors = manager.terminate_instances(instances)

        assert len(terminated) == 0
        assert len(deferred) == 0
        assert len(errors) == 1

    def test_terminate_instances_various_states(self):
        """Test terminating instances in various terminable states."""
        mock_ec2 = MagicMock()
        manager = EC2Manager(mock_ec2, dry_run=False)

        instances = [
            create_packer_instance("i-001", state="pending"),
            create_packer_instance("i-002", state="running"),
            create_packer_instance("i-003", state="stopping"),
            create_packer_instance("i-004", state="stopped"),
            create_packer_instance("i-005", state="rebooting"),
        ]

        terminated, deferred, errors = manager.terminate_instances(instances)

        assert len(terminated) == 5
        assert len(deferred) == 0
        assert len(errors) == 0


class TestEC2ManagerGetInstanceState:
    """Tests for get_instance_state method."""

    def test_get_instance_state_success(self):
        """Test getting instance state successfully."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-001", "State": {"Name": "running"}}]}]
        }

        manager = EC2Manager(mock_ec2)
        state = manager.get_instance_state("i-001")

        assert state == "running"

    def test_get_instance_state_not_found(self):
        """Test getting state for non-existent instance."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        manager = EC2Manager(mock_ec2)
        state = manager.get_instance_state("i-nonexistent")

        assert state is None

    def test_get_instance_state_exception(self):
        """Test getting state handles exceptions."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = Exception("API error")

        manager = EC2Manager(mock_ec2)
        state = manager.get_instance_state("i-001")

        assert state is None


class TestEC2ManagerWaitForTermination:
    """Tests for wait_for_termination method."""

    def test_wait_for_termination_success(self):
        """Test waiting for termination successfully."""
        mock_ec2 = MagicMock()
        mock_waiter = MagicMock()
        mock_ec2.get_waiter.return_value = mock_waiter

        manager = EC2Manager(mock_ec2, dry_run=False)
        result = manager.wait_for_termination(["i-001", "i-002"])

        assert result == {"i-001": "terminated", "i-002": "terminated"}
        mock_waiter.wait.assert_called_once()

    def test_wait_for_termination_dry_run(self):
        """Test waiting for termination in dry run mode."""
        mock_ec2 = MagicMock()
        manager = EC2Manager(mock_ec2, dry_run=True)

        result = manager.wait_for_termination(["i-001", "i-002"])

        assert result == {"i-001": "terminated", "i-002": "terminated"}
        mock_ec2.get_waiter.assert_not_called()

    def test_wait_for_termination_empty_list(self):
        """Test waiting for termination with empty list."""
        mock_ec2 = MagicMock()
        manager = EC2Manager(mock_ec2, dry_run=False)

        result = manager.wait_for_termination([])

        assert result == {}
        mock_ec2.get_waiter.assert_not_called()

    def test_wait_for_termination_timeout(self):
        """Test waiting for termination handles timeout."""
        mock_ec2 = MagicMock()
        mock_waiter = MagicMock()
        mock_waiter.wait.side_effect = Exception("Waiter timeout")
        mock_ec2.get_waiter.return_value = mock_waiter
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-001", "State": {"Name": "shutting-down"}}]}
            ]
        }

        manager = EC2Manager(mock_ec2, dry_run=False)
        result = manager.wait_for_termination(["i-001"])

        assert result["i-001"] == "shutting-down"
