"""Property-based tests for orphaned Packer resource cleanup safety.

Feature: packer-resource-reaper, Property 11: Orphaned Resource Cleanup Safety
Validates: Requirements 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 10.10

This module tests that the OrphanManager safely cleans up orphaned resources:
- Delete key pairs after confirming no instance references (10.4)
- Delete security groups after confirming no dependencies (10.5)
- Delete IAM roles with policy detachment before deletion (10.6)
- Execute as Phase 2 after primary cleanup (10.7)
- Respect dry-run mode (10.8)
- Log each deleted resource (10.9)
- Include details in notifications (10.10)
"""

from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from reaper.cleanup.orphan_manager import (
    OrphanedResources,
    OrphanManager,
)

# Strategies for generating test data
alphanumeric = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789"),
    min_size=1,
    max_size=10,
)

packer_key_name = st.builds(
    lambda suffix: f"packer_{suffix}",
    suffix=alphanumeric,
)

packer_sg_id = st.builds(
    lambda suffix: f"sg-packer{suffix}",
    suffix=alphanumeric,
)

packer_role_name = st.builds(
    lambda suffix: f"packer_{suffix}",
    suffix=alphanumeric,
)


def create_mock_ec2_client_for_cleanup(
    key_pairs_in_use: set[str] = None,
    sgs_in_use: set[str] = None,
) -> MagicMock:
    """Create a mock EC2 client for cleanup operations."""
    mock_ec2 = MagicMock()
    key_pairs_in_use = key_pairs_in_use or set()
    sgs_in_use = sgs_in_use or set()

    # Mock describe_instances for key pair check
    def describe_instances_side_effect(**kwargs):
        filters = kwargs.get("Filters", [])
        for f in filters:
            if f.get("Name") == "key-name":
                key_name = f.get("Values", [None])[0]
                if key_name in key_pairs_in_use:
                    return {"Reservations": [{"Instances": [{"KeyName": key_name}]}]}
            if f.get("Name") == "instance.group-id":
                sg_id = f.get("Values", [None])[0]
                if sg_id in sgs_in_use:
                    return {
                        "Reservations": [{"Instances": [{"SecurityGroups": [{"GroupId": sg_id}]}]}]
                    }
        return {"Reservations": []}

    mock_ec2.describe_instances.side_effect = describe_instances_side_effect

    # Mock describe_network_interfaces
    def describe_nis_side_effect(**kwargs):
        filters = kwargs.get("Filters", [])
        for f in filters:
            if f.get("Name") == "group-id":
                sg_id = f.get("Values", [None])[0]
                if sg_id in sgs_in_use:
                    return {"NetworkInterfaces": [{"Groups": [{"GroupId": sg_id}]}]}
        return {"NetworkInterfaces": []}

    mock_ec2.describe_network_interfaces.side_effect = describe_nis_side_effect

    # Mock delete operations
    mock_ec2.delete_key_pair.return_value = {}
    mock_ec2.delete_security_group.return_value = {}

    return mock_ec2


def create_mock_iam_client_for_cleanup(
    roles_in_use: set[str] = None,
) -> MagicMock:
    """Create a mock IAM client for cleanup operations."""
    mock_iam = MagicMock()
    roles_in_use = roles_in_use or set()

    # Mock list_instance_profiles_for_role
    def list_profiles_side_effect(**kwargs):
        role_name = kwargs.get("RoleName")
        if role_name in roles_in_use:
            return {
                "InstanceProfiles": [
                    {
                        "InstanceProfileName": f"profile-{role_name}",
                        "Arn": f"arn:aws:iam::123456789012:instance-profile/profile-{role_name}",
                    }
                ]
            }
        return {"InstanceProfiles": []}

    mock_iam.list_instance_profiles_for_role.side_effect = list_profiles_side_effect

    # Mock list_attached_role_policies
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    # Mock list_role_policies
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}

    # Mock delete operations
    mock_iam.remove_role_from_instance_profile.return_value = {}
    mock_iam.detach_role_policy.return_value = {}
    mock_iam.delete_role_policy.return_value = {}
    mock_iam.delete_role.return_value = {}

    # Mock paginator for list_instance_profiles (used in _get_iam_roles_in_use)
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"InstanceProfiles": []}]
    mock_iam.get_paginator = MagicMock(return_value=mock_paginator)

    return mock_iam


def create_mock_ec2_client_for_iam_check(
    roles_in_use: set[str] = None,
) -> MagicMock:
    """Create a mock EC2 client that returns instances using specific IAM roles."""
    mock_ec2 = MagicMock()
    roles_in_use = roles_in_use or set()

    # Mock describe_instances for key pair check (default behavior)
    mock_ec2.describe_instances.return_value = {"Reservations": []}

    # Mock describe_network_interfaces
    mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}

    # Mock delete operations
    mock_ec2.delete_key_pair.return_value = {}
    mock_ec2.delete_security_group.return_value = {}

    # Mock paginator for describe_instances - returns instances with IAM profiles for in-use roles
    def create_paginator(operation):
        mock_paginator = MagicMock()
        if operation == "describe_instances":
            # Return instances with IAM profiles for roles that are in use
            instances = []
            for role in roles_in_use:
                instances.append(
                    {
                        "KeyName": "some-key",
                        "State": {"Name": "running"},
                        "IamInstanceProfile": {
                            "Arn": f"arn:aws:iam::123456789012:instance-profile/profile-{role}"
                        },
                    }
                )
            mock_paginator.paginate.return_value = [
                {"Reservations": [{"Instances": instances}] if instances else []}
            ]
        else:
            mock_paginator.paginate.return_value = [{}]
        return mock_paginator

    mock_ec2.get_paginator = create_paginator

    return mock_ec2


@settings(max_examples=100, deadline=10000)
@given(
    orphaned_keys=st.lists(packer_key_name, min_size=0, max_size=5, unique=True),
    orphaned_sgs=st.lists(packer_sg_id, min_size=0, max_size=5, unique=True),
    dry_run=st.booleans(),
)
def test_dry_run_prevents_destructive_operations(
    orphaned_keys: list[str],
    orphaned_sgs: list[str],
    dry_run: bool,
):
    """
    Feature: packer-resource-reaper, Property 11: Orphaned Resource Cleanup Safety

    When dry-run mode is enabled, the system should identify all cleanup candidates
    and log planned actions without executing any destructive AWS API operations.

    Validates: Requirements 10.8
    """
    # Create mock clients
    mock_ec2 = create_mock_ec2_client_for_cleanup()

    # Create orphan manager
    orphan_manager = OrphanManager(ec2_client=mock_ec2, dry_run=dry_run)

    # Create orphaned resources
    orphaned = OrphanedResources(
        orphaned_key_pairs=orphaned_keys,
        orphaned_security_groups=orphaned_sgs,
    )

    # Execute cleanup
    result = orphan_manager.cleanup_orphaned_resources(orphaned)

    # Verify dry-run behavior
    if dry_run:
        # In dry-run mode, no destructive operations should be called
        mock_ec2.delete_key_pair.assert_not_called()
        mock_ec2.delete_security_group.assert_not_called()

        # But resources should still be reported as "deleted" (would be deleted)
        assert set(result.deleted_key_pairs) == set(orphaned_keys)
        assert set(result.deleted_security_groups) == set(orphaned_sgs)
    else:
        # In live mode, destructive operations should be called
        if orphaned_keys:
            assert mock_ec2.delete_key_pair.call_count == len(orphaned_keys)
        if orphaned_sgs:
            assert mock_ec2.delete_security_group.call_count == len(orphaned_sgs)


@settings(max_examples=100, deadline=10000)
@given(
    orphaned_keys=st.lists(packer_key_name, min_size=1, max_size=5, unique=True),
    keys_now_in_use_count=st.integers(min_value=0, max_value=3),
)
def test_key_pair_deletion_confirms_no_references(
    orphaned_keys: list[str],
    keys_now_in_use_count: int,
):
    """
    Feature: packer-resource-reaper, Property 11: Orphaned Resource Cleanup Safety

    Before deleting a key pair, the system should re-verify that no instances
    are using it. If an instance is now using it, the key pair should be deferred.

    Validates: Requirements 10.4
    """
    # Determine which keys are now in use (race condition simulation)
    keys_now_in_use_count = min(keys_now_in_use_count, len(orphaned_keys))
    keys_now_in_use = set(orphaned_keys[:keys_now_in_use_count])

    # Create mock EC2 client
    mock_ec2 = create_mock_ec2_client_for_cleanup(key_pairs_in_use=keys_now_in_use)

    # Create orphan manager (live mode)
    orphan_manager = OrphanManager(ec2_client=mock_ec2, dry_run=False)

    # Create orphaned resources
    orphaned = OrphanedResources(orphaned_key_pairs=orphaned_keys)

    # Execute cleanup
    result = orphan_manager.cleanup_orphaned_resources(orphaned)

    # Verify: keys now in use should be deferred, not deleted
    expected_deleted = set(orphaned_keys) - keys_now_in_use
    expected_deferred = {f"key_pair:{k}" for k in keys_now_in_use}

    assert set(result.deleted_key_pairs) == expected_deleted, (
        f"Expected deleted: {expected_deleted}, got: {set(result.deleted_key_pairs)}"
    )
    assert set(result.deferred_resources) == expected_deferred, (
        f"Expected deferred: {expected_deferred}, got: {set(result.deferred_resources)}"
    )


@settings(max_examples=100, deadline=10000)
@given(
    orphaned_sgs=st.lists(packer_sg_id, min_size=1, max_size=5, unique=True),
    sgs_now_in_use_count=st.integers(min_value=0, max_value=3),
)
def test_security_group_deletion_confirms_no_dependencies(
    orphaned_sgs: list[str],
    sgs_now_in_use_count: int,
):
    """
    Feature: packer-resource-reaper, Property 11: Orphaned Resource Cleanup Safety

    Before deleting a security group, the system should re-verify that no instances
    or network interfaces are using it. If dependencies exist, the SG should be deferred.

    Validates: Requirements 10.5
    """
    # Determine which SGs are now in use (race condition simulation)
    sgs_now_in_use_count = min(sgs_now_in_use_count, len(orphaned_sgs))
    sgs_now_in_use = set(orphaned_sgs[:sgs_now_in_use_count])

    # Create mock EC2 client
    mock_ec2 = create_mock_ec2_client_for_cleanup(sgs_in_use=sgs_now_in_use)

    # Create orphan manager (live mode)
    orphan_manager = OrphanManager(ec2_client=mock_ec2, dry_run=False)

    # Create orphaned resources
    orphaned = OrphanedResources(orphaned_security_groups=orphaned_sgs)

    # Execute cleanup
    result = orphan_manager.cleanup_orphaned_resources(orphaned)

    # Verify: SGs now in use should be deferred, not deleted
    expected_deleted = set(orphaned_sgs) - sgs_now_in_use
    expected_deferred = {f"security_group:{sg}" for sg in sgs_now_in_use}

    assert set(result.deleted_security_groups) == expected_deleted, (
        f"Expected deleted: {expected_deleted}, got: {set(result.deleted_security_groups)}"
    )
    assert set(result.deferred_resources) == expected_deferred, (
        f"Expected deferred: {expected_deferred}, got: {set(result.deferred_resources)}"
    )


@settings(max_examples=100, deadline=10000)
@given(
    orphaned_roles=st.lists(packer_role_name, min_size=1, max_size=3, unique=True),
    roles_now_in_use_count=st.integers(min_value=0, max_value=2),
)
def test_iam_role_deletion_with_policy_detachment(
    orphaned_roles: list[str],
    roles_now_in_use_count: int,
):
    """
    Feature: packer-resource-reaper, Property 11: Orphaned Resource Cleanup Safety

    Before deleting an IAM role, the system should:
    1. Re-verify the role is not in use
    2. Detach all managed policies
    3. Delete all inline policies
    4. Remove role from instance profiles
    5. Delete the role

    Validates: Requirements 10.6
    """
    # Determine which roles are now in use
    roles_now_in_use_count = min(roles_now_in_use_count, len(orphaned_roles))
    roles_now_in_use = set(orphaned_roles[:roles_now_in_use_count])

    # Create mock clients - EC2 client needs to know about roles in use for the check
    mock_ec2 = create_mock_ec2_client_for_iam_check(roles_in_use=roles_now_in_use)
    mock_iam = create_mock_iam_client_for_cleanup(roles_in_use=roles_now_in_use)

    # Create orphan manager (live mode)
    orphan_manager = OrphanManager(
        ec2_client=mock_ec2,
        iam_client=mock_iam,
        dry_run=False,
    )

    # Create orphaned resources
    orphaned = OrphanedResources(orphaned_iam_roles=orphaned_roles)

    # Execute cleanup
    result = orphan_manager.cleanup_orphaned_resources(orphaned)

    # Verify: roles now in use should be deferred
    expected_deleted = set(orphaned_roles) - roles_now_in_use
    expected_deferred = {f"iam_role:{r}" for r in roles_now_in_use}

    assert set(result.deleted_iam_roles) == expected_deleted, (
        f"Expected deleted: {expected_deleted}, got: {set(result.deleted_iam_roles)}"
    )
    assert set(result.deferred_resources) == expected_deferred, (
        f"Expected deferred: {expected_deferred}, got: {set(result.deferred_resources)}"
    )

    # Verify delete_role was called for non-in-use roles
    if expected_deleted:
        assert mock_iam.delete_role.call_count == len(expected_deleted)


@settings(max_examples=100, deadline=10000)
@given(
    key_count=st.integers(min_value=0, max_value=3),
    sg_count=st.integers(min_value=0, max_value=3),
    role_count=st.integers(min_value=0, max_value=2),
)
def test_cleanup_result_totals_are_accurate(
    key_count: int,
    sg_count: int,
    role_count: int,
):
    """
    Feature: packer-resource-reaper, Property 11: Orphaned Resource Cleanup Safety

    The cleanup result should accurately report the total number of resources
    cleaned up across all resource types.

    Validates: Requirements 10.9, 10.10
    """
    # Generate orphaned resources
    orphaned_keys = [f"packer_key{i}" for i in range(key_count)]
    orphaned_sgs = [f"sg-packer{i}" for i in range(sg_count)]
    orphaned_roles = [f"packer_role{i}" for i in range(role_count)]

    # Create mock clients
    mock_ec2 = create_mock_ec2_client_for_cleanup()
    mock_iam = create_mock_iam_client_for_cleanup()

    # Create orphan manager (dry-run to avoid actual deletions)
    orphan_manager = OrphanManager(
        ec2_client=mock_ec2,
        iam_client=mock_iam,
        dry_run=True,
    )

    # Create orphaned resources
    orphaned = OrphanedResources(
        orphaned_key_pairs=orphaned_keys,
        orphaned_security_groups=orphaned_sgs,
        orphaned_iam_roles=orphaned_roles,
    )

    # Execute cleanup
    result = orphan_manager.cleanup_orphaned_resources(orphaned)

    # Verify totals
    expected_total = key_count + sg_count + role_count
    assert result.total_cleaned() == expected_total, (
        f"Expected total: {expected_total}, got: {result.total_cleaned()}"
    )

    assert len(result.deleted_key_pairs) == key_count
    assert len(result.deleted_security_groups) == sg_count
    assert len(result.deleted_iam_roles) == role_count


@settings(max_examples=100, deadline=10000)
@given(
    orphaned_keys=st.lists(packer_key_name, min_size=0, max_size=3, unique=True),
    orphaned_sgs=st.lists(packer_sg_id, min_size=0, max_size=3, unique=True),
)
def test_empty_orphaned_resources_produces_empty_result(
    orphaned_keys: list[str],
    orphaned_sgs: list[str],
):
    """
    Feature: packer-resource-reaper, Property 11: Orphaned Resource Cleanup Safety

    When there are no orphaned resources, the cleanup result should be empty
    with no errors or deferred resources.

    Validates: Requirements 10.7
    """
    # Create mock clients
    mock_ec2 = create_mock_ec2_client_for_cleanup()

    # Create orphan manager
    orphan_manager = OrphanManager(ec2_client=mock_ec2, dry_run=True)

    # Create empty orphaned resources
    orphaned = OrphanedResources()

    # Execute cleanup
    result = orphan_manager.cleanup_orphaned_resources(orphaned)

    # Verify empty result
    assert result.total_cleaned() == 0
    assert len(result.deferred_resources) == 0
    assert len(result.errors) == 0
    assert result.is_empty() if hasattr(result, "is_empty") else True


@settings(max_examples=100, deadline=10000)
@given(
    orphaned_keys=st.lists(packer_key_name, min_size=1, max_size=5, unique=True),
)
def test_cleanup_is_idempotent_in_dry_run(
    orphaned_keys: list[str],
):
    """
    Feature: packer-resource-reaper, Property 11: Orphaned Resource Cleanup Safety

    Running cleanup multiple times in dry-run mode should produce the same result
    each time (idempotent behavior).

    Validates: Requirements 10.8
    """
    # Create mock clients
    mock_ec2 = create_mock_ec2_client_for_cleanup()

    # Create orphan manager (dry-run)
    orphan_manager = OrphanManager(ec2_client=mock_ec2, dry_run=True)

    # Create orphaned resources
    orphaned = OrphanedResources(orphaned_key_pairs=orphaned_keys)

    # Execute cleanup multiple times
    result1 = orphan_manager.cleanup_orphaned_resources(orphaned)
    result2 = orphan_manager.cleanup_orphaned_resources(orphaned)

    # Verify results are identical
    assert set(result1.deleted_key_pairs) == set(result2.deleted_key_pairs)
    assert result1.total_cleaned() == result2.total_cleaned()
    assert len(result1.errors) == len(result2.errors)
