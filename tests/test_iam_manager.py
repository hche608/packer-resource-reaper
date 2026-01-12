"""Tests for IAM manager functionality.

Tests for instance profile scanning, deletion, and pattern matching.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from reaper.cleanup.iam_manager import IAMManager
from reaper.models import PackerInstanceProfile, ResourceType


def create_instance_profile(
    profile_name: str,
    profile_id: str = "AIPA123456789",
    roles: list = None,
    path: str = "/",
) -> dict:
    """Create a mock instance profile response."""
    return {
        "InstanceProfileName": profile_name,
        "InstanceProfileId": profile_id,
        "Arn": f"arn:aws:iam::123456789012:instance-profile{path}{profile_name}",
        "Path": path,
        "CreateDate": datetime.now(UTC),
        "Roles": [{"RoleName": r} for r in (roles or [])],
    }


def create_packer_instance_profile(
    profile_name: str,
    profile_id: str = "AIPA123456789",
    roles: list = None,
) -> PackerInstanceProfile:
    """Create a PackerInstanceProfile for testing."""
    return PackerInstanceProfile(
        resource_id=profile_id,
        resource_type=ResourceType.INSTANCE_PROFILE,
        creation_time=datetime.now(UTC),
        tags={},
        region="us-east-1",
        account_id="123456789012",
        instance_profile_name=profile_name,
        instance_profile_id=profile_id,
        arn=f"arn:aws:iam::123456789012:instance-profile/{profile_name}",
        path="/",
        roles=roles or [],
    )


class TestIAMManagerScanInstanceProfiles:
    """Tests for scan_instance_profiles method."""

    def test_scan_finds_packer_profiles(self):
        """Test scanning finds profiles matching packer_ pattern."""
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "InstanceProfiles": [
                    create_instance_profile("packer_profile_1", "AIPA001"),
                    create_instance_profile("packer_profile_2", "AIPA002"),
                    create_instance_profile("production_profile", "AIPA003"),
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        manager = IAMManager(mock_iam)
        profiles = manager.scan_instance_profiles("123456789012", "us-east-1")

        assert len(profiles) == 2
        assert all(p.instance_profile_name.startswith("packer_") for p in profiles)

    def test_scan_with_custom_pattern(self):
        """Test scanning with custom pattern."""
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "InstanceProfiles": [
                    create_instance_profile("custom_profile_1", "AIPA001"),
                    create_instance_profile("packer_profile", "AIPA002"),
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        manager = IAMManager(mock_iam)
        profiles = manager.scan_instance_profiles("123456789012", "us-east-1", pattern="custom_")

        assert len(profiles) == 1
        assert profiles[0].instance_profile_name == "custom_profile_1"

    def test_scan_extracts_roles(self):
        """Test that roles are extracted from profiles."""
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "InstanceProfiles": [
                    create_instance_profile("packer_profile", "AIPA001", roles=["role1", "role2"]),
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        manager = IAMManager(mock_iam)
        profiles = manager.scan_instance_profiles("123456789012", "us-east-1")

        assert len(profiles) == 1
        assert profiles[0].roles == ["role1", "role2"]

    def test_scan_handles_empty_results(self):
        """Test scanning handles empty results."""
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"InstanceProfiles": []}]
        mock_iam.get_paginator.return_value = mock_paginator

        manager = IAMManager(mock_iam)
        profiles = manager.scan_instance_profiles("123456789012", "us-east-1")

        assert len(profiles) == 0

    def test_scan_handles_exception(self):
        """Test scanning handles exceptions gracefully."""
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = Exception("API error")
        mock_iam.get_paginator.return_value = mock_paginator

        manager = IAMManager(mock_iam)
        profiles = manager.scan_instance_profiles("123456789012", "us-east-1")

        assert len(profiles) == 0


class TestIAMManagerGetInstanceProfileByName:
    """Tests for get_instance_profile_by_name method."""

    def test_get_profile_by_name_success(self):
        """Test getting profile by name successfully."""
        mock_iam = MagicMock()
        mock_iam.get_instance_profile.return_value = {
            "InstanceProfile": create_instance_profile(
                "packer_test", "AIPA001", roles=["test_role"]
            )
        }

        manager = IAMManager(mock_iam)
        profile = manager.get_instance_profile_by_name("packer_test", "123456789012", "us-east-1")

        assert profile is not None
        assert profile.instance_profile_name == "packer_test"
        assert profile.roles == ["test_role"]

    def test_get_profile_by_name_not_found(self):
        """Test getting profile that doesn't exist."""
        mock_iam = MagicMock()
        mock_iam.get_instance_profile.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "GetInstanceProfile",
        )

        manager = IAMManager(mock_iam)
        profile = manager.get_instance_profile_by_name("nonexistent", "123456789012", "us-east-1")

        assert profile is None

    def test_get_profile_by_name_empty_name(self):
        """Test getting profile with empty name returns None."""
        mock_iam = MagicMock()
        manager = IAMManager(mock_iam)

        profile = manager.get_instance_profile_by_name("", "123456789012", "us-east-1")

        assert profile is None
        mock_iam.get_instance_profile.assert_not_called()

    def test_get_profile_by_name_none_name(self):
        """Test getting profile with None name returns None."""
        mock_iam = MagicMock()
        manager = IAMManager(mock_iam)

        profile = manager.get_instance_profile_by_name(None, "123456789012", "us-east-1")

        assert profile is None

    def test_get_profile_by_name_other_error(self):
        """Test getting profile handles other errors."""
        mock_iam = MagicMock()
        mock_iam.get_instance_profile.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "GetInstanceProfile",
        )

        manager = IAMManager(mock_iam)
        profile = manager.get_instance_profile_by_name("test", "123456789012", "us-east-1")

        assert profile is None

    def test_get_profile_by_name_generic_exception(self):
        """Test getting profile handles generic exceptions."""
        mock_iam = MagicMock()
        mock_iam.get_instance_profile.side_effect = Exception("Unexpected error")

        manager = IAMManager(mock_iam)
        profile = manager.get_instance_profile_by_name("test", "123456789012", "us-east-1")

        assert profile is None


class TestIAMManagerDeleteInstanceProfiles:
    """Tests for delete_instance_profiles method."""

    def test_delete_profiles_success(self):
        """Test deleting profiles successfully."""
        mock_iam = MagicMock()
        manager = IAMManager(mock_iam, dry_run=False)

        profiles = [
            create_packer_instance_profile("packer_profile_1", "AIPA001"),
            create_packer_instance_profile("packer_profile_2", "AIPA002"),
        ]

        deleted, deferred, errors = manager.delete_instance_profiles(profiles)

        assert len(deleted) == 2
        assert len(deferred) == 0
        assert len(errors) == 0

    def test_delete_profiles_with_roles(self):
        """Test deleting profiles detaches roles first."""
        mock_iam = MagicMock()
        manager = IAMManager(mock_iam, dry_run=False)

        profiles = [
            create_packer_instance_profile("packer_profile", "AIPA001", roles=["role1", "role2"]),
        ]

        deleted, deferred, errors = manager.delete_instance_profiles(profiles)

        assert len(deleted) == 1
        assert mock_iam.remove_role_from_instance_profile.call_count == 2
        mock_iam.delete_instance_profile.assert_called_once()

    def test_delete_profiles_dry_run(self):
        """Test deleting profiles in dry run mode."""
        mock_iam = MagicMock()
        manager = IAMManager(mock_iam, dry_run=True)

        profiles = [
            create_packer_instance_profile("packer_profile", "AIPA001", roles=["role1"]),
        ]

        deleted, deferred, errors = manager.delete_instance_profiles(profiles)

        assert len(deleted) == 1
        mock_iam.remove_role_from_instance_profile.assert_not_called()
        mock_iam.delete_instance_profile.assert_not_called()

    def test_delete_profiles_dependency_conflict(self):
        """Test deleting profiles handles dependency conflicts."""
        mock_iam = MagicMock()
        mock_iam.delete_instance_profile.side_effect = ClientError(
            {"Error": {"Code": "DeleteConflict", "Message": "Has dependencies"}},
            "DeleteInstanceProfile",
        )
        manager = IAMManager(mock_iam, dry_run=False)

        profiles = [create_packer_instance_profile("packer_profile", "AIPA001")]

        deleted, deferred, errors = manager.delete_instance_profiles(profiles)

        assert len(deleted) == 0
        assert len(deferred) == 1
        assert len(errors) == 0

    def test_delete_profiles_already_deleted(self):
        """Test deleting profiles that are already deleted."""
        mock_iam = MagicMock()
        mock_iam.delete_instance_profile.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "DeleteInstanceProfile",
        )
        manager = IAMManager(mock_iam, dry_run=False)

        profiles = [create_packer_instance_profile("packer_profile", "AIPA001")]

        deleted, deferred, errors = manager.delete_instance_profiles(profiles)

        assert len(deleted) == 1
        assert len(deferred) == 0
        assert len(errors) == 0

    def test_delete_profiles_other_error(self):
        """Test deleting profiles handles other errors."""
        mock_iam = MagicMock()
        mock_iam.delete_instance_profile.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "DeleteInstanceProfile",
        )
        manager = IAMManager(mock_iam, dry_run=False)

        profiles = [create_packer_instance_profile("packer_profile", "AIPA001")]

        deleted, deferred, errors = manager.delete_instance_profiles(profiles)

        assert len(deleted) == 0
        assert len(deferred) == 0
        assert len(errors) == 1

    def test_delete_profiles_generic_exception(self):
        """Test deleting profiles handles generic exceptions."""
        mock_iam = MagicMock()
        mock_iam.delete_instance_profile.side_effect = Exception("Unexpected error")
        manager = IAMManager(mock_iam, dry_run=False)

        profiles = [create_packer_instance_profile("packer_profile", "AIPA001")]

        deleted, deferred, errors = manager.delete_instance_profiles(profiles)

        assert len(deleted) == 0
        assert len(deferred) == 0
        assert len(errors) == 1


class TestIAMManagerMatchesPackerPattern:
    """Tests for matches_packer_pattern method."""

    def test_matches_packer_pattern_valid(self):
        """Test pattern matching with valid packer names."""
        manager = IAMManager(MagicMock())

        assert manager.matches_packer_pattern("packer_profile") is True
        assert manager.matches_packer_pattern("packer_") is True
        assert manager.matches_packer_pattern("packer_abc123") is True

    def test_matches_packer_pattern_invalid(self):
        """Test pattern matching with invalid names."""
        manager = IAMManager(MagicMock())

        assert manager.matches_packer_pattern("production_profile") is False
        assert manager.matches_packer_pattern("Packer_profile") is False
        assert manager.matches_packer_pattern("my_packer_profile") is False

    def test_matches_packer_pattern_empty(self):
        """Test pattern matching with empty string."""
        manager = IAMManager(MagicMock())

        assert manager.matches_packer_pattern("") is False

    def test_matches_packer_pattern_none(self):
        """Test pattern matching with None."""
        manager = IAMManager(MagicMock())

        assert manager.matches_packer_pattern(None) is False
