"""Tests for security validation functionality.

Tests for input validation, sanitization, and scope enforcement.
"""

from reaper.utils.security import (
    FilterScopeEnforcer,
    InputValidator,
    LogSanitizer,
    ScopeEnforcer,
    ValidationResult,
    validate_cleanup_request,
    validate_instance_for_cleanup,
    validate_key_pair_pattern,
)


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_valid_result(self):
        """Test creating a valid result."""
        result = ValidationResult.valid("sanitized_value")

        assert result.is_valid is True
        assert result.errors == []
        assert result.sanitized_value == "sanitized_value"

    def test_invalid_result(self):
        """Test creating an invalid result."""
        result = ValidationResult.invalid(["Error 1", "Error 2"])

        assert result.is_valid is False
        assert len(result.errors) == 2
        assert result.sanitized_value is None


class TestInputValidatorResourceId:
    """Tests for InputValidator.validate_resource_id."""

    def test_valid_instance_id(self):
        """Test valid instance ID."""
        result = InputValidator.validate_resource_id("i-1234567890abcdef0", "instance_id")

        assert result.is_valid is True

    def test_valid_volume_id(self):
        """Test valid volume ID."""
        result = InputValidator.validate_resource_id("vol-1234567890abcdef0", "volume_id")

        assert result.is_valid is True

    def test_valid_snapshot_id(self):
        """Test valid snapshot ID."""
        result = InputValidator.validate_resource_id("snap-1234567890abcdef0", "snapshot_id")

        assert result.is_valid is True

    def test_valid_security_group_id(self):
        """Test valid security group ID."""
        result = InputValidator.validate_resource_id("sg-1234567890abcdef0", "security_group_id")

        assert result.is_valid is True

    def test_empty_resource_id(self):
        """Test empty resource ID."""
        result = InputValidator.validate_resource_id("", "instance_id")

        assert result.is_valid is False
        assert "cannot be empty" in result.errors[0]

    def test_resource_id_too_long(self):
        """Test resource ID exceeding max length."""
        result = InputValidator.validate_resource_id("i-" + "a" * 100, "instance_id")

        assert result.is_valid is False
        assert "exceeds maximum length" in result.errors[0]

    def test_resource_id_dangerous_characters(self):
        """Test resource ID with dangerous characters."""
        result = InputValidator.validate_resource_id("i-123<script>", "instance_id")

        assert result.is_valid is False
        assert "dangerous characters" in result.errors[0]

    def test_resource_id_invalid_pattern(self):
        """Test resource ID with invalid pattern."""
        result = InputValidator.validate_resource_id("invalid-id", "instance_id")

        assert result.is_valid is False
        assert "does not match expected pattern" in result.errors[0]


class TestInputValidatorRegion:
    """Tests for InputValidator.validate_region."""

    def test_valid_region(self):
        """Test valid region."""
        result = InputValidator.validate_region("us-east-1")

        assert result.is_valid is True

    def test_valid_region_eu(self):
        """Test valid EU region."""
        result = InputValidator.validate_region("eu-west-1")

        assert result.is_valid is True

    def test_empty_region(self):
        """Test empty region."""
        result = InputValidator.validate_region("")

        assert result.is_valid is False
        assert "cannot be empty" in result.errors[0]

    def test_region_too_long(self):
        """Test region exceeding max length."""
        result = InputValidator.validate_region("a" * 50)

        assert result.is_valid is False
        assert "exceeds maximum length" in result.errors[0]

    def test_region_dangerous_characters(self):
        """Test region with dangerous characters."""
        result = InputValidator.validate_region("us-east-1<script>")

        assert result.is_valid is False

    def test_region_invalid_pattern(self):
        """Test region with invalid pattern."""
        result = InputValidator.validate_region("invalid-region")

        assert result.is_valid is False
        assert "does not match expected pattern" in result.errors[0]


class TestInputValidatorAccountId:
    """Tests for InputValidator.validate_account_id."""

    def test_valid_account_id(self):
        """Test valid account ID."""
        result = InputValidator.validate_account_id("123456789012")

        assert result.is_valid is True

    def test_empty_account_id(self):
        """Test empty account ID."""
        result = InputValidator.validate_account_id("")

        assert result.is_valid is False
        assert "cannot be empty" in result.errors[0]

    def test_account_id_wrong_length(self):
        """Test account ID with wrong length."""
        result = InputValidator.validate_account_id("12345")

        assert result.is_valid is False
        assert "exactly 12 digits" in result.errors[0]

    def test_account_id_non_digits(self):
        """Test account ID with non-digit characters."""
        result = InputValidator.validate_account_id("12345678901a")

        assert result.is_valid is False
        assert "only digits" in result.errors[0]


class TestInputValidatorTagKey:
    """Tests for InputValidator.validate_tag_key."""

    def test_valid_tag_key(self):
        """Test valid tag key."""
        result = InputValidator.validate_tag_key("Name")

        assert result.is_valid is True

    def test_valid_tag_key_with_special_chars(self):
        """Test valid tag key with allowed special characters."""
        result = InputValidator.validate_tag_key("aws:cloudformation:stack-name")

        assert result.is_valid is True

    def test_empty_tag_key(self):
        """Test empty tag key."""
        result = InputValidator.validate_tag_key("")

        assert result.is_valid is False
        assert "cannot be empty" in result.errors[0]

    def test_tag_key_too_long(self):
        """Test tag key exceeding max length."""
        result = InputValidator.validate_tag_key("a" * 200)

        assert result.is_valid is False
        assert "exceeds maximum length" in result.errors[0]

    def test_tag_key_invalid_characters(self):
        """Test tag key with invalid characters."""
        result = InputValidator.validate_tag_key("Name<script>")

        assert result.is_valid is False
        assert "invalid characters" in result.errors[0]


class TestInputValidatorTagValue:
    """Tests for InputValidator.validate_tag_value."""

    def test_valid_tag_value(self):
        """Test valid tag value."""
        result = InputValidator.validate_tag_value("my-value")

        assert result.is_valid is True

    def test_empty_tag_value(self):
        """Test empty tag value is allowed."""
        result = InputValidator.validate_tag_value("")

        assert result.is_valid is True


class TestInputValidatorArn:
    """Tests for InputValidator.validate_arn."""

    def test_valid_arn(self):
        """Test valid ARN."""
        result = InputValidator.validate_arn("arn:aws:sns:us-east-1:123456789012:my-topic")

        assert result.is_valid is True

    def test_empty_arn(self):
        """Test empty ARN."""
        result = InputValidator.validate_arn("")

        assert result.is_valid is False
        assert "cannot be empty" in result.errors[0]

    def test_invalid_arn_format(self):
        """Test invalid ARN format."""
        result = InputValidator.validate_arn("invalid-arn")

        assert result.is_valid is False
        assert "must start with" in result.errors[0]

    def test_arn_not_enough_components(self):
        """Test ARN with not enough components."""
        result = InputValidator.validate_arn("arn:aws:sns")

        assert result.is_valid is False
        assert "not have enough components" in result.errors[0]


class TestLogSanitizer:
    """Tests for LogSanitizer class."""

    def test_sanitize_normal_string(self):
        """Test sanitizing normal string."""
        result = LogSanitizer.sanitize("Normal log message")

        assert result == "Normal log message"

    def test_sanitize_with_access_key(self):
        """Test sanitizing string with access key."""
        result = LogSanitizer.sanitize("Key: AKIAIOSFODNN7EXAMPLE")

        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED_ACCESS_KEY]" in result

    def test_sanitize_with_secret_key(self):
        """Test sanitizing string with secret key."""
        result = LogSanitizer.sanitize("secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

        assert "wJalrXUtnFEMI" not in result
        assert "[REDACTED]" in result

    def test_sanitize_dict(self):
        """Test sanitizing dictionary."""
        data = {
            "access_id": "AKIAIOSFODNN7EXAMPLE",
            "normal": "value",
        }
        result = LogSanitizer.sanitize_dict(data)

        assert "[REDACTED_ACCESS_KEY]" in result["access_id"]
        assert result["normal"] == "value"

    def test_sanitize_dict_sensitive_key(self):
        """Test sanitizing dictionary with sensitive key."""
        data = {
            "password": "secret123",
            "normal": "value",
        }
        result = LogSanitizer.sanitize_dict(data)

        assert result["password"] == "[REDACTED]"
        assert result["normal"] == "value"

    def test_sanitize_dict_nested(self):
        """Test sanitizing nested dictionary."""
        data = {
            "outer": {
                "password": "secret123",
            },
        }
        result = LogSanitizer.sanitize_dict(data)

        assert result["outer"]["password"] == "[REDACTED]"

    def test_sanitize_dict_with_list(self):
        """Test sanitizing dictionary with list values."""
        data = {
            "items": ["normal", "AKIAIOSFODNN7EXAMPLE"],
        }
        result = LogSanitizer.sanitize_dict(data)

        assert "[REDACTED_ACCESS_KEY]" in result["items"][1]


class TestScopeEnforcer:
    """Tests for ScopeEnforcer class."""

    def test_init_with_restrictions(self):
        """Test initialization with restrictions."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1", "us-west-2"},
            allowed_account_ids={"123456789012"},
        )

        assert enforcer.allowed_regions == {"us-east-1", "us-west-2"}
        assert enforcer.allowed_account_ids == {"123456789012"}

    def test_init_without_restrictions(self):
        """Test initialization without restrictions."""
        enforcer = ScopeEnforcer()

        assert enforcer.allowed_regions is None
        assert enforcer.allowed_account_ids is None

    def test_is_region_in_scope_allowed(self):
        """Test region in scope when allowed."""
        enforcer = ScopeEnforcer(allowed_regions={"us-east-1"})

        in_scope, reason = enforcer.is_region_in_scope("us-east-1")

        assert in_scope is True
        assert "allowed" in reason

    def test_is_region_in_scope_not_allowed(self):
        """Test region not in scope when not allowed."""
        enforcer = ScopeEnforcer(allowed_regions={"us-east-1"})

        in_scope, reason = enforcer.is_region_in_scope("eu-west-1")

        assert in_scope is False
        assert "not in allowed" in reason

    def test_is_region_in_scope_no_restrictions(self):
        """Test region in scope when no restrictions."""
        enforcer = ScopeEnforcer()

        in_scope, reason = enforcer.is_region_in_scope("any-region-1")

        assert in_scope is True
        assert "No region restrictions" in reason

    def test_is_account_in_scope_allowed(self):
        """Test account in scope when allowed."""
        enforcer = ScopeEnforcer(allowed_account_ids={"123456789012"})

        in_scope, reason = enforcer.is_account_in_scope("123456789012")

        assert in_scope is True
        assert "allowed" in reason

    def test_is_account_in_scope_not_allowed(self):
        """Test account not in scope when not allowed."""
        enforcer = ScopeEnforcer(allowed_account_ids={"123456789012"})

        in_scope, reason = enforcer.is_account_in_scope("999999999999")

        assert in_scope is False
        assert "not in allowed" in reason

    def test_is_account_in_scope_no_restrictions(self):
        """Test account in scope when no restrictions."""
        enforcer = ScopeEnforcer()

        in_scope, reason = enforcer.is_account_in_scope("any-account")

        assert in_scope is True
        assert "No account restrictions" in reason

    def test_is_resource_in_scope_both_allowed(self):
        """Test resource in scope when both region and account allowed."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )

        in_scope, reasons = enforcer.is_resource_in_scope("us-east-1", "123456789012")

        assert in_scope is True
        assert len(reasons) == 0

    def test_is_resource_in_scope_region_not_allowed(self):
        """Test resource not in scope when region not allowed."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )

        in_scope, reasons = enforcer.is_resource_in_scope("eu-west-1", "123456789012")

        assert in_scope is False
        assert len(reasons) > 0

    def test_is_resource_in_scope_account_not_allowed(self):
        """Test resource not in scope when account not allowed."""
        enforcer = ScopeEnforcer(
            allowed_regions={"us-east-1"},
            allowed_account_ids={"123456789012"},
        )

        in_scope, reasons = enforcer.is_resource_in_scope("us-east-1", "999999999999")

        assert in_scope is False
        assert len(reasons) > 0


class TestInputValidatorTags:
    """Tests for InputValidator.validate_tags."""

    def test_valid_tags(self):
        """Test valid tags dictionary."""
        tags = {"Name": "test-instance", "Environment": "dev"}
        result = InputValidator.validate_tags(tags)

        assert result.is_valid is True
        assert result.sanitized_value == tags

    def test_invalid_tags_not_dict(self):
        """Test invalid tags when not a dictionary."""
        result = InputValidator.validate_tags("not-a-dict")

        assert result.is_valid is False
        assert "must be a dictionary" in result.errors[0]

    def test_tags_with_invalid_key(self):
        """Test tags with invalid key."""
        tags = {"Name<script>": "value"}
        result = InputValidator.validate_tags(tags)

        assert result.is_valid is False
        assert "invalid characters" in result.errors[0]

    def test_tags_with_invalid_value(self):
        """Test tags with invalid value."""
        tags = {"Name": "value<script>"}
        result = InputValidator.validate_tags(tags)

        assert result.is_valid is False
        assert "invalid characters" in result.errors[0]

    def test_empty_tags(self):
        """Test empty tags dictionary."""
        result = InputValidator.validate_tags({})

        assert result.is_valid is True
        assert result.sanitized_value == {}


class TestInputValidatorPattern:
    """Tests for InputValidator.validate_pattern."""

    def test_valid_pattern(self):
        """Test valid regex pattern."""
        result = InputValidator.validate_pattern("packer_.*")

        assert result.is_valid is True

    def test_empty_pattern(self):
        """Test empty pattern."""
        result = InputValidator.validate_pattern("")

        assert result.is_valid is False
        assert "cannot be empty" in result.errors[0]

    def test_pattern_too_long(self):
        """Test pattern exceeding max length."""
        result = InputValidator.validate_pattern("a" * 300)

        assert result.is_valid is False
        assert "exceeds maximum length" in result.errors[0]

    def test_invalid_regex_pattern(self):
        """Test invalid regex pattern."""
        result = InputValidator.validate_pattern("[invalid")

        assert result.is_valid is False
        assert "Invalid regex pattern" in result.errors[0]

    def test_dangerous_regex_pattern(self):
        """Test dangerous regex pattern (ReDoS)."""
        result = InputValidator.validate_pattern("(.+)+")

        assert result.is_valid is False
        assert "dangerous regex" in result.errors[0]


class TestInputValidatorTagValueLong:
    """Additional tests for InputValidator.validate_tag_value."""

    def test_tag_value_too_long(self):
        """Test tag value exceeding max length."""
        result = InputValidator.validate_tag_value("a" * 300)

        assert result.is_valid is False
        assert "exceeds maximum length" in result.errors[0]

    def test_tag_value_invalid_characters(self):
        """Test tag value with invalid characters."""
        result = InputValidator.validate_tag_value("value<script>")

        assert result.is_valid is False
        assert "invalid characters" in result.errors[0]


class TestInputValidatorArnLong:
    """Additional tests for InputValidator.validate_arn."""

    def test_arn_too_long(self):
        """Test ARN exceeding max length."""
        result = InputValidator.validate_arn("arn:aws:sns:" + "a" * 3000)

        assert result.is_valid is False
        assert "exceeds maximum length" in result.errors[0]

    def test_arn_dangerous_characters(self):
        """Test ARN with dangerous characters."""
        result = InputValidator.validate_arn("arn:aws:sns:us-east-1:123456789012:topic<script>")

        assert result.is_valid is False
        assert "dangerous characters" in result.errors[0]


class TestFilterScopeEnforcer:
    """Tests for FilterScopeEnforcer class."""

    def test_init_empty(self):
        """Test initialization with empty registries."""
        enforcer = FilterScopeEnforcer()
        counts = enforcer.get_registered_counts()

        assert counts["instances"] == 0
        assert counts["volumes"] == 0
        assert counts["snapshots"] == 0

    def test_register_filtered_resources(self):
        """Test registering filtered resources."""
        enforcer = FilterScopeEnforcer()
        enforcer.register_filtered_resources(
            instance_ids=["i-001", "i-002"],
            volume_ids=["vol-001"],
            snapshot_ids=["snap-001"],
            security_group_ids=["sg-001"],
            key_pair_ids=["key-001"],
            eip_ids=["eipalloc-001"],
        )

        counts = enforcer.get_registered_counts()
        assert counts["instances"] == 2
        assert counts["volumes"] == 1
        assert counts["snapshots"] == 1
        assert counts["security_groups"] == 1
        assert counts["key_pairs"] == 1
        assert counts["eips"] == 1

    def test_is_instance_in_scope_registered(self):
        """Test instance in scope when registered."""
        enforcer = FilterScopeEnforcer()
        enforcer.register_filtered_resources(instance_ids=["i-001"])

        in_scope, reason = enforcer.is_instance_in_scope("i-001")

        assert in_scope is True
        assert "registered" in reason

    def test_is_instance_in_scope_not_registered(self):
        """Test instance not in scope when not registered."""
        enforcer = FilterScopeEnforcer()

        in_scope, reason = enforcer.is_instance_in_scope("i-001")

        assert in_scope is False
        assert "not registered" in reason

    def test_is_volume_in_scope_registered(self):
        """Test volume in scope when registered."""
        enforcer = FilterScopeEnforcer()
        enforcer.register_filtered_resources(volume_ids=["vol-001"])

        in_scope, reason = enforcer.is_volume_in_scope("vol-001")

        assert in_scope is True

    def test_is_volume_in_scope_not_registered(self):
        """Test volume not in scope when not registered."""
        enforcer = FilterScopeEnforcer()

        in_scope, reason = enforcer.is_volume_in_scope("vol-001")

        assert in_scope is False

    def test_is_snapshot_in_scope_registered(self):
        """Test snapshot in scope when registered."""
        enforcer = FilterScopeEnforcer()
        enforcer.register_filtered_resources(snapshot_ids=["snap-001"])

        in_scope, reason = enforcer.is_snapshot_in_scope("snap-001")

        assert in_scope is True

    def test_is_snapshot_in_scope_not_registered(self):
        """Test snapshot not in scope when not registered."""
        enforcer = FilterScopeEnforcer()

        in_scope, reason = enforcer.is_snapshot_in_scope("snap-001")

        assert in_scope is False

    def test_is_security_group_in_scope_registered(self):
        """Test security group in scope when registered."""
        enforcer = FilterScopeEnforcer()
        enforcer.register_filtered_resources(security_group_ids=["sg-001"])

        in_scope, reason = enforcer.is_security_group_in_scope("sg-001")

        assert in_scope is True

    def test_is_security_group_in_scope_not_registered(self):
        """Test security group not in scope when not registered."""
        enforcer = FilterScopeEnforcer()

        in_scope, reason = enforcer.is_security_group_in_scope("sg-001")

        assert in_scope is False

    def test_is_key_pair_in_scope_registered(self):
        """Test key pair in scope when registered."""
        enforcer = FilterScopeEnforcer()
        enforcer.register_filtered_resources(key_pair_ids=["key-001"])

        in_scope, reason = enforcer.is_key_pair_in_scope("key-001")

        assert in_scope is True

    def test_is_key_pair_in_scope_not_registered(self):
        """Test key pair not in scope when not registered."""
        enforcer = FilterScopeEnforcer()

        in_scope, reason = enforcer.is_key_pair_in_scope("key-001")

        assert in_scope is False

    def test_is_eip_in_scope_registered(self):
        """Test EIP in scope when registered."""
        enforcer = FilterScopeEnforcer()
        enforcer.register_filtered_resources(eip_ids=["eipalloc-001"])

        in_scope, reason = enforcer.is_eip_in_scope("eipalloc-001")

        assert in_scope is True

    def test_is_eip_in_scope_not_registered(self):
        """Test EIP not in scope when not registered."""
        enforcer = FilterScopeEnforcer()

        in_scope, reason = enforcer.is_eip_in_scope("eipalloc-001")

        assert in_scope is False

    def test_validate_cleanup_targets_all_registered(self):
        """Test validating cleanup targets when all registered."""
        enforcer = FilterScopeEnforcer()
        enforcer.register_filtered_resources(
            instance_ids=["i-001"],
            volume_ids=["vol-001"],
        )

        result = enforcer.validate_cleanup_targets(
            instance_ids=["i-001"],
            volume_ids=["vol-001"],
        )

        assert result.is_valid is True

    def test_validate_cleanup_targets_some_not_registered(self):
        """Test validating cleanup targets when some not registered."""
        enforcer = FilterScopeEnforcer()
        enforcer.register_filtered_resources(instance_ids=["i-001"])

        result = enforcer.validate_cleanup_targets(
            instance_ids=["i-001", "i-002"],
        )

        assert result.is_valid is False
        assert "i-002" in result.errors[0]

    def test_validate_cleanup_targets_all_types(self):
        """Test validating all resource types."""
        enforcer = FilterScopeEnforcer()

        result = enforcer.validate_cleanup_targets(
            instance_ids=["i-001"],
            volume_ids=["vol-001"],
            snapshot_ids=["snap-001"],
            security_group_ids=["sg-001"],
            key_pair_ids=["key-001"],
            eip_ids=["eipalloc-001"],
        )

        assert result.is_valid is False
        assert len(result.errors) == 6

    def test_clear_registrations(self):
        """Test clearing all registrations."""
        enforcer = FilterScopeEnforcer()
        enforcer.register_filtered_resources(instance_ids=["i-001"])

        enforcer.clear_registrations()
        counts = enforcer.get_registered_counts()

        assert counts["instances"] == 0


class TestValidateCleanupRequest:
    """Tests for validate_cleanup_request function."""

    def test_valid_cleanup_request(self):
        """Test valid cleanup request."""
        result = validate_cleanup_request(
            resource_ids=["i-1234567890abcdef0"],
            resource_type="instance_id",
            region="us-east-1",
            account_id="123456789012",
        )

        assert result.is_valid is True

    def test_invalid_resource_id(self):
        """Test cleanup request with invalid resource ID."""
        result = validate_cleanup_request(
            resource_ids=["invalid-id"],
            resource_type="instance_id",
            region="us-east-1",
            account_id="123456789012",
        )

        assert result.is_valid is False
        assert "does not match expected pattern" in result.errors[0]

    def test_invalid_region(self):
        """Test cleanup request with invalid region."""
        result = validate_cleanup_request(
            resource_ids=["i-1234567890abcdef0"],
            resource_type="instance_id",
            region="invalid",
            account_id="123456789012",
        )

        assert result.is_valid is False

    def test_invalid_account_id(self):
        """Test cleanup request with invalid account ID."""
        result = validate_cleanup_request(
            resource_ids=["i-1234567890abcdef0"],
            resource_type="instance_id",
            region="us-east-1",
            account_id="invalid",
        )

        assert result.is_valid is False


class TestValidateKeyPairPattern:
    """Tests for validate_key_pair_pattern function."""

    def test_valid_key_pair_pattern(self):
        """Test valid key pair matching pattern."""
        result = validate_key_pair_pattern("packer_12345678")

        assert result.is_valid is True
        assert result.sanitized_value == "packer_12345678"

    def test_key_pair_none(self):
        """Test key pair name is None."""
        result = validate_key_pair_pattern(None)

        assert result.is_valid is False
        assert "None" in result.errors[0]

    def test_key_pair_empty(self):
        """Test key pair name is empty."""
        result = validate_key_pair_pattern("")

        assert result.is_valid is False
        assert "empty" in result.errors[0]

    def test_key_pair_dangerous_characters(self):
        """Test key pair with dangerous characters."""
        result = validate_key_pair_pattern("packer_<script>")

        assert result.is_valid is False
        assert "dangerous characters" in result.errors[0]

    def test_key_pair_wrong_pattern(self):
        """Test key pair not matching pattern."""
        result = validate_key_pair_pattern("production_key")

        assert result.is_valid is False
        assert "does not match expected pattern" in result.errors[0]

    def test_key_pair_custom_pattern(self):
        """Test key pair with custom pattern."""
        result = validate_key_pair_pattern("custom_key", pattern="custom_")

        assert result.is_valid is True


class TestValidateInstanceForCleanup:
    """Tests for validate_instance_for_cleanup function."""

    def test_valid_instance_for_cleanup(self):
        """Test valid instance meeting all criteria."""
        result = validate_instance_for_cleanup(
            instance_id="i-1234567890abcdef0",
            key_name="packer_12345678",
            age_hours=5.0,
            max_age_hours=2,
        )

        assert result.is_valid is True

    def test_invalid_instance_id(self):
        """Test instance with invalid ID."""
        result = validate_instance_for_cleanup(
            instance_id="invalid-id",
            key_name="packer_12345678",
            age_hours=5.0,
            max_age_hours=2,
        )

        assert result.is_valid is False
        assert "does not match expected pattern" in result.errors[0]

    def test_invalid_key_name(self):
        """Test instance with invalid key name."""
        result = validate_instance_for_cleanup(
            instance_id="i-1234567890abcdef0",
            key_name="production_key",
            age_hours=5.0,
            max_age_hours=2,
        )

        assert result.is_valid is False
        assert "does not match expected pattern" in result.errors[0]

    def test_instance_too_young(self):
        """Test instance that doesn't exceed age threshold."""
        result = validate_instance_for_cleanup(
            instance_id="i-1234567890abcdef0",
            key_name="packer_12345678",
            age_hours=1.0,
            max_age_hours=2,
        )

        assert result.is_valid is False
        assert "does not exceed threshold" in result.errors[0]

    def test_instance_multiple_errors(self):
        """Test instance with multiple validation errors."""
        result = validate_instance_for_cleanup(
            instance_id="invalid-id",
            key_name="production_key",
            age_hours=1.0,
            max_age_hours=2,
        )

        assert result.is_valid is False
        assert len(result.errors) >= 3
