"""Security validation and input sanitization for AWS Packer Resource Reaper.

This module provides input validation, sanitization, and security boundary
enforcement to prevent injection attacks and ensure operations stay within
configured scope.

Requirements: 6.2, 6.5
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

# AWS Resource ID patterns
AWS_RESOURCE_PATTERNS = {
    "instance_id": re.compile(r"^i-[a-f0-9]{8,17}$"),
    "volume_id": re.compile(r"^vol-[a-f0-9]{8,17}$"),
    "snapshot_id": re.compile(r"^snap-[a-f0-9]{8,17}$"),
    "security_group_id": re.compile(r"^sg-[a-f0-9]{8,17}$"),
    "key_pair_id": re.compile(r"^key-[a-f0-9]{8,17}$"),
    "allocation_id": re.compile(r"^eipalloc-[a-f0-9]{8,17}$"),
    "account_id": re.compile(r"^[0-9]{12}$"),
    "region": re.compile(r"^[a-z]{2}-[a-z]+-[0-9]$"),
    "arn": re.compile(r"^arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[a-zA-Z0-9/_-]+$"),
}

# Characters that could be used in injection attacks
DANGEROUS_CHARACTERS = set("<>{}[]|\\`$;!&*()\"'\n\r\t")

# Maximum lengths for various inputs
MAX_LENGTHS = {
    "tag_key": 128,
    "tag_value": 256,
    "resource_id": 50,
    "region": 20,
    "account_id": 12,
    "pattern": 256,
    "arn": 2048,
}

# Allowed characters for tag keys and values
TAG_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9\s_.:/=+\-@]+$")
TAG_VALUE_PATTERN = re.compile(r"^[a-zA-Z0-9\s_.:/=+\-@]*$")


@dataclass
class ValidationResult:
    """Result of input validation."""

    is_valid: bool
    errors: List[str]
    sanitized_value: Optional[Any] = None

    @classmethod
    def valid(cls, sanitized_value: Any = None) -> "ValidationResult":
        """Create a valid result."""
        return cls(is_valid=True, errors=[], sanitized_value=sanitized_value)

    @classmethod
    def invalid(cls, errors: List[str]) -> "ValidationResult":
        """Create an invalid result."""
        return cls(is_valid=False, errors=errors)


class InputValidator:
    """Validates and sanitizes input parameters to prevent injection attacks."""

    @staticmethod
    def validate_resource_id(resource_id: str, resource_type: str) -> ValidationResult:
        """
        Validate an AWS resource ID.

        Args:
            resource_id: The resource ID to validate
            resource_type: Type of resource (instance_id, volume_id, etc.)

        Returns:
            ValidationResult with validation status and any errors
        """
        errors = []

        if not resource_id:
            return ValidationResult.invalid(["Resource ID cannot be empty"])

        if len(resource_id) > MAX_LENGTHS["resource_id"]:
            errors.append(
                f"Resource ID exceeds maximum length of {MAX_LENGTHS['resource_id']}"
            )

        # Check for dangerous characters
        if any(c in resource_id for c in DANGEROUS_CHARACTERS):
            errors.append("Resource ID contains potentially dangerous characters")

        # Validate against pattern if known type
        pattern = AWS_RESOURCE_PATTERNS.get(resource_type)
        if pattern and not pattern.match(resource_id):
            errors.append(
                f"Resource ID does not match expected pattern for {resource_type}"
            )

        if errors:
            return ValidationResult.invalid(errors)

        return ValidationResult.valid(resource_id)

    @staticmethod
    def validate_region(region: str) -> ValidationResult:
        """
        Validate an AWS region.

        Args:
            region: The region to validate

        Returns:
            ValidationResult with validation status and any errors
        """
        if not region:
            return ValidationResult.invalid(["Region cannot be empty"])

        errors = []

        if len(region) > MAX_LENGTHS["region"]:
            errors.append(f"Region exceeds maximum length of {MAX_LENGTHS['region']}")

        if any(c in region for c in DANGEROUS_CHARACTERS):
            errors.append("Region contains potentially dangerous characters")

        if not AWS_RESOURCE_PATTERNS["region"].match(region):
            errors.append("Region does not match expected pattern (e.g., us-east-1)")

        if errors:
            return ValidationResult.invalid(errors)

        return ValidationResult.valid(region)

    @staticmethod
    def validate_account_id(account_id: str) -> ValidationResult:
        """
        Validate an AWS account ID.

        Args:
            account_id: The account ID to validate

        Returns:
            ValidationResult with validation status and any errors
        """
        if not account_id:
            return ValidationResult.invalid(["Account ID cannot be empty"])

        errors = []

        if len(account_id) != 12:
            errors.append("Account ID must be exactly 12 digits")

        if not AWS_RESOURCE_PATTERNS["account_id"].match(account_id):
            errors.append("Account ID must contain only digits")

        if errors:
            return ValidationResult.invalid(errors)

        return ValidationResult.valid(account_id)

    @staticmethod
    def validate_tag_key(key: str) -> ValidationResult:
        """
        Validate a tag key.

        Args:
            key: The tag key to validate

        Returns:
            ValidationResult with validation status and any errors
        """
        if not key:
            return ValidationResult.invalid(["Tag key cannot be empty"])

        errors = []

        if len(key) > MAX_LENGTHS["tag_key"]:
            errors.append(f"Tag key exceeds maximum length of {MAX_LENGTHS['tag_key']}")

        if not TAG_KEY_PATTERN.match(key):
            errors.append("Tag key contains invalid characters")

        if errors:
            return ValidationResult.invalid(errors)

        return ValidationResult.valid(key)

    @staticmethod
    def validate_tag_value(value: str) -> ValidationResult:
        """
        Validate a tag value.

        Args:
            value: The tag value to validate

        Returns:
            ValidationResult with validation status and any errors
        """
        # Empty tag values are allowed
        if not value:
            return ValidationResult.valid(value)

        errors = []

        if len(value) > MAX_LENGTHS["tag_value"]:
            errors.append(
                f"Tag value exceeds maximum length of {MAX_LENGTHS['tag_value']}"
            )

        if not TAG_VALUE_PATTERN.match(value):
            errors.append("Tag value contains invalid characters")

        if errors:
            return ValidationResult.invalid(errors)

        return ValidationResult.valid(value)

    @staticmethod
    def validate_tags(tags: Dict[str, str]) -> ValidationResult:
        """
        Validate a dictionary of tags.

        Args:
            tags: Dictionary of tag key-value pairs

        Returns:
            ValidationResult with validation status and any errors
        """
        if not isinstance(tags, dict):
            return ValidationResult.invalid(["Tags must be a dictionary"])

        errors = []
        sanitized_tags = {}

        for key, value in tags.items():
            key_result = InputValidator.validate_tag_key(key)
            if not key_result.is_valid:
                errors.extend([f"Tag key '{key}': {e}" for e in key_result.errors])
                continue

            value_result = InputValidator.validate_tag_value(value)
            if not value_result.is_valid:
                errors.extend(
                    [f"Tag value for '{key}': {e}" for e in value_result.errors]
                )
                continue

            sanitized_tags[key] = value

        if errors:
            return ValidationResult.invalid(errors)

        return ValidationResult.valid(sanitized_tags)

    @staticmethod
    def validate_pattern(pattern: str) -> ValidationResult:
        """
        Validate a regex pattern for safety.

        Args:
            pattern: The regex pattern to validate

        Returns:
            ValidationResult with validation status and any errors
        """
        if not pattern:
            return ValidationResult.invalid(["Pattern cannot be empty"])

        errors = []

        if len(pattern) > MAX_LENGTHS["pattern"]:
            errors.append(f"Pattern exceeds maximum length of {MAX_LENGTHS['pattern']}")

        # Try to compile the pattern to check for validity
        try:
            re.compile(pattern)
        except re.error as e:
            errors.append(f"Invalid regex pattern: {e}")

        # Check for potentially dangerous regex patterns (ReDoS)
        dangerous_patterns = [
            r"(.+)+",  # Nested quantifiers
            r"(.*)*",  # Nested quantifiers
            r"(a+)+",  # Nested quantifiers
            r"(a|a)+",  # Overlapping alternation
        ]
        for dangerous in dangerous_patterns:
            if dangerous in pattern:
                errors.append("Pattern contains potentially dangerous regex constructs")
                break

        if errors:
            return ValidationResult.invalid(errors)

        return ValidationResult.valid(pattern)

    @staticmethod
    def validate_arn(arn: str) -> ValidationResult:
        """
        Validate an AWS ARN.

        Args:
            arn: The ARN to validate

        Returns:
            ValidationResult with validation status and any errors
        """
        if not arn:
            return ValidationResult.invalid(["ARN cannot be empty"])

        errors = []

        if len(arn) > MAX_LENGTHS["arn"]:
            errors.append(f"ARN exceeds maximum length of {MAX_LENGTHS['arn']}")

        if any(c in arn for c in DANGEROUS_CHARACTERS - {":"}):
            errors.append("ARN contains potentially dangerous characters")

        if not arn.startswith("arn:aws:"):
            errors.append("ARN must start with 'arn:aws:'")

        # Basic ARN structure validation
        parts = arn.split(":")
        if len(parts) < 6:
            errors.append("ARN does not have enough components")

        if errors:
            return ValidationResult.invalid(errors)

        return ValidationResult.valid(arn)


class ScopeEnforcer:
    """Enforces resource scope boundaries for security.

    This implements Requirements 8.1-8.6: single account/region boundary
    enforcement. The reaper only operates within the deployed AWS account
    and region.
    """

    def __init__(
        self,
        allowed_regions: Optional[Set[str]] = None,
        allowed_account_ids: Optional[Set[str]] = None,
    ):
        """
        Initialize scope enforcer.

        Args:
            allowed_regions: Set of regions that operations are allowed in
            allowed_account_ids: Set of account IDs that operations are allowed in
        """
        self.allowed_regions = allowed_regions
        self.allowed_account_ids = allowed_account_ids

    def is_region_in_scope(self, region: str) -> Tuple[bool, str]:
        """
        Check if a region is within the allowed scope.

        Args:
            region: The region to check

        Returns:
            Tuple of (is_in_scope, reason)
        """
        if self.allowed_regions is None:
            return True, "No region restrictions configured"

        if region in self.allowed_regions:
            return True, f"Region {region} is in allowed list"

        return False, f"Region {region} is not in allowed list: {self.allowed_regions}"

    def is_account_in_scope(self, account_id: str) -> Tuple[bool, str]:
        """
        Check if an account is within the allowed scope.

        Args:
            account_id: The account ID to check

        Returns:
            Tuple of (is_in_scope, reason)
        """
        if self.allowed_account_ids is None:
            return True, "No account restrictions configured"

        if account_id in self.allowed_account_ids:
            return True, f"Account {account_id} is in allowed list"

        return False, f"Account {account_id} is not in allowed list"

    def is_resource_in_scope(
        self,
        region: str,
        account_id: str,
    ) -> Tuple[bool, List[str]]:
        """
        Check if a resource is within the allowed scope.

        This implements Requirements 8.1-8.6: single account/region boundary.

        Args:
            region: The resource's region
            account_id: The resource's account ID

        Returns:
            Tuple of (is_in_scope, list of reasons)
        """
        reasons = []

        # Check region scope (Requirements 8.3, 8.4)
        region_in_scope, region_reason = self.is_region_in_scope(region)
        if not region_in_scope:
            reasons.append(region_reason)

        # Check account scope (Requirements 8.1, 8.2)
        account_in_scope, account_reason = self.is_account_in_scope(account_id)
        if not account_in_scope:
            reasons.append(account_reason)

        is_in_scope = len(reasons) == 0
        return is_in_scope, reasons


class LogSanitizer:
    """Sanitizes log output to prevent sensitive data exposure."""

    # Patterns for sensitive data
    SENSITIVE_PATTERNS = [
        (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_ACCESS_KEY]"),
        (re.compile(r"(?i)password\s*[=:]\s*\S+"), "password=[REDACTED]"),
        (re.compile(r"(?i)secret\s*[=:]\s*\S+"), "secret=[REDACTED]"),
        (re.compile(r"(?i)token\s*[=:]\s*\S+"), "token=[REDACTED]"),
        (re.compile(r"(?i)api[_-]?key\s*[=:]\s*\S+"), "api_key=[REDACTED]"),
        (re.compile(r"[a-zA-Z0-9+/]{40}"), "[REDACTED_SECRET]"),  # Base64 secrets
    ]

    @classmethod
    def sanitize(cls, message: str) -> str:
        """
        Sanitize a log message to remove sensitive data.

        Args:
            message: The message to sanitize

        Returns:
            Sanitized message
        """
        sanitized = message
        for pattern, replacement in cls.SENSITIVE_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a dictionary for logging.

        Args:
            data: Dictionary to sanitize

        Returns:
            Sanitized dictionary
        """
        sanitized = {}
        sensitive_keys = {"password", "secret", "token", "key", "credential", "auth"}

        for key, value in data.items():
            key_lower = key.lower()
            if any(s in key_lower for s in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, str):
                sanitized[key] = cls.sanitize(value)
            elif isinstance(value, dict):
                sanitized[key] = cls.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    cls.sanitize(v) if isinstance(v, str) else v for v in value
                ]
            else:
                sanitized[key] = value

        return sanitized


def validate_cleanup_request(
    resource_ids: List[str],
    resource_type: str,
    region: str,
    account_id: str,
) -> ValidationResult:
    """
    Validate a cleanup request for security.

    Args:
        resource_ids: List of resource IDs to clean up
        resource_type: Type of resources
        region: Target region
        account_id: Target account ID

    Returns:
        ValidationResult with validation status and any errors
    """
    errors = []

    # Validate each resource ID
    for resource_id in resource_ids:
        result = InputValidator.validate_resource_id(resource_id, resource_type)
        if not result.is_valid:
            errors.extend([f"Resource {resource_id}: {e}" for e in result.errors])

    # Validate region
    region_result = InputValidator.validate_region(region)
    if not region_result.is_valid:
        errors.extend(region_result.errors)

    # Validate account ID
    account_result = InputValidator.validate_account_id(account_id)
    if not account_result.is_valid:
        errors.extend(account_result.errors)

    if errors:
        return ValidationResult.invalid(errors)

    return ValidationResult.valid()


class FilterScopeEnforcer:
    """Enforces that cleanup operations only target filter-matched resources.

    This implements Requirement 7.2: WHEN accessing resources, THE Reaper SHALL
    only operate on resources that match the configured filters.

    The enforcer maintains a registry of resources that have passed through
    the filter pipeline and validates that any cleanup operation only targets
    those registered resources.
    """

    def __init__(self):
        """Initialize the filter scope enforcer with empty registries."""
        self._registered_instance_ids: Set[str] = set()
        self._registered_volume_ids: Set[str] = set()
        self._registered_snapshot_ids: Set[str] = set()
        self._registered_security_group_ids: Set[str] = set()
        self._registered_key_pair_ids: Set[str] = set()
        self._registered_eip_ids: Set[str] = set()

    def register_filtered_resources(
        self,
        instance_ids: Optional[List[str]] = None,
        volume_ids: Optional[List[str]] = None,
        snapshot_ids: Optional[List[str]] = None,
        security_group_ids: Optional[List[str]] = None,
        key_pair_ids: Optional[List[str]] = None,
        eip_ids: Optional[List[str]] = None,
    ) -> None:
        """
        Register resources that have passed through the filter pipeline.

        Only registered resources can be targeted for cleanup operations.

        Args:
            instance_ids: List of instance IDs that passed filters
            volume_ids: List of volume IDs that passed filters
            snapshot_ids: List of snapshot IDs that passed filters
            security_group_ids: List of security group IDs that passed filters
            key_pair_ids: List of key pair IDs that passed filters
            eip_ids: List of EIP IDs that passed filters
        """
        if instance_ids:
            self._registered_instance_ids.update(instance_ids)
        if volume_ids:
            self._registered_volume_ids.update(volume_ids)
        if snapshot_ids:
            self._registered_snapshot_ids.update(snapshot_ids)
        if security_group_ids:
            self._registered_security_group_ids.update(security_group_ids)
        if key_pair_ids:
            self._registered_key_pair_ids.update(key_pair_ids)
        if eip_ids:
            self._registered_eip_ids.update(eip_ids)

    def is_instance_in_scope(self, instance_id: str) -> Tuple[bool, str]:
        """
        Check if an instance is registered for cleanup.

        Args:
            instance_id: The instance ID to check

        Returns:
            Tuple of (is_in_scope, reason)
        """
        if instance_id in self._registered_instance_ids:
            return True, f"Instance {instance_id} is registered for cleanup"
        return (
            False,
            f"Instance {instance_id} was not registered through filter pipeline",
        )

    def is_volume_in_scope(self, volume_id: str) -> Tuple[bool, str]:
        """
        Check if a volume is registered for cleanup.

        Args:
            volume_id: The volume ID to check

        Returns:
            Tuple of (is_in_scope, reason)
        """
        if volume_id in self._registered_volume_ids:
            return True, f"Volume {volume_id} is registered for cleanup"
        return False, f"Volume {volume_id} was not registered through filter pipeline"

    def is_snapshot_in_scope(self, snapshot_id: str) -> Tuple[bool, str]:
        """
        Check if a snapshot is registered for cleanup.

        Args:
            snapshot_id: The snapshot ID to check

        Returns:
            Tuple of (is_in_scope, reason)
        """
        if snapshot_id in self._registered_snapshot_ids:
            return True, f"Snapshot {snapshot_id} is registered for cleanup"
        return (
            False,
            f"Snapshot {snapshot_id} was not registered through filter pipeline",
        )

    def is_security_group_in_scope(self, sg_id: str) -> Tuple[bool, str]:
        """
        Check if a security group is registered for cleanup.

        Args:
            sg_id: The security group ID to check

        Returns:
            Tuple of (is_in_scope, reason)
        """
        if sg_id in self._registered_security_group_ids:
            return True, f"Security group {sg_id} is registered for cleanup"
        return (
            False,
            f"Security group {sg_id} was not registered through filter pipeline",
        )

    def is_key_pair_in_scope(self, key_pair_id: str) -> Tuple[bool, str]:
        """
        Check if a key pair is registered for cleanup.

        Args:
            key_pair_id: The key pair ID to check

        Returns:
            Tuple of (is_in_scope, reason)
        """
        if key_pair_id in self._registered_key_pair_ids:
            return True, f"Key pair {key_pair_id} is registered for cleanup"
        return (
            False,
            f"Key pair {key_pair_id} was not registered through filter pipeline",
        )

    def is_eip_in_scope(self, eip_id: str) -> Tuple[bool, str]:
        """
        Check if an EIP is registered for cleanup.

        Args:
            eip_id: The EIP ID to check

        Returns:
            Tuple of (is_in_scope, reason)
        """
        if eip_id in self._registered_eip_ids:
            return True, f"EIP {eip_id} is registered for cleanup"
        return False, f"EIP {eip_id} was not registered through filter pipeline"

    def validate_cleanup_targets(
        self,
        instance_ids: Optional[List[str]] = None,
        volume_ids: Optional[List[str]] = None,
        snapshot_ids: Optional[List[str]] = None,
        security_group_ids: Optional[List[str]] = None,
        key_pair_ids: Optional[List[str]] = None,
        eip_ids: Optional[List[str]] = None,
    ) -> ValidationResult:
        """
        Validate that all cleanup targets are registered through the filter pipeline.

        This is the main enforcement method that ensures Requirement 7.2 is met:
        only resources that match configured filters can be cleaned up.

        Args:
            instance_ids: Instance IDs to validate
            volume_ids: Volume IDs to validate
            snapshot_ids: Snapshot IDs to validate
            security_group_ids: Security group IDs to validate
            key_pair_ids: Key pair IDs to validate
            eip_ids: EIP IDs to validate

        Returns:
            ValidationResult with validation status and any errors
        """
        errors = []

        # Validate instances
        for instance_id in instance_ids or []:
            in_scope, reason = self.is_instance_in_scope(instance_id)
            if not in_scope:
                errors.append(reason)

        # Validate volumes
        for volume_id in volume_ids or []:
            in_scope, reason = self.is_volume_in_scope(volume_id)
            if not in_scope:
                errors.append(reason)

        # Validate snapshots
        for snapshot_id in snapshot_ids or []:
            in_scope, reason = self.is_snapshot_in_scope(snapshot_id)
            if not in_scope:
                errors.append(reason)

        # Validate security groups
        for sg_id in security_group_ids or []:
            in_scope, reason = self.is_security_group_in_scope(sg_id)
            if not in_scope:
                errors.append(reason)

        # Validate key pairs
        for key_pair_id in key_pair_ids or []:
            in_scope, reason = self.is_key_pair_in_scope(key_pair_id)
            if not in_scope:
                errors.append(reason)

        # Validate EIPs
        for eip_id in eip_ids or []:
            in_scope, reason = self.is_eip_in_scope(eip_id)
            if not in_scope:
                errors.append(reason)

        if errors:
            return ValidationResult.invalid(errors)

        return ValidationResult.valid()

    def clear_registrations(self) -> None:
        """Clear all registered resources. Useful for testing or reset."""
        self._registered_instance_ids.clear()
        self._registered_volume_ids.clear()
        self._registered_snapshot_ids.clear()
        self._registered_security_group_ids.clear()
        self._registered_key_pair_ids.clear()
        self._registered_eip_ids.clear()

    def get_registered_counts(self) -> Dict[str, int]:
        """
        Get counts of registered resources by type.

        Returns:
            Dictionary with resource type as key and count as value
        """
        return {
            "instances": len(self._registered_instance_ids),
            "volumes": len(self._registered_volume_ids),
            "snapshots": len(self._registered_snapshot_ids),
            "security_groups": len(self._registered_security_group_ids),
            "key_pairs": len(self._registered_key_pair_ids),
            "eips": len(self._registered_eip_ids),
        }


def validate_key_pair_pattern(
    key_name: Optional[str], pattern: str = "packer_"
) -> ValidationResult:
    """
    Validate that a key pair name matches the expected Packer pattern.

    This implements part of Requirement 7.2: ensuring operations only target
    resources that match the configured filters (specifically the key pair pattern).

    Args:
        key_name: The key pair name to validate
        pattern: The expected pattern prefix (default: "packer_")

    Returns:
        ValidationResult with validation status and any errors
    """
    if key_name is None:
        return ValidationResult.invalid(["Key pair name is None"])

    if not key_name:
        return ValidationResult.invalid(["Key pair name is empty"])

    # Check for dangerous characters
    if any(c in key_name for c in DANGEROUS_CHARACTERS):
        return ValidationResult.invalid(["Key pair name contains dangerous characters"])

    # Check pattern match
    if not key_name.startswith(pattern):
        return ValidationResult.invalid(
            [f"Key pair name '{key_name}' does not match expected pattern '{pattern}*'"]
        )

    return ValidationResult.valid(key_name)


def validate_instance_for_cleanup(
    instance_id: str,
    key_name: Optional[str],
    age_hours: float,
    max_age_hours: int,
    key_pattern: str = "packer_",
) -> ValidationResult:
    """
    Validate that an instance meets all criteria for cleanup.

    This is a comprehensive validation that checks both the two-criteria filter
    (key pair pattern + age threshold) and input validation requirements.

    Implements Requirements 1.1, 1.2, 7.2.

    Args:
        instance_id: The instance ID to validate
        key_name: The instance's key pair name
        age_hours: The instance's age in hours
        max_age_hours: The maximum age threshold
        key_pattern: The expected key pair pattern prefix

    Returns:
        ValidationResult with validation status and any errors
    """
    errors = []

    # Validate instance ID format
    id_result = InputValidator.validate_resource_id(instance_id, "instance_id")
    if not id_result.is_valid:
        errors.extend(id_result.errors)

    # Validate key pair pattern (Requirement 1.2)
    key_result = validate_key_pair_pattern(key_name, key_pattern)
    if not key_result.is_valid:
        errors.extend(key_result.errors)

    # Validate age threshold (Requirement 1.1)
    if age_hours <= max_age_hours:
        errors.append(
            f"Instance age ({age_hours:.2f} hours) does not exceed threshold ({max_age_hours} hours)"
        )

    if errors:
        return ValidationResult.invalid(errors)

    return ValidationResult.valid()
