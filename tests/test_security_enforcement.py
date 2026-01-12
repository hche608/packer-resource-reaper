"""Property-based tests for security and scope enforcement.

Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement
Validates: Requirements 7.2, 7.4, 8.1-8.6
"""

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from reaper.utils.security import (
    DANGEROUS_CHARACTERS,
    MAX_LENGTHS,
    FilterScopeEnforcer,
    InputValidator,
    LogSanitizer,
    ScopeEnforcer,
    validate_instance_for_cleanup,
    validate_key_pair_pattern,
)

# Strategies for valid AWS resource IDs
valid_instance_id_strategy = st.from_regex(r"i-[a-f0-9]{8,17}", fullmatch=True)
valid_volume_id_strategy = st.from_regex(r"vol-[a-f0-9]{8,17}", fullmatch=True)
valid_snapshot_id_strategy = st.from_regex(r"snap-[a-f0-9]{8,17}", fullmatch=True)
valid_sg_id_strategy = st.from_regex(r"sg-[a-f0-9]{8,17}", fullmatch=True)
valid_vpc_id_strategy = st.from_regex(r"vpc-[a-f0-9]{8,17}", fullmatch=True)
valid_account_id_strategy = st.from_regex(r"[0-9]{12}", fullmatch=True)
valid_region_strategy = st.sampled_from(
    ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "sa-east-1"]
)

# Strategy for invalid resource IDs (containing dangerous characters)
dangerous_char_strategy = st.sampled_from(list(DANGEROUS_CHARACTERS))

# Strategy for valid tag keys and values
valid_tag_key_strategy = st.from_regex(r"[a-zA-Z][a-zA-Z0-9_-]{0,126}", fullmatch=True)
valid_tag_value_strategy = st.from_regex(r"[a-zA-Z0-9_-]{0,255}", fullmatch=True)

# Strategy for tags dictionary
valid_tags_strategy = st.dictionaries(
    keys=valid_tag_key_strategy,
    values=valid_tag_value_strategy,
    min_size=0,
    max_size=5,
)


@settings(max_examples=100, deadline=5000)
@given(instance_id=valid_instance_id_strategy)
def test_valid_instance_id_passes_validation(instance_id: str):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    For any valid EC2 instance ID (i-xxxxxxxx format), the input validator
    should accept it without errors.

    Validates: Requirements 6.5
    """
    result = InputValidator.validate_resource_id(instance_id, "instance_id")

    assert result.is_valid, f"Valid instance ID {instance_id} should pass validation"
    assert len(result.errors) == 0


@settings(max_examples=100, deadline=5000)
@given(volume_id=valid_volume_id_strategy)
def test_valid_volume_id_passes_validation(volume_id: str):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    For any valid EBS volume ID (vol-xxxxxxxx format), the input validator
    should accept it without errors.

    Validates: Requirements 6.5
    """
    result = InputValidator.validate_resource_id(volume_id, "volume_id")

    assert result.is_valid, f"Valid volume ID {volume_id} should pass validation"
    assert len(result.errors) == 0


@settings(max_examples=100, deadline=5000)
@given(region=valid_region_strategy)
def test_valid_region_passes_validation(region: str):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    For any valid AWS region, the input validator should accept it without errors.

    Validates: Requirements 6.5
    """
    result = InputValidator.validate_region(region)

    assert result.is_valid, f"Valid region {region} should pass validation"
    assert len(result.errors) == 0


@settings(max_examples=100, deadline=5000)
@given(tags=valid_tags_strategy)
def test_valid_tags_pass_validation(tags: dict[str, str]):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    For any dictionary of valid tag key-value pairs, the input validator
    should accept them without errors.

    Validates: Requirements 6.5
    """
    result = InputValidator.validate_tags(tags)

    assert result.is_valid, f"Valid tags {tags} should pass validation"
    assert len(result.errors) == 0


@settings(max_examples=100, deadline=5000)
@given(
    region=valid_region_strategy,
    allowed_regions=st.lists(valid_region_strategy, min_size=1, max_size=3),
)
def test_scope_enforcer_region_restriction(region: str, allowed_regions: list):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    For any region and set of allowed regions, the scope enforcer should only
    allow operations on resources within the allowed regions.

    Validates: Requirements 6.2
    """
    enforcer = ScopeEnforcer(allowed_regions=set(allowed_regions))

    in_scope, reason = enforcer.is_region_in_scope(region)

    if region in allowed_regions:
        assert in_scope, f"Region {region} should be in scope when in allowed list"
    else:
        assert not in_scope, f"Region {region} should not be in scope when not in allowed list"


@settings(max_examples=100, deadline=5000)
@given(
    account_id=valid_account_id_strategy,
    allowed_accounts=st.lists(valid_account_id_strategy, min_size=1, max_size=3),
)
def test_scope_enforcer_account_restriction(account_id: str, allowed_accounts: list):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    For any account ID and set of allowed accounts, the scope enforcer should only
    allow operations on resources within the allowed accounts.

    Validates: Requirements 8.1, 8.2
    """
    enforcer = ScopeEnforcer(allowed_account_ids=set(allowed_accounts))

    in_scope, reason = enforcer.is_account_in_scope(account_id)

    if account_id in allowed_accounts:
        assert in_scope, f"Account {account_id} should be in scope when in allowed list"
    else:
        assert not in_scope, f"Account {account_id} should not be in scope when not in allowed list"


@settings(max_examples=100, deadline=5000)
@given(
    message=st.text(min_size=0, max_size=500),
)
def test_log_sanitizer_removes_access_keys(message: str):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    For any log message containing AWS access key patterns, the log sanitizer
    should redact them to prevent sensitive data exposure.

    Validates: Requirements 6.4
    """
    # Inject a fake access key into the message
    fake_key = "AKIAIOSFODNN7EXAMPLE"
    message_with_key = f"{message} key={fake_key} end"

    sanitized = LogSanitizer.sanitize(message_with_key)

    assert fake_key not in sanitized, "Access key should be redacted from log message"
    assert "[REDACTED" in sanitized, "Redaction marker should be present"


@settings(max_examples=100, deadline=5000)
@given(
    data=st.dictionaries(
        keys=st.text(min_size=1, max_size=20),
        values=st.text(min_size=0, max_size=50),
        min_size=0,
        max_size=5,
    ),
)
def test_log_sanitizer_dict_redacts_sensitive_keys(data: dict[str, str]):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    For any dictionary with sensitive key names (password, secret, token),
    the log sanitizer should redact their values.

    Validates: Requirements 7.4
    """
    # Add a sensitive key
    data_with_secret = {**data, "password": "super_secret_123"}

    sanitized = LogSanitizer.sanitize_dict(data_with_secret)

    assert sanitized.get("password") == "[REDACTED]", "Password value should be redacted"


@settings(max_examples=100, deadline=5000)
@given(
    region=valid_region_strategy,
    account_id=valid_account_id_strategy,
)
def test_scope_enforcer_no_restrictions_allows_all(
    region: str,
    account_id: str,
):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    When no scope restrictions are configured, all resources should be in scope.

    Validates: Requirements 8.1-8.6
    """
    # Create enforcer with no restrictions
    enforcer = ScopeEnforcer()

    in_scope, reasons = enforcer.is_resource_in_scope(
        region=region,
        account_id=account_id,
    )

    assert in_scope, "Resource without restrictions should be in scope"
    assert len(reasons) == 0


@settings(max_examples=100, deadline=5000)
@given(
    region=valid_region_strategy,
    account_id=valid_account_id_strategy,
)
def test_scope_enforcer_combined_restrictions(
    region: str,
    account_id: str,
):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    When multiple scope restrictions are configured, a resource must satisfy
    ALL restrictions to be in scope.

    Validates: Requirements 8.1-8.6
    """
    # Create enforcer with specific restrictions
    enforcer = ScopeEnforcer(
        allowed_regions={region},
        allowed_account_ids={account_id},
    )

    # Resource matching all restrictions should be in scope
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=region,
        account_id=account_id,
    )

    assert in_scope, "Resource matching all restrictions should be in scope"
    assert len(reasons) == 0, "No exclusion reasons should be present"


@settings(max_examples=100, deadline=5000)
@given(
    region=valid_region_strategy,
    other_region=valid_region_strategy,
    account_id=valid_account_id_strategy,
)
def test_scope_enforcer_partial_match_excluded(
    region: str,
    other_region: str,
    account_id: str,
):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    When a resource only partially matches scope restrictions (e.g., wrong region),
    it should be excluded from scope.

    Validates: Requirements 8.3, 8.4
    """
    assume(region != other_region)  # Ensure regions are different

    # Create enforcer allowing only specific region
    enforcer = ScopeEnforcer(
        allowed_regions={region},
        allowed_account_ids={account_id},
    )

    # Resource with different region should be excluded
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=other_region,  # Different region
        account_id=account_id,
    )

    assert not in_scope, "Resource with wrong region should be excluded"
    assert len(reasons) > 0, "Exclusion reason should be provided"


@settings(max_examples=100, deadline=5000)
@given(
    long_string=st.text(min_size=MAX_LENGTHS["resource_id"] + 1, max_size=100),
)
def test_input_validator_rejects_oversized_inputs(long_string: str):
    """
    Feature: packer-resource-reaper, Property 9: Security and Scope Enforcement

    For any input exceeding maximum allowed length, the input validator
    should reject it to prevent buffer overflow or DoS attacks.

    Validates: Requirements 6.5
    """
    result = InputValidator.validate_resource_id(long_string, "instance_id")

    assert not result.is_valid, "Oversized input should be rejected"
    assert any("length" in e.lower() for e in result.errors), (
        "Error should mention length violation"
    )


# =============================================================================
# Property 8: Security and Scope Enforcement
# Validates: Requirements 7.2, 7.4, 8.1-8.6
# =============================================================================


@settings(max_examples=100, deadline=5000)
@given(
    instance_ids=st.lists(valid_instance_id_strategy, min_size=1, max_size=5),
    extra_instance_id=valid_instance_id_strategy,
)
def test_filter_scope_enforcer_only_allows_registered_instances(
    instance_ids: list,
    extra_instance_id: str,
):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any set of registered instance IDs, the FilterScopeEnforcer should only
    allow cleanup operations on those registered instances. Unregistered instances
    should be rejected.

    Validates: Requirements 7.2
    """
    assume(extra_instance_id not in instance_ids)

    enforcer = FilterScopeEnforcer()
    enforcer.register_filtered_resources(instance_ids=instance_ids)

    # Registered instances should be in scope
    for instance_id in instance_ids:
        in_scope, reason = enforcer.is_instance_in_scope(instance_id)
        assert in_scope, f"Registered instance {instance_id} should be in scope"

    # Unregistered instance should NOT be in scope
    in_scope, reason = enforcer.is_instance_in_scope(extra_instance_id)
    assert not in_scope, f"Unregistered instance {extra_instance_id} should not be in scope"


@settings(max_examples=100, deadline=5000)
@given(
    volume_ids=st.lists(valid_volume_id_strategy, min_size=1, max_size=5),
    extra_volume_id=valid_volume_id_strategy,
)
def test_filter_scope_enforcer_only_allows_registered_volumes(
    volume_ids: list,
    extra_volume_id: str,
):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any set of registered volume IDs, the FilterScopeEnforcer should only
    allow cleanup operations on those registered volumes.

    Validates: Requirements 7.2
    """
    assume(extra_volume_id not in volume_ids)

    enforcer = FilterScopeEnforcer()
    enforcer.register_filtered_resources(volume_ids=volume_ids)

    # Registered volumes should be in scope
    for volume_id in volume_ids:
        in_scope, reason = enforcer.is_volume_in_scope(volume_id)
        assert in_scope, f"Registered volume {volume_id} should be in scope"

    # Unregistered volume should NOT be in scope
    in_scope, reason = enforcer.is_volume_in_scope(extra_volume_id)
    assert not in_scope, f"Unregistered volume {extra_volume_id} should not be in scope"


@settings(max_examples=100, deadline=5000)
@given(
    sg_ids=st.lists(valid_sg_id_strategy, min_size=1, max_size=5),
    extra_sg_id=valid_sg_id_strategy,
)
def test_filter_scope_enforcer_only_allows_registered_security_groups(
    sg_ids: list,
    extra_sg_id: str,
):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any set of registered security group IDs, the FilterScopeEnforcer should
    only allow cleanup operations on those registered security groups.

    Validates: Requirements 7.2
    """
    assume(extra_sg_id not in sg_ids)

    enforcer = FilterScopeEnforcer()
    enforcer.register_filtered_resources(security_group_ids=sg_ids)

    # Registered security groups should be in scope
    for sg_id in sg_ids:
        in_scope, reason = enforcer.is_security_group_in_scope(sg_id)
        assert in_scope, f"Registered security group {sg_id} should be in scope"

    # Unregistered security group should NOT be in scope
    in_scope, reason = enforcer.is_security_group_in_scope(extra_sg_id)
    assert not in_scope, f"Unregistered security group {extra_sg_id} should not be in scope"


@settings(max_examples=100, deadline=5000)
@given(
    instance_ids=st.lists(valid_instance_id_strategy, min_size=0, max_size=3),
    volume_ids=st.lists(valid_volume_id_strategy, min_size=0, max_size=3),
    unregistered_instance=valid_instance_id_strategy,
)
def test_filter_scope_enforcer_validate_cleanup_targets(
    instance_ids: list,
    volume_ids: list,
    unregistered_instance: str,
):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any set of registered resources, validate_cleanup_targets should accept
    only registered resources and reject any unregistered ones.

    Validates: Requirements 7.2
    """
    assume(unregistered_instance not in instance_ids)

    enforcer = FilterScopeEnforcer()
    enforcer.register_filtered_resources(
        instance_ids=instance_ids,
        volume_ids=volume_ids,
    )

    # Validating registered resources should succeed
    result = enforcer.validate_cleanup_targets(
        instance_ids=instance_ids,
        volume_ids=volume_ids,
    )
    assert result.is_valid, "Registered resources should pass validation"

    # Validating with unregistered instance should fail
    result = enforcer.validate_cleanup_targets(
        instance_ids=[unregistered_instance],
    )
    assert not result.is_valid, "Unregistered instance should fail validation"
    assert len(result.errors) > 0


@settings(max_examples=100, deadline=5000)
@given(
    key_name=st.from_regex(r"packer_[a-z0-9]{8,16}", fullmatch=True),
)
def test_key_pair_pattern_validation_accepts_valid_packer_keys(key_name: str):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any key pair name starting with 'packer_', the pattern validation
    should accept it as a valid Packer key pair.

    Validates: Requirements 7.2, 1.2
    """
    result = validate_key_pair_pattern(key_name, "packer_")

    assert result.is_valid, f"Valid Packer key '{key_name}' should pass validation"
    assert len(result.errors) == 0


@settings(max_examples=100, deadline=5000)
@given(
    key_name=st.text(min_size=1, max_size=30).filter(
        lambda x: not x.startswith("packer_") and not any(c in x for c in DANGEROUS_CHARACTERS)
    ),
)
def test_key_pair_pattern_validation_rejects_non_packer_keys(key_name: str):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any key pair name NOT starting with 'packer_', the pattern validation
    should reject it to ensure only Packer resources are targeted.

    Validates: Requirements 7.2, 1.2
    """
    result = validate_key_pair_pattern(key_name, "packer_")

    assert not result.is_valid, f"Non-Packer key '{key_name}' should fail validation"
    assert len(result.errors) > 0


@settings(max_examples=100, deadline=5000)
@given(
    instance_id=valid_instance_id_strategy,
    key_name=st.from_regex(r"packer_[a-z0-9]{8,16}", fullmatch=True),
    age_hours=st.floats(min_value=3.0, max_value=168.0),
    max_age_hours=st.integers(min_value=1, max_value=2),
)
def test_instance_cleanup_validation_accepts_matching_instances(
    instance_id: str,
    key_name: str,
    age_hours: float,
    max_age_hours: int,
):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any instance that matches BOTH criteria (packer_* key pattern AND
    age exceeds threshold), the validation should accept it for cleanup.

    Validates: Requirements 7.2, 1.1, 1.2
    """
    # Ensure age exceeds threshold
    assume(age_hours > max_age_hours)

    result = validate_instance_for_cleanup(
        instance_id=instance_id,
        key_name=key_name,
        age_hours=age_hours,
        max_age_hours=max_age_hours,
        key_pattern="packer_",
    )

    assert result.is_valid, "Instance matching both criteria should pass validation"


@settings(max_examples=100, deadline=5000)
@given(
    instance_id=valid_instance_id_strategy,
    key_name=st.text(min_size=1, max_size=20).filter(
        lambda x: not x.startswith("packer_") and not any(c in x for c in DANGEROUS_CHARACTERS)
    ),
    age_hours=st.floats(min_value=3.0, max_value=168.0),
    max_age_hours=st.integers(min_value=1, max_value=2),
)
def test_instance_cleanup_validation_rejects_wrong_key_pattern(
    instance_id: str,
    key_name: str,
    age_hours: float,
    max_age_hours: int,
):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any instance with a key pair NOT matching 'packer_*' pattern,
    the validation should reject it even if age exceeds threshold.

    Validates: Requirements 7.2, 1.2
    """
    assume(age_hours > max_age_hours)

    result = validate_instance_for_cleanup(
        instance_id=instance_id,
        key_name=key_name,
        age_hours=age_hours,
        max_age_hours=max_age_hours,
        key_pattern="packer_",
    )

    assert not result.is_valid, "Instance with wrong key pattern should fail validation"
    assert any("pattern" in e.lower() for e in result.errors)


@settings(max_examples=100, deadline=5000)
@given(
    instance_id=valid_instance_id_strategy,
    key_name=st.from_regex(r"packer_[a-z0-9]{8,16}", fullmatch=True),
    age_hours=st.floats(min_value=0.1, max_value=1.5),
    max_age_hours=st.integers(min_value=2, max_value=24),
)
def test_instance_cleanup_validation_rejects_young_instances(
    instance_id: str,
    key_name: str,
    age_hours: float,
    max_age_hours: int,
):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any instance with age NOT exceeding the threshold,
    the validation should reject it even if key pattern matches.

    Validates: Requirements 7.2, 1.1
    """
    assume(age_hours <= max_age_hours)

    result = validate_instance_for_cleanup(
        instance_id=instance_id,
        key_name=key_name,
        age_hours=age_hours,
        max_age_hours=max_age_hours,
        key_pattern="packer_",
    )

    assert not result.is_valid, "Instance below age threshold should fail validation"
    assert any("age" in e.lower() or "threshold" in e.lower() for e in result.errors)


@settings(max_examples=100, deadline=5000)
@given(
    current_region=valid_region_strategy,
    other_region=valid_region_strategy,
    account_id=valid_account_id_strategy,
)
def test_single_region_boundary_enforcement(
    current_region: str,
    other_region: str,
    account_id: str,
):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any system execution, operations should only be allowed in the
    configured region. Resources in other regions should be excluded.

    Validates: Requirements 8.3, 8.4, 8.6
    """
    assume(current_region != other_region)

    # Create enforcer scoped to current region only
    enforcer = ScopeEnforcer(
        allowed_regions={current_region},
        allowed_account_ids={account_id},
    )

    # Resource in current region should be in scope
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=current_region,
        account_id=account_id,
    )
    assert in_scope, f"Resource in configured region {current_region} should be in scope"

    # Resource in other region should NOT be in scope
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=other_region,
        account_id=account_id,
    )
    assert not in_scope, f"Resource in other region {other_region} should not be in scope"


@settings(max_examples=100, deadline=5000)
@given(
    current_account=valid_account_id_strategy,
    other_account=valid_account_id_strategy,
    region=valid_region_strategy,
)
def test_single_account_boundary_enforcement(
    current_account: str,
    other_account: str,
    region: str,
):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any system execution, operations should only be allowed in the
    configured account. Resources in other accounts should be excluded.

    Validates: Requirements 8.1, 8.2, 8.6
    """
    assume(current_account != other_account)

    # Create enforcer scoped to current account only
    enforcer = ScopeEnforcer(
        allowed_regions={region},
        allowed_account_ids={current_account},
    )

    # Resource in current account should be in scope
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=region,
        account_id=current_account,
    )
    assert in_scope, f"Resource in configured account {current_account} should be in scope"

    # Resource in other account should NOT be in scope
    in_scope, reasons = enforcer.is_resource_in_scope(
        region=region,
        account_id=other_account,
    )
    assert not in_scope, f"Resource in other account {other_account} should not be in scope"


@settings(max_examples=100, deadline=5000)
@given(
    message=st.text(min_size=0, max_size=200),
)
def test_log_sanitizer_never_exposes_password_patterns(message: str):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any log message containing password patterns, the log sanitizer
    should redact them to prevent sensitive data exposure in CloudWatch logs.

    Validates: Requirements 7.4
    """
    # Inject a password pattern
    message_with_password = f"{message} password=SuperSecret123! end"

    sanitized = LogSanitizer.sanitize(message_with_password)

    assert "SuperSecret123!" not in sanitized, "Password value should be redacted from log message"


@settings(max_examples=100, deadline=5000)
@given(
    message=st.text(min_size=0, max_size=200),
)
def test_log_sanitizer_never_exposes_token_patterns(message: str):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    For any log message containing token patterns, the log sanitizer
    should redact them to prevent sensitive data exposure in CloudWatch logs.

    Validates: Requirements 7.4
    """
    # Inject a token pattern
    message_with_token = f"{message} token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 end"

    sanitized = LogSanitizer.sanitize(message_with_token)

    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized, (
        "Token value should be redacted from log message"
    )


@settings(max_examples=100, deadline=5000)
@given(
    instance_ids=st.lists(valid_instance_id_strategy, min_size=1, max_size=5),
)
def test_filter_scope_enforcer_clear_registrations(instance_ids: list):
    """
    Feature: packer-resource-reaper, Property 8: Security and Scope Enforcement

    After clearing registrations, previously registered resources should
    no longer be in scope.

    Validates: Requirements 7.2
    """
    enforcer = FilterScopeEnforcer()
    enforcer.register_filtered_resources(instance_ids=instance_ids)

    # Verify instances are registered
    for instance_id in instance_ids:
        in_scope, _ = enforcer.is_instance_in_scope(instance_id)
        assert in_scope, "Instance should be in scope after registration"

    # Clear registrations
    enforcer.clear_registrations()

    # Verify instances are no longer in scope
    for instance_id in instance_ids:
        in_scope, _ = enforcer.is_instance_in_scope(instance_id)
        assert not in_scope, "Instance should not be in scope after clearing"
