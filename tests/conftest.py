"""Pytest configuration and shared fixtures."""

import os
from datetime import datetime, timezone
from typing import Dict

import pytest

# Set AWS region for tests
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_REGION", "us-east-1")


@pytest.fixture
def sample_tags() -> Dict[str, str]:
    """Sample Packer-related tags."""
    return {
        "Name": "Packer Builder",
        "packer": "true",
        "packer-build-name": "test-build",
    }


@pytest.fixture
def sample_instance_data(sample_tags) -> Dict:
    """Sample EC2 instance data."""
    return {
        "InstanceId": "i-1234567890abcdef0",
        "InstanceType": "t3.micro",
        "State": {"Name": "running"},
        "VpcId": "vpc-12345678",
        "SecurityGroups": [{"GroupId": "sg-12345678", "GroupName": "packer_sg"}],
        "KeyName": "packer_key",
        "LaunchTime": datetime.now(timezone.utc),
        "Tags": [{"Key": k, "Value": v} for k, v in sample_tags.items()],
    }


@pytest.fixture
def sample_volume_data(sample_tags) -> Dict:
    """Sample EBS volume data."""
    return {
        "VolumeId": "vol-1234567890abcdef0",
        "Size": 8,
        "State": "available",
        "CreateTime": datetime.now(timezone.utc),
        "Attachments": [],
        "Tags": [{"Key": k, "Value": v} for k, v in sample_tags.items()],
    }


@pytest.fixture
def sample_security_group_data(sample_tags) -> Dict:
    """Sample security group data."""
    return {
        "GroupId": "sg-1234567890abcdef0",
        "GroupName": "packer_security_group",
        "VpcId": "vpc-12345678",
        "Description": "Packer temporary security group",
        "Tags": [{"Key": k, "Value": v} for k, v in sample_tags.items()],
    }


@pytest.fixture
def sample_key_pair_data() -> Dict:
    """Sample key pair data."""
    return {
        "KeyPairId": "key-1234567890abcdef0",
        "KeyName": "packer_key_12345",
        "KeyFingerprint": "ab:cd:ef:12:34:56:78:90",
        "CreateTime": datetime.now(timezone.utc),
        "Tags": [],
    }
