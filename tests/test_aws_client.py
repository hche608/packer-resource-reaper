"""Tests for AWS client management functionality.

Tests for retry strategy, client manager, and session handling.
"""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from reaper.utils.aws_client import AWSClientManager, RetryStrategy


class TestRetryStrategy:
    """Tests for RetryStrategy class."""

    def test_execute_with_retry_success_first_attempt(self):
        """Test successful execution on first attempt."""
        strategy = RetryStrategy(max_retries=3)
        operation = MagicMock(return_value="success")

        result = strategy.execute_with_retry(operation, "arg1", kwarg1="value1")

        assert result == "success"
        operation.assert_called_once_with("arg1", kwarg1="value1")

    def test_execute_with_retry_success_after_retries(self):
        """Test successful execution after retries."""
        strategy = RetryStrategy(max_retries=3, base_delay=0.01)
        operation = MagicMock(
            side_effect=[
                ClientError(
                    {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                    "TestOperation",
                ),
                ClientError(
                    {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                    "TestOperation",
                ),
                "success",
            ]
        )

        result = strategy.execute_with_retry(operation)

        assert result == "success"
        assert operation.call_count == 3

    def test_execute_with_retry_exhausted(self):
        """Test retry exhaustion raises exception."""
        strategy = RetryStrategy(max_retries=2, base_delay=0.01)
        error = ClientError(
            {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
            "TestOperation",
        )
        operation = MagicMock(side_effect=error)

        with pytest.raises(ClientError):
            strategy.execute_with_retry(operation)

        assert operation.call_count == 3  # Initial + 2 retries

    def test_execute_with_retry_non_retryable_error(self):
        """Test non-retryable error raises immediately."""
        strategy = RetryStrategy(max_retries=3)
        error = ClientError(
            {"Error": {"Code": "InvalidParameterValue", "Message": "Invalid"}},
            "TestOperation",
        )
        operation = MagicMock(side_effect=error)

        with pytest.raises(ClientError):
            strategy.execute_with_retry(operation)

        operation.assert_called_once()

    def test_is_retryable_error_throttling(self):
        """Test throttling errors are retryable."""
        strategy = RetryStrategy()

        assert strategy._is_retryable_error("Throttling") is True
        assert strategy._is_retryable_error("ThrottlingException") is True
        assert strategy._is_retryable_error("RequestLimitExceeded") is True

    def test_is_retryable_error_service_errors(self):
        """Test service errors are retryable."""
        strategy = RetryStrategy()

        assert strategy._is_retryable_error("ServiceUnavailable") is True
        assert strategy._is_retryable_error("InternalError") is True
        assert strategy._is_retryable_error("RequestTimeout") is True

    def test_is_retryable_error_non_retryable(self):
        """Test non-retryable errors."""
        strategy = RetryStrategy()

        assert strategy._is_retryable_error("InvalidParameterValue") is False
        assert strategy._is_retryable_error("AccessDenied") is False
        assert strategy._is_retryable_error("ResourceNotFound") is False

    def test_calculate_delay_exponential_backoff(self):
        """Test delay calculation with exponential backoff."""
        strategy = RetryStrategy(base_delay=1.0, max_delay=60.0, jitter=False)

        assert strategy._calculate_delay(0) == 1.0
        assert strategy._calculate_delay(1) == 2.0
        assert strategy._calculate_delay(2) == 4.0
        assert strategy._calculate_delay(3) == 8.0

    def test_calculate_delay_max_cap(self):
        """Test delay is capped at max_delay."""
        strategy = RetryStrategy(base_delay=1.0, max_delay=10.0, jitter=False)

        assert strategy._calculate_delay(10) == 10.0

    def test_calculate_delay_with_jitter(self):
        """Test delay calculation with jitter."""
        strategy = RetryStrategy(base_delay=1.0, max_delay=60.0, jitter=True)

        # With jitter, delay should be between 0.5 and 1.0 times the base
        delay = strategy._calculate_delay(0)
        assert 0.5 <= delay <= 1.0


class TestAWSClientManager:
    """Tests for AWSClientManager class."""

    @patch("reaper.utils.aws_client.boto3.Session")
    def test_get_client_creates_client(self, mock_session_class):
        """Test get_client creates and caches client."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        manager = AWSClientManager(region="us-east-1")
        client = manager.get_client("ec2")

        assert client == mock_client
        mock_session.client.assert_called_once()

    @patch("reaper.utils.aws_client.boto3.Session")
    def test_get_client_caches_client(self, mock_session_class):
        """Test get_client returns cached client."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        manager = AWSClientManager(region="us-east-1")
        client1 = manager.get_client("ec2")
        client2 = manager.get_client("ec2")

        assert client1 is client2
        assert mock_session.client.call_count == 1

    @patch("reaper.utils.aws_client.boto3.Session")
    def test_ec2_property(self, mock_session_class):
        """Test ec2 property returns EC2 client."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        manager = AWSClientManager(region="us-east-1")
        client = manager.ec2

        assert client == mock_client

    @patch("reaper.utils.aws_client.boto3.Session")
    def test_sns_property(self, mock_session_class):
        """Test sns property returns SNS client."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        manager = AWSClientManager(region="us-east-1")
        client = manager.sns

        assert client == mock_client

    @patch("reaper.utils.aws_client.boto3.Session")
    def test_sts_property(self, mock_session_class):
        """Test sts property returns STS client."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        manager = AWSClientManager(region="us-east-1")
        client = manager.sts

        assert client == mock_client

    @patch("reaper.utils.aws_client.boto3.Session")
    def test_iam_property(self, mock_session_class):
        """Test iam property returns IAM client."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        manager = AWSClientManager(region="us-east-1")
        client = manager.iam

        assert client == mock_client

    @patch("reaper.utils.aws_client.boto3.Session")
    def test_get_account_id(self, mock_session_class):
        """Test get_account_id returns account ID."""
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        manager = AWSClientManager(region="us-east-1")
        account_id = manager.get_account_id()

        assert account_id == "123456789012"

    @patch("reaper.utils.aws_client.boto3.client")
    @patch("reaper.utils.aws_client.boto3.Session")
    def test_get_session_with_role_arn(self, mock_session_class, mock_boto_client):
        """Test session creation with role assumption."""
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }
        mock_boto_client.return_value = mock_sts

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        manager = AWSClientManager(
            region="us-east-1",
            role_arn="arn:aws:iam::123456789012:role/TestRole",
        )
        manager._get_session()

        mock_sts.assume_role.assert_called_once()
        mock_session_class.assert_called_with(
            aws_access_key_id="AKIATEST",
            aws_secret_access_key="secret",
            aws_session_token="token",
            region_name="us-east-1",
        )

    @patch("reaper.utils.aws_client.boto3.Session")
    def test_get_session_without_role_arn(self, mock_session_class):
        """Test session creation without role assumption."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        manager = AWSClientManager(region="us-east-1")
        manager._get_session()

        mock_session_class.assert_called_with(region_name="us-east-1")

    @patch("reaper.utils.aws_client.boto3.Session")
    def test_get_session_caches_session(self, mock_session_class):
        """Test session is cached."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        manager = AWSClientManager(region="us-east-1")
        session1 = manager._get_session()
        session2 = manager._get_session()

        assert session1 is session2
        assert mock_session_class.call_count == 1

    def test_custom_retry_strategy(self):
        """Test manager accepts custom retry strategy."""
        custom_strategy = RetryStrategy(max_retries=5, base_delay=2.0)
        manager = AWSClientManager(region="us-east-1", retry_strategy=custom_strategy)

        assert manager.retry_strategy is custom_strategy
        assert manager.retry_strategy.max_retries == 5
        assert manager.retry_strategy.base_delay == 2.0

    def test_default_retry_strategy(self):
        """Test manager creates default retry strategy."""
        manager = AWSClientManager(region="us-east-1")

        assert manager.retry_strategy is not None
        assert isinstance(manager.retry_strategy, RetryStrategy)
