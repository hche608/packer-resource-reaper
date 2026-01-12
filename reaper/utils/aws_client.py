"""AWS client management for Packer Resource Reaper."""

import logging
import random
import time
from collections.abc import Callable
from typing import Any, TypeVar

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

T = TypeVar("T")


class RetryStrategy:
    """Retry strategy with exponential backoff and jitter."""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        jitter: bool = True,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter

    def execute_with_retry(self, operation: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Execute operation with exponential backoff retry."""
        last_exception: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                return operation(*args, **kwargs)
            except ClientError as e:
                last_exception = e
                error_code = e.response.get("Error", {}).get("Code", "")

                if self._is_retryable_error(error_code) and attempt < self.max_retries:
                    delay = self._calculate_delay(attempt)
                    logger.warning(
                        f"Retryable error {error_code}, attempt {attempt + 1}/{self.max_retries + 1}, "
                        f"waiting {delay:.2f}s"
                    )
                    time.sleep(delay)
                else:
                    raise

        # Should not reach here, but just in case
        if last_exception:
            raise last_exception
        raise RuntimeError("Unexpected retry loop exit")

    def _is_retryable_error(self, error_code: str) -> bool:
        """Check if error is retryable."""
        retryable_codes = {
            "Throttling",
            "ThrottlingException",
            "RequestLimitExceeded",
            "ProvisionedThroughputExceededException",
            "ServiceUnavailable",
            "InternalError",
            "RequestTimeout",
        }
        return error_code in retryable_codes

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay with exponential backoff and optional jitter."""
        delay: float = min(self.base_delay * (2**attempt), self.max_delay)
        if self.jitter:
            delay *= 0.5 + random.random() * 0.5
        return delay


class AWSClientManager:
    """Manages AWS boto3 clients with retry logic and cross-account support."""

    def __init__(
        self,
        region: str = "us-east-1",
        role_arn: str | None = None,
        retry_strategy: RetryStrategy | None = None,
    ):
        self.region = region
        self.role_arn = role_arn
        self.retry_strategy = retry_strategy or RetryStrategy()
        self._session: boto3.Session | None = None
        self._clients: dict[str, Any] = {}

    def _get_session(self) -> boto3.Session:
        """Get or create boto3 session, with role assumption if configured."""
        if self._session is not None:
            return self._session

        if self.role_arn:
            # Assume cross-account role
            sts_client = boto3.client("sts", region_name=self.region)
            response = sts_client.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName="PackerResourceReaper",
                DurationSeconds=3600,
            )
            credentials = response["Credentials"]
            self._session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=self.region,
            )
        else:
            self._session = boto3.Session(region_name=self.region)

        return self._session

    def get_client(self, service_name: str) -> Any:
        """Get boto3 client for specified service."""
        if service_name not in self._clients:
            session = self._get_session()
            config = Config(retries={"max_attempts": 0})  # We handle retries ourselves
            self._clients[service_name] = session.client(
                service_name,
                config=config,
                region_name=self.region,  # type: ignore[call-overload]
            )
        return self._clients[service_name]

    @property
    def ec2(self) -> Any:
        """Get EC2 client."""
        return self.get_client("ec2")

    @property
    def sns(self) -> Any:
        """Get SNS client."""
        return self.get_client("sns")

    @property
    def sts(self) -> Any:
        """Get STS client."""
        return self.get_client("sts")

    @property
    def iam(self) -> Any:
        """Get IAM client."""
        return self.get_client("iam")

    def get_account_id(self) -> str:
        """Get current AWS account ID."""
        response = self.sts.get_caller_identity()
        account_id: str = response["Account"]
        return account_id
