"""Batch processor for concurrent resource deletions.

This module implements batch processing for resource deletions as per
Requirements 12.1-12.7.

Key features:
- Process deletions in configurable batches (Requirement 12.1, 12.2)
- Concurrent execution within batches using ThreadPoolExecutor (Requirement 12.3)
- Wait for batch completion before proceeding (Requirement 12.4)
- Log failures and continue processing (Requirement 12.5)
- Respect dependency-aware cleanup order (Requirement 12.6)

Note: Uses ThreadPoolExecutor (not asyncio) because boto3 is synchronous.
asyncio.gather with blocking boto3 calls would execute sequentially.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class BatchResult:
    """Result of batch processing operations.

    Attributes:
        successful: List of successfully processed resource IDs
        failed: List of failed resource IDs
        errors: Dict mapping resource ID to error message
    """

    successful: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    errors: dict = field(default_factory=dict)


class BatchProcessor:
    """Process resource deletions in configurable batches.

    This implements Requirements 12.1-12.7:
    - 12.1: Process deletions in batches of the specified size
    - 12.2: Default to 1 (sequential deletion) when not set
    - 12.3: Process multiple deletions concurrently within each batch
    - 12.4: Wait for all deletions in current batch before proceeding
    - 12.5: Log failures and continue processing remaining items
    - 12.6: Respect dependency-aware cleanup order (caller's responsibility)
    - 12.7: Default to 1 for invalid values (handled by config)
    """

    def __init__(self, batch_size: int = 1):
        """Initialize batch processor.

        Args:
            batch_size: Number of resources to process concurrently in each batch.
                       Defaults to 1 (sequential deletion).
        """
        self.batch_size = max(1, batch_size)  # Ensure minimum of 1
        logger.debug(f"BatchProcessor initialized with batch_size={self.batch_size}")

    def process_deletions(
        self,
        resources: List[str],
        delete_func: Callable[[str], bool],
        resource_type: str = "resource",
    ) -> BatchResult:
        """Process resource deletions in batches.

        This implements Requirements 12.3, 12.4, 12.5:
        - 12.3: Process multiple deletions concurrently within each batch
        - 12.4: Wait for all deletions in current batch before proceeding
        - 12.5: Log failures and continue processing remaining items

        Args:
            resources: List of resource identifiers to delete
            delete_func: Function that takes a resource ID and returns True on success,
                        False on failure. May raise exceptions.
            resource_type: Human-readable resource type for logging

        Returns:
            BatchResult containing successful, failed, and error details
        """
        result = BatchResult()

        if not resources:
            logger.debug(f"No {resource_type}s to process")
            return result

        total_resources = len(resources)
        logger.info(
            f"Processing {total_resources} {resource_type}(s) in batches of {self.batch_size}"
        )

        # Process in batches
        for batch_num, i in enumerate(
            range(0, total_resources, self.batch_size), start=1
        ):
            batch = resources[i : i + self.batch_size]
            batch_size = len(batch)

            logger.debug(
                f"Processing batch {batch_num}: {batch_size} {resource_type}(s)"
            )

            if self.batch_size > 1 and batch_size > 1:
                # Concurrent processing within batch (Requirement 12.3)
                batch_result = self._process_batch_concurrent(
                    batch, delete_func, resource_type
                )
            else:
                # Sequential processing (batch_size = 1 or single item)
                batch_result = self._process_batch_sequential(
                    batch, delete_func, resource_type
                )

            # Merge batch results
            result.successful.extend(batch_result.successful)
            result.failed.extend(batch_result.failed)
            result.errors.update(batch_result.errors)

            # Log batch completion (Requirement 12.4 - wait for batch completion)
            logger.debug(
                f"Batch {batch_num} complete: {len(batch_result.successful)} succeeded, "
                f"{len(batch_result.failed)} failed"
            )

        logger.info(
            f"Batch processing complete: {len(result.successful)} {resource_type}(s) deleted, "
            f"{len(result.failed)} failed"
        )

        return result

    def _process_batch_concurrent(
        self,
        batch: List[str],
        delete_func: Callable[[str], bool],
        resource_type: str,
    ) -> BatchResult:
        """Process a batch of deletions concurrently using ThreadPoolExecutor.

        This implements Requirement 12.3: process multiple resource deletions
        concurrently within each batch.

        Args:
            batch: List of resource IDs in this batch
            delete_func: Function to delete a single resource
            resource_type: Human-readable resource type for logging

        Returns:
            BatchResult for this batch
        """
        result = BatchResult()

        with ThreadPoolExecutor(max_workers=len(batch)) as executor:
            # Submit all deletion tasks
            future_to_resource = {
                executor.submit(
                    self._safe_delete, delete_func, resource_id
                ): resource_id
                for resource_id in batch
            }

            # Wait for all tasks to complete (Requirement 12.4)
            for future in as_completed(future_to_resource):
                resource_id = future_to_resource[future]
                try:
                    success, error_msg = future.result()
                    if success:
                        result.successful.append(resource_id)
                        logger.debug(
                            f"Successfully deleted {resource_type} {resource_id}"
                        )
                    else:
                        result.failed.append(resource_id)
                        if error_msg:
                            result.errors[resource_id] = error_msg
                        # Log failure and continue (Requirement 12.5)
                        logger.warning(
                            f"Failed to delete {resource_type} {resource_id}: {error_msg}"
                        )
                except Exception as e:
                    # Log failure and continue (Requirement 12.5)
                    result.failed.append(resource_id)
                    result.errors[resource_id] = str(e)
                    logger.error(
                        f"Exception deleting {resource_type} {resource_id}: {e}"
                    )

        return result

    def _process_batch_sequential(
        self,
        batch: List[str],
        delete_func: Callable[[str], bool],
        resource_type: str,
    ) -> BatchResult:
        """Process a batch of deletions sequentially.

        Used when batch_size is 1 or for single-item batches.

        Args:
            batch: List of resource IDs in this batch
            delete_func: Function to delete a single resource
            resource_type: Human-readable resource type for logging

        Returns:
            BatchResult for this batch
        """
        result = BatchResult()

        for resource_id in batch:
            success, error_msg = self._safe_delete(delete_func, resource_id)
            if success:
                result.successful.append(resource_id)
                logger.debug(f"Successfully deleted {resource_type} {resource_id}")
            else:
                result.failed.append(resource_id)
                if error_msg:
                    result.errors[resource_id] = error_msg
                # Log failure and continue (Requirement 12.5)
                logger.warning(
                    f"Failed to delete {resource_type} {resource_id}: {error_msg}"
                )

        return result

    def _safe_delete(
        self,
        delete_func: Callable[[str], bool],
        resource_id: str,
    ) -> Tuple[bool, Optional[str]]:
        """Safely execute a delete function, catching exceptions.

        Args:
            delete_func: Function to delete a single resource
            resource_id: ID of the resource to delete

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        try:
            success = delete_func(resource_id)
            return (success, None if success else "Delete returned False")
        except Exception as e:
            return (False, str(e))
