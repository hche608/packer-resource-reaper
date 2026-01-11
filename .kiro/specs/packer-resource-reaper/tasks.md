# Implementation Plan: AWS Packer Resource Reaper

## Overview

This implementation plan converts the serverless reaper design into discrete Python coding tasks using AWS Lambda, boto3, and AWS SAM for Infrastructure as Code deployment. The system uses simple two-criteria filtering (key pair pattern + age threshold) and is completely stateless.

## Tasks

- [x] 1. Set up project structure and core interfaces
  - Create Python package structure with modules for filters, cleanup, notifications, and utils
  - Define base interfaces and data classes using Python dataclasses and typing
  - Set up AWS SAM template for Lambda function, EventBridge, and SNS
  - Configure development dependencies including boto3, hypothesis, and pytest
  - _Requirements: 5.1, 5.2_

- [x] 2. Implement resource filtering system
  - [x] 2.1 Create temporal filter for age-based resource identification
    - Implement age calculation logic using instance launch time
    - Filter instances exceeding configurable MaxInstanceAge threshold
    - _Requirements: 1.1_

  - [x] 2.2 Create identity filter for key pair pattern matching
    - Implement key pair pattern matching for "packer_*" prefix
    - Return true only for instances with key_name starting with "packer_"
    - _Requirements: 1.2_

  - [x] 2.3 Write property test for two-criteria filter selection
    - **Property 1: Two-Criteria Filter Selection**
    - **Validates: Requirements 1.1, 1.2**

  - [x] 2.4 Write property test for key pair pattern matching
    - **Property 2: Key Pair Pattern Matching Consistency**
    - **Validates: Requirements 1.2**

- [x] 3. Implement AWS resource managers
  - [x] 3.1 Create EC2 instance manager
    - Implement instance scanning with boto3 EC2 client
    - Add instance termination with state verification
    - Handle various instance states including "hung" and "rebooting"
    - _Requirements: 2.1, 2.3, 2.5, 6.4_

  - [x] 3.2 Create storage manager for EBS volumes
    - Implement volume identification for instances being terminated
    - Implement cleanup operations for attached volumes
    - _Requirements: 2.2, 2.8_

  - [x] 3.3 Create network manager for security groups, key pairs, and EIPs
    - Implement security group cleanup with dependency checking
    - Add key pair removal functionality
    - Implement EIP release operations
    - _Requirements: 2.4, 2.6, 2.8_

  - [x] 3.4 Create IAM manager for instance profiles
    - Implement instance profile scanning for `packer_*` pattern
    - Add instance profile deletion with role detachment
    - Handle orphaned instance profiles from failed Packer builds
    - _Requirements: 2.2, 2.4, 2.8, 7.1, 7.2_

- [x] 4. Implement cleanup orchestration engine
  - [x] 4.1 Create dependency-aware cleanup sequencer
    - Implement cleanup operation ordering (instances before dependent resources)
    - Add state-based deferral for shutting-down instances
    - Collect directly associated resources before termination
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.7, 2.8_

  - [x] 4.2 Write property test for cleanup sequencing
    - **Property 3: Dependency-Aware Cleanup Sequencing**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.7, 2.8**

  - [x] 4.3 Implement error handling and retry logic
    - Add exponential backoff with jitter for AWS API calls
    - Implement DependencyViolation error handling (log and continue)
    - _Requirements: 2.6, 6.1, 6.2, 6.3_

  - [x] 4.4 Write property test for error recovery
    - **Property 4: Error Recovery Without State**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 6.1, 6.3**

- [x] 5. Implement configuration management
  - [x] 5.1 Add configuration management system
    - Implement environment variable parsing and validation
    - Create dry-run mode configuration handling
    - Validate MaxInstanceAge is positive integer
    - _Requirements: 5.2, 9.5_

  - [x] 5.2 Write property test for configuration validation
    - **Property 6: Configuration Validation and Parsing**
    - **Validates: Requirements 5.2, 9.5**

- [x] 5A. Implement configurable log level
  - [x] 5A.1 Add LOG_LEVEL environment variable support
    - Implement LOG_LEVEL parsing with validation for valid levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - Default to INFO when LOG_LEVEL is not set
    - Default to INFO with warning when invalid LOG_LEVEL is provided
    - Configure logging output based on selected level
    - _Requirements: 11.1, 11.2, 11.5_

  - [x] 5A.2 Implement log level behavior
    - Output detailed API calls, resource attributes, and processing steps at DEBUG level
    - Output only error conditions and critical failures at ERROR level or higher
    - _Requirements: 11.3, 11.4_

  - [x] 5A.3 Write property test for log level configuration
    - **Property 12: Log Level Configuration**
    - **Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5**

- [x] 5B. Implement batch delete operations
  - [x] 5B.1 Add BATCH_DELETE_SIZE environment variable support
    - Implement BATCH_DELETE_SIZE parsing with validation for positive integers
    - Default to 1 (sequential deletion) when not set
    - Default to 1 with warning when invalid value is provided
    - _Requirements: 12.1, 12.2, 12.7_

  - [x] 5B.2 Create batch processor for concurrent deletions
    - Implement batch processing that groups deletions by BATCH_DELETE_SIZE
    - Process multiple resource deletions concurrently within each batch
    - Wait for all deletions in current batch to complete before proceeding to next batch
    - _Requirements: 12.3, 12.4_

  - [x] 5B.3 Implement batch failure handling
    - Log failures within a batch and continue processing remaining items
    - Ensure batch processing respects dependency-aware cleanup order
    - _Requirements: 12.5, 12.6_

  - [x] 5B.4 Write property test for batch delete processing
    - **Property 13: Batch Delete Processing**
    - **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7**

- [x] 6. Checkpoint - Core functionality validation
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Implement dry-run and safety features
  - [x] 7.1 Create dry-run execution mode
    - Implement resource identification without destructive operations
    - Add comprehensive logging of planned cleanup actions
    - Generate simulation reports for SNS notifications
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

  - [x] 7.2 Write property test for dry-run safety
    - **Property 5: Dry Run Safety Guarantee**
    - **Validates: Requirements 9.1, 9.2, 9.3, 9.4**

- [x] 8. Implement logging and notification system
  - [x] 8.1 Create CloudWatch logging integration
    - Implement comprehensive resource scanning and action logging
    - Add error logging with detailed information
    - Implement log sanitization for sensitive data
    - _Requirements: 4.2, 6.3, 7.4_

  - [x] 8.2 Create SNS notification system
    - Implement notification message formatting with all required fields
    - Include instance ID, type, termination reason, and deleted resources
    - Handle both cleanup and dry-run notification scenarios
    - _Requirements: 4.3, 4.4_

  - [x] 8.3 Write property test for logging and notifications
    - **Property 7: Comprehensive Logging and Notification**
    - **Validates: Requirements 4.2, 4.3, 4.4**

- [x] 9. Implement security and access control
  - [x] 9.1 Add input validation and sanitization
    - Implement parameter validation
    - Add resource scope enforcement (filter matching only)
    - _Requirements: 7.2_

  - [x] 9.2 Write property test for security enforcement
    - **Property 8: Security and Scope Enforcement**
    - **Validates: Requirements 7.2, 7.4, 8.1-8.6**

- [x] 10. Implement orphaned Packer resource cleanup
  - [x] 10.1 Create orphan manager for detecting orphaned resources
    - Implement scanning for key pairs starting with `packer_` not used by any running/pending instances
    - Implement scanning for security groups with `packer` in name/description not attached to any instances or network interfaces
    - Implement scanning for IAM roles starting with `packer_` not in any active instance profiles
    - _Requirements: 10.1, 10.2, 10.3_

  - [x] 10.2 Implement orphaned resource cleanup operations
    - Add key pair deletion after confirming no instance references
    - Add security group deletion after confirming no dependencies
    - Add IAM role cleanup with policy detachment before deletion
    - _Requirements: 10.4, 10.5, 10.6_

  - [x] 10.3 Integrate orphaned cleanup into main cleanup engine
    - Execute orphaned resource cleanup after primary zombie instance cleanup completes
    - Apply same dry-run mode behavior to orphaned resource operations
    - _Requirements: 10.7, 10.8_

  - [x] 10.4 Add orphaned resource logging and notifications
    - Log each deleted orphaned resource type and identifier to CloudWatch
    - Include orphaned resource details in SNS notifications
    - _Requirements: 10.9, 10.10_

  - [x] 10.5 Write property test for orphaned resource identification
    - **Property 10: Orphaned Resource Identification**
    - **Validates: Requirements 10.1, 10.2, 10.3**

  - [x] 10.6 Write property test for orphaned resource cleanup safety
    - **Property 11: Orphaned Resource Cleanup Safety**
    - **Validates: Requirements 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 10.10**

- [x] 11. Checkpoint - Orphaned resource cleanup validation
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Create Lambda handler and integration
  - [x] 12.1 Implement main Lambda handler function
    - Create entry point that orchestrates all components
    - Integrate filters, cleanup engine, and notification systems
    - Use default Lambda execution environment credentials
    - _Requirements: 5.4, 8.5_

  - [x] 12.2 Wire all components together
    - Connect filtering system to cleanup engine
    - Connect logging and notification systems
    - Ensure stateless execution (fresh scan each run)
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [x] 12.3 Write integration tests for complete workflow
    - Test end-to-end cleanup scenarios
    - Validate cross-component interactions
    - Test error propagation and recovery

  - [x] 12.4 Write property test for single account/region boundary
    - **Property 9: Single Account/Region Boundary**
    - **Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6**

- [x] 13. Complete AWS SAM infrastructure template
  - [x] 13.1 Finalize SAM template with all resources
    - Complete Lambda function configuration with proper IAM roles
    - Configure EventBridge scheduling with configurable frequency
    - Set up SNS topic with proper permissions
    - _Requirements: 5.1, 7.1_

  - [x] 13.2 Add deployment and configuration documentation
    - Create deployment instructions and configuration examples
    - Document environment variable settings and IAM requirements
    - Add troubleshooting guide for common deployment issues

- [x] 14. Update Lambda handler to include orphaned resource cleanup
  - [x] 14.1 Integrate orphan manager into Lambda handler
    - Add orphan manager initialization in handler
    - Call orphaned resource cleanup after primary cleanup completes
    - _Requirements: 10.7_

  - [x] 14.2 Update integration tests for orphaned resource workflow
    - Test end-to-end orphaned resource cleanup scenarios
    - Validate orphaned resources are cleaned after primary cleanup
    - Test dry-run mode for orphaned resources

- [x] 15. Final checkpoint - Complete system validation
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- All tasks including property tests and integration tests are required for comprehensive coverage
- Each task references specific requirements for traceability
- Property tests use Hypothesis framework with minimum 100 iterations
- All Python code follows PEP 8 style guidelines
- AWS SAM template enables Infrastructure as Code deployment
- System is completely stateless - no DynamoDB or state persistence
- Single account/region scope only - no cross-account support
- IAM instance profiles matching `packer_*` pattern are included in cleanup
- Orphaned resource cleanup (key pairs, security groups, IAM roles) runs as Phase 2 after primary zombie instance cleanup
- Checkpoints ensure incremental validation and user feedback
- LOG_LEVEL configuration supports DEBUG, INFO, WARNING, ERROR, CRITICAL with INFO as default
- BATCH_DELETE_SIZE enables concurrent deletion within batches while maintaining dependency order
