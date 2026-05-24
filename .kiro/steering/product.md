# AWS Packer Resource Reaper

A serverless Lambda application that automatically identifies and cleans up "zombie" EC2 instances and associated resources left behind by failed or interrupted Packer builds.

## Core Purpose
- Detect Packer-created resources using SSH key name pattern (`packer_*`)
- Clean up orphaned instances, security groups, key pairs, volumes, EIPs, and IAM roles
- Operate as an external watchdog within a single AWS account and region
- Published to AWS Serverless Application Repository (SAR) for easy deployment

## Key Safety Features
- Two-criteria filtering: instances must match BOTH key pair pattern AND age threshold
- Dry-run mode enabled by default for safe testing
- Dependency-aware cleanup sequencing (terminate instances before deleting dependent resources)
- Age-based filtering for orphaned resources to prevent race conditions with active builds
- Concurrency limit (ReservedConcurrentExecutions: 1) prevents parallel execution conflicts
- Explicit name checks for orphaned resources to prevent accidental production deletion

## Architecture
- ARM64 (Graviton) for cost optimization
- Two-phase cleanup: zombie instances → orphaned resources
- Batch processing with configurable concurrency (ThreadPoolExecutor)
- Stateless execution: no database, fresh scan each invocation

## Critical Warning
Do NOT use if you have non-Packer instances using similar key naming patterns (e.g., `packer_mykey`, `packer_production`) as they may be incorrectly identified and terminated.
