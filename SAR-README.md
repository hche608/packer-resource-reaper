# AWS Packer Resource Reaper

Automatically clean up zombie EC2 instances and associated resources left behind by failed Packer builds.

## ⚠️ Important Warning

**Do NOT use if you have non-Packer instances using `packer_*` key naming patterns** — they may be incorrectly terminated.

## What It Does

- Identifies EC2 instances launched with `packer_*` key pairs that exceed an age threshold
- Terminates zombie instances and cleans up associated resources:
  - Security Groups
  - Key Pairs
  - EBS Volumes
  - Elastic IPs
  - IAM Instance Profiles (matching `packer_*` or `packer-*`)
- Sends SNS notifications for all cleanup actions

## Quick Start

1. **Deploy with dry-run mode** (default) to verify detection logic
2. **Review CloudWatch Logs** to confirm correct resource identification
3. **Redeploy with `DryRun=false`** to enable actual cleanup

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `MaxInstanceAgeHours` | Age threshold before cleanup (hours) | `2` |
| `DryRun` | Simulate cleanup without deleting | `true` |
| `ScheduleExpression` | How often to run | `rate(1 hour)` |
| `NotificationEmail` | Email for alerts (optional) | — |
| `KeyPairPattern` | Key pair prefix to match | `packer_` |
| `LogLevel` | Logging verbosity | `INFO` |

## Safety Features

- **Dry-run by default** — no deletions until you explicitly enable
- **Two-criteria filtering** — instances must match BOTH key pattern AND age threshold
- **Dependency-aware** — terminates instances before deleting dependent resources

## Monitoring

- CloudWatch Logs: `/aws/lambda/<stack-name>-function`
- CloudWatch Alarms for errors and throttling
- SNS notifications for all cleanup actions

## Source Code

[GitHub Repository](https://github.com/hche608/packer-resource-reaper)

## License

MIT
