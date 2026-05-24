# AWS Packer Resource Reaper (BYOR - Bring Your Own Role)

Automatically clean up zombie EC2 instances and associated resources left behind by failed Packer builds.

**This is the BYOR (Bring Your Own Role) variant** — you provide a pre-created IAM role ARN. No `CAPABILITY_IAM` required for deployment. Ideal for enterprises with strict IAM policies.

> For the open-box version that creates its own IAM role, see [packer-resource-reaper](https://github.com/hche608/packer-resource-reaper).

## ⚠️ Important Warning

**Do NOT use if you have non-Packer instances using `packer_*` key naming patterns** — they may be incorrectly terminated.

## Prerequisites

Create an IAM role with the following policy before deploying:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2Read",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeAddresses",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeImages"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2Cleanup",
      "Effect": "Allow",
      "Action": [
        "ec2:TerminateInstances",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteKeyPair",
        "ec2:DeleteVolume",
        "ec2:DeleteSnapshot",
        "ec2:ReleaseAddress"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMCleanup",
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles",
        "iam:ListInstanceProfiles",
        "iam:ListInstanceProfilesForRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:RemoveRoleFromInstanceProfile",
        "iam:DetachRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:DeleteRole"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SNS",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "*"
    },
    {
      "Sid": "STS",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    },
    {
      "Sid": "Logs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

The role trust policy must allow Lambda to assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `LambdaRoleArn` | **Required.** ARN of your pre-created IAM role | — |
| `MaxInstanceAgeHours` | Age threshold before cleanup (hours) | `2` |
| `DryRun` | Simulate cleanup without deleting | `true` |
| `ScheduleExpression` | How often to run | `rate(1 hour)` |
| `NotificationEmail` | Email for alerts (optional) | — |
| `KeyPairPattern` | Key pair prefix to match | `packer_` |
| `LogLevel` | Logging verbosity | `INFO` |
| `BatchDeleteSize` | Concurrent deletions per batch | `1` |

## Quick Start

1. Create the IAM role with the policy above
2. Deploy this app, providing the role ARN
3. Review CloudWatch Logs to confirm correct detection
4. Set `DryRun=false` to enable cleanup

## Source Code

[GitHub Repository](https://github.com/hche608/packer-resource-reaper)

## License

MIT
