# Deployment Guide

This guide provides detailed instructions for deploying the AWS Packer Resource Reaper.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Deployment Options](#deployment-options)
- [Step-by-Step Deployment](#step-by-step-deployment)
- [Configuration Reference](#configuration-reference)
- [Post-Deployment Verification](#post-deployment-verification)
- [Updating the Deployment](#updating-the-deployment)
- [Uninstalling](#uninstalling)

## Prerequisites

### Required Tools

1. **AWS CLI v2.x**
   ```bash
   # Install on macOS
   brew install awscli
   
   # Install on Linux
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip
   sudo ./aws/install
   
   # Verify installation
   aws --version
   ```

2. **AWS SAM CLI v1.x**
   ```bash
   # Install on macOS
   brew install aws-sam-cli
   
   # Install on Linux
   pip install aws-sam-cli
   
   # Verify installation
   sam --version
   ```

3. **Python 3.11+**
   ```bash
   python3 --version
   ```

4. **uv** (Python package manager)
   ```bash
   # Install uv
   curl -LsSf https://astral.sh/uv/install.sh | sh
   
   # Verify installation
   uv --version
   ```

### AWS Credentials

Configure AWS credentials with permissions to:
- Create/update CloudFormation stacks
- Create IAM roles and policies
- Create Lambda functions
- Create SNS topics
- Create EventBridge rules
- Create CloudWatch log groups and alarms

```bash
# Configure credentials
aws configure

# Or use environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

## Deployment Options

### Option 1: Guided Deployment (Recommended for First Time)

```bash
sam build
sam deploy --guided
```

### Option 2: Using Makefile (Recommended)

```bash
# Default environment (dry-run mode)
make deploy

# Production environment
make deploy-prod

# Development environment
make deploy-dev
```

### Option 3: Using samconfig.toml Directly

```bash
# Default environment (dry-run mode)
sam build && sam deploy

# Production environment
sam build && sam deploy --config-env prod

# Development environment
sam build && sam deploy --config-env dev
```

### Option 4: Command Line Parameters

```bash
sam build
sam deploy \
  --stack-name packer-resource-reaper \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    MaxInstanceAgeHours=2 \
    DryRun=true \
    ScheduleExpression="rate(1 hour)" \
    NotificationEmail=devops@example.com \
    LogRetentionDays=30
```

## Step-by-Step Deployment

### Step 1: Clone and Setup

```bash
git clone <repository-url>
cd packer-resource-reaper
make install-dev
```

### Step 2: Build the Application

```bash
make build
```

This creates a `.aws-sam/build` directory with the packaged Lambda function.

### Step 3: Deploy (Guided)

```bash
sam deploy --guided
```

You'll be prompted for:

| Prompt | Description | Recommended Value |
|--------|-------------|-------------------|
| Stack Name | CloudFormation stack name | `packer-resource-reaper` |
| AWS Region | Deployment region | Your target region |
| MaxInstanceAgeHours | Instance age threshold | `2` |
| DryRun | Enable dry-run mode | `true` (for first deployment) |
| ScheduleExpression | Execution schedule | `rate(1 hour)` |
| NotificationEmail | Email for notifications | Your email |
| LogRetentionDays | Log retention period | `30` |
| Confirm changes | Review changeset | `y` |
| Allow SAM CLI IAM role creation | Create IAM resources | `y` |
| Save arguments to configuration file | Save to samconfig.toml | `y` |

### Step 4: Confirm Email Subscription

If you provided a notification email:
1. Check your inbox for an email from AWS SNS
2. Click the "Confirm subscription" link
3. You'll see a confirmation page

### Step 5: Verify Deployment

```bash
# Check stack status
aws cloudformation describe-stacks \
  --stack-name packer-resource-reaper \
  --query 'Stacks[0].StackStatus'

# List stack outputs
aws cloudformation describe-stacks \
  --stack-name packer-resource-reaper \
  --query 'Stacks[0].Outputs'
```

## Configuration Reference

### SAM Template Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `MaxInstanceAgeHours` | Number | `2` | Maximum instance age before cleanup (1-168 hours) |
| `DryRun` | String | `true` | Enable dry-run mode (`true`/`false`) |
| `ScheduleExpression` | String | `rate(1 hour)` | EventBridge schedule expression |
| `NotificationEmail` | String | (empty) | Email for SNS notifications |
| `LogRetentionDays` | Number | `30` | CloudWatch log retention (days) |

### Schedule Expression Examples

| Expression | Description |
|------------|-------------|
| `rate(1 hour)` | Every hour |
| `rate(30 minutes)` | Every 30 minutes |
| `rate(6 hours)` | Every 6 hours |
| `cron(0 * * * ? *)` | Every hour at minute 0 |
| `cron(0 9 * * ? *)` | Daily at 9:00 AM UTC |
| `cron(0 9-17 ? * MON-FRI *)` | Hourly 9 AM-5 PM, Mon-Fri |

### Environment Variables

These are set automatically by the SAM template:

| Variable | Description |
|----------|-------------|
| `MAX_INSTANCE_AGE_HOURS` | From `MaxInstanceAgeHours` parameter |
| `DRY_RUN` | From `DryRun` parameter |
| `SNS_TOPIC_ARN` | Auto-created SNS topic ARN |

## Post-Deployment Verification

### 1. Check Lambda Function

```bash
# Get function details
aws lambda get-function \
  --function-name packer-resource-reaper-function

# Check function configuration
aws lambda get-function-configuration \
  --function-name packer-resource-reaper-function \
  --query '{Runtime: Runtime, Timeout: Timeout, MemorySize: MemorySize, Environment: Environment.Variables}'
```

### 2. Test Manual Invocation

```bash
# Invoke the function
aws lambda invoke \
  --function-name packer-resource-reaper-function \
  --payload '{}' \
  response.json

# View response
cat response.json | jq .
```

### 3. Check CloudWatch Logs

```bash
# View recent logs
aws logs tail /aws/lambda/packer-resource-reaper-function --follow

# Or use the AWS Console
# Navigate to: CloudWatch > Log groups > /aws/lambda/packer-resource-reaper-function
```

### 4. Verify EventBridge Rule

```bash
# List rules
aws events list-rules --name-prefix packer-resource-reaper

# Check rule details
aws events describe-rule --name packer-resource-reaper-schedule
```

### 5. Check SNS Topic

```bash
# Get topic ARN from stack outputs
TOPIC_ARN=$(aws cloudformation describe-stacks \
  --stack-name packer-resource-reaper \
  --query 'Stacks[0].Outputs[?OutputKey==`NotificationTopicArn`].OutputValue' \
  --output text)

# List subscriptions
aws sns list-subscriptions-by-topic --topic-arn $TOPIC_ARN
```

## Updating the Deployment

### Update Parameters

```bash
# Rebuild and redeploy with new parameters
make build
sam deploy --parameter-overrides DryRun=false MaxInstanceAgeHours=4
```

### Update Code Only

```bash
# Rebuild and deploy
make deploy
```

### Update Lambda Configuration Directly

```bash
# Update environment variables
aws lambda update-function-configuration \
  --function-name packer-resource-reaper-function \
  --environment "Variables={MAX_INSTANCE_AGE_HOURS=4,DRY_RUN=false,SNS_TOPIC_ARN=<topic-arn>}"
```

### Transitioning to Live Mode

**Important**: Always verify dry-run behavior first!

1. Review CloudWatch logs from dry-run executions
2. Confirm the correct resources are being identified
3. Deploy with `DryRun=false`:
   ```bash
   sam deploy --parameter-overrides DryRun=false
   ```
4. Monitor the first live execution closely

## Uninstalling

### Delete the Stack

```bash
# Delete all resources
aws cloudformation delete-stack --stack-name packer-resource-reaper

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete --stack-name packer-resource-reaper
```

### Manual Cleanup (if needed)

If stack deletion fails, manually delete:

1. **Lambda Function**:
   ```bash
   aws lambda delete-function --function-name packer-resource-reaper-function
   ```

2. **CloudWatch Log Group**:
   ```bash
   aws logs delete-log-group --log-group-name /aws/lambda/packer-resource-reaper-function
   ```

3. **SNS Topic**:
   ```bash
   aws sns delete-topic --topic-arn <topic-arn>
   ```

4. **IAM Role and Policies**:
   ```bash
   # List and delete policies
   aws iam list-role-policies --role-name packer-resource-reaper-lambda-role
   aws iam delete-role-policy --role-name packer-resource-reaper-lambda-role --policy-name <policy-name>
   
   # Delete role
   aws iam delete-role --role-name packer-resource-reaper-lambda-role
   ```

## Multi-Region Deployment

To deploy to multiple regions:

```bash
# Deploy to each region
for region in us-east-1 us-west-2 eu-west-1; do
  sam deploy \
    --stack-name packer-resource-reaper \
    --region $region \
    --parameter-overrides \
      MaxInstanceAgeHours=2 \
      DryRun=true \
      NotificationEmail=devops@example.com
done
```

## Troubleshooting Deployment Issues

### Stack Creation Failed

```bash
# Check stack events for errors
aws cloudformation describe-stack-events \
  --stack-name packer-resource-reaper \
  --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`]'
```

### IAM Permission Errors

Ensure your AWS credentials have these permissions:
- `cloudformation:*`
- `lambda:*`
- `iam:CreateRole`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`
- `sns:*`
- `events:*`
- `logs:*`
- `s3:*` (for SAM deployment bucket)

### S3 Bucket Issues

SAM CLI creates an S3 bucket for deployment artifacts. If you encounter issues:

```bash
# Use a specific bucket
sam deploy --s3-bucket my-deployment-bucket

# Or let SAM create one
sam deploy --resolve-s3
```

## Local Development

### Running Tests Before Deployment

```bash
# Run all quality checks
make check

# Run tests
make test

# Run tests with coverage
make test-cov
```

### Local Invocation

```bash
# Build and invoke locally (requires Docker)
make invoke

# Or with debug logging
make invoke-debug
```

### Cleaning Up Build Artifacts

```bash
# Remove build artifacts and caches
make clean

# Remove everything including .venv
make deep-clean
```
