# Project Structure

```
├── reaper/                    # Main application package
│   ├── handler.py             # Lambda entry point
│   ├── models.py              # Data models (dataclasses)
│   ├── cleanup/               # Cleanup orchestration
│   │   ├── engine.py          # Main cleanup orchestrator
│   │   ├── ec2_manager.py     # EC2 instance operations
│   │   ├── storage_manager.py # Volume/snapshot operations
│   │   ├── network_manager.py # Security groups, key pairs, EIPs
│   │   ├── iam_manager.py     # IAM instance profile cleanup
│   │   ├── orphan_manager.py  # Orphaned resource detection
│   │   ├── batch_processor.py # Batch delete operations
│   │   └── dry_run.py         # Dry-run simulation
│   ├── filters/               # Resource filtering
│   │   ├── base.py            # Abstract filter interface
│   │   ├── identity.py        # Key pair pattern matching
│   │   └── temporal.py        # Age-based filtering
│   ├── notifications/         # SNS notifications
│   │   └── sns_notifier.py
│   └── utils/                 # Shared utilities
│       ├── aws_client.py      # AWS client management, retry logic
│       ├── config.py          # Environment configuration
│       ├── logging.py         # Logging setup
│       └── security.py        # Input validation, scope enforcement
├── tests/                     # Test suite
│   ├── conftest.py            # Shared fixtures
│   └── test_*.py              # Test modules
├── template.yaml              # SAM/CloudFormation template
├── samconfig.toml             # SAM deployment configs
├── pyproject.toml             # Python project config
├── Makefile                   # Development commands
└── events/                    # Sample Lambda events
    └── scheduled.json
```

## Architecture Patterns
- Stateless execution: fresh scan each Lambda invocation
- Two-phase cleanup: primary zombie cleanup → orphaned resource cleanup
- Dependency-aware sequencing: instances terminated before dependent resources
- Manager pattern: separate managers for EC2, storage, network, IAM operations
- Abstract filter interface: `ResourceFilter` base class for filtering strategies
- Dataclass models: `PackerResource` hierarchy for type-safe resource handling
