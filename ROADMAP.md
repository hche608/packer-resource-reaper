# Roadmap

## Planned Improvements

### Observability & Metrics

- [ ] Emit custom CloudWatch metrics: `ResourcesFound`, `ResourcesCleaned`, `ExecutionDuration`, `ErrorCount`
- [ ] Create CloudWatch dashboard for reaper operations
- [ ] Add metric-based alarms (e.g., alert when resources_found spikes)

### Graceful Timeout Handling

- [ ] Detect approaching Lambda timeout (check `context.get_remaining_time_in_millis()`)
- [ ] Stop processing new resources when < 30s remaining
- [ ] Report partial progress in the response and SNS notification
- [ ] Log which resources were not processed for the next invocation to pick up

### Multi-Region Support

- [ ] Optional parameter to deploy a single stack that fans out to multiple regions
- [ ] Cross-region summary notifications

### Resource Tagging

- [ ] Tag identified resources with `reaper:identified-at` timestamp before deletion
- [ ] Provides audit trail and prevents re-processing on timeout

---

## Completed

- [x] SAR publishing metadata
- [x] ARM64 (Graviton) architecture for cost savings
- [x] Batch processing for concurrent deletions
- [x] Concurrency limit (ReservedConcurrentExecutions: 1)
- [x] CI: SAM template validation
- [x] CI: Python 3.11 + 3.12 matrix testing
