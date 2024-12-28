# Recovery Steps and Best Practices for Handling Lagging Finality

## Recovery Steps
### 1. **Detect Lagging Finality**
- **Check Logs**:
  - Parse the logs for keywords like `"finality is lagging"` or discrepancies between the `best block` and `finalized block` heights.
- **Monitor Metrics**:
  - Compare `best_block_height` and `finalized_block_height`. If the gap exceeds a predefined threshold, finality is lagging.

### 2. **Diagnose the Issue**
- **Validator Status**:
  - Identify offline validators by querying the validator statuses.
  - Check if validators are unreachable or experiencing issues.
- **Network Health**:
  - Detect network partitions or connectivity issues by examining peer counts and latency metrics.

### 3. **Take Corrective Actions**
#### a. Restart Offline Validators
1. Identify the validators that are down.
2. Restart them using the appropriate system or orchestration tool (e.g., Docker, Kubernetes).
3. Verify that the validators have rejoined the network.

#### b. Resynchronize Nodes
1. Identify out-of-sync nodes.
2. Resynchronize them by resetting their database or reinitializing their state.

#### c. Resolve Network Partitions
1. Investigate and fix connectivity issues causing the partition.
2. Ensure that nodes can communicate across subnets or regions.

### 4. **Verify Recovery**
- Compare `best_block_height` and `finalized_block_height`. If they match, finality has been restored.
- Confirm that validators are online and producing blocks.

## Best Practices
1. **Validator Setup**:
   - Use reliable hardware with redundancy.
   - Maintain backup nodes for failover.
2. **Network Configuration**:
   - Ensure low-latency, high-bandwidth connections.
   - Distribute nodes geographically to avoid single points of failure.
3. **Monitoring and Alerts**:
   - Use tools like Prometheus and Grafana to monitor metrics.
   - Set alerts for abnormal block height discrepancies or validator downtime.
4. **Disaster Recovery Plan**:
   - Maintain and test recovery scripts regularly.
   - Document procedures for common failure scenarios.
