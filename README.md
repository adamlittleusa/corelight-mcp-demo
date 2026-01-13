# corelight-mcp-demo
Corelight MCP Demo

## Quick Start

### Option 1: Optimized Smart PCAP Setup (Recommended)
```bash
./setup_smart_pcap_optimized.sh
```

This setup includes:
- Automatic Elasticsearch health checks
- RED cluster detection and auto-fix
- Selective log ingestion (conn, http, dns, notice, weird)
- **Synthetic data injection for complete demo coverage**
- Optimized for disk-constrained environments
- Smart PCAP workflow with on-demand packet extraction

**Synthetic Data Included:**
- 4 Smart PCAP triggers (suspicious HTTP methods, large uploads, etc.)
- 3 FTP cleartext credential sessions
- 3 long-lived connections (C2 indicators, 2-4 hour durations)
- 30 suspicious DNS queries (beaconing/DGA patterns)
- 14 protocol anomalies (weird events)

All MCP tools guaranteed to return meaningful demo results!

### Option 2: Simple Setup
```bash
./setup_smart_pcap_simple.sh
```

### Testing the Health Check
```bash
./test_health_check.sh
```

This validates:
- Elasticsearch connectivity
- Cluster status detection
- Disk watermark configuration
- Shard allocation status
- RED status auto-fix readiness

## Features

### Automatic Health Recovery
The setup script automatically detects and fixes common Elasticsearch issues:
- **RED cluster status** - Adjusts disk watermarks when storage exceeds thresholds
- **Unassigned shards** - Waits for recovery before proceeding
- **Disk pressure** - Increases watermark limits (95% low, 97% high, 99% flood)

### Smart PCAP Workflow
- Indexes metadata for all connections
- Full packets available on-demand via MCP tools
- Extract specific connections by UID
- Zeek triggers for suspicious activity

## MCP Tools Available

- `search_zeek_logs()` - Search across all indexed logs
- `get_top_talkers()` - Volume analysis by source IP
- `find_long_connections()` - Detect persistent connections (C2)
- `audit_cleartext_creds()` - Find exposed passwords
- `get_dns_summary()` - DNS beaconing detection
- `get_weird_events()` - Protocol anomalies and malformed packets
- `find_smart_pcap_triggers()` - List suspicious events for packet extraction
- `extract_packets(uid)` - Extract full PCAP for specific connection
- `get_connection_details(uid)` - Detailed connection metadata

## Troubleshooting

### Cluster Status RED
The setup script automatically handles this, but you can manually check:
```bash
curl -s "http://localhost:9200/_cluster/health?pretty"
```

If RED, run the health check test to see details:
```bash
./test_health_check.sh
```

### Disk Space Issues
Check current usage:
```bash
df -h /
```

Free up space:
```bash
docker system prune -f --volumes
```

### Verify Ingestion
```bash
curl -s "http://localhost:9200/_cat/indices?v"
```
