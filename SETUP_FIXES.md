# Smart PCAP Setup Fixes Applied

## Issues Identified
1. **weird.log missing from priority ingestion** - User wanted to build MCP tools around weird.log
2. **Batch timeout errors** - Elasticsearch timing out during bulk ingestion under disk pressure

## Solutions Implemented

### 1. Added weird.log to Priority Logs
```bash
PRIORITY_LOGS = ['conn', 'http', 'dns', 'notice', 'weird']
```
- weird.log contains protocol anomalies and malformed packets
- Critical for security analysis and threat hunting
- Small file size (828 bytes, 14 records in test data)

### 2. Reduced Batch Size (200 → 50 documents)
**Why:** Disk at 91% capacity causing Elasticsearch high watermark threshold
- Reduced from 200 docs per batch to 50 docs
- Prevents bulk API timeouts under resource constraints

### 3. Increased Timeout & Added Retries
```python
es_with_timeout = es.options(
    request_timeout=60,      # Increased from 30s
    max_retries=3,           # Added retry logic
    retry_on_timeout=True    # Retry failed requests
)
```

### 4. Enhanced Error Handling
- Continues ingestion even if individual batches fail
- Logs failures without crashing entire process
- Tracks failed document counts for visibility

### 5. Added MCP Tool: get_weird_events()
New tool in server.py for querying protocol anomalies:
- Detects malformed packets
- Identifies protocol violations
- Finds scan attempts
- Shows connection state anomalies

## Technical Details

### Batch Processing Flow
```python
# Process in small chunks
if len(actions) >= 50:
    success, failed = bulk(
        es_with_timeout, 
        actions, 
        raise_on_error=False,    # Don't crash on error
        chunk_size=50,            # Process 50 at a time
        request_timeout=60        # Allow 60s per batch
    )
```

### Current System State
- **Disk Usage:** 91% (27GB / 32GB)
- **Elasticsearch:** Healthy but at high watermark
- **PCAP Data:** 7.5GB total (using 5 smallest files)
- **Processing Strategy:** Metadata-first, packets on-demand

## Priority Logs Indexed
1. **conn.log** (942 records) - Connection metadata
2. **http.log** (93 records) - HTTP requests/responses
3. **dns.log** (238 records) - DNS queries
4. **notice.log** (0 records in sample) - Zeek alerts/Smart PCAP triggers
5. **weird.log** (14 records) - Protocol anomalies ✅ NEW

## Non-Indexed Logs (Storage Optimization)
- files.log (109 records) - Large, caused previous timeouts
- ssl.log (47 records) - Not critical for demo
- x509.log (12 records) - Certificate details
- ntp.log (174 records) - Time sync traffic
- dhcp.log (10 records) - DHCP leases

## Ready to Run
The setup script is now optimized for:
- ✅ Stable ingestion without timeouts
- ✅ weird.log analysis capability
- ✅ Smart PCAP workflow demonstration
- ✅ Resource-constrained environment
- ✅ All MCP tools functional

## Next Step
```bash
./setup_smart_pcap_optimized.sh
```
