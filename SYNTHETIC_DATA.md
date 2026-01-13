# Synthetic Demo Data Summary

## Overview
The setup script now automatically injects synthetic data to ensure every MCP tool returns meaningful results during demos.

## Data Injected by Category

### 1. Smart PCAP Triggers (zeek-notice)
**Count:** 4 events  
**Purpose:** Demonstrate `find_smart_pcap_triggers()` tool

**Events:**
- Unusual HTTP method (TRACE) to /admin/config
- Large upload detected (250KB) - potential data exfiltration
- HTTP service on non-standard port 8080
- DNS query to suspicious TLD (.xyz domain)

**Demo Use:**
```
Agent: "Show me smart pcap triggers"
Returns: 4 suspicious events with UIDs for packet extraction
```

### 2. Cleartext Credentials (zeek-ftp)
**Count:** 3 FTP sessions  
**Purpose:** Demonstrate `audit_cleartext_creds()` tool

**Sessions:**
- admin/Password123! → 203.0.113.100:21
- backup/backup2024 → 198.51.100.75:21
- anonymous/guest@example.com → 93.184.216.100:21

**Demo Use:**
```
Agent: "Show me cleartext credentials"
Returns: 3 FTP sessions with exposed passwords
```

### 3. Long-Lived Connections (zeek-conn)
**Count:** 3 connections (plus 933 normal connections)  
**Purpose:** Demonstrate `find_long_connections()` tool

**Connections:**
- 192.168.1.45 → 185.220.101.5:443 (2 hours, SSL)
- 192.168.1.75 → 194.150.168.35:8443 (4 hours, SSL)
- 192.168.1.120 → 45.142.212.61:443 (3 hours, SSL)

**Demo Use:**
```
Agent: "Find long connections"
Returns: 3 persistent connections indicating possible C2 activity
```

### 4. Suspicious DNS Queries (zeek-dns)
**Count:** 30 queries (plus 229 normal queries)  
**Purpose:** Demonstrate `get_dns_summary()` tool

**Patterns:**
- 25 repetitive queries to c2-beacon.malware.xyz (beaconing)
- 5 DGA-like domains (.tk, .xyz, .top, .ga, .ml TLDs)

**Demo Use:**
```
Agent: "Show me DNS summary"
Returns: Top domains including suspicious beaconing pattern
```

### 5. Protocol Anomalies (zeek-weird)
**Count:** 14 events (10 original + 4 synthetic)  
**Purpose:** Demonstrate `get_weird_events()` tool

**New Events:**
- SMB directory traversal attempt
- HTTP bad chunk size (invalid Transfer-Encoding)
- SSH excessive version string
- SSL invalid server certificate

**Demo Use:**
```
Agent: "Get weird events"
Returns: 14 protocol anomalies and malformed packets
```

## Data Generation Logic

### Timestamps
All synthetic data uses timestamps from the past 24 hours to appear recent and relevant.

### IP Addresses
- Source IPs: 192.168.1.0/24 (internal)
- Destination IPs: Public IPs in documentation ranges and known suspicious IPs

### UIDs
All connections have valid Zeek UIDs for:
- Connection correlation
- Packet extraction via `extract_packets(uid)`
- Connection details via `get_connection_details(uid)`

## Integration with Setup

The synthetic data injection runs automatically as **Step 7** in `setup_smart_pcap_optimized.sh`:

```bash
>>> Step 7: Injecting synthetic data for demo...
```

This ensures:
1. All indices exist before injection
2. Real PCAP data is processed first
3. Synthetic data supplements (doesn't replace) real data
4. Every tool has guaranteed demo content

## Testing Individual Tools

After setup, test each tool:

```bash
# In the Chainlit UI
"menu"                          # Show all tools
"show me smart pcap triggers"   # 4 results
"audit cleartext credentials"   # 3 results
"find long connections"         # 3 results
"get dns summary"              # 259 total, 30 suspicious
"get weird events"             # 14 results
"show me top talkers"          # Volume metrics
"search for dns"               # 259 results
```

## File Location
- **Injection Script:** `inject_synthetic_data.py`
- **Called From:** `setup_smart_pcap_optimized.sh` (Step 7)
- **Can Run Standalone:** `python3 inject_synthetic_data.py`

## Future Enhancements
- Add more variety to connection patterns
- Include additional protocol types (SSH, RDP)
- Add time-series data for trend analysis
- Include failed authentication attempts
- Add port scanning patterns
