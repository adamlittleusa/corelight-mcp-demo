from fastmcp import FastMCP
from elasticsearch import Elasticsearch
import subprocess
import os

# 1. Define the MCP Server
mcp = FastMCP("Corelight-SIEM-Gateway")

# 2. Connect to SIEM (Elasticsearch)
# In Codespaces, localhost:9200 hits the docker container
es = Elasticsearch("http://localhost:9200")

# 3. Smart PCAP Configuration
PCAP_PATH = "pcap/demo.pcap"
EXTRACTED_PCAP_DIR = "pcap/extracted"

@mcp.tool()
def search_zeek_logs(query_string: str, max_results: int = 10) -> str:
    """
    Search Zeek logs in the SIEM for specific activity. 
    Useful for finding specific IPs, protocols (DNS, HTTP), or patterns.
    Use * for wildcard searches.
    """
    try:
        if not es.ping():
            return "Error: Could not connect to Elasticsearch. Is the docker container running?"

        # If query is just *, return some sample events
        if query_string.strip() == "*":
            response = es.search(
                index="zeek-*",
                body={
                    "size": max_results,
                    "query": {"match_all": {}},
                    "sort": [{"ts": {"order": "desc"}}]
                }
            )
        else:
            # Build a more intelligent query that searches multiple fields
            response = es.search(
                index="zeek-*",
                body={
                    "size": max_results,
                    "query": {
                        "multi_match": {
                            "query": query_string,
                            "fields": ["id.orig_h", "id.resp_h", "host", "method", "proto", "user", "*"],
                            "fuzziness": "AUTO"
                        }
                    },
                    "sort": [{"ts": {"order": "desc"}}]
                }
            )
        
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return f"No logs found matching '{query_string}'. Try searching for: protocol names (dns, http), IP addresses, hostnames, or use * for all events."
        
        results = []
        for hit in hits:
            src = hit['_source']
            index_type = hit['_index'].replace('zeek-', '').upper()
            ts = src.get('ts', 'unknown')
            orig = src.get('id.orig_h', 'unknown')
            resp = src.get('id.resp_h', 'unknown')
            
            # Format based on log type
            if 'http' in hit['_index']:
                method = src.get('method', 'unknown')
                host = src.get('host', 'unknown')
                results.append(f"[{index_type}] {orig} -> {host} ({method}) @ {ts}")
            elif 'ftp' in hit['_index']:
                user = src.get('user', 'unknown')
                results.append(f"[{index_type}] {orig} -> {resp} (user: {user}) @ {ts}")
            else:
                proto = src.get('proto', 'unknown')
                results.append(f"[{index_type}] {orig} -> {resp} ({proto}) @ {ts}")
        
        return "\n".join(results)
    except Exception as e:
        return f"Error querying SIEM: {str(e)}"

@mcp.tool()
def get_top_talkers(top_n: int = 5) -> str:
    """Identifies the high-volume source IPs (Top Talkers) in the dataset."""
    try:
        if not es.ping():
            return "Error: Could not connect to Elasticsearch."

        response = es.search(
            index="zeek-*",
            body={
                "size": 0,
                    "aggs": {"top_sources": {"terms": {"field": "id.orig_h", "size": top_n}}}
            }
        )
        buckets = response['aggregations']['top_sources']['buckets']
        return "\n".join([f"IP: {b['key']} - Flow Count: {b['doc_count']}" for b in buckets])
    except Exception as e:
        return f"Error aggregating SIEM data: {str(e)}"


@mcp.tool()
def find_long_connections(threshold_seconds: int = 3600) -> str:
    """Finds network connections that stayed open longer than the threshold (default 1hr)."""
    try:
        # Ensure ES is reachable
        if not es.ping():
            return "Error: Could not connect to Elasticsearch."
        # Check whether the 'duration' field exists in the index mapping
        try:
            mapping = es.indices.get_mapping(index='zeek-conn')
            # drill down to properties if present
            props = None
            for idx_name, idx_map in mapping.items():
                props = idx_map.get('mappings', {}).get('properties', {})
                if props is not None:
                    break
            if not props or 'duration' not in props:
                return "No 'duration' field found in 'zeek-conn' mapping; cannot search for long connections."
        except Exception:
            # If mapping query fails, continue but guard the search with try/except
            props = None

        try:
            response = es.search(
                index="zeek-conn",
                body={
                    "query": {"range": {"duration": {"gt": threshold_seconds}}},
                    "sort": [{"duration": {"order": "desc"}}],
                    "size": 100
                }
            )

            hits = response.get('hits', {}).get('hits', [])
            if not hits:
                return "No long-lived connections found."

            results = []
            for h in hits:
                src = h.get('_source', {})
                dur = src.get('duration', 'unknown')
                orig = src.get('id.orig_h', 'unknown')
                resp = src.get('id.resp_h', 'unknown')
                svc = src.get('service', src.get('proto', 'unknown'))
                results.append(f"Duration: {dur}s | {orig} -> {resp} (Service: {svc})")

            return "\n".join(results)
        except Exception as e:
            return f"Error searching for long connections: {e}"
    except Exception as e:
        return f"Error searching for long connections: {e}"

    # Fallback: if 'duration' field is not available, fetch conn docs and compute max(ts)-min(ts) per uid
    try:
        # fetch all conn docs (for demo datasets this is OK)
        resp = es.search(index='zeek-conn', body={"size": 10000, "query": {"match_all": {}}})
        hits = resp.get('hits', {}).get('hits', [])
        if not hits:
            return "No connection documents available to analyze."

        # group by uid (or by src->dst if uid missing)
        groups = {}
        for h in hits:
            src = h.get('_source', {})
            uid = src.get('uid') or f"{src.get('id.orig_h','unknown')}-{src.get('id.resp_h','unknown')}"
            try:
                ts = float(src.get('ts', 0))
            except Exception:
                ts = 0.0
            entry = groups.setdefault(uid, {"min": ts, "max": ts, "orig": src.get('id.orig_h','unknown'), "resp": src.get('id.resp_h','unknown'), "service": src.get('service', src.get('proto','unknown'))})
            if ts < entry['min']:
                entry['min'] = ts
            if ts > entry['max']:
                entry['max'] = ts

        # compute durations and filter by threshold
        results = []
        for uid, v in groups.items():
            duration = v['max'] - v['min']
            if duration > threshold_seconds:
                results.append((duration, v['orig'], v['resp'], v['service']))

        if not results:
            return "No long-lived connections found (fallback analysis)."

        # sort by duration desc and format
        results.sort(reverse=True, key=lambda x: x[0])
        out = [f"Duration: {int(d)}s | {o} -> {r} (Service: {s})" for d,o,r,s in results[:100]]
        return "\n".join(out)
    except Exception as e:
        return f"Error during fallback duration analysis: {e}"


@mcp.tool()
def audit_cleartext_creds() -> str:
    """
    Searches for cleartext credentials and passwords extracted by Zeek from network traffic.
    Finds exposed FTP credentials, HTTP Basic Auth usernames/passwords, and other cleartext authentication.
    Returns user accounts, passwords, and the servers they were sent to.
    Use this when asked about: credentials, passwords, cleartext, FTP, exposed authentication, insecure logins.
    """
    try:
        if not es.ping():
            return "Error: Could not connect to Elasticsearch."
        
        # Search for credentials across available indices
        # Use ignore_unavailable to handle missing indices gracefully
        response = es.search(
            index="zeek-ftp,zeek-http",
            body={
                "query": {"exists": {"field": "user"}},
                "size": 100
            },
            ignore_unavailable=True
        )
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return "No cleartext credentials identified in logs."
        
        results = []
        results.append(f"Found {len(hits)} cleartext credential exposures:\n")
        for h in hits:
            src = h['_source']
            service = h['_index'].replace('zeek-', '').upper()
            user = src.get('user', 'unknown')
            password = src.get('password', 'N/A')
            server = src.get('id.resp_h', 'unknown')
            port = src.get('id.resp_p', 'unknown')
            client = src.get('id.orig_h', 'unknown')
            results.append(f"  [{service}] {client} → {server}:{port}")
            results.append(f"           User: {user}")
            results.append(f"           Password: {password}\n")
        
        return "\n".join(results)
    except Exception as e:
        return f"Error searching for credentials: {str(e)}"

@mcp.tool()
def get_dns_summary() -> str:
    """Returns the most frequently queried DNS domains (helps spot beaconing/DGA)."""
    try:
        if not es.ping():
            return "Error: Could not connect to Elasticsearch."
        # Aggregate on the 'query' field; our mappings store it as 'keyword'
        response = es.search(
            index="zeek-dns",
            body={
                "size": 0,
                "aggs": {
                    "top_domains": {
                        "terms": {"field": "query", "size": 10}
                    }
                }
            }
        )
        buckets = response.get('aggregations', {}).get('top_domains', {}).get('buckets', [])
        if not buckets:
            return "No DNS query data available."
        return "\n".join([f"Domain: {b['key']} ({b['doc_count']} queries)" for b in buckets])
    except Exception as e:
        return f"Error summarizing DNS: {str(e)}"


@mcp.tool()
def get_weird_events(max_results: int = 20) -> str:
    """
    Get protocol anomalies and weird network behavior detected by Zeek.
    weird.log contains anomalies like malformed packets, protocol violations,
    scan attempts, and other unusual network behavior.
    
    Args:
        max_results: Maximum number of weird events to return (default 20)
    
    Returns:
        List of weird/anomalous network events
    """
    try:
        if not es.ping():
            return "Error: Could not connect to Elasticsearch."
        
        response = es.search(
            index="zeek-weird",
            body={
                "size": max_results,
                "query": {"match_all": {}},
                "sort": [{"ts": {"order": "desc"}}]
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return ("No weird events found.\n\n"
                   "This means Zeek detected no protocol anomalies or unusual behavior.\n"
                   "Weird events include:\n"
                   "- Malformed packets\n"
                   "- Protocol violations\n"
                   "- Port scanning attempts\n"
                   "- Connection state anomalies")
        
        # Count by type
        weird_types = {}
        for hit in hits:
            name = hit['_source'].get('name', 'unknown')
            weird_types[name] = weird_types.get(name, 0) + 1
        
        results = []
        results.append("🔍 PROTOCOL ANOMALIES DETECTED\n")
        results.append(f"Total weird events: {len(hits)}\n")
        
        # Summary by type
        results.append("Anomaly Types:")
        for name, count in sorted(weird_types.items(), key=lambda x: x[1], reverse=True):
            results.append(f"  • {name}: {count} occurrences")
        
        results.append("\nDetailed Events:")
        for hit in hits[:max_results]:
            src = hit['_source']
            ts = src.get('ts', 'unknown')
            name = src.get('name', 'Unknown')
            addl = src.get('addl', '')
            orig = src.get('id.orig_h', 'unknown')
            resp = src.get('id.resp_h', 'unknown')
            uid = src.get('uid', 'N/A')
            
            results.append(f"\n  [{name}] @ {ts}")
            results.append(f"    Connection: {orig} -> {resp}")
            results.append(f"    UID: {uid}")
            if addl:
                results.append(f"    Details: {addl}")
        
        return "\n".join(results)
    except Exception as e:
        return f"Error querying weird events: {str(e)}"


@mcp.tool()
def find_smart_pcap_triggers() -> str:
    """
    Find Smart PCAP triggers - suspicious events that warrant full packet capture.
    These are alerts generated by Zeek for unusual activity like:
    - Unusual HTTP methods
    - Large uploads (potential data exfiltration)
    - Suspicious DNS queries
    - Failed authentication patterns
    """
    try:
        if not es.ping():
            return "Error: Could not connect to Elasticsearch."
        
        response = es.search(
            index="zeek-notice",
            body={
                "size": 50,
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"msg": "*Smart PCAP Trigger*"}},
                            {"wildcard": {"note": "*Suspicious*"}},
                            {"wildcard": {"note": "*SmartPCAP*"}}
                        ]
                    }
                },
                "sort": [{"ts": {"order": "desc"}}]
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return ("No Smart PCAP triggers found.\n\n"
                   "This means the current dataset contains normal traffic patterns.\n"
                   "Smart PCAP triggers fire on suspicious activity like:\n"
                   "- Unusual HTTP methods (TRACE, CONNECT, etc.)\n"
                   "- Large uploads (>100KB)\n"
                   "- Non-standard port usage\n"
                   "- Suspicious DNS queries (.xyz, .tk domains)")
        
        results = []
        results.append("🎯 SMART PCAP TRIGGERS DETECTED\n")
        results.append("These events have full packet capture available:\n")
        
        for hit in hits:
            src = hit['_source']
            ts = src.get('ts', 'unknown')
            uid = src.get('uid', 'N/A')
            msg = src.get('msg', 'No message')
            note = src.get('note', 'Unknown')
            orig = src.get('id.orig_h', 'unknown')
            resp = src.get('id.resp_h', 'unknown')
            
            results.append(f"\n[{note}] @ {ts}")
            results.append(f"  Connection: {orig} -> {resp}")
            results.append(f"  UID: {uid}")
            results.append(f"  Alert: {msg}")
            results.append(f"  Action: Use 'extract_packets(\"{uid}\")' to get full PCAP")
        
        return "\n".join(results)
    except Exception as e:
        return f"Error searching for Smart PCAP triggers: {str(e)}"


@mcp.tool()
def extract_packets(uid: str) -> str:
    """
    Extract full packet capture for a specific connection UID.
    
    This is the core Smart PCAP functionality - given a UID from Zeek logs,
    extract only those packets from the full PCAP file.
    
    Args:
        uid: Zeek connection UID (from conn.log or notice.log)
    
    Returns:
        Path to extracted PCAP file and extraction details
    """
    try:
        if not es.ping():
            return "Error: Could not connect to Elasticsearch."
        
        # Step 1: Get connection details from Zeek logs
        response = es.search(
            index="zeek-conn",
            body={
                "size": 1,
                "query": {"term": {"uid": uid}}
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return (f"Connection UID '{uid}' not found in logs.\n\n"
                   "Use 'find_smart_pcap_triggers()' to see available UIDs, or\n"
                   "search_zeek_logs() to find specific connections.")
        
        conn = hits[0]['_source']
        
        # Extract connection 5-tuple
        src_ip = conn.get('id.orig_h', 'unknown')
        dst_ip = conn.get('id.resp_h', 'unknown')
        src_port = conn.get('id.orig_p', 'unknown')
        dst_port = conn.get('id.resp_p', 'unknown')
        proto = conn.get('proto', 'tcp').lower()
        service = conn.get('service', 'unknown')
        
        # Step 2: Build BPF filter
        bpf_filter = (f"{proto} and "
                     f"((host {src_ip} and port {src_port}) and "
                     f"(host {dst_ip} and port {dst_port}))")
        
        # Step 3: Extract packets using tcpdump
        os.makedirs(EXTRACTED_PCAP_DIR, exist_ok=True)
        output_file = f"{EXTRACTED_PCAP_DIR}/{uid}.pcap"
        
        result = subprocess.run(
            ['tcpdump', '-r', PCAP_PATH, '-w', output_file, bpf_filter],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return f"Error extracting packets: {result.stderr}"
        
        # Check output file size
        if os.path.exists(output_file):
            size_bytes = os.path.getsize(output_file)
            size_kb = size_bytes / 1024
            
            # Get packet count
            count_result = subprocess.run(
                ['tcpdump', '-r', output_file, '-q'],
                capture_output=True,
                text=True
            )
            packet_count = len(count_result.stdout.splitlines())
            
            summary = []
            summary.append("✅ SMART PCAP EXTRACTION SUCCESSFUL\n")
            summary.append(f"Connection Details:")
            summary.append(f"  UID: {uid}")
            summary.append(f"  Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            summary.append(f"  Protocol: {proto.upper()}")
            summary.append(f"  Service: {service}")
            summary.append(f"\nExtracted PCAP:")
            summary.append(f"  File: {output_file}")
            summary.append(f"  Size: {size_kb:.2f} KB")
            summary.append(f"  Packets: {packet_count}")
            summary.append(f"\nNext Steps:")
            summary.append(f"  - Open in Wireshark: wireshark {output_file}")
            summary.append(f"  - Analyze with tcpdump: tcpdump -r {output_file} -A")
            summary.append(f"  - View headers: tcpdump -r {output_file} -nn")
            
            return "\n".join(summary)
        else:
            return "Error: Output file was not created"
        
    except subprocess.TimeoutExpired:
        return "Error: Packet extraction timed out (PCAP may be too large)"
    except Exception as e:
        return f"Error during packet extraction: {str(e)}"


@mcp.tool()
def get_connection_details(uid: str) -> str:
    """
    Get detailed information about a specific connection by UID.
    Shows all metadata from conn.log including duration, bytes transferred, etc.
    
    Args:
        uid: Zeek connection UID
    
    Returns:
        Detailed connection metadata
    """
    try:
        if not es.ping():
            return "Error: Could not connect to Elasticsearch."
        
        response = es.search(
            index="zeek-conn",
            body={
                "size": 1,
                "query": {"term": {"uid": uid}}
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return f"Connection UID '{uid}' not found in conn.log"
        
        conn = hits[0]['_source']
        
        # Format comprehensive connection details
        details = []
        details.append(f"Connection UID: {uid}\n")
        details.append("=" * 60)
        details.append(f"\n5-Tuple:")
        details.append(f"  Source:      {conn.get('id.orig_h', 'unknown')}:{conn.get('id.orig_p', 'unknown')}")
        details.append(f"  Destination: {conn.get('id.resp_h', 'unknown')}:{conn.get('id.resp_p', 'unknown')}")
        details.append(f"  Protocol:    {conn.get('proto', 'unknown')}")
        
        if 'service' in conn:
            details.append(f"  Service:     {conn['service']}")
        
        details.append(f"\nTiming:")
        details.append(f"  Start:       {conn.get('ts', 'unknown')}")
        if 'duration' in conn:
            details.append(f"  Duration:    {conn['duration']:.2f} seconds")
        
        details.append(f"\nData Transfer:")
        if 'orig_bytes' in conn:
            details.append(f"  Sent:        {conn['orig_bytes']:,} bytes")
        if 'resp_bytes' in conn:
            details.append(f"  Received:    {conn['resp_bytes']:,} bytes")
        if 'orig_pkts' in conn:
            details.append(f"  Sent Pkts:   {conn['orig_pkts']}")
        if 'resp_pkts' in conn:
            details.append(f"  Recv Pkts:   {conn['resp_pkts']}")
        
        details.append(f"\nConnection State:")
        if 'conn_state' in conn:
            details.append(f"  State:       {conn['conn_state']}")
        if 'history' in conn:
            details.append(f"  History:     {conn['history']}")
        
        # Add related logs info
        details.append(f"\n" + "=" * 60)
        details.append(f"Smart PCAP Actions:")
        details.append(f"  • Extract packets: extract_packets(\"{uid}\")")
        details.append(f"  • Search HTTP logs: search_zeek_logs(\"{uid}\")")
        
        return "\n".join(details)
    except Exception as e:
        return f"Error retrieving connection details: {str(e)}"

if __name__ == "__main__":
    # Runs the MCP server on stdio (standard input/output)
    mcp.run()
