from fastmcp import FastMCP
from elasticsearch import Elasticsearch

# 1. Define the MCP Server
mcp = FastMCP("Corelight-SIEM-Gateway")

# 2. Connect to SIEM (Elasticsearch)
# In Codespaces, localhost:9200 hits the docker container
es = Elasticsearch("http://localhost:9200")

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
    """Searches for cleartext credentials extracted by Zeek (e.g., from FTP or HTTP Basic Auth)."""
    try:
        if not es.ping():
            return "Error: Could not connect to Elasticsearch."
        
        # Search across FTP and HTTP logs for user field
        response = es.search(
            index="zeek-ftp,zeek-http",
            body={
                "query": {"exists": {"field": "user"}},
                "size": 100
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return "No cleartext credentials identified in logs."
        
        results = []
        for h in hits:
            src = h['_source']
            service = h['_index'].replace('zeek-', '').upper()
            user = src.get('user', 'unknown')
            password = src.get('password', 'N/A')
            server = src.get('id.resp_h', 'unknown')
            port = src.get('id.resp_p', 'unknown')
            results.append(f"[{service}] User: {user} | Password: {password} | Server: {server}:{port}")
        
        return "\n".join(results)
    except Exception as e:
        return f"Error searching for credentials: {str(e)}"

if __name__ == "__main__":
    # Runs the MCP server on stdio (standard input/output)
    mcp.run()
