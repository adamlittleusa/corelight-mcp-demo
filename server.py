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
    Useful for finding specific IPs, protocols (DNS, HTTP), or error codes.
    """
    try:
        if not es.ping():
            return "Error: Could not connect to Elasticsearch. Is the docker container running?"

        response = es.search(
            index="zeek-*",
            body={
                "size": max_results,
                "query": {"query_string": {"query": query_string, "analyze_wildcard": True}},
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return "No logs found matching that query."
        
        results = []
        for hit in hits:
            src = hit['_source']
            # Format strictly as evidence string
            ts = src.get('@timestamp', 'unknown')
            orig = src.get('id.orig_h', 'unknown')
            resp = src.get('id.resp_h', 'unknown')
            proto = src.get('proto', 'unknown')
            results.append(f"[{ts}] {orig} -> {resp} ({proto})")
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
                "aggs": {"top_sources": {"terms": {"field": "id.orig_h.keyword", "size": top_n}}}
            }
        )
        buckets = response['aggregations']['top_sources']['buckets']
        return "\n".join([f"IP: {b['key']} - Flow Count: {b['doc_count']}" for b in buckets])
    except Exception as e:
        return f"Error aggregating SIEM data: {str(e)}"

if __name__ == "__main__":
    # Runs the MCP server on stdio (standard input/output)
    mcp.run()
