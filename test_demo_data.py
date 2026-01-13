#!/usr/bin/env python3
"""
Quick test to verify all MCP tools return data
"""

from elasticsearch import Elasticsearch

es = Elasticsearch('http://localhost:9200')

print("="*60)
print("MCP TOOL DATA VALIDATION")
print("="*60)

tests = [
    ("search_zeek_logs", "zeek-*", {"match_all": {}}, "> 1000 docs"),
    ("get_top_talkers", "zeek-conn", {"exists": {"field": "id.orig_h"}}, "> 900 docs"),
    ("find_long_connections", "zeek-conn", {"range": {"duration": {"gte": 3600}}}, ">= 3 docs"),
    ("audit_cleartext_creds", "zeek-ftp", {"exists": {"field": "user"}}, ">= 3 docs"),
    ("get_dns_summary", "zeek-dns", {"match_all": {}}, "> 250 docs"),
    ("get_weird_events", "zeek-weird", {"match_all": {}}, ">= 14 docs"),
    ("find_smart_pcap_triggers", "zeek-notice", {"match_all": {}}, ">= 4 docs"),
]

all_passed = True

for tool_name, index, query, expected in tests:
    try:
        result = es.count(index=index, body={"query": query})
        count = result['count']
        
        # Parse expected
        if ">=" in expected:
            threshold = int(expected.split(">=")[1].split()[0])
            passed = count >= threshold
        elif ">" in expected:
            threshold = int(expected.split(">")[1].split()[0])
            passed = count > threshold
        else:
            passed = False
        
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status} {tool_name:30s} {count:5d} docs (expected {expected})")
        
        if not passed:
            all_passed = False
            
    except Exception as e:
        print(f"✗ FAIL {tool_name:30s} ERROR: {e}")
        all_passed = False

print("="*60)
if all_passed:
    print("✓ ALL TOOLS HAVE DEMO DATA")
else:
    print("✗ SOME TOOLS MISSING DATA - Run inject_synthetic_data.py")
print("="*60)
