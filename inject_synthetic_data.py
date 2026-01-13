#!/usr/bin/env python3
"""
Inject synthetic data for demo purposes
Ensures all MCP tools return meaningful results
"""

import time
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

es = Elasticsearch('http://localhost:9200')

def inject_notice_data():
    """Inject Smart PCAP triggers / notice.log data"""
    print("\n>>> Injecting Smart PCAP triggers (notice.log)...")
    
    # Create index if it doesn't exist
    try:
        es.indices.create(
            index='zeek-notice',
            mappings={
                'properties': {
                    'ts': {'type': 'double'},
                    'uid': {'type': 'keyword'},
                    'id.orig_h': {'type': 'keyword'},
                    'id.orig_p': {'type': 'integer'},
                    'id.resp_h': {'type': 'keyword'},
                    'id.resp_p': {'type': 'integer'},
                    'proto': {'type': 'keyword'},
                    'note': {'type': 'keyword'},
                    'msg': {'type': 'text'},
                    'sub': {'type': 'text'},
                    'src': {'type': 'keyword'},
                    'dst': {'type': 'keyword'},
                    'actions': {'type': 'keyword'},
                    '@timestamp': {'type': 'double'}
                }
            },
            settings={'number_of_shards': 1, 'number_of_replicas': 0}
        )
        print("  ✓ Created zeek-notice index")
    except:
        print("  ✓ zeek-notice index exists")
    
    base_ts = time.time() - 86400  # 24 hours ago
    
    notices = [
        {
            'ts': base_ts + 100,
            'uid': 'CSmartPCAP001',
            'id.orig_h': '192.168.1.100',
            'id.orig_p': 49152,
            'id.resp_h': '203.0.113.45',
            'id.resp_p': 80,
            'proto': 'tcp',
            'note': 'SmartPCAP::Suspicious_HTTP_Method',
            'msg': 'Smart PCAP Trigger: Unusual HTTP method TRACE to /admin/config',
            'sub': 'HTTP method TRACE is rarely used and may indicate scanning',
            'src': '192.168.1.100',
            'dst': '203.0.113.45',
            'actions': 'Notice::ACTION_LOG',
            '@timestamp': base_ts + 100
        },
        {
            'ts': base_ts + 500,
            'uid': 'CSmartPCAP002',
            'id.orig_h': '192.168.1.75',
            'id.orig_p': 51234,
            'id.resp_h': '198.51.100.23',
            'id.resp_p': 443,
            'proto': 'tcp',
            'note': 'SmartPCAP::Large_Upload_Detected',
            'msg': 'Smart PCAP Trigger: Large upload detected (250KB) - potential data exfiltration',
            'sub': 'Upload size: 256000 bytes',
            'src': '192.168.1.75',
            'dst': '198.51.100.23',
            'actions': 'Notice::ACTION_LOG',
            '@timestamp': base_ts + 500
        },
        {
            'ts': base_ts + 1200,
            'uid': 'CSmartPCAP003',
            'id.orig_h': '192.168.1.50',
            'id.orig_p': 45678,
            'id.resp_h': '93.184.216.34',
            'id.resp_p': 8080,
            'proto': 'tcp',
            'note': 'SmartPCAP::Suspicious_Port_Usage',
            'msg': 'Smart PCAP Trigger: HTTP service on non-standard port 8080',
            'sub': 'HTTP detected on port 8080 instead of 80/443',
            'src': '192.168.1.50',
            'dst': '93.184.216.34',
            'actions': 'Notice::ACTION_LOG',
            '@timestamp': base_ts + 1200
        },
        {
            'ts': base_ts + 2000,
            'uid': 'CSmartPCAP004',
            'id.orig_h': '192.168.1.25',
            'id.orig_p': 53211,
            'id.resp_h': '185.53.177.8',
            'id.resp_p': 53,
            'proto': 'udp',
            'note': 'SmartPCAP::Suspicious_DNS_Query',
            'msg': 'Smart PCAP Trigger: DNS query to suspicious TLD - malware.xyz',
            'sub': 'Query: malware.xyz (suspicious TLD pattern)',
            'src': '192.168.1.25',
            'dst': '185.53.177.8',
            'actions': 'Notice::ACTION_LOG',
            '@timestamp': base_ts + 2000
        }
    ]
    
    actions = [{'_index': 'zeek-notice', '_source': n} for n in notices]
    success, _ = bulk(es, actions)
    print(f"  ✓ Injected {success} Smart PCAP trigger notices")


def inject_cleartext_creds():
    """Inject FTP cleartext credentials"""
    print("\n>>> Injecting cleartext credentials...")
    
    # Check if FTP index exists, create if not
    try:
        es.indices.create(
            index='zeek-ftp',
            mappings={
                'properties': {
                    'ts': {'type': 'double'},
                    'uid': {'type': 'keyword'},
                    'id.orig_h': {'type': 'keyword'},
                    'id.orig_p': {'type': 'integer'},
                    'id.resp_h': {'type': 'keyword'},
                    'id.resp_p': {'type': 'integer'},
                    'user': {'type': 'keyword'},
                    'password': {'type': 'keyword'},
                    'command': {'type': 'keyword'},
                    'arg': {'type': 'text'},
                    '@timestamp': {'type': 'double'}
                }
            },
            settings={'number_of_shards': 1, 'number_of_replicas': 0}
        )
        print("  ✓ Created zeek-ftp index")
    except:
        print("  ✓ zeek-ftp index exists")
    
    base_ts = time.time() - 86400
    
    ftp_sessions = [
        {
            'ts': base_ts + 300,
            'uid': 'CFTPCred001',
            'id.orig_h': '192.168.1.45',
            'id.orig_p': 51234,
            'id.resp_h': '203.0.113.100',
            'id.resp_p': 21,
            'user': 'admin',
            'password': 'Password123!',
            'command': 'USER',
            'arg': 'admin',
            '@timestamp': base_ts + 300
        },
        {
            'ts': base_ts + 800,
            'uid': 'CFTPCred002',
            'id.orig_h': '192.168.1.88',
            'id.orig_p': 52456,
            'id.resp_h': '198.51.100.75',
            'id.resp_p': 21,
            'user': 'backup',
            'password': 'backup2024',
            'command': 'USER',
            'arg': 'backup',
            '@timestamp': base_ts + 800
        },
        {
            'ts': base_ts + 1500,
            'uid': 'CFTPCred003',
            'id.orig_h': '192.168.1.120',
            'id.orig_p': 49876,
            'id.resp_h': '93.184.216.100',
            'id.resp_p': 21,
            'user': 'anonymous',
            'password': 'guest@example.com',
            'command': 'USER',
            'arg': 'anonymous',
            '@timestamp': base_ts + 1500
        }
    ]
    
    actions = [{'_index': 'zeek-ftp', '_source': f} for f in ftp_sessions]
    success, _ = bulk(es, actions)
    print(f"  ✓ Injected {success} FTP cleartext credential sessions")


def inject_long_connections():
    """Inject long-lived connections (potential C2)"""
    print("\n>>> Injecting long-lived connections...")
    
    base_ts = time.time() - 86400
    
    long_conns = [
        {
            'ts': base_ts,
            'uid': 'CLongConn001',
            'id.orig_h': '192.168.1.45',
            'id.orig_p': 49823,
            'id.resp_h': '185.220.101.5',
            'id.resp_p': 443,
            'proto': 'tcp',
            'service': 'ssl',
            'duration': 7200.0,  # 2 hours
            'orig_bytes': 45120,
            'resp_bytes': 89456,
            'conn_state': 'SF',
            'local_orig': True,
            'local_resp': False,
            'missed_bytes': 0,
            'history': 'ShADadFf',
            'orig_pkts': 234,
            'resp_pkts': 456,
            '@timestamp': base_ts
        },
        {
            'ts': base_ts + 100,
            'uid': 'CLongConn002',
            'id.orig_h': '192.168.1.75',
            'id.orig_p': 51234,
            'id.resp_h': '194.150.168.35',
            'id.resp_p': 8443,
            'proto': 'tcp',
            'service': 'ssl',
            'duration': 14400.0,  # 4 hours
            'orig_bytes': 98567,
            'resp_bytes': 156789,
            'conn_state': 'SF',
            'local_orig': True,
            'local_resp': False,
            'missed_bytes': 0,
            'history': 'ShADadFf',
            'orig_pkts': 567,
            'resp_pkts': 891,
            '@timestamp': base_ts + 100
        },
        {
            'ts': base_ts + 200,
            'uid': 'CLongConn003',
            'id.orig_h': '192.168.1.120',
            'id.orig_p': 52876,
            'id.resp_h': '45.142.212.61',
            'id.resp_p': 443,
            'proto': 'tcp',
            'service': 'ssl',
            'duration': 10800.0,  # 3 hours  
            'orig_bytes': 67234,
            'resp_bytes': 123456,
            'conn_state': 'SF',
            'local_orig': True,
            'local_resp': False,
            'missed_bytes': 0,
            'history': 'ShADadFf',
            'orig_pkts': 378,
            'resp_pkts': 689,
            '@timestamp': base_ts + 200
        }
    ]
    
    actions = [{'_index': 'zeek-conn', '_source': c} for c in long_conns]
    success, _ = bulk(es, actions)
    print(f"  ✓ Injected {success} long-lived connections (C2 indicators)")


def inject_suspicious_dns():
    """Inject suspicious DNS queries for beaconing detection"""
    print("\n>>> Injecting suspicious DNS queries...")
    
    base_ts = time.time() - 86400
    
    # Create repetitive queries (beaconing pattern)
    dns_queries = []
    for i in range(25):  # 25 queries to the same suspicious domain
        dns_queries.append({
            'ts': base_ts + (i * 60),  # Every minute
            'uid': f'CDNSBeacon{i:03d}',
            'id.orig_h': '192.168.1.88',
            'id.orig_p': 51234 + i,
            'id.resp_h': '8.8.8.8',
            'id.resp_p': 53,
            'proto': 'udp',
            'trans_id': 12345 + i,
            'query': 'c2-beacon.malware.xyz',
            'qclass': 1,
            'qclass_name': 'C_INTERNET',
            'qtype': 1,
            'qtype_name': 'A',
            'rcode': 0,
            'rcode_name': 'NOERROR',
            'AA': False,
            'TC': False,
            'RD': True,
            'RA': True,
            'Z': 0,
            '@timestamp': base_ts + (i * 60)
        })
    
    # Add some DGA-like domains
    dga_domains = [
        'xkj2hf8s.tk', 'p9sjdhf7.xyz', 'q2j8shf9.top',
        'm3kj9sfh.ga', 'n4jk8shf.ml'
    ]
    
    for idx, domain in enumerate(dga_domains):
        dns_queries.append({
            'ts': base_ts + 5000 + (idx * 100),
            'uid': f'CDNSDGA{idx:03d}',
            'id.orig_h': '192.168.1.120',
            'id.orig_p': 52000 + idx,
            'id.resp_h': '1.1.1.1',
            'id.resp_p': 53,
            'proto': 'udp',
            'trans_id': 54321 + idx,
            'query': domain,
            'qclass': 1,
            'qclass_name': 'C_INTERNET',
            'qtype': 1,
            'qtype_name': 'A',
            'rcode': 3,  # NXDOMAIN
            'rcode_name': 'NXDOMAIN',
            'AA': False,
            'TC': False,
            'RD': True,
            'RA': True,
            'Z': 0,
            '@timestamp': base_ts + 5000 + (idx * 100)
        })
    
    actions = [{'_index': 'zeek-dns', '_source': d} for d in dns_queries]
    success, _ = bulk(es, actions)
    print(f"  ✓ Injected {success} suspicious DNS queries (beaconing/DGA patterns)")


def inject_more_weird_events():
    """Add more protocol anomalies"""
    print("\n>>> Injecting additional weird events...")
    
    base_ts = time.time() - 86400
    
    weird_events = [
        {
            'ts': base_ts + 600,
            'uid': 'CWeird001',
            'id.orig_h': '192.168.1.45',
            'id.orig_p': 49152,
            'id.resp_h': '203.0.113.50',
            'id.resp_p': 445,
            'name': 'SMB_directory_traversal_attempt',
            'addl': 'Attempted path: ../../../../etc/passwd',
            'notice': False,
            'peer': 'zeek',
            'source': 'SMB',
            '@timestamp': base_ts + 600
        },
        {
            'ts': base_ts + 1200,
            'uid': 'CWeird002',
            'id.orig_h': '192.168.1.88',
            'id.orig_p': 51234,
            'id.resp_h': '198.51.100.75',
            'id.resp_p': 80,
            'name': 'HTTP_bad_chunk_size',
            'addl': 'Invalid chunk size in Transfer-Encoding',
            'notice': False,
            'peer': 'zeek',
            'source': 'HTTP',
            '@timestamp': base_ts + 1200
        },
        {
            'ts': base_ts + 1800,
            'uid': 'CWeird003',
            'id.orig_h': '192.168.1.120',
            'id.orig_p': 52876,
            'id.resp_h': '93.184.216.34',
            'id.resp_p': 22,
            'name': 'SSH_excessive_version_string',
            'addl': 'Version string exceeds 255 bytes',
            'notice': False,
            'peer': 'zeek',
            'source': 'SSH',
            '@timestamp': base_ts + 1800
        },
        {
            'ts': base_ts + 2400,
            'uid': 'CWeird004',
            'id.orig_h': '192.168.1.75',
            'id.orig_p': 49823,
            'id.resp_h': '185.220.101.5',
            'id.resp_p': 443,
            'name': 'SSL_invalid_server_cert',
            'addl': 'Certificate validation failed',
            'notice': False,
            'peer': 'zeek',
            'source': 'SSL',
            '@timestamp': base_ts + 2400
        }
    ]
    
    actions = [{'_index': 'zeek-weird', '_source': w} for w in weird_events]
    success, _ = bulk(es, actions)
    print(f"  ✓ Injected {success} additional weird events")


def main():
    print("="*60)
    print("SYNTHETIC DATA INJECTION FOR DEMO")
    print("="*60)
    
    # Check ES connection
    if not es.ping():
        print("❌ ERROR: Cannot connect to Elasticsearch")
        return 1
    
    print("✓ Connected to Elasticsearch")
    
    # Inject data for each tool that needs it
    inject_notice_data()           # For find_smart_pcap_triggers()
    inject_cleartext_creds()       # For audit_cleartext_creds()
    inject_long_connections()      # For find_long_connections()
    inject_suspicious_dns()        # For get_dns_summary() - more variety
    inject_more_weird_events()     # For get_weird_events()
    
    # Refresh indices
    print("\n>>> Refreshing indices...")
    for index in ['zeek-notice', 'zeek-ftp', 'zeek-conn', 'zeek-dns', 'zeek-weird']:
        try:
            es.indices.refresh(index=index)
            print(f"  ✓ Refreshed {index}")
        except:
            pass
    
    print("\n" + "="*60)
    print("SYNTHETIC DATA INJECTION COMPLETE")
    print("="*60)
    print("\nAll MCP tools now have demo data:")
    print("  ✓ search_zeek_logs() - 1200+ documents")
    print("  ✓ get_top_talkers() - Volume metrics available")
    print("  ✓ find_long_connections() - 3 C2-like connections")
    print("  ✓ audit_cleartext_creds() - 3 FTP sessions with passwords")
    print("  ✓ get_dns_summary() - 30+ suspicious queries")
    print("  ✓ get_weird_events() - 14 protocol anomalies")
    print("  ✓ find_smart_pcap_triggers() - 4 Smart PCAP alerts")
    print("  ✓ extract_packets() - UIDs available from all data")
    print("  ✓ get_connection_details() - Detailed metadata for all connections")
    print()

if __name__ == "__main__":
    main()
