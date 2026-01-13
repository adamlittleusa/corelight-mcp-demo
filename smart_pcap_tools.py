#!/usr/bin/env python3
"""
Smart PCAP Tools - Selective packet extraction and analysis
Based on Corelight Smart PCAP workflow
"""

import subprocess
import json
import os
from typing import List, Dict, Optional
from elasticsearch import Elasticsearch


class SmartPCAPExtractor:
    """Extract specific packets from PCAP files based on Zeek UIDs"""
    
    def __init__(self, pcap_path: str = "pcap/demo.pcap"):
        self.pcap_path = pcap_path
        
    def extract_by_uid(self, uid: str, output_path: Optional[str] = None) -> str:
        """
        Extract packets for a specific Zeek UID from the main PCAP file.
        
        This emulates Corelight's Smart PCAP feature where you can retrieve
        full packet captures for specific connections identified in logs.
        
        Args:
            uid: Zeek connection UID
            output_path: Where to save extracted PCAP (default: pcap/extracted_{uid}.pcap)
        
        Returns:
            Path to extracted PCAP file
        """
        if output_path is None:
            output_path = f"pcap/extracted_{uid}.pcap"
        
        # Use zeek-cut to find the connection details, then tcpdump to extract
        # In a real Corelight setup, this would query the Smart PCAP API
        print(f"Extracting packets for UID: {uid}")
        print(f"Output: {output_path}")
        
        # This would use Zeek's conn.log to find 5-tuple, then extract via BPF filter
        # For now, we'll document the workflow
        
        return output_path
    
    def extract_by_filter(self, bpf_filter: str, output_path: str, 
                         max_bytes: int = 2000) -> str:
        """
        Extract packets matching a BPF filter, limiting to first N bytes.
        
        This implements the "capture first 2000 bytes" Smart PCAP strategy.
        
        Args:
            bpf_filter: Berkeley Packet Filter expression
            output_path: Where to save extracted PCAP
            max_bytes: Maximum bytes to capture per packet (default 2000)
        
        Returns:
            Path to extracted PCAP file
        """
        cmd = [
            'tcpdump',
            '-r', self.pcap_path,
            '-w', output_path,
            '-s', str(max_bytes),  # Snap length - first N bytes only
            bpf_filter
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"Extracted packets to {output_path}")
            print(f"Capture limited to first {max_bytes} bytes per packet")
            return output_path
        except subprocess.CalledProcessError as e:
            print(f"Extraction failed: {e.stderr}")
            raise


class SmartPCAPAnalyzer:
    """Analyze Zeek logs to identify Smart PCAP triggers"""
    
    def __init__(self, es_host: str = "http://localhost:9200"):
        self.es = Elasticsearch(es_host)
    
    def find_smart_pcap_triggers(self) -> List[Dict]:
        """
        Query notice.log for Smart PCAP triggers.
        
        Returns list of notices that should trigger packet capture.
        """
        try:
            result = self.es.search(
                index='zeek-notice',
                body={
                    'size': 100,
                    'query': {
                        'bool': {
                            'must': [
                                {'exists': {'field': 'uid'}},
                                {'wildcard': {'msg': '*Smart PCAP Trigger*'}}
                            ]
                        }
                    },
                    'sort': [{'ts': 'desc'}]
                }
            )
            
            triggers = []
            for hit in result['hits']['hits']:
                doc = hit['_source']
                triggers.append({
                    'uid': doc.get('uid'),
                    'timestamp': doc.get('ts'),
                    'message': doc.get('msg'),
                    'note_type': doc.get('note'),
                    'source_ip': doc.get('id.orig_h'),
                    'dest_ip': doc.get('id.resp_h')
                })
            
            return triggers
        except Exception as e:
            print(f"Error querying triggers: {e}")
            return []
    
    def get_connection_details(self, uid: str) -> Optional[Dict]:
        """
        Get full connection details for a given UID from conn.log.
        
        This provides the 5-tuple needed for packet extraction.
        """
        try:
            result = self.es.search(
                index='zeek-conn',
                body={
                    'size': 1,
                    'query': {'term': {'uid': uid}}
                }
            )
            
            if result['hits']['total']['value'] > 0:
                return result['hits']['hits'][0]['_source']
            return None
        except Exception as e:
            print(f"Error getting connection details: {e}")
            return None
    
    def build_bpf_filter(self, conn_details: Dict) -> str:
        """
        Build a BPF filter from connection details.
        
        Args:
            conn_details: Connection details from conn.log
        
        Returns:
            BPF filter string for tcpdump
        """
        src_ip = conn_details.get('id.orig_h')
        dst_ip = conn_details.get('id.resp_h')
        src_port = conn_details.get('id.orig_p')
        dst_port = conn_details.get('id.resp_p')
        proto = conn_details.get('proto', 'tcp')
        
        bpf = f"{proto} and "
        bpf += f"((host {src_ip} and port {src_port}) and "
        bpf += f"(host {dst_ip} and port {dst_port}))"
        
        return bpf
    
    def smart_pivot_workflow(self, uid: str) -> Dict:
        """
        Complete Smart PCAP pivot workflow:
        1. Find connection in logs
        2. Build BPF filter
        3. Extract relevant packets (first 2000 bytes)
        4. Return analysis results
        
        This is the main workflow for the MCP agent to use.
        """
        print(f"\n{'='*60}")
        print(f"SMART PCAP PIVOT: {uid}")
        print(f"{'='*60}\n")
        
        # Step 1: Get connection details
        print("Step 1: Retrieving connection metadata from Zeek logs...")
        conn = self.get_connection_details(uid)
        
        if not conn:
            return {
                'success': False,
                'error': f'Connection {uid} not found in logs'
            }
        
        print(f"  Found: {conn.get('id.orig_h')}:{conn.get('id.orig_p')} -> "
              f"{conn.get('id.resp_h')}:{conn.get('id.resp_p')}")
        
        # Step 2: Build BPF filter
        print("\nStep 2: Building packet filter...")
        bpf = self.build_bpf_filter(conn)
        print(f"  BPF: {bpf}")
        
        # Step 3: Would extract packets (optional in demo)
        print("\nStep 3: Ready for Smart PCAP extraction")
        print("  Strategy: Capture first 2000 bytes (Corelight baseline)")
        print("  This provides protocol analysis without full payload storage")
        
        return {
            'success': True,
            'uid': uid,
            'connection': conn,
            'bpf_filter': bpf,
            'extraction_ready': True,
            'metadata': {
                'duration': conn.get('duration'),
                'bytes_sent': conn.get('orig_bytes'),
                'bytes_recv': conn.get('resp_bytes'),
                'service': conn.get('service')
            }
        }


def demo_smart_pcap_workflow():
    """Demonstration of Smart PCAP workflow for presentations"""
    
    print("\n" + "="*60)
    print("CORELIGHT SMART PCAP DEMONSTRATION")
    print("="*60)
    
    analyzer = SmartPCAPAnalyzer()
    
    print("\nPhase 1: Detection - Finding Smart PCAP Triggers")
    print("-" * 60)
    triggers = analyzer.find_smart_pcap_triggers()
    
    if triggers:
        print(f"Found {len(triggers)} Smart PCAP triggers:")
        for i, trigger in enumerate(triggers[:5], 1):
            print(f"\n  {i}. {trigger['note_type']}")
            print(f"     UID: {trigger['uid']}")
            print(f"     Message: {trigger['message']}")
            print(f"     {trigger['source_ip']} -> {trigger['dest_ip']}")
    else:
        print("  No Smart PCAP triggers found (checking sample connection)")
        # Fallback: get any connection for demo
        result = analyzer.es.search(
            index='zeek-conn',
            body={'size': 1, 'query': {'match_all': {}}}
        )
        if result['hits']['total']['value'] > 0:
            sample_uid = result['hits']['hits'][0]['_source'].get('uid')
            triggers = [{'uid': sample_uid, 'message': 'Sample connection for demo'}]
    
    if triggers:
        print("\n\nPhase 2: Smart Pivot - Selective PCAP Retrieval")
        print("-" * 60)
        
        sample_trigger = triggers[0]
        result = analyzer.smart_pivot_workflow(sample_trigger['uid'])
        
        if result['success']:
            print("\n✓ Smart PCAP pivot successful!")
            print("\nKey Advantages:")
            print("  • Searched metadata (logs) first - instant results")
            print("  • Only retrieve full packets when needed")
            print("  • Capture first 2000 bytes - enough for analysis")
            print("  • Massive storage savings vs full packet capture")
    
    print("\n" + "="*60)


if __name__ == '__main__':
    demo_smart_pcap_workflow()
