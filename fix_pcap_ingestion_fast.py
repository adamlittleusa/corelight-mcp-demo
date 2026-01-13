#!/usr/bin/env python3
"""
Fast PCAP ingestion using bulk indexing
"""

import os
import glob
import subprocess
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import json

def main():
    os.chdir('/workspaces/corelight-mcp-demo')
    
    print("="*60)
    print("FAST PCAP INGESTION (BULK MODE)")
    print("="*60)
    
    # Step 1: Find smallest PCAP file
    print("\n>>> Finding smallest PCAP file...")
    pcap_files = glob.glob('demo_pcap_upload/2015-*/snort.log.*')
    
    if not pcap_files:
        print("ERROR: No PCAP files found!")
        return 1
    
    pcap_files_with_size = [(f, os.path.getsize(f)) for f in pcap_files]
    pcap_files_with_size.sort(key=lambda x: x[1])
    
    sample_pcap, size = pcap_files_with_size[0]
    print(f"Selected: {sample_pcap}")
    print(f"Size: {size:,} bytes ({size/1024/1024:.1f} MB)")
    
    # Step 2: Delete existing indices
    print("\n>>> Deleting existing indices...")
    es = Elasticsearch('http://localhost:9200')
    
    for index in ['zeek-conn', 'zeek-http', 'zeek-dns', 'zeek-ftp', 'zeek-ssl', 
                  'zeek-ntp', 'zeek-dhcp', 'zeek-files', 'zeek-weird', 'zeek-x509', 
                  'zeek-packet_filter']:
        try:
            es.indices.delete(index=index)
            print(f"  Deleted {index}")
        except:
            pass
    
    # Step 3: Copy PCAP (reuse if already there)
    if not os.path.exists('pcap/demo.pcap') or os.path.getsize('pcap/demo.pcap') != size:
        print("\n>>> Copying PCAP to pcap/demo.pcap...")
        subprocess.run(['cp', sample_pcap, 'pcap/demo.pcap'], check=True)
    else:
        print("\n>>> Using existing pcap/demo.pcap")
    
    # Step 4: Check if Zeek logs already exist
    log_files = glob.glob('logs/*.log')
    if not log_files or len(log_files) < 5:
        print("\n>>> Running Zeek analysis...")
        subprocess.run(['rm', '-f'] + glob.glob('logs/*.log'))
        
        result = subprocess.run([
            'docker', 'run', '--rm',
            '-v', f'{os.getcwd()}/pcap:/pcap',
            '-v', f'{os.getcwd()}/logs:/logs',
            'zeek/zeek:latest',
            'bash', '-c', 'cd /logs && zeek -C -r /pcap/demo.pcap'
        ], capture_output=True, text=True, timeout=180)
        
        if result.returncode != 0:
            print(f"ERROR: Zeek failed: {result.stderr}")
            return 1
        
        log_files = glob.glob('logs/*.log')
    
    print(f"\n>>> Found {len(log_files)} log files")
    
    # Step 5: Fast bulk ingest
    print("\n>>> Fast bulk ingestion into Elasticsearch...")
    
    TYPE_MAPPING = {
        'time': 'double', 'interval': 'double', 'count': 'long',
        'int': 'long', 'double': 'double', 'bool': 'boolean',
        'string': 'keyword', 'addr': 'keyword', 'port': 'integer',
        'enum': 'keyword', 'vector': 'text', 'set': 'text',
        'table': 'text', 'record': 'text'
    }
    
    # Collect mappings
    all_mappings = {}
    for log_file in log_files:
        log_type = os.path.basename(log_file).split('.')[0]
        fields = None
        field_types = None
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.rstrip('\n')
                if line.startswith('#fields'):
                    fields = line.split()[1:]
                elif line.startswith('#types'):
                    field_types = line.split()[1:]
                    if fields and field_types:
                        mappings = {}
                        for fname, ftype in zip(fields, field_types):
                            es_type = TYPE_MAPPING.get(ftype, 'keyword')
                            mappings[fname] = {'type': es_type}
                        all_mappings[log_type] = (mappings, fields, field_types)
                    break
    
    # Create indices
    for log_type, (mappings, _, _) in all_mappings.items():
        try:
            es.indices.create(
                index=f'zeek-{log_type}',
                mappings={'properties': mappings}
            )
            print(f"  Created index zeek-{log_type}")
        except Exception as e:
            print(f"  Index zeek-{log_type} exists")
    
    # Bulk ingest
    total_docs = 0
    for log_file in log_files:
        log_type = os.path.basename(log_file).split('.')[0]
        
        if log_type not in all_mappings:
            continue
            
        _, fields, field_types = all_mappings[log_type]
        sep = '\t'
        
        # Prepare bulk data
        actions = []
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.rstrip('\n')
                if not line or line.startswith('#'):
                    if line.startswith('#separator'):
                        parts = line.split(' ', 1)
                        if len(parts) > 1:
                            try:
                                sep = parts[1].encode('utf-8').decode('unicode_escape')
                            except:
                                sep = '\t'
                    continue
                
                if fields is None:
                    continue
                
                parts = line.split(sep)
                if len(parts) < len(fields):
                    parts += [''] * (len(fields) - len(parts))
                
                doc = {}
                for k, v, ftype in zip(fields, parts, field_types if field_types else ['string']*len(fields)):
                    if v == '-' or v == '':
                        continue
                    try:
                        if ftype in ('time', 'interval', 'count', 'int', 'double'):
                            doc[k] = float(v) if ftype in ('time', 'interval', 'double') else int(v)
                        elif ftype == 'bool':
                            doc[k] = v.lower() in ('t', 'true', '1')
                        else:
                            doc[k] = v
                    except (ValueError, TypeError):
                        doc[k] = v
                
                if 'ts' in doc:
                    doc['@timestamp'] = doc['ts']
                
                actions.append({
                    '_index': f'zeek-{log_type}',
                    '_source': doc
                })
        
        # Bulk index
        if actions:
            success, failed = bulk(es, actions, raise_on_error=False)
            total_docs += success
            print(f"  Ingested {success} documents into zeek-{log_type}")
    
    print(f"\n>>> Total documents ingested: {total_docs}")
    print("\n" + "="*60)
    print("FAST INGESTION COMPLETE!")
    print("="*60)
    print("\nRun tests: python test_pcap_ingestion.py")
    
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
