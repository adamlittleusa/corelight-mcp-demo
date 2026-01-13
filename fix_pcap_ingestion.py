#!/usr/bin/env python3
"""
Fix PCAP ingestion by processing real PCAP data
"""

import os
import glob
import subprocess
from elasticsearch import Elasticsearch
import json

def main():
    os.chdir('/workspaces/corelight-mcp-demo')
    
    print("="*60)
    print("PCAP INGESTION FIX")
    print("="*60)
    
    # Step 1: Find smallest PCAP file
    print("\n>>> Finding smallest PCAP file...")
    pcap_files = glob.glob('demo_pcap_upload/2015-*/snort.log.*')
    
    if not pcap_files:
        print("ERROR: No PCAP files found!")
        return 1
    
    # Sort by size and get smallest
    pcap_files_with_size = [(f, os.path.getsize(f)) for f in pcap_files]
    pcap_files_with_size.sort(key=lambda x: x[1])
    
    sample_pcap, size = pcap_files_with_size[0]
    print(f"Selected: {sample_pcap}")
    print(f"Size: {size:,} bytes ({size/1024/1024:.1f} MB)")
    
    # Step 2: Delete existing indices
    print("\n>>> Deleting existing indices...")
    es = Elasticsearch('http://localhost:9200')
    
    for index in ['zeek-conn', 'zeek-http', 'zeek-dns', 'zeek-ftp']:
        try:
            es.indices.delete(index=index)
            print(f"  Deleted {index}")
        except:
            print(f"  {index} not found")
    
    # Step 3: Copy PCAP
    print("\n>>> Copying PCAP to pcap/demo.pcap...")
    subprocess.run(['cp', sample_pcap, 'pcap/demo.pcap'], check=True)
    
    # Step 4: Run Zeek
    print("\n>>> Running Zeek analysis (this may take a while)...")
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
    
    # Check generated logs
    log_files = glob.glob('logs/*.log')
    print(f"\n>>> Generated {len(log_files)} log files:")
    for lf in log_files:
        lines = sum(1 for line in open(lf) if not line.startswith('#'))
        print(f"  {os.path.basename(lf)}: {lines} records")
    
    # Step 5: Ingest into Elasticsearch
    print("\n>>> Ingesting into Elasticsearch...")
    
    TYPE_MAPPING = {
        'time': 'double',
        'interval': 'double',
        'count': 'long',
        'int': 'long',
        'double': 'double',
        'bool': 'boolean',
        'string': 'keyword',
        'addr': 'keyword',
        'port': 'integer',
        'enum': 'keyword',
        'vector': 'text',
        'set': 'text',
        'table': 'text',
        'record': 'text'
    }
    
    # First pass: collect mappings
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
                        all_mappings[log_type] = mappings
                    break
    
    # Create indices
    for log_type, mappings in all_mappings.items():
        try:
            es.indices.create(
                index=f'zeek-{log_type}',
                mappings={'properties': mappings}
            )
            print(f"  Created index zeek-{log_type}")
        except Exception as e:
            print(f"  Warning: {e}")
    
    # Second pass: ingest data
    total_docs = 0
    for log_file in log_files:
        log_type = os.path.basename(log_file).split('.')[0]
        fields = None
        field_types = None
        sep = '\t'
        doc_count = 0
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.rstrip('\n')
                if not line:
                    continue
                if line.startswith('#separator'):
                    parts = line.split(' ', 1)
                    if len(parts) > 1:
                        sep_spec = parts[1]
                        try:
                            sep = sep_spec.encode('utf-8').decode('unicode_escape')
                        except:
                            sep = '\t'
                    continue
                if line.startswith('#fields'):
                    fields = line.split()[1:]
                    continue
                if line.startswith('#types'):
                    field_types = line.split()[1:]
                    continue
                if line.startswith('#'):
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
                
                try:
                    es.index(index=f'zeek-{log_type}', document=doc)
                    doc_count += 1
                except Exception as e:
                    pass  # Skip errors
        
        print(f"  Ingested {doc_count} documents into zeek-{log_type}")
        total_docs += doc_count
    
    print(f"\n>>> Total documents ingested: {total_docs}")
    print("\n" + "="*60)
    print("FIX COMPLETE!")
    print("="*60)
    print("\nRun tests: python test_pcap_ingestion.py")
    
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
