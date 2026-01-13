#!/bin/bash
set -e

echo "=== PCAP INGESTION FIX SCRIPT ==="
echo ""
echo "This script will:"
echo "1. Delete existing synthetic data from Elasticsearch"
echo "2. Process real PCAP files from demo_pcap_upload"
echo "3. Re-ingest with Zeek logs"
echo ""

# Step 1: Delete existing indices
echo ">>> Deleting existing indices..."
for index in zeek-conn zeek-http zeek-dns zeek-ftp; do
    curl -X DELETE "http://localhost:9200/$index" 2>/dev/null && echo "Deleted $index" || echo "Index $index not found"
done
echo ""

# Step 2: Process one of the real PCAP files
echo ">>> Processing real PCAP file with Zeek..."
mkdir -p logs

# Find one of the smaller PCAP files (they're all quite large, pick smallest)
SAMPLE_PCAP=$(ls -Sr demo_pcap_upload/2015-*/snort.log.* | head -1)

if [ -z "$SAMPLE_PCAP" ]; then
    echo "ERROR: No suitable PCAP file found!"
    exit 1
fi

echo ">>> Using PCAP file: $SAMPLE_PCAP"
FILESIZE=$(du -h "$SAMPLE_PCAP" | cut -f1)
echo ">>> File size: $FILESIZE"

# Copy to pcap directory
cp "$SAMPLE_PCAP" pcap/demo.pcap
echo ">>> Copied to pcap/demo.pcap"

# Process with Zeek using Docker
echo ">>> Running Zeek analysis..."
rm -f logs/*.log

docker run --rm \
    -v "$(pwd)/pcap:/pcap" \
    -v "$(pwd)/logs:/logs" \
    zeek/zeek:latest \
    bash -c "cd /logs && zeek -C -r /pcap/demo.pcap"

echo ">>> Zeek processing complete!"

# Check what logs were generated
echo ""
echo ">>> Generated log files:"
ls -lh logs/*.log 2>/dev/null || echo "No logs generated"
echo ""

# Step 3: Ingest logs into Elasticsearch
echo ">>> Ingesting logs into Elasticsearch..."

python3 - <<'PY'
import os, glob, json
from elasticsearch import Elasticsearch

es = Elasticsearch('http://localhost:9200')
log_files = glob.glob('logs/*.log')
print(f'Found {len(log_files)} log files.')

# Zeek type to Elasticsearch type mapping
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

# First pass: collect all field types from all logs
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

# Create indices with proper mappings
for log_type, mappings in all_mappings.items():
    try:
        es.indices.create(
            index=f'zeek-{log_type}',
            mappings={'properties': mappings},
            ignore=400
        )
        print(f'Created index zeek-{log_type}')
    except Exception as e:
        print(f'Warning: Could not create index zeek-{log_type}: {e}')

# Second pass: ingest data with type conversion
doc_counts = {}
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
                    except Exception:
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
            
            # Convert types during ingestion
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
                print(f"Failed to index doc from {log_file}: {e}")
    
    doc_counts[log_type] = doc_count
    print(f'Indexed {doc_count} documents from {log_file}')

print(f'\nTotal documents indexed: {sum(doc_counts.values())}')
print('Ingestion Complete.')
PY

echo ""
echo "=== FIX COMPLETE ==="
echo ">>> Now run the tests again: python test_pcap_ingestion.py"
