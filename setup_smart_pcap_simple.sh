#!/bin/bash
set -e

echo ">>> SMART PCAP SETUP (SIMPLIFIED) <<<"
echo ""

# Step 1: Ensure infrastructure is running
echo ">>> Checking Elasticsearch..."
if ! curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo "Starting Elasticsearch..."
    docker-compose up -d
    sleep 25
fi

# Step 2: Process PCAP with Smart PCAP script
echo ""
echo ">>> Processing PCAP with Smart PCAP triggers..."

PCAP_PATH="pcap/demo.pcap"

if [ ! -f "$PCAP_PATH" ]; then
    echo "Finding PCAP file..."
    SAMPLE_PCAP=$(ls -Sr demo_pcap_upload/2015-*/snort.log.* | head -1)
    if [ -n "$SAMPLE_PCAP" ]; then
        cp "$SAMPLE_PCAP" "$PCAP_PATH"
        echo "Copied: $(basename $SAMPLE_PCAP)"
    fi
fi

# Run Zeek with Smart PCAP script
if [ ! -f "logs/conn.log" ] || [ ! -f "logs/notice.log" ]; then
    echo "Running Zeek analysis..."
    rm -f logs/*.log
    
    docker run --rm \
        -v "$(pwd)/pcap:/pcap" \
        -v "$(pwd)/logs:/logs" \
        -v "$(pwd)/zeek_scripts:/scripts" \
        zeek/zeek:latest \
        bash -c "cd /logs && zeek -C -r /pcap/demo.pcap /scripts/smart_pcap_trigger.zeek" || true
    
    echo "Zeek processing complete!"
else
    echo "Using existing Zeek logs"
fi

# Step 3: Use original ingestion script (which already works)
echo ""
echo ">>> Ingesting logs with original script..."

# Reuse the working ingestion from setup_data.sh
python3 - <<'PY'
import os, glob, json
from elasticsearch import Elasticsearch

es = Elasticsearch('http://localhost:9200')
log_files = glob.glob('logs/*.log')
print(f'Found {len(log_files)} log files.')

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
                    all_mappings[log_type] = mappings
                break

# Create indices
for log_type, mappings in all_mappings.items():
    try:
        es.indices.create(
            index=f'zeek-{log_type}',
            mappings={'properties': mappings},
            settings={'number_of_shards': 1, 'number_of_replicas': 0}
        )
        print(f'Created index zeek-{log_type}')
    except Exception as e:
        pass  # Already exists

# Ingest data - simple approach, one doc at a time
print('Ingesting documents...')
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
                    try:
                        sep = parts[1].encode('utf-8').decode('unicode_escape')
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
                total_docs += 1
                
                # Show progress every 100 docs
                if doc_count % 100 == 0:
                    print(f'  {log_type}: {doc_count}...')
            except:
                pass  # Skip errors

    if doc_count > 0:
        print(f'  {log_type}: {doc_count} total')

print(f'\n✓ Total documents ingested: {total_docs}')
PY

echo ""
echo ">>> SMART PCAP SETUP COMPLETE <<<"
echo ""
echo "Test the Smart PCAP workflow:"
echo "  python3 smart_pcap_tools.py"
echo ""
