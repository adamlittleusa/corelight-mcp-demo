#!/bin/bash
set -e

echo ">>> SMART PCAP SETUP <<<"
echo "Implementing selective capture with Zeek triggers"
echo ""

# Step 1: Ensure infrastructure is running
echo ">>> Checking infrastructure..."
if ! docker ps | grep -q demo-siem; then
    echo "Starting Elasticsearch..."
    docker-compose up -d
    sleep 20
fi

# Step 2: Process PCAP with Smart PCAP script
echo ""
echo ">>> Processing PCAP with Smart PCAP triggers..."
mkdir -p logs zeek_scripts

PCAP_PATH="pcap/demo.pcap"

if [ ! -f "$PCAP_PATH" ]; then
    echo "Finding PCAP file..."
    SAMPLE_PCAP=$(ls -Sr demo_pcap_upload/2015-*/snort.log.* | head -1)
    if [ -n "$SAMPLE_PCAP" ]; then
        cp "$SAMPLE_PCAP" "$PCAP_PATH"
        echo "Copied: $SAMPLE_PCAP"
    else
        echo "ERROR: No PCAP file found!"
        exit 1
    fi
fi

# Run Zeek with Smart PCAP script
echo "Running Zeek analysis with Smart PCAP triggers..."
rm -f logs/*.log

docker run --rm \
    -v "$(pwd)/pcap:/pcap" \
    -v "$(pwd)/logs:/logs" \
    -v "$(pwd)/zeek_scripts:/scripts" \
    zeek/zeek:latest \
    bash -c "cd /logs && zeek -C -r /pcap/demo.pcap /scripts/smart_pcap_trigger.zeek"

echo "Zeek processing complete!"

# Step 3: Ingest ONLY essential metadata (not full data)
echo ""
echo ">>> Smart ingestion: metadata only..."

python3 - <<'PY'
import os, glob
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

os.chdir('/workspaces/corelight-mcp-demo')
es = Elasticsearch('http://localhost:9200')

# Delete old indices
print("Cleaning old indices...")
for idx in ['zeek-conn', 'zeek-notice', 'zeek-http', 'zeek-dns']:
    try:
        es.indices.delete(index=idx)
    except:
        pass

log_files = glob.glob('logs/*.log')
print(f"Found {len(log_files)} log files")

TYPE_MAPPING = {
    'time': 'double', 'interval': 'double', 'count': 'long', 'int': 'long',
    'double': 'double', 'bool': 'boolean', 'string': 'keyword', 'addr': 'keyword',
    'port': 'integer', 'enum': 'keyword'
}

# Focus on key logs only: conn, notice, http, dns
priority_logs = {'conn', 'notice', 'http', 'dns'}

# Collect mappings
all_mappings = {}
for log_file in log_files:
    log_type = os.path.basename(log_file).split('.')[0]
    
    # Skip non-priority logs for resource efficiency
    if log_type not in priority_logs:
        continue
    
    with open(log_file, 'r') as f:
        fields, field_types = None, None
        for line in f:
            if line.startswith('#fields'):
                fields = line.split()[1:]
            elif line.startswith('#types'):
                field_types = line.split()[1:]
                if fields and field_types:
                    mappings = {fname: {'type': TYPE_MAPPING.get(ftype, 'keyword')} 
                               for fname, ftype in zip(fields, field_types)}
                    all_mappings[log_type] = (mappings, fields, field_types)
                break

# Create indices
print("\nCreating indices for priority logs...")
for log_type, (mappings, _, _) in all_mappings.items():
    try:
        es.indices.create(
            index=f'zeek-{log_type}', 
            mappings={'properties': mappings},
            settings={
                'number_of_shards': 1,
                'number_of_replicas': 0  # No replicas for single-node
            }
        )
        print(f"  Created zeek-{log_type}")
    except Exception as e:
        print(f"  Index zeek-{log_type} exists")

# Bulk ingest with smaller chunks
print("\nIngesting priority logs...")
total = 0

for log_file in log_files:
    log_type = os.path.basename(log_file).split('.')[0]
    
    if log_type not in all_mappings:
        continue
    
    _, fields, field_types = all_mappings[log_type]
    actions = []
    
    with open(log_file, 'r') as f:
        for line in f:
            if not line.strip() or line.startswith('#'):
                continue
            
            parts = line.rstrip('\n').split('\t')
            doc = {}
            
            for k, v, ftype in zip(fields, parts, field_types):
                if v in ('-', ''):
                    continue
                try:
                    if ftype in ('time', 'interval', 'double'):
                        doc[k] = float(v)
                    elif ftype in ('count', 'int', 'port'):
                        doc[k] = int(v)
                    elif ftype == 'bool':
                        doc[k] = v.lower() in ('t', 'true')
                    else:
                        doc[k] = v
                except:
                    doc[k] = v
            
            if 'ts' in doc:
                doc['@timestamp'] = doc['ts']
            
            actions.append({'_index': f'zeek-{log_type}', '_source': doc})
            
            # Batch in smaller chunks (100 docs) to avoid timeout
            if len(actions) >= 100:
                try:
                    es_with_timeout = es.options(request_timeout=30)
                    success, _ = bulk(es_with_timeout, actions, raise_on_error=False)
                    total += success
                except Exception as e:
                    print(f"  Batch error: {e}")
                actions = []
    
    # Final batch
    if actions:
        try:
            es_with_timeout = es.options(request_timeout=30)
            success, _ = bulk(es_with_timeout, actions, raise_on_error=False)
            total += success
            print(f"  zeek-{log_type}: ingested")
        except Exception as e:
            print(f"  Final batch error for {log_type}: {e}")

print(f"\n✓ Smart ingestion complete: {total} documents")
print("  (Metadata only - full packets available on demand)")
PY

echo ""
echo ">>> SMART PCAP SETUP COMPLETE <<<"
echo ""
echo "Next steps:"
echo "  1. View Smart PCAP triggers: python3 smart_pcap_tools.py"
echo "  2. Test workflow: python3 test_pcap_ingestion.py"
echo "  3. Start demo app: chainlit run agent.py -w"
echo ""
