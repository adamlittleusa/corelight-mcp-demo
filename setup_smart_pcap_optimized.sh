#!/bin/bash
set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         SMART PCAP DEMO - OPTIMIZED SETUP                      ║"
echo "║  Metadata Everywhere, Full Packets Only When Needed            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
MAX_PCAPS=5
PCAP_DIR="demo_pcap_upload"
TARGET_DIR="pcap"
LOG_DIR="logs"

# Step 1: Check Elasticsearch
echo ">>> Step 1: Checking Elasticsearch..."
if ! curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
    echo "Starting Elasticsearch..."
    docker-compose up -d
    echo "Waiting for Elasticsearch to be ready..."
    sleep 25
    
    # Verify it's up
    for i in {1..10}; do
        if curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
            echo "✓ Elasticsearch is ready"
            break
        fi
        echo "  Waiting... ($i/10)"
        sleep 3
    done
else
    echo "✓ Elasticsearch is running"
fi

# Health Check: Detect and fix RED cluster status
echo ""
echo ">>> Health Check: Verifying cluster status..."

CLUSTER_STATUS=$(curl -s "http://localhost:9200/_cluster/health" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
echo "Current cluster status: $CLUSTER_STATUS"

if [ "$CLUSTER_STATUS" = "red" ]; then
    echo "⚠️  WARNING: Cluster status is RED!"
    echo "   This is usually caused by disk watermark threshold exceeded."
    echo ""
    echo "   Applying automatic fix..."
    
    # Check current disk usage
    DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    echo "   Disk usage: ${DISK_USAGE}%"
    
    # Increase disk watermark thresholds
    curl -s -X PUT "http://localhost:9200/_cluster/settings" \
         -H 'Content-Type: application/json' \
         -d '{
           "persistent": {
             "cluster.routing.allocation.disk.watermark.low": "95%",
             "cluster.routing.allocation.disk.watermark.high": "97%",
             "cluster.routing.allocation.disk.watermark.flood_stage": "99%"
           }
         }' > /dev/null
    
    echo "   ✓ Disk watermark thresholds adjusted (high: 97%, flood: 99%)"
    echo "   Waiting for cluster recovery..."
    
    # Wait for cluster to recover (up to 30 seconds)
    for i in {1..10}; do
        sleep 3
        NEW_STATUS=$(curl -s "http://localhost:9200/_cluster/health" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        
        if [ "$NEW_STATUS" != "red" ]; then
            echo "   ✓ Cluster recovered to: $NEW_STATUS"
            break
        fi
        
        if [ $i -eq 10 ]; then
            echo "   ⚠️  Cluster still RED after 30 seconds"
            echo "   Continuing anyway - ingestion may be slower..."
        fi
    done
    echo ""
elif [ "$CLUSTER_STATUS" = "yellow" ]; then
    echo "✓ Cluster status is YELLOW (normal for single-node)"
else
    echo "✓ Cluster status is GREEN"
fi

# Step 2: Clean up existing data
echo ""
echo ">>> Step 2: Cleaning up old data..."

# Delete old indices (if any)
for index in zeek-conn zeek-http zeek-dns zeek-notice zeek-files zeek-ssl zeek-x509; do
    curl -s -X DELETE "http://localhost:9200/$index" > /dev/null 2>&1 || true
done
echo "✓ Old indices removed"

# Clear old logs
rm -rf ${LOG_DIR}/*.log
echo "✓ Old logs cleared"

# Step 3: Prepare PCAP file for analysis
echo ""
echo ">>> Step 3: Preparing PCAP for analysis..."

# Ensure target directory exists
mkdir -p "$TARGET_DIR"

# Check if demo.pcap already exists
if [ -f "$TARGET_DIR/demo.pcap" ] && [ -s "$TARGET_DIR/demo.pcap" ]; then
    PCAP_SIZE=$(stat -c%s "$TARGET_DIR/demo.pcap" 2>/dev/null || stat -f%z "$TARGET_DIR/demo.pcap" 2>/dev/null)
    PCAP_SIZE_MB=$((PCAP_SIZE / 1024 / 1024))
    echo "✓ Using existing PCAP: $TARGET_DIR/demo.pcap (${PCAP_SIZE_MB}MB)"
else
    # Try to find PCAP files in demo_pcap_upload directory
    if [ -d "$PCAP_DIR" ]; then
        SELECTED_PCAPS=$(find "$PCAP_DIR" -type f \( -name "*.pcap" -o -name "*.pcapng" -o -name "snort.log.*" \) -printf "%s %p\n" 2>/dev/null | sort -n | head -${MAX_PCAPS} | awk '{print $2}')
        
        if [ -n "$SELECTED_PCAPS" ]; then
            echo "Found PCAP files in $PCAP_DIR:"
            TOTAL_SIZE=0
            for pcap in $SELECTED_PCAPS; do
                SIZE=$(stat -c%s "$pcap" 2>/dev/null || stat -f%z "$pcap" 2>/dev/null)
                SIZE_MB=$((SIZE / 1024 / 1024))
                TOTAL_SIZE=$((TOTAL_SIZE + SIZE))
                echo "  $(basename $pcap) - ${SIZE_MB}MB"
            done
            
            TOTAL_SIZE_MB=$((TOTAL_SIZE / 1024 / 1024))
            echo "✓ Total size: ${TOTAL_SIZE_MB}MB"
            
            # Copy first file as base
            FIRST_PCAP=$(echo "$SELECTED_PCAPS" | head -1)
            cp "$FIRST_PCAP" "$TARGET_DIR/demo.pcap"
            echo "✓ PCAP created from: $(basename $FIRST_PCAP)"
        fi
    fi
    
    # If still no PCAP, try to download sample
    if [ ! -f "$TARGET_DIR/demo.pcap" ] || [ ! -s "$TARGET_DIR/demo.pcap" ]; then
        echo "No PCAP found in $PCAP_DIR, downloading sample..."
        if curl -L -o "$TARGET_DIR/demo.pcap" "https://github.com/activecm/zeek-pcap-samples/raw/master/trickbot-infection.pcap" 2>/dev/null; then
            PCAP_SIZE=$(stat -c%s "$TARGET_DIR/demo.pcap" 2>/dev/null || stat -f%z "$TARGET_DIR/demo.pcap" 2>/dev/null)
            PCAP_SIZE_MB=$((PCAP_SIZE / 1024 / 1024))
            echo "✓ Downloaded sample PCAP (${PCAP_SIZE_MB}MB)"
        else
            echo "⚠️  WARNING: Could not download sample PCAP"
            echo "   Generating synthetic PCAP..."
            # Generate a minimal PCAP using Python/scapy
            python3 generate_demo_pcap.py "$TARGET_DIR/demo.pcap" || touch "$TARGET_DIR/demo.pcap"
        fi
    fi
fi

# Step 4: Verify PCAP is ready
echo ""
echo ">>> Step 4: Verifying PCAP..."
if [ -f "$TARGET_DIR/demo.pcap" ] && [ -s "$TARGET_DIR/demo.pcap" ]; then
    echo "✓ PCAP ready: $TARGET_DIR/demo.pcap"
else
    echo "⚠️  No valid PCAP available - will use synthetic data only"
fi

# Step 5: Run Zeek with Smart PCAP triggers
echo ""
echo ">>> Step 5: Running Zeek analysis with Smart PCAP triggers..."

# Only run Zeek if we have a valid PCAP
if [ -f "$TARGET_DIR/demo.pcap" ] && [ -s "$TARGET_DIR/demo.pcap" ]; then
    docker run --rm \
        -v "$(pwd)/$TARGET_DIR:/pcap" \
        -v "$(pwd)/$LOG_DIR:/logs" \
        -v "$(pwd)/zeek_scripts:/scripts" \
        zeek/zeek:latest \
        bash -c "cd /logs && zeek -C -r /pcap/demo.pcap /scripts/smart_pcap_trigger.zeek"
    
    # Check what was generated
    LOG_FILES=$(ls -1 ${LOG_DIR}/*.log 2>/dev/null | wc -l)
    echo "✓ Zeek generated ${LOG_FILES} log files"
else
    echo "⚠️  Skipping Zeek analysis (no valid PCAP)"
    echo "   Will rely on synthetic data injection"
fi

# Show log statistics
echo ""
echo "Log file statistics:"
for log in ${LOG_DIR}/*.log; do
    if [ -f "$log" ]; then
        LINES=$(grep -v "^#" "$log" | wc -l)
        echo "  $(basename $log): $LINES records"
    fi
done

# Step 6: Ingest priority logs only (avoid files.log timeout issues)
echo ""
echo ">>> Step 6: Ingesting priority logs into Elasticsearch..."

python3 - <<'PYTHON_SCRIPT'
import os
import glob
import json
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

es = Elasticsearch('http://localhost:9200')

# Only index these critical logs (skip heavy logs like files, ssl, x509)
# weird.log is critical for anomaly detection
PRIORITY_LOGS = ['conn', 'http', 'dns', 'notice', 'weird']

TYPE_MAPPING = {
    'time': 'double', 'interval': 'double', 'count': 'long',
    'int': 'long', 'double': 'double', 'bool': 'boolean',
    'string': 'keyword', 'addr': 'keyword', 'port': 'integer',
    'enum': 'keyword', 'vector': 'text', 'set': 'text'
}

log_files = glob.glob('logs/*.log')
print(f"Found {len(log_files)} log files")

# First pass: collect mappings for priority logs only
all_mappings = {}

for log_file in log_files:
    log_type = os.path.basename(log_file).split('.')[0]
    
    # Skip non-priority logs
    if log_type not in PRIORITY_LOGS:
        print(f"Skipping {log_type} (not in priority list)")
        continue
    
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

print(f"\nCreating indices for {len(all_mappings)} log types...")

# Create indices
for log_type, (mappings, _, _) in all_mappings.items():
    try:
        es.indices.create(
            index=f'zeek-{log_type}',
            mappings={'properties': mappings},
            settings={
                'number_of_shards': 1,
                'number_of_replicas': 0,
                'refresh_interval': '30s'  # Reduce refresh frequency
            }
        )
        print(f"  ✓ Created zeek-{log_type}")
    except Exception as e:
        print(f"  ⚠ Index zeek-{log_type} already exists")

# Bulk ingest with optimized batching
print("\nIngesting logs (using smart batching)...")
total_docs = 0

for log_file in log_files:
    log_type = os.path.basename(log_file).split('.')[0]
    
    if log_type not in all_mappings:
        continue
    
    _, fields, field_types = all_mappings[log_type]
    actions = []
    
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip() or line.startswith('#'):
                continue
            
            parts = line.rstrip('\n').split('\t')
            if len(parts) != len(fields):
                continue
            
            doc = {}
            for k, v, ftype in zip(fields, parts, field_types):
                if v in ('-', '(empty)'):
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
            
            # Batch every 50 documents to avoid timeouts under disk pressure
            if len(actions) >= 50:
                try:
                    es_with_timeout = es.options(request_timeout=60, max_retries=3, retry_on_timeout=True)
                    success, failed = bulk(
                        es_with_timeout, 
                        actions, 
                        raise_on_error=False,
                        chunk_size=50
                    )
                    total_docs += success
                    if failed:
                        print(f"  ⚠ {len(failed)} docs failed in batch")
                except Exception as e:
                    print(f"  ⚠ Batch error: {str(e)[:100]}")
                    # Continue even on error - don't crash the whole ingestion
                actions = []
    
    # Final batch for this log type
    if actions:
        try:
            es_with_timeout = es.options(request_timeout=60, max_retries=3, retry_on_timeout=True)
            success, failed = bulk(
                es_with_timeout, 
                actions, 
                raise_on_error=False,
                chunk_size=50
            )
            total_docs += success
            if failed:
                print(f"  ⚠ {len(failed)} docs failed in final batch")
        except Exception as e:
            print(f"  ⚠ Final batch error: {str(e)[:100]}")
    
    print(f"  ✓ zeek-{log_type} indexed")

print(f"\n✓ Total documents indexed: {total_docs}")

# Refresh indices to make data searchable
for log_type in all_mappings.keys():
    try:
        es.indices.refresh(index=f'zeek-{log_type}')
    except:
        pass

print("\n" + "="*60)
print("SMART PCAP SETUP COMPLETE")
print("="*60)
print("\nIndexed logs:")
for log_type in all_mappings.keys():
    try:
        count = es.count(index=f'zeek-{log_type}')['count']
        print(f"  zeek-{log_type}: {count:,} documents")
    except:
        print(f"  zeek-{log_type}: (query failed)")

# Check for Smart PCAP triggers
try:
    trigger_count = es.count(
        index='zeek-notice',
        body={
            'query': {
                'wildcard': {'msg': '*Smart PCAP Trigger*'}
            }
        }
    )['count']
    
    if trigger_count > 0:
        print(f"\n🎯 Found {trigger_count} Smart PCAP triggers!")
        print("   These events are available for on-demand packet extraction.")
    else:
        print("\nℹ  No Smart PCAP triggers found in this dataset.")
        print("   (Normal traffic - no suspicious patterns detected)")
except:
    print("\nℹ  Could not query for Smart PCAP triggers")

print("\n✓ Full PCAP available at: pcap/demo.pcap")
print("✓ Ready for Smart PCAP queries via MCP agent")
PYTHON_SCRIPT

# Step 7: Inject synthetic data for demo completeness
echo ""
echo ">>> Step 7: Injecting synthetic data for demo..."
python3 inject_synthetic_data.py

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    SETUP COMPLETE                              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Start the agent: chainlit run agent.py"
echo "  2. Try queries like:"
echo "     - 'Show me top talkers'"
echo "     - 'Find long connections'"
echo "     - 'Search for suspicious DNS'"
echo "     - 'Extract packets for connection <UID>'"
echo ""
