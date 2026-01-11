#!/bin/bash
set -e

echo ">>> Starting Infrastructure..."
docker-compose up -d

echo ">>> Waiting for Elasticsearch to initialize (30s)..."
sleep 30

echo ">>> Setting up PCAP..."
mkdir -p pcap

# Check if demo PCAP exists in demo_pcap_upload
if [ -f "demo_pcap_upload/FIRST-2015_Hands-on_Network_Forensics_PCAP.zip" ]; then
    echo ">>> Extracting demo PCAP from demo_pcap_upload..."
    cd demo_pcap_upload
    unzip -o "FIRST-2015_Hands-on_Network_Forensics_PCAP.zip" -d .
    EXTRACTED_PCAP=$(find . -maxdepth 1 -name "*.pcap" -o -name "*.pcapng" | head -1)
    if [ -n "$EXTRACTED_PCAP" ]; then
        cp "$EXTRACTED_PCAP" ../pcap/demo.pcap
        echo ">>> Using extracted PCAP: $EXTRACTED_PCAP"
    fi
    cd ..
fi

PCAP_PATH="pcap/demo.pcap"

if [ ! -s "$PCAP_PATH" ]; then
    echo ">>> PCAP not found in demo_pcap_upload. Attempting download..."
    # High-fidelity Trickbot infection trace
    wget -O "$PCAP_PATH" "https://github.com/activecm/zeek-pcap-samples/raw/master/trickbot-infection.pcap"
    
    if [ ! -s "$PCAP_PATH" ]; then
        echo "ERROR: Failed to find or download PCAP. Please ensure network access or place pcap/demo.pcap manually." >&2
        exit 1
    fi
fi

if [ -n "$PCAP_PATH" ]; then
    echo ">>> Processing PCAP with Zeek (Ephemeral Container)..."
    # Runs Zeek, reads pcap, writes ASCII logs to ./logs
    docker run --rm -v $(pwd)/pcap:/pcap -v $(pwd)/logs:/logs zeek/zeek:latest bash -c "cd /logs && zeek -C -r /pcap/demo.pcap"
else
    echo ">>> Skipping Zeek processing (using synthetic logs)."
fi

echo ">>> Ingesting Logs into Elasticsearch..."
# Parse Zeek ASCII logs (tab-separated with #fields header) and index into Elasticsearch
python3 - <<'PY'
import os, glob, json
from elasticsearch import Elasticsearch

es = Elasticsearch('http://localhost:9200')
log_files = glob.glob('logs/*.log')
print(f'Found {len(log_files)} log files.')

for log_file in log_files:
    log_type = os.path.basename(log_file).split('.')[0]
    fields = None
    sep = '\t'
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            if line.startswith('#separator'):
                parts = line.split(' ', 1)
                if len(parts) > 1:
                    # Zeek writes separators like "\\x09" for tab
                    sep_spec = parts[1]
                    try:
                        sep = sep_spec.encode('utf-8').decode('unicode_escape')
                    except Exception:
                        sep = '\t'
                continue
            if line.startswith('#fields'):
                fields = line.split()[1:]
                continue
            if line.startswith('#'):
                continue
            if fields is None:
                continue
            parts = line.split(sep)
            if len(parts) < len(fields):
                parts += [''] * (len(fields) - len(parts))
            doc = {k: (None if v == '-' else v) for k, v in zip(fields, parts)}
            if 'ts' in doc and doc['ts']:
                doc['@timestamp'] = doc['ts']
            try:
                es.index(index=f'zeek-{log_type}', document=doc)
            except Exception as e:
                print(f"Failed to index doc from {log_file}: {e}")

print('Ingestion Complete.')
PY

echo ">>> SETUP COMPLETE. Run 'chainlit run agent.py -w' to start."
