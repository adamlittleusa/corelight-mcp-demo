#!/bin/bash
set -e

echo ">>> Starting Infrastructure..."
docker-compose up -d

echo ">>> Waiting for Elasticsearch to initialize (30s)..."
sleep 30

echo ">>> Downloading PCAP (Malware Traffic Analysis)..."
mkdir -p pcap
# Using a reliable, small PCAP example for demo speed
wget -O pcap/demo.pcap "https://github.com/zeek/zeek/raw/master/testing/btest/Traces/http/get.pcap"

echo ">>> Processing PCAP with Zeek (Ephemeral Container)..."
# Runs Zeek, reads pcap, writes JSON logs to ./logs
docker run --rm -v $(pwd)/pcap:/pcap -v $(pwd)/logs:/logs zeek/zeek:latest bash -c "zeek -C -r /pcap/demo.pcap Log::default_logdir=/logs json-logs"

echo ">>> Ingesting Logs into Elasticsearch..."
# Simple python one-liner to push logs (Avoids Filebeat configuration complexity for demo)
python3 -c "
import os, json, glob
from elasticsearch import Elasticsearch
es = Elasticsearch('http://localhost:9200')
log_files = glob.glob('logs/*.log')
print(f'Found {len(log_files)} log files.')
for log_file in log_files:
    log_type = os.path.basename(log_file).split('.')[0]
    with open(log_file) as f:
        for line in f:
            try:
                doc = json.loads(line)
                doc['@timestamp'] = doc.get('ts') # Remap Zeek ts to @timestamp
                es.index(index=f'zeek-{log_type}', document=doc)
            except: pass
print('Ingestion Complete.')
"

echo ">>> SETUP COMPLETE. Run 'chainlit run agent.py -w' to start."
