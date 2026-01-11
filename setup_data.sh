#!/bin/bash
set -e

echo ">>> Starting Infrastructure..."
docker-compose up -d

echo ">>> Waiting for Elasticsearch to initialize (30s)..."
sleep 30

echo ">>> Downloading PCAP (attempting multiple fallbacks)..."
mkdir -p pcap
# Try several known raw URLs until one succeeds
PCAP_PATH="pcap/demo.pcap"
urls=(
    "https://raw.githubusercontent.com/zeek/zeek/master/testing/btest/Traces/http/get.pcap"
    "https://raw.githubusercontent.com/seladb/PcapPlusPlus/master/TestPcapFiles/http_0.pcap"
    "https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/master/tests/ping.pcap"
)
success=0
for u in "${urls[@]}"; do
    echo "Trying $u"
    if wget -q -O "$PCAP_PATH" "$u"; then
        echo "Downloaded $u"
        success=1
        break
    else
        echo "Failed: $u"
    fi
done
if [ $success -ne 1 ] || [ ! -s "$PCAP_PATH" ]; then
    echo "WARNING: Could not download a test PCAP. Falling back to synthetic Zeek logs..."
    mkdir -p logs
    cat > logs/conn.log <<'EOF'
#separator \x09
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto state
#types time string addr port addr port string string
1610000000.0	ABC123	192.168.0.2	54321	93.184.216.34	80	tcp	SF
EOF
    cat > logs/http.log <<'EOF'
#separator \x09
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p method host uri user_agent status_code
#types time string addr port addr port string string string int
1610000000.0	ABC123	192.168.0.2	54321	93.184.216.34	80	GET	example.com	/	agent	200
EOF
    echo "Wrote synthetic logs to logs/"
    PCAP_PATH=""
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
