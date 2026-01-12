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
    echo ">>> PCAP not found. Attempting download..."
    # High-fidelity Trickbot infection trace
    if wget -q -O "$PCAP_PATH" "https://github.com/activecm/zeek-pcap-samples/raw/master/trickbot-infection.pcap"; then
        echo "Downloaded Trickbot PCAP."
    else
        echo "WARNING: Could not download PCAP. Falling back to synthetic logs..."
        mkdir -p logs
        cat > logs/conn.log <<'EOF'
#separator \x09
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto state duration bytes_orig bytes_resp
#types time string addr port addr port string string interval count count
1609459200.0	ABC123	192.168.1.10	54321	10.0.0.100	443	tcp	SF	7200.5	25000	50000
1609459205.0	XYZ789	192.168.1.20	54322	10.0.0.101	443	tcp	SF	5400.2	18000	102400
1609459210.0	DEF456	192.168.1.30	54323	10.0.0.102	443	tcp	SF	3650.7	512000	256000
1609459215.0	GHI789	192.168.1.40	54324	10.0.0.103	80	tcp	SF	1800.1	5120	2560
1609459220.0	JKL012	192.168.1.50	54325	10.0.0.104	22	tcp	SF	45.7	512	256
1609459225.0	MNO345	192.168.1.60	54326	10.0.0.105	443	tcp	SF	4500.0	1024000	512000
1609459230.0	PQR678	192.168.1.70	54327	10.0.0.106	8080	tcp	SF	2200.5	256000	128000
EOF
        cat > logs/http.log <<'EOF'
#separator \x09
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p method host uri user_agent request_body_len response_body_len status_code
#types time string addr port addr port string string string string count count count
1609459200.0	ABC123	192.168.1.10	54321	10.0.0.100	443	GET	example.com	/api/endpoint	Mozilla	0	2048	200
1609459205.0	XYZ789	192.168.1.20	54322	10.0.0.101	80	POST	www.example.org	/form	Chrome	512	256	404
EOF
        echo "Wrote synthetic logs to logs/"
        PCAP_PATH=""
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
# Parse Zeek ASCII logs with proper type mapping for aggregations and sorting
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
            ignore=400  # Ignore if already exists
        )
        print(f'Created index zeek-{log_type} with proper field types')
    except Exception as e:
        print(f'Warning: Could not create index zeek-{log_type}: {e}')

# Second pass: ingest data with type conversion
for log_file in log_files:
    log_type = os.path.basename(log_file).split('.')[0]
    fields = None
    field_types = None
    sep = '\t'
    
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
            except Exception as e:
                print(f"Failed to index doc from {log_file}: {e}")

print('Ingestion Complete.')
PY

echo ">>> SETUP COMPLETE. Run 'chainlit run agent.py -w' to start."
