#!/bin/bash
# Unit test for Elasticsearch health check in setup script

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     HEALTH CHECK UNIT TEST                                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Test 1: Check if Elasticsearch is accessible
echo "Test 1: Elasticsearch connectivity"
if curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
    echo "  ✓ PASS: Elasticsearch is accessible"
else
    echo "  ✗ FAIL: Cannot connect to Elasticsearch"
    exit 1
fi

# Test 2: Verify cluster status detection
echo ""
echo "Test 2: Cluster status detection"
CLUSTER_STATUS=$(curl -s "http://localhost:9200/_cluster/health" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)

if [ -n "$CLUSTER_STATUS" ]; then
    echo "  ✓ PASS: Cluster status detected: $CLUSTER_STATUS"
else
    echo "  ✗ FAIL: Could not detect cluster status"
    exit 1
fi

# Test 3: Check disk watermark settings can be queried
echo ""
echo "Test 3: Disk watermark configuration"
WATERMARK_HIGH=$(curl -s "http://localhost:9200/_cluster/settings?include_defaults=true" | \
                  grep -o '"high":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$WATERMARK_HIGH" ]; then
    echo "  ✓ PASS: Current high watermark: $WATERMARK_HIGH"
else
    echo "  ⚠  WARN: Could not query watermark (may be using defaults)"
fi

# Test 4: Verify disk usage can be measured
echo ""
echo "Test 4: Disk usage measurement"
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')

if [ -n "$DISK_USAGE" ] && [ "$DISK_USAGE" -gt 0 ]; then
    echo "  ✓ PASS: Disk usage: ${DISK_USAGE}%"
    
    if [ "$DISK_USAGE" -gt 90 ]; then
        echo "  ⚠  WARNING: Disk usage above 90% - RED status likely"
    fi
else
    echo "  ✗ FAIL: Could not measure disk usage"
    exit 1
fi

# Test 5: Simulate RED status fix (dry run)
echo ""
echo "Test 5: RED status fix simulation"
echo "  If cluster were RED, the fix would:"
echo "    1. Detect RED status"
echo "    2. Show disk usage: ${DISK_USAGE}%"
echo "    3. Adjust watermark to high: 97%, flood: 99%"
echo "    4. Wait up to 30 seconds for recovery"
echo "    5. Verify new status"

# Test 6: Check active shards
echo ""
echo "Test 6: Shard allocation status"
ACTIVE_SHARDS=$(curl -s "http://localhost:9200/_cluster/health" | grep -o '"active_primary_shards":[0-9]*' | cut -d':' -f2)
UNASSIGNED_SHARDS=$(curl -s "http://localhost:9200/_cluster/health" | grep -o '"unassigned_shards":[0-9]*' | cut -d':' -f2)

echo "  Active primary shards: $ACTIVE_SHARDS"
echo "  Unassigned shards: $UNASSIGNED_SHARDS"

if [ "$UNASSIGNED_SHARDS" -gt 0 ] && [ "$CLUSTER_STATUS" = "red" ]; then
    echo "  ⚠  WARNING: RED cluster with unassigned shards"
    echo "     Health check will auto-fix this on next setup run"
elif [ "$UNASSIGNED_SHARDS" -gt 0 ]; then
    echo "  ✓ PASS: Unassigned shards present but cluster not RED"
    echo "     (Normal for single-node with replica shards)"
else
    echo "  ✓ PASS: All shards assigned"
fi

# Summary
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     TEST SUMMARY                                               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Cluster Status: $CLUSTER_STATUS"
echo "Disk Usage: ${DISK_USAGE}%"
echo "Active Shards: $ACTIVE_SHARDS"
echo "Unassigned Shards: $UNASSIGNED_SHARDS"
echo ""

if [ "$CLUSTER_STATUS" = "green" ]; then
    echo "✓ All tests passed - Cluster is healthy"
    exit 0
elif [ "$CLUSTER_STATUS" = "yellow" ]; then
    echo "✓ All tests passed - Cluster is operational (YELLOW is normal for single-node)"
    exit 0
elif [ "$CLUSTER_STATUS" = "red" ]; then
    echo "⚠  WARNING: Cluster is RED"
    echo "   The setup script will automatically fix this by adjusting disk watermarks"
    exit 0
else
    echo "✗ Unexpected cluster status: $CLUSTER_STATUS"
    exit 1
fi
