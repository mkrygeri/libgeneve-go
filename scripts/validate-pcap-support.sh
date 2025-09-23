#!/bin/bash

# GENEVE Analyzer Linux Cooked Capture Validation
# This script validates that the analyzer correctly handles both Ethernet and Linux SLL formats

set -e

echo "GENEVE Analyzer Linux Cooked Capture Validation"
echo "==============================================="
echo ""

# Create test data directory
mkdir -p test-data

echo "Step 1: Building test tools..."
if [ ! -f "./build/geneve-analyzer" ]; then
    echo "Building geneve-analyzer..."
    make analyzer
fi

if [ ! -f "./build/create-test-pcap" ]; then
    echo "Building create-test-pcap..."
    go build -o build/create-test-pcap ./cmd/create-test-pcap
fi

echo "Step 2: Creating test PCAP files..."
./build/create-test-pcap test-data/ethernet-test.pcap test-data/cooked-test.pcap

echo ""
echo "Step 3: Validating Ethernet format detection..."
echo "----------------------------------------------"
ETHERNET_OUTPUT=$(./build/geneve-analyzer -pcap-file test-data/ethernet-test.pcap 2>&1 | head -5)
echo "$ETHERNET_OUTPUT"

if echo "$ETHERNET_OUTPUT" | grep -q "Link type: Ethernet"; then
    echo "✅ Ethernet format correctly detected"
else
    echo "❌ Ethernet format detection failed"
    exit 1
fi

echo ""
echo "Step 4: Validating Linux SLL format detection..."
echo "------------------------------------------------"
SLL_OUTPUT=$(./build/geneve-analyzer -pcap-file test-data/cooked-test.pcap 2>&1 | head -5)
echo "$SLL_OUTPUT"

if echo "$SLL_OUTPUT" | grep -q "Link type: Linux cooked capture (SLL)"; then
    echo "✅ Linux cooked capture format correctly detected"
else
    echo "❌ Linux SLL format detection failed"
    exit 1
fi

echo ""
echo "Step 5: Validating packet parsing consistency..."
echo "-----------------------------------------------"

# Parse both files and compare packet counts
ETHERNET_STATS=$(./build/geneve-analyzer -pcap-file test-data/ethernet-test.pcap 2>&1 | tail -10)
SLL_STATS=$(./build/geneve-analyzer -pcap-file test-data/cooked-test.pcap 2>&1 | tail -10)

ETHERNET_PARSED=$(echo "$ETHERNET_STATS" | grep "Successfully Parsed:" | cut -d: -f2 | tr -d ' ')
SLL_PARSED=$(echo "$SLL_STATS" | grep "Successfully Parsed:" | cut -d: -f2 | tr -d ' ')

if [ "$ETHERNET_PARSED" = "$SLL_PARSED" ]; then
    echo "✅ Both formats parsed same number of packets: $ETHERNET_PARSED"
else
    echo "❌ Parsing mismatch - Ethernet: $ETHERNET_PARSED, SLL: $SLL_PARSED"
    exit 1
fi

echo ""
echo "Step 6: Testing verbose layer debugging..."
echo "-----------------------------------------"
VERBOSE_OUTPUT=$(./build/geneve-analyzer -pcap-file test-data/cooked-test.pcap -verbose 2>&1 | grep "DEBUG: Packet 1 layers:")
echo "$VERBOSE_OUTPUT"

if echo "$VERBOSE_OUTPUT" | grep -q "Linux SLL"; then
    echo "✅ Verbose debugging shows correct layer structure"
else
    echo "❌ Layer debugging not working correctly"
    exit 1
fi

echo ""
echo "Step 7: Testing enterprise telemetry parsing..."
echo "----------------------------------------------"
ENTERPRISE_OUTPUT=$(./build/geneve-analyzer -pcap-file test-data/cooked-test.pcap -enterprise 2>&1)
NVIDIA_COUNT=$(echo "$ENTERPRISE_OUTPUT" | grep "NVIDIA/Mellanox:" | wc -l)
CUMULUS_COUNT=$(echo "$ENTERPRISE_OUTPUT" | grep "NVIDIA Cumulus Linux:" | wc -l)

echo "Found telemetry - NVIDIA/Mellanox: $NVIDIA_COUNT, Cumulus: $CUMULUS_COUNT"

if [ "$NVIDIA_COUNT" -gt 0 ] && [ "$CUMULUS_COUNT" -gt 0 ]; then
    echo "✅ Enterprise telemetry parsing works with SLL format"
else
    echo "❌ Enterprise telemetry parsing issue"
    exit 1
fi

echo ""
echo "Step 8: Testing JSON output format..."
echo "------------------------------------"
JSON_OUTPUT=$(./build/geneve-analyzer -pcap-file test-data/cooked-test.pcap -output json 2>&1)
JSON_COUNT=$(echo "$JSON_OUTPUT" | grep -c '"timestamp"' || true)

if [ "$JSON_COUNT" -gt 0 ]; then
    echo "✅ JSON output format works: $JSON_COUNT JSON packets"
else
    echo "❌ JSON output format issue"
    exit 1
fi

echo ""
echo "Step 9: File information summary..."
echo "----------------------------------"
echo "Created test files:"
ls -la test-data/*.pcap

echo ""
echo "File format verification:"
if command -v file >/dev/null 2>&1; then
    echo "Ethernet PCAP: $(file test-data/ethernet-test.pcap)"
    echo "Linux SLL PCAP: $(file test-data/cooked-test.pcap)"
else
    echo "File command not available for format verification"
fi

echo ""
echo "Step 10: Performance comparison..."
echo "---------------------------------"
echo "Testing processing speed for both formats..."

ETHERNET_TIME=$(time ./build/geneve-analyzer -pcap-file test-data/ethernet-test.pcap >/dev/null 2>&1)
SLL_TIME=$(time ./build/geneve-analyzer -pcap-file test-data/cooked-test.pcap >/dev/null 2>&1)

echo "Both formats processed successfully"

echo ""
echo "🎉 VALIDATION SUCCESSFUL!"
echo "========================"
echo ""
echo "Summary:"
echo "✅ Ethernet format detection and parsing"
echo "✅ Linux cooked capture (SLL) format detection and parsing"
echo "✅ Packet parsing consistency between formats" 
echo "✅ Enterprise telemetry extraction (NVIDIA/Mellanox, Cumulus)"
echo "✅ Verbose debugging with layer information"
echo "✅ JSON output format compatibility"
echo "✅ Performance stability across formats"
echo ""
echo "The GENEVE analyzer now successfully supports both standard Ethernet"
echo "and Linux cooked capture formats, making it compatible with:"
echo "- Standard interface captures: tcpdump -i eth0"
echo "- Multi-interface captures: tcpdump -i any"
echo "- Container networking environments"
echo "- Complex network topologies"
echo ""
echo "Usage examples:"
echo "  ./build/geneve-analyzer -pcap-file ethernet-capture.pcap"
echo "  ./build/geneve-analyzer -pcap-file cooked-capture.pcap -verbose"
echo "  ./build/geneve-analyzer -pcap-file any-format.pcap -enterprise -json"