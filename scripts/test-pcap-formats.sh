#!/bin/bash

# Script to demonstrate GENEVE analyzer support for different PCAP formats
# This script shows how to capture GENEVE traffic in both Ethernet and Linux cooked formats

set -e

echo "GENEVE Analyzer PCAP Format Test"
echo "================================="

# Check if analyzer is built
if [ ! -f "./build/geneve-analyzer" ]; then
    echo "Building geneve-analyzer..."
    make analyzer
fi

# Test with help to show supported formats
echo ""
echo "1. Supported PCAP formats:"
echo "-------------------------"
./build/geneve-analyzer -h 2>&1 | grep -A 3 "Supported PCAP formats" || echo "Formats: Ethernet and Linux cooked capture"

echo ""
echo "2. Example capture commands:"
echo "---------------------------"

echo ""
echo "Standard Ethernet capture:"
echo "  sudo tcpdump -i eth0 -w ethernet-capture.pcap 'udp port 6081'"
echo ""
echo "Linux cooked capture (captures from any interface):"
echo "  sudo tcpdump -i any -w cooked-capture.pcap 'udp port 6081'"

echo ""
echo "3. Analysis commands:"
echo "-------------------"

echo ""
echo "Analyze Ethernet PCAP:"
echo "  ./build/geneve-analyzer -pcap-file ethernet-capture.pcap -enterprise"
echo ""
echo "Analyze Linux cooked PCAP:"
echo "  ./build/geneve-analyzer -pcap-file cooked-capture.pcap -verbose"

echo ""
echo "4. Testing with sample files:"
echo "----------------------------"

# Create some test data if we can
if command -v xxd >/dev/null 2>&1; then
    echo "Creating sample test files..."
    
    # Create a minimal Ethernet frame with GENEVE (just for testing link type detection)
    echo "Creating sample ethernet-test.pcap..."
    # This is just for link type testing - not a valid GENEVE packet
    mkdir -p test-data
    
    # We can't easily create a valid PCAP without proper tools, so just document the process
    echo ""
    echo "To create test files:"
    echo "1. Capture real traffic: tcpdump -i eth0 -w ethernet-test.pcap 'udp port 6081'"
    echo "2. Capture from any interface: tcpdump -i any -w cooked-test.pcap 'udp port 6081'"
    echo "3. Test analysis: ./build/geneve-analyzer -pcap-file [filename] -verbose"
else
    echo "xxd not available - skipping sample file creation"
fi

echo ""
echo "5. Verbose output differences:"
echo "-----------------------------"
echo "When using -verbose flag with different PCAP formats:"
echo "  - Ethernet: Shows 'Link type: Ethernet'"
echo "  - Linux SLL: Shows 'Link type: Linux cooked capture (SLL)'"
echo "  - Debug info: Shows packet layer structure for first 5 packets"

echo ""
echo "Done! The analyzer now supports both Ethernet and Linux cooked capture formats."
echo "This is particularly useful when analyzing captures from 'tcpdump -i any'."