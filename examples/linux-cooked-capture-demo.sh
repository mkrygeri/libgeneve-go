#!/bin/bash
# Example: Analyzing GENEVE packets from Linux cooked capture format
# This demonstrates how the analyzer handles PCAP files created with "tcpdump -i any"

echo "=== Linux Cooked Capture GENEVE Analysis Example ==="
echo ""

# Check if analyzer exists
if [ ! -f "../build/geneve-analyzer" ]; then
    echo "Please build the analyzer first:"
    echo "  make analyzer"
    exit 1
fi

echo "This example shows how to analyze GENEVE packets from Linux cooked"
echo "capture format, commonly created when using 'tcpdump -i any'."
echo ""

echo "1. Creating a Linux cooked capture:"
echo "   sudo tcpdump -i any -w cooked-geneve.pcap 'udp port 6081'"
echo ""

echo "2. Analyzing the cooked capture with basic output:"
echo "   ../build/geneve-analyzer -pcap-file cooked-geneve.pcap"
echo ""

echo "3. Analyzing with verbose output (shows link type detection):"
echo "   ../build/geneve-analyzer -pcap-file cooked-geneve.pcap -verbose"
echo ""

echo "4. Analyzing with enterprise telemetry and JSON output:"
echo "   ../build/geneve-analyzer -pcap-file cooked-geneve.pcap -enterprise -output json"
echo ""

echo "The analyzer automatically detects the capture format:"
echo ""
echo "For Ethernet captures, you'll see:"
echo "  Link type: Ethernet"
echo ""
echo "For Linux cooked captures, you'll see:"
echo "  Link type: Linux cooked capture (SLL)"
echo ""

echo "Key benefits of Linux cooked capture support:"
echo "- Captures from any interface simultaneously"
echo "- Useful in containerized environments"
echo "- Works with complex network topologies"
echo "- Standard format from tcpdump -i any"
echo ""

echo "Example verbose output showing layer detection:"
echo "  DEBUG: Packet 1 layers: LinuxSLL IPv4 UDP"
echo "  DEBUG: Found GENEVE packet - UDP payload size: 64 bytes"
echo "  Link type: Linux cooked capture (SLL)"