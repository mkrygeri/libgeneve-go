package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/mkrygeri/libgeneve-go/geneve"
)

const (
	defaultSnaplen  = 1600
	promiscuous     = false
	timeout         = pcap.BlockForever
	genevePort      = 6081
)

type Config struct {
	Interface    string
	PcapFile     string
	OutputFormat string
	Verbose      bool
	Count        int
	Filter       string
	Enterprise   bool
	JSONOutput   bool
	Port         int
	SFlowEnabled bool
}

type PacketStats struct {
	TotalPackets    int
	GenevePackets   int
	ParsedPackets   int
	ErrorPackets    int
	VendorCounts    map[string]int
	StartTime       time.Time
}

// processLinuxSLL2Packet handles Linux Cooked Capture v2 packets by manually parsing the 20-byte header
// and creating a packet from the inner payload  
func processLinuxSLL2Packet(data []byte, ci gopacket.CaptureInfo) gopacket.Packet {
	if len(data) < 20 {
		log.Printf("Linux SLL2 packet too short: %d bytes", len(data))
		return nil
	}

	// Linux SLL2 header structure (20 bytes):
	// 0-1:   Protocol (network byte order)
	// 2-3:   Reserved (MBZ)
	// 4-7:   Interface index
	// 8-9:   ARPHRD type
	// 10:    Packet type  
	// 11:    Hardware address length
	// 12-19: Hardware address (8 bytes)

	// Extract protocol from first 2 bytes (network byte order)
	protocol := uint16(data[0])<<8 | uint16(data[1])
	
	// Skip the 20-byte Linux SLL2 header to get to the network layer
	innerData := data[20:]
	
	var layerType gopacket.LayerType
	switch protocol {
	case 0x0800: // IPv4
		layerType = layers.LayerTypeIPv4
	case 0x86DD: // IPv6  
		layerType = layers.LayerTypeIPv6
	case 0x0806: // ARP
		layerType = layers.LayerTypeARP
	default:
		// Unknown protocol, try IPv4 as default
		layerType = layers.LayerTypeIPv4
	}
	
	// Create packet from the inner data
	packet := gopacket.NewPacket(innerData, layerType, gopacket.Default)
	packet.Metadata().Timestamp = ci.Timestamp
	packet.Metadata().CaptureLength = ci.CaptureLength
	packet.Metadata().Length = ci.Length
	
	return packet
}

// isSFlowPort checks if the given port is a common sFlow port
func isSFlowPort(port int) bool {
	sflowPorts := []int{6343, 9995, 9996, 9997}
	for _, p := range sflowPorts {
		if port == p {
			return true
		}
	}
	return false
}

// isLikelyGENEVE performs a heuristic check to see if payload looks like GENEVE
func isLikelyGENEVE(payload []byte) bool {
	if len(payload) < 8 {
		return false
	}
	
	// GENEVE header structure:
	// 0: Ver(2) + OptLen(6) 
	// 1: OAM(1) + Critical(1) + Reserved(6)
	// 2-3: Protocol Type (typically 0x6558 for Ethernet, 0x0800 for IPv4)
	// 4-6: VNI (24 bits)
	// 7: Reserved
	
	version := (payload[0] >> 6) & 0x03
	protocol := uint16(payload[2])<<8 | uint16(payload[3])
	
	// Check for GENEVE version 0 and common protocol types
	return version == 0 && (protocol == 0x6558 || protocol == 0x0800 || protocol == 0x86DD)
}

// processSFlowPacket extracts and processes packet samples from sFlow datagrams
func processSFlowPacket(payload []byte, parser *geneve.Parser, config *Config, stats *PacketStats, timestamp time.Time) {
	if len(payload) < 28 { // Minimum sFlow header
		if config.Verbose {
			fmt.Printf("sFlow packet too short: %d bytes\n", len(payload))
		}
		return
	}
	
	// Parse sFlow header
	version := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	if version != 5 { // sFlow v5
		if config.Verbose {
			fmt.Printf("Unsupported sFlow version: %d\n", version)
		}
		return
	}
	
	// Skip to sample records (after 28-byte sFlow header) 
	// sFlow v5 header: version(4) + address_type(4) + agent_address(4) + sub_agent_id(4) + sequence(4) + uptime(4) + sample_count(4)
	sampleCount := uint32(payload[24])<<24 | uint32(payload[25])<<16 | uint32(payload[26])<<8 | uint32(payload[27])
	if config.Verbose {
		fmt.Printf("DEBUG: sFlow v%d with %d samples\n", version, sampleCount)
	}
	
	offset := 28
	for i := uint32(0); i < sampleCount && offset < len(payload)-8; i++ {
		if offset+8 > len(payload) {
			break
		}
		
		// Read sample type and length
		sampleType := uint32(payload[offset])<<24 | uint32(payload[offset+1])<<16 | uint32(payload[offset+2])<<8 | uint32(payload[offset+3])
		sampleLength := uint32(payload[offset+4])<<24 | uint32(payload[offset+5])<<16 | uint32(payload[offset+6])<<8 | uint32(payload[offset+7])
		
		offset += 8
		
		if offset+int(sampleLength) > len(payload) {
			break
		}
		
		// Process flow sample (type 1) or packet sample
		if sampleType == 1 {
			processSFlowSample(payload[offset:offset+int(sampleLength)], parser, config, stats, timestamp, sampleType)
		} else if config.Verbose {
			// Just log that we're skipping counter samples, don't process them
			fmt.Printf("DEBUG: Skipping counter sample (type %d, length %d)\n", sampleType, sampleLength)
		}
		
		offset += int(sampleLength)
	}
}

// processSFlowSample extracts packet data from an sFlow sample record
func processSFlowSample(sampleData []byte, parser *geneve.Parser, config *Config, stats *PacketStats, timestamp time.Time, sampleType uint32) {
	// Only process flow samples (type 1), ignore counter samples (type 2)
	if sampleType != 1 {
		if config.Verbose {
			fmt.Printf("DEBUG: Ignoring counter sample (type %d)\n", sampleType)
		}
		return
	}
	
	if len(sampleData) < 20 {
		if config.Verbose {
			fmt.Printf("DEBUG: Flow sample too short: %d bytes\n", len(sampleData))
		}
		return
	}
	
	// sFlow Flow Sample structure:
	// 0-3: Sample sequence number
	// 4-7: Source ID (type + index)  
	// 8-11: Sampling rate
	// 12-15: Sample pool
	// 16-19: Drops
	// 20-23: Input interface
	// 24-27: Output interface  
	// 28-31: Flow record count
	
	if len(sampleData) < 32 {
		if config.Verbose {
			fmt.Printf("DEBUG: Flow sample header too short: %d bytes\n", len(sampleData))
		}
		return
	}
	
	// Skip to flow record count at offset 28
	recordCount := uint32(sampleData[28])<<24 | uint32(sampleData[29])<<16 | uint32(sampleData[30])<<8 | uint32(sampleData[31])
	offset := 32
	
	if config.Verbose {
		fmt.Printf("DEBUG: Processing flow sample with %d flow records\n", recordCount)
	}
	
	// Process each flow record
	for i := uint32(0); i < recordCount && offset < len(sampleData)-8; i++ {
		if offset+8 > len(sampleData) {
			break
		}
		
		// Read record type and length
		recordType := uint32(sampleData[offset])<<24 | uint32(sampleData[offset+1])<<16 | uint32(sampleData[offset+2])<<8 | uint32(sampleData[offset+3])
		recordLength := uint32(sampleData[offset+4])<<24 | uint32(sampleData[offset+5])<<16 | uint32(sampleData[offset+6])<<8 | uint32(sampleData[offset+7])
		
		offset += 8
		
		if offset+int(recordLength) > len(sampleData) {
			if config.Verbose {
				fmt.Printf("DEBUG: Flow record extends beyond sample data\n")
			}
			break
		}
		
		// Process raw packet header record (type 1)
		if recordType == 1 {
			if config.Verbose {
				fmt.Printf("DEBUG: Processing raw packet header record (type %d, length %d)\n", recordType, recordLength)
			}
			extractGENEVEFromRawPacket(sampleData[offset:offset+int(recordLength)], parser, config, stats, timestamp)
		} else {
			if config.Verbose {
				fmt.Printf("DEBUG: Skipping flow record type %d (length %d)\n", recordType, recordLength)
			}
		}
		
		offset += int(recordLength)
	}
}

// extractGENEVEFromRawPacket extracts GENEVE packets from sFlow raw packet samples  
func extractGENEVEFromRawPacket(recordData []byte, parser *geneve.Parser, config *Config, stats *PacketStats, timestamp time.Time) {
	if len(recordData) < 12 {
		if config.Verbose {
			fmt.Printf("DEBUG: Raw packet record too short: %d bytes\n", len(recordData))
		}
		return
	}
	
	// sFlow raw packet header record:
	// 0-3: Protocol (header protocol)
	// 4-7: Frame length
	// 8-11: Stripped octets
	// 12-15: Header length
	
	protocol := uint32(recordData[0])<<24 | uint32(recordData[1])<<16 | uint32(recordData[2])<<8 | uint32(recordData[3])
	frameLength := uint32(recordData[4])<<24 | uint32(recordData[5])<<16 | uint32(recordData[6])<<8 | uint32(recordData[7])
	strippedOctets := uint32(recordData[8])<<24 | uint32(recordData[9])<<16 | uint32(recordData[10])<<8 | uint32(recordData[11])
	headerLength := uint32(recordData[12])<<24 | uint32(recordData[13])<<16 | uint32(recordData[14])<<8 | uint32(recordData[15])
	
	if config.Verbose {
		fmt.Printf("DEBUG: Raw packet - protocol: %d, frame: %d bytes, stripped: %d, header: %d bytes\n", 
			protocol, frameLength, strippedOctets, headerLength)
	}
	
	// Check if we have enough data and if header length is reasonable
	if len(recordData) < int(16+headerLength) {
		if config.Verbose {
			fmt.Printf("DEBUG: Insufficient data for header: need %d, have %d\n", 16+headerLength, len(recordData))
		}
		return
	}
	
	// If header is too small to contain UDP data, skip it
	if headerLength < 42 { // Ethernet(14) + IP(20) + UDP(8) minimum
		if config.Verbose {
			fmt.Printf("DEBUG: Header too small for UDP packet: %d bytes\n", headerLength)
		}
		return
	}
	
	// Extract the raw packet header
	packetHeader := recordData[16 : 16+headerLength]
	
	if config.Verbose {
		fmt.Printf("DEBUG: Extracted %d-byte packet from sFlow sample, protocol %d\n", len(packetHeader), protocol)
	}
	
	// Parse the packet header to look for GENEVE
	packet := gopacket.NewPacket(packetHeader, layers.LayerTypeEthernet, gopacket.Default)
	
	// Look for UDP layer in the extracted packet
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		if config.Verbose {
			fmt.Printf("DEBUG: No UDP layer found in extracted packet\n")
		}
		return
	}
	
	udp, _ := udpLayer.(*layers.UDP)
	
	if config.Verbose {
		fmt.Printf("DEBUG: Found UDP layer - %d->%d, payload: %d bytes\n", udp.SrcPort, udp.DstPort, len(udp.Payload))
	}
	
	// Check if this UDP payload contains GENEVE
	if len(udp.Payload) >= 8 && isLikelyGENEVE(udp.Payload) {
		if config.Verbose {
			fmt.Printf("DEBUG: Found GENEVE packet in sFlow sample - UDP payload size: %d bytes\n", len(udp.Payload))
		}
		
		stats.GenevePackets++
		
		// Parse GENEVE packet
		result, err := parser.ParsePacket(udp.Payload)
		if err != nil {
			stats.ErrorPackets++
			if config.Verbose {
				fmt.Printf("Error parsing GENEVE packet from sFlow: %v\n", err)
			}
			return
		}
		
		stats.ParsedPackets++
		
		// Track vendor statistics
		if result.EnterpriseOptions != nil {
			for _, opt := range result.EnterpriseOptions {
				vendorName := opt.VendorName
				if vendorName == "" {
					vendorName = fmt.Sprintf("Class-0x%04X", opt.Class)
				}
				stats.VendorCounts[vendorName]++
			}
		}
		
		// Output the parsed GENEVE packet
		printGeneveResult(result, config, timestamp)
	} else {
		if config.Verbose {
			fmt.Printf("DEBUG: UDP payload doesn't appear to be GENEVE (port %d->%d, %d bytes)\n", 
				udp.SrcPort, udp.DstPort, len(udp.Payload))
			// Show first few bytes of payload for debugging
			if len(udp.Payload) >= 8 {
				fmt.Printf("DEBUG: Payload start: %02x %02x %02x %02x %02x %02x %02x %02x\n",
					udp.Payload[0], udp.Payload[1], udp.Payload[2], udp.Payload[3],
					udp.Payload[4], udp.Payload[5], udp.Payload[6], udp.Payload[7])
			}
		}
	}
}

// printGeneveResult outputs a GENEVE parsing result using the configured format
func printGeneveResult(result *geneve.ParseResult, config *Config, timestamp time.Time) {
	// Convert timestamp to string format
	timestampStr := timestamp.Format("2006-01-02 15:04:05.000000")
	
	// Use existing output functions based on configuration
	switch config.OutputFormat {
	case "json":
		outputJSON(timestampStr, result)
	case "summary":
		outputSummary(timestampStr, result)
	default:
		outputDetailed(timestampStr, result, config)
	}
}

func main() {
	config := parseFlags()
	
	if config.Interface == "" && config.PcapFile == "" {
		fmt.Println("Error: Must specify either -interface or -pcap-file")
		flag.Usage()
		os.Exit(1)
	}

	// Create GENEVE parser
	parser := geneve.NewParser()
	if config.Enterprise {
		parser.EnableEnterpriseExtensions()
	}

	// Initialize statistics
	stats := &PacketStats{
		VendorCounts: make(map[string]int),
		StartTime:    time.Now(),
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if config.PcapFile != "" {
		processPcapFile(config, parser, stats)
	} else {
		captureFromInterface(config, parser, stats, sigChan)
	}

	printFinalStats(stats)
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.Interface, "interface", "", "Network interface to capture from (e.g., eth0)")
	flag.StringVar(&config.Interface, "i", "", "Network interface to capture from (short)")
	flag.StringVar(&config.PcapFile, "pcap-file", "", "PCAP file to read from")
	flag.StringVar(&config.PcapFile, "r", "", "PCAP file to read from (short)")
	flag.StringVar(&config.OutputFormat, "output", "detailed", "Output format: detailed, summary, json")
	flag.StringVar(&config.OutputFormat, "o", "detailed", "Output format (short)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&config.Verbose, "v", false, "Enable verbose output (short)")
	flag.IntVar(&config.Count, "count", 0, "Number of packets to process (0 = unlimited)")
	flag.IntVar(&config.Count, "c", 0, "Number of packets to process (short)")
	flag.StringVar(&config.Filter, "filter", "", "BPF filter expression")
	flag.StringVar(&config.Filter, "f", "", "BPF filter expression (short)")
	flag.BoolVar(&config.Enterprise, "enterprise", true, "Enable enterprise telemetry parsing")
	flag.BoolVar(&config.Enterprise, "e", true, "Enable enterprise telemetry parsing (short)")
	flag.BoolVar(&config.JSONOutput, "json", false, "Output results as JSON")
	flag.IntVar(&config.Port, "port", 0, "GENEVE UDP port (0 = auto-detect, default 6081)")
	flag.IntVar(&config.Port, "p", 0, "GENEVE UDP port (short)")
	flag.BoolVar(&config.SFlowEnabled, "sflow", false, "Parse sFlow packet samples for GENEVE packets")
	flag.BoolVar(&config.SFlowEnabled, "s", false, "Parse sFlow packet samples (short)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "GENEVE Telemetry Analyzer\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSupported PCAP formats:\n")
		fmt.Fprintf(os.Stderr, "  - Standard Ethernet (DLT_EN10MB)\n")
		fmt.Fprintf(os.Stderr, "  - Linux cooked capture v1 (DLT_LINUX_SLL)\n")
		fmt.Fprintf(os.Stderr, "  - Linux cooked capture v2 (DLT_LINUX_SLL2)\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -interface eth0\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -pcap-file capture.pcap -enterprise\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -pcap-file cooked.pcap -verbose\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -i eth0 -filter \"port 6081\" -count 100\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r network.pcap -output json\n", os.Args[0])
	}

	flag.Parse()

	return config
}

func captureFromInterface(config *Config, parser *geneve.Parser, stats *PacketStats, sigChan chan os.Signal) {
	fmt.Printf("Starting live capture on interface %s...\n", config.Interface)
	
	// Open device
	handle, err := pcap.OpenLive(config.Interface, defaultSnaplen, promiscuous, timeout)
	if err != nil {
		log.Fatalf("Error opening interface %s: %v", config.Interface, err)
	}
	defer handle.Close()

	// Set BPF filter
	filterStr := config.Filter
	if filterStr == "" {
		filterStr = fmt.Sprintf("udp port %d", genevePort)
	}
	
	if err := handle.SetBPFFilter(filterStr); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	fmt.Printf("Filter: %s\n", filterStr)
	fmt.Printf("Press Ctrl+C to stop...\n\n")

	// Start packet processing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	for {
		select {
		case packet := <-packetChan:
			processPacket(packet, parser, config, stats)
			
			if config.Count > 0 && stats.TotalPackets >= config.Count {
				return
			}

		case <-sigChan:
			fmt.Printf("\nReceived interrupt signal, stopping...\n")
			return
		}
	}
}

func processPcapFile(config *Config, parser *geneve.Parser, stats *PacketStats) {
	fmt.Printf("Processing PCAP file: %s\n", config.PcapFile)

	// Open pcap file
	file, err := os.Open(config.PcapFile)
	if err != nil {
		log.Fatalf("Error opening pcap file: %v", err)
	}
	defer file.Close()

	// Create pcap reader
	pcapReader, err := pcapgo.NewReader(file)
	if err != nil {
		log.Fatalf("Error creating pcap reader: %v", err)
	}

	// Determine link type from the pcap file
	linkType := pcapReader.LinkType()
	var layerType gopacket.LayerType
	var isLinuxSLL2 bool
	
	switch linkType {
	case layers.LinkTypeEthernet:
		layerType = layers.LayerTypeEthernet
		fmt.Printf("Link type: Ethernet\n")
	case layers.LinkTypeLinuxSLL:
		layerType = layers.LayerTypeLinuxSLL
		fmt.Printf("Link type: Linux cooked capture (SLL v1)\n")
	case layers.LinkType(20): // Linux SLL2 - not yet supported by gopacket constants
		isLinuxSLL2 = true
		layerType = layers.LayerTypeEthernet // We'll handle SLL2 manually
		fmt.Printf("Link type: Linux cooked capture (SLL v2)\n")
	default:
		// Check if this might be Linux SLL2 based on the numeric value
		if int(linkType) == 276 { // DLT_LINUX_SLL2
			isLinuxSLL2 = true
			layerType = layers.LayerTypeEthernet // We'll handle SLL2 manually  
			fmt.Printf("Link type: Linux cooked capture (SLL v2 - detected by value %d)\n", linkType)
		} else {
			// Try to auto-detect or default to Ethernet
			layerType = layers.LayerTypeEthernet
			fmt.Printf("Link type: %v (defaulting to Ethernet - may not work correctly)\n", linkType)
			fmt.Printf("Warning: Unsupported link type. Supported types are Ethernet, Linux SLL v1, and Linux SLL v2\n")
		}
	}

	// Read packets
	for {
		data, ci, err := pcapReader.ReadPacketData()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Printf("Error reading packet: %v", err)
			continue
		}

		var packet gopacket.Packet

		// Handle Linux SLL2 manually since gopacket doesn't support it yet
		if isLinuxSLL2 {
			packet = processLinuxSLL2Packet(data, ci)
		} else {
			// Create packet from data with appropriate link layer type
			packet = gopacket.NewPacket(data, layerType, gopacket.Default)
			packet.Metadata().Timestamp = ci.Timestamp
			packet.Metadata().CaptureLength = ci.CaptureLength
			packet.Metadata().Length = ci.Length
		}

		if packet != nil {
			processPacket(packet, parser, config, stats)
		}

		if config.Count > 0 && stats.TotalPackets >= config.Count {
			break
		}
	}
}

func processPacket(packet gopacket.Packet, parser *geneve.Parser, config *Config, stats *PacketStats) {
	stats.TotalPackets++

	if config.Verbose && stats.TotalPackets <= 5 {
		// Debug first few packets to show layer structure
		fmt.Printf("DEBUG: Packet %d layers: ", stats.TotalPackets)
		for _, layer := range packet.Layers() {
			fmt.Printf("%v ", layer.LayerType())
		}
		fmt.Printf("\n")
	}

	// Look for UDP layer - works for both Ethernet and Linux SLL formats
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp, _ := udpLayer.(*layers.UDP)
	
	// Determine the effective GENEVE port to check
	effectivePort := genevePort
	if config.Port != 0 {
		effectivePort = config.Port
	}
	
	// Check for sFlow packets first (common sFlow ports: 6343, 9995, 9996)
	if config.SFlowEnabled || isSFlowPort(int(udp.DstPort)) || isSFlowPort(int(udp.SrcPort)) {
		if config.Verbose {
			fmt.Printf("DEBUG: Detected sFlow packet on port %d->%d, extracting packet samples\n", udp.SrcPort, udp.DstPort)
		}
		processSFlowPacket(udp.Payload, parser, config, stats, packet.Metadata().Timestamp)
		return
	}
	
	// Check if it's direct GENEVE traffic
	if uint16(udp.DstPort) != uint16(effectivePort) && uint16(udp.SrcPort) != uint16(effectivePort) {
		// If port is 0 (auto-detect), try to parse as GENEVE anyway if the payload looks like GENEVE
		if config.Port == 0 && len(udp.Payload) >= 8 {
			if isLikelyGENEVE(udp.Payload) {
				if config.Verbose {
					fmt.Printf("DEBUG: Auto-detected GENEVE-like packet on port %d->%d\n", udp.SrcPort, udp.DstPort)
				}
			} else {
				return
			}
		} else {
			return
		}
	}

	if config.Verbose {
		fmt.Printf("DEBUG: Found GENEVE packet - UDP payload size: %d bytes\n", len(udp.Payload))
	}

	stats.GenevePackets++

	// Parse GENEVE packet
	result, err := parser.ParsePacket(udp.Payload)
	if err != nil {
		stats.ErrorPackets++
		if config.Verbose {
			fmt.Printf("Error parsing GENEVE packet: %v\n", err)
		}
		return
	}

	stats.ParsedPackets++
	updateVendorCounts(result, stats)

	// Output packet information
	outputPacketInfo(packet, result, config)
}

func updateVendorCounts(result *geneve.ParseResult, stats *PacketStats) {
	if len(result.VMwareOptions) > 0 {
		stats.VendorCounts["VMware"]++
	}
	if len(result.CiscoOptions) > 0 {
		stats.VendorCounts["Cisco"]++
	}
	if len(result.AristaOptions) > 0 || len(result.AristaLatencyOptions) > 0 {
		stats.VendorCounts["Arista"]++
	}
	if len(result.BroadcomOptions) > 0 || len(result.BroadcomLatencyOptions) > 0 {
		stats.VendorCounts["Broadcom"]++
	}
	
	// Count enterprise options by vendor
	vendorMap := make(map[string]bool)
	for _, enterprise := range result.EnterpriseOptions {
		if !vendorMap[enterprise.VendorName] {
			stats.VendorCounts[enterprise.VendorName]++
			vendorMap[enterprise.VendorName] = true
		}
	}
}

func outputPacketInfo(packet gopacket.Packet, result *geneve.ParseResult, config *Config) {
	timestamp := packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.000000")

	switch config.OutputFormat {
	case "json":
		outputJSON(timestamp, result)
	case "summary":
		outputSummary(timestamp, result)
	default:
		outputDetailed(timestamp, result, config)
	}
}

func outputDetailed(timestamp string, result *geneve.ParseResult, config *Config) {
	fmt.Printf("=== GENEVE Packet @ %s ===\n", timestamp)
	fmt.Printf("VNI: %d (0x%06x)\n", result.Header.VNI, result.Header.VNI)
	fmt.Printf("Protocol: %s (0x%04x)\n", result.Header.GetProtocolName(), result.Header.ProtocolType)
	fmt.Printf("Options: %d, Payload: %d bytes\n", len(result.Options), len(result.Payload))

	// Basic option information
	if len(result.Options) > 0 {
		fmt.Printf("\nGeneric Options:\n")
		for i, opt := range result.Options {
			fmt.Printf("  [%d] %s\n", i+1, opt.GetOptionDescription())
			fmt.Printf("      Class: %s, Type: %s, Critical: %t\n", 
				opt.GetOptionClassName(), opt.GetOptionTypeName(), opt.IsCritical())
		}
	}

	// INT telemetry
	if len(result.INTOptions) > 0 {
		fmt.Printf("\nINT Telemetry (%d options):\n", len(result.INTOptions))
		for i, intOpt := range result.INTOptions {
			fmt.Printf("  [%d] Version: %s, Flags: %s\n", 
				i+1, intOpt.GetVersionName(), intOpt.GetFlagsDescription())
			instructions := intOpt.GetINTInstructionNames()
			if len(instructions) > 0 {
				fmt.Printf("      Instructions: %v\n", instructions)
			}
		}
	}

	// VMware NSX telemetry
	if len(result.VMwareOptions) > 0 {
		fmt.Printf("\nVMware NSX Telemetry (%d options):\n", len(result.VMwareOptions))
		for i, vmware := range result.VMwareOptions {
			fmt.Printf("  [%d] VSID: %d, Policy: %d, TEP: 0x%08x\n", 
				i+1, vmware.VSID, vmware.PolicyID, vmware.SourceTEP)
			fmt.Printf("      Source VNI: %d, Flags: 0x%04x\n", 
				vmware.SourceVNI, vmware.Flags)
		}
	}

	// Cisco ACI telemetry
	if len(result.CiscoOptions) > 0 {
		fmt.Printf("\nCisco ACI Telemetry (%d options):\n", len(result.CiscoOptions))
		for i, cisco := range result.CiscoOptions {
			fmt.Printf("  [%d] EPG: %d, Tenant: %d, Contract: %d\n", 
				i+1, cisco.EPGID, cisco.TenantID, cisco.ContractID)
			fmt.Printf("      BD: %d, VRF: %d, App: %d\n", 
				cisco.BridgeDomain, cisco.VRF, cisco.ApplicationID)
		}
	}

	// Arista telemetry
	if len(result.AristaOptions) > 0 {
		fmt.Printf("\nArista TAP Telemetry (%d options):\n", len(result.AristaOptions))
		for i, arista := range result.AristaOptions {
			fmt.Printf("  [%d] Flow: 0x%08x, Ports: %d->%d\n", 
				i+1, arista.FlowID, arista.IngressPort, arista.EgressPort)
			fmt.Printf("      Timestamp: %d, Queue: %d, Latency: %d μs\n", 
				arista.Timestamp, arista.QueueDepth, arista.Latency)
		}
	}

	if len(result.AristaLatencyOptions) > 0 {
		fmt.Printf("\nArista Latency Telemetry (%d options):\n", len(result.AristaLatencyOptions))
		for i, lat := range result.AristaLatencyOptions {
			latencyNs := lat.EgressTS - lat.IngressTS
			fmt.Printf("  [%d] Flow Hash: 0x%08x, Latency: %d ns\n", 
				i+1, lat.FlowHash, latencyNs)
			fmt.Printf("      Ingress: %d, Egress: %d, Queue Wait: %d ns\n", 
				lat.IngressTS, lat.EgressTS, lat.QueueWaitTime)
		}
	}

	// Broadcom telemetry
	if len(result.BroadcomOptions) > 0 {
		fmt.Printf("\nBroadcom Switch Telemetry (%d options):\n", len(result.BroadcomOptions))
		for i, broadcom := range result.BroadcomOptions {
			fmt.Printf("  [%d] Switch: %d, Chip: %d, Pipeline: %d\n", 
				i+1, broadcom.SwitchID, broadcom.ChipID, broadcom.PipelineID)
			fmt.Printf("      Buffer: %.2f%%, Rate: %d pps / %.2f Gbps\n", 
				float64(broadcom.BufferUtil)/100.0, broadcom.PacketRate, float64(broadcom.ByteRate)*8/1e9)
			fmt.Printf("      Drops: %d, Errors: %d\n", 
				broadcom.DropCount, broadcom.ErrorCount)
		}
	}

	if len(result.BroadcomLatencyOptions) > 0 {
		fmt.Printf("\nBroadcom Latency Histogram (%d options):\n", len(result.BroadcomLatencyOptions))
		for i, hist := range result.BroadcomLatencyOptions {
			fmt.Printf("  [%d] Port: %d, Latency Range: %d-%d μs (avg: %d μs)\n", 
				i+1, hist.PortID, hist.MinLatency, hist.MaxLatency, hist.AvgLatency)
			fmt.Printf("      Buckets: 0-1μs:%d, 1-10μs:%d, 10-100μs:%d, 100μs-1ms:%d, 1-10ms:%d, >10ms:%d\n", 
				hist.Bucket0_1us, hist.Bucket1_10us, hist.Bucket10_100us, 
				hist.Bucket100us_1ms, hist.Bucket1ms_10ms, hist.BucketOver10ms)
		}
	}

	// Enterprise options (cloud vendors and new hardware vendors)
	if len(result.EnterpriseOptions) > 0 {
		fmt.Printf("\nEnterprise Options (%d decoded):\n", len(result.EnterpriseOptions))
		for i, enterprise := range result.EnterpriseOptions {
			fmt.Printf("  [%d] %s:", i+1, enterprise.VendorName)
			if enterprise.Decoded {
				fmt.Printf(" ✓ Decoded\n")
				if config.Verbose {
					data, _ := json.MarshalIndent(enterprise.DecodedData, "      ", "  ")
					fmt.Printf("      %s\n", string(data))
				}
			} else {
				fmt.Printf(" Raw data (%d bytes)\n", len(enterprise.Option.Data))
			}
		}
	}

	fmt.Printf("\n")
}

func outputSummary(timestamp string, result *geneve.ParseResult) {
	vendors := []string{}
	
	if len(result.VMwareOptions) > 0 {
		vendors = append(vendors, fmt.Sprintf("VMware(%d)", len(result.VMwareOptions)))
	}
	if len(result.CiscoOptions) > 0 {
		vendors = append(vendors, fmt.Sprintf("Cisco(%d)", len(result.CiscoOptions)))
	}
	if len(result.AristaOptions) > 0 || len(result.AristaLatencyOptions) > 0 {
		vendors = append(vendors, fmt.Sprintf("Arista(%d)", len(result.AristaOptions)+len(result.AristaLatencyOptions)))
	}
	if len(result.BroadcomOptions) > 0 || len(result.BroadcomLatencyOptions) > 0 {
		vendors = append(vendors, fmt.Sprintf("Broadcom(%d)", len(result.BroadcomOptions)+len(result.BroadcomLatencyOptions)))
	}

	// Count unique enterprise vendors
	vendorMap := make(map[string]int)
	for _, enterprise := range result.EnterpriseOptions {
		if enterprise.VendorName != "VMware" && enterprise.VendorName != "Cisco" {
			vendorMap[enterprise.VendorName]++
		}
	}
	for vendor, count := range vendorMap {
		vendors = append(vendors, fmt.Sprintf("%s(%d)", vendor, count))
	}

	vendorStr := "None"
	if len(vendors) > 0 {
		vendorStr = fmt.Sprintf("%v", vendors)
	}

	fmt.Printf("%s VNI:%d Proto:%s Opts:%d Vendors:%s\n", 
		timestamp, result.Header.VNI, result.Header.GetProtocolName(), 
		len(result.Options), vendorStr)
}

func outputJSON(timestamp string, result *geneve.ParseResult) {
	output := map[string]interface{}{
		"timestamp": timestamp,
		"header": map[string]interface{}{
			"vni":           result.Header.VNI,
			"protocol_type": result.Header.ProtocolType,
			"protocol_name": result.Header.GetProtocolName(),
			"options_count": len(result.Options),
		},
		"payload_size": len(result.Payload),
		"telemetry": map[string]interface{}{},
	}

	// Add vendor-specific telemetry
	telemetry := output["telemetry"].(map[string]interface{})

	if len(result.VMwareOptions) > 0 {
		vmwareData := make([]map[string]interface{}, len(result.VMwareOptions))
		for i, vmware := range result.VMwareOptions {
			vmwareData[i] = map[string]interface{}{
				"vsid":        vmware.VSID,
				"source_vni":  vmware.SourceVNI,
				"policy_id":   vmware.PolicyID,
				"source_tep":  vmware.SourceTEP,
				"flags":       vmware.Flags,
			}
		}
		telemetry["vmware"] = vmwareData
	}

	if len(result.CiscoOptions) > 0 {
		ciscoData := make([]map[string]interface{}, len(result.CiscoOptions))
		for i, cisco := range result.CiscoOptions {
			ciscoData[i] = map[string]interface{}{
				"epg_id":         cisco.EPGID,
				"tenant_id":      cisco.TenantID,
				"contract_id":    cisco.ContractID,
				"bridge_domain":  cisco.BridgeDomain,
				"vrf":            cisco.VRF,
				"application_id": cisco.ApplicationID,
				"flags":          cisco.Flags,
			}
		}
		telemetry["cisco"] = ciscoData
	}

	if len(result.AristaOptions) > 0 {
		aristaData := make([]map[string]interface{}, len(result.AristaOptions))
		for i, arista := range result.AristaOptions {
			aristaData[i] = map[string]interface{}{
				"flow_id":       arista.FlowID,
				"ingress_port":  arista.IngressPort,
				"egress_port":   arista.EgressPort,
				"timestamp":     arista.Timestamp,
				"packet_size":   arista.PacketSize,
				"flags":         arista.Flags,
				"queue_depth":   arista.QueueDepth,
				"latency":       arista.Latency,
			}
		}
		telemetry["arista_tap"] = aristaData
	}

	if len(result.AristaLatencyOptions) > 0 {
		aristaLatData := make([]map[string]interface{}, len(result.AristaLatencyOptions))
		for i, lat := range result.AristaLatencyOptions {
			aristaLatData[i] = map[string]interface{}{
				"flow_hash":       lat.FlowHash,
				"ingress_ts":      lat.IngressTS,
				"egress_ts":       lat.EgressTS,
				"latency_ns":      lat.EgressTS - lat.IngressTS,
				"queue_wait_time": lat.QueueWaitTime,
			}
		}
		telemetry["arista_latency"] = aristaLatData
	}

	if len(result.BroadcomOptions) > 0 {
		broadcomData := make([]map[string]interface{}, len(result.BroadcomOptions))
		for i, broadcom := range result.BroadcomOptions {
			broadcomData[i] = map[string]interface{}{
				"switch_id":     broadcom.SwitchID,
				"chip_id":       broadcom.ChipID,
				"pipeline_id":   broadcom.PipelineID,
				"buffer_util":   broadcom.BufferUtil,
				"packet_rate":   broadcom.PacketRate,
				"byte_rate":     broadcom.ByteRate,
				"drop_count":    broadcom.DropCount,
				"error_count":   broadcom.ErrorCount,
			}
		}
		telemetry["broadcom_switch"] = broadcomData
	}

	if len(result.BroadcomLatencyOptions) > 0 {
		broadcomLatData := make([]map[string]interface{}, len(result.BroadcomLatencyOptions))
		for i, hist := range result.BroadcomLatencyOptions {
			broadcomLatData[i] = map[string]interface{}{
				"port_id":          hist.PortID,
				"bucket_0_1us":     hist.Bucket0_1us,
				"bucket_1_10us":    hist.Bucket1_10us,
				"bucket_10_100us":  hist.Bucket10_100us,
				"bucket_100us_1ms": hist.Bucket100us_1ms,
				"bucket_1ms_10ms":  hist.Bucket1ms_10ms,
				"bucket_over_10ms": hist.BucketOver10ms,
				"max_latency":      hist.MaxLatency,
				"min_latency":      hist.MinLatency,
				"avg_latency":      hist.AvgLatency,
			}
		}
		telemetry["broadcom_latency"] = broadcomLatData
	}

	// Add enterprise options
	if len(result.EnterpriseOptions) > 0 {
		enterpriseData := make([]map[string]interface{}, 0)
		for _, enterprise := range result.EnterpriseOptions {
			item := map[string]interface{}{
				"vendor_name": enterprise.VendorName,
				"decoded":     enterprise.Decoded,
			}
			if enterprise.Decoded {
				item["data"] = enterprise.DecodedData
			}
			enterpriseData = append(enterpriseData, item)
		}
		telemetry["enterprise"] = enterpriseData
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Printf("Error marshaling JSON: %v", err)
		return
	}

	fmt.Println(string(jsonData))
}

func printFinalStats(stats *PacketStats) {
	duration := time.Since(stats.StartTime)
	
	fmt.Printf("\n=== Final Statistics ===\n")
	fmt.Printf("Capture Duration: %v\n", duration)
	fmt.Printf("Total Packets: %d\n", stats.TotalPackets)
	fmt.Printf("GENEVE Packets: %d\n", stats.GenevePackets)
	fmt.Printf("Successfully Parsed: %d\n", stats.ParsedPackets)
	fmt.Printf("Parse Errors: %d\n", stats.ErrorPackets)
	
	if stats.TotalPackets > 0 {
		fmt.Printf("GENEVE Rate: %.2f%%\n", 
			float64(stats.GenevePackets)*100/float64(stats.TotalPackets))
		fmt.Printf("Parse Success Rate: %.2f%%\n", 
			float64(stats.ParsedPackets)*100/float64(stats.GenevePackets))
	}
	
	if duration > 0 {
		fmt.Printf("Packet Rate: %.2f pps\n", 
			float64(stats.TotalPackets)/duration.Seconds())
	}

	if len(stats.VendorCounts) > 0 {
		fmt.Printf("\nVendor Telemetry Counts:\n")
		for vendor, count := range stats.VendorCounts {
			fmt.Printf("  %s: %d\n", vendor, count)
		}
	}
}