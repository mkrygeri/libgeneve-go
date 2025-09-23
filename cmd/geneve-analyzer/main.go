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
}

type PacketStats struct {
	TotalPackets    int
	GenevePackets   int
	ParsedPackets   int
	ErrorPackets    int
	VendorCounts    map[string]int
	StartTime       time.Time
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

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "GENEVE Telemetry Analyzer\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -interface eth0\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -pcap-file capture.pcap -enterprise\n", os.Args[0])
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

		// Create packet from data
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		packet.Metadata().Timestamp = ci.Timestamp
		packet.Metadata().CaptureLength = ci.CaptureLength
		packet.Metadata().Length = ci.Length

		processPacket(packet, parser, config, stats)

		if config.Count > 0 && stats.TotalPackets >= config.Count {
			break
		}
	}
}

func processPacket(packet gopacket.Packet, parser *geneve.Parser, config *Config, stats *PacketStats) {
	stats.TotalPackets++

	// Look for UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp, _ := udpLayer.(*layers.UDP)
	
	// Check if it's GENEVE traffic (typically port 6081)
	if uint16(udp.DstPort) != genevePort && uint16(udp.SrcPort) != genevePort {
		return
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

	// Enterprise options (cloud vendors)
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