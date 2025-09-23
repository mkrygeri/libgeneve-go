package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mkrygeri/libgeneve-go/geneve"
)

// TelemetryRecord represents structured telemetry data for monitoring systems
type TelemetryRecord struct {
	Timestamp        time.Time              `json:"timestamp"`
	VNI              uint32                 `json:"vni"`
	Protocol         string                 `json:"protocol"`
	INTData          *INTTelemetry          `json:"int_data,omitempty"`
	EnterpriseData   []EnterpriseContext    `json:"enterprise_data,omitempty"`
	NetworkIssues    []string               `json:"network_issues,omitempty"`
	PolicyContext    map[string]interface{} `json:"policy_context,omitempty"`
}

type INTTelemetry struct {
	Version         string   `json:"version"`
	Domain          string   `json:"domain"`
	RemainingHops   uint8    `json:"remaining_hops"`
	Instructions    []string `json:"instructions"`
	HopDataLength   uint8    `json:"hop_data_length"`
	Flags           []string `json:"flags"`
	NetworkIssues   []string `json:"issues"`
}

type EnterpriseContext struct {
	Vendor      string                 `json:"vendor"`
	Class       string                 `json:"class"`
	Type        string                 `json:"type"`
	Decoded     bool                   `json:"decoded"`
	DecodedData map[string]interface{} `json:"decoded_data,omitempty"`
}

func main() {
	fmt.Println("=== GENEVE Telemetry Data Extraction for Monitoring Systems ===\n")
	
	parser := geneve.NewParser()
	
	// Process multiple packets and extract structured telemetry
	packets := [][]byte{
		createVMwareINTPacket(),
		createCiscoINTPacket(),
		createMultiVendorPacket(),
	}
	
	var telemetryRecords []TelemetryRecord
	
	for i, packetData := range packets {
		fmt.Printf("Processing Packet %d...\n", i+1)
		
		result, err := parser.ParsePacket(packetData)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			continue
		}
		
		record := extractTelemetryData(result)
		telemetryRecords = append(telemetryRecords, record)
		
		// Display human-readable summary
		displayTelemetrySummary(i+1, &record)
	}
	
	// Output JSON for monitoring system integration
	fmt.Println("\n=== JSON Output for Monitoring Systems ===")
	for i, record := range telemetryRecords {
		fmt.Printf("\nPacket %d JSON:\n", i+1)
		jsonData, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling JSON: %v\n", err)
			continue
		}
		fmt.Println(string(jsonData))
	}
	
	// Generate monitoring alerts
	fmt.Println("\n=== Monitoring Alerts ===")
	generateMonitoringAlerts(telemetryRecords)
}

func extractTelemetryData(result *geneve.ParseResult) TelemetryRecord {
	record := TelemetryRecord{
		Timestamp:      time.Now(),
		VNI:            result.Header.VNI,
		Protocol:       result.Header.GetProtocolName(),
		NetworkIssues:  []string{},
		PolicyContext:  make(map[string]interface{}),
	}
	
	// Extract INT telemetry
	if len(result.INTOptions) > 0 {
		intOpt := result.INTOptions[0]
		flags := []string{}
		issues := []string{}
		
		if intOpt.Discard {
			flags = append(flags, "DISCARD")
			issues = append(issues, "Packet marked for discard")
		}
		if intOpt.MTUExceeded {
			flags = append(flags, "MTU_EXCEEDED")
			issues = append(issues, "MTU exceeded")
		}
		if intOpt.ExceededMaxHops {
			flags = append(flags, "MAX_HOPS_EXCEEDED")
			issues = append(issues, "Maximum hops exceeded")
		}
		
		record.INTData = &INTTelemetry{
			Version:         intOpt.GetVersionName(),
			Domain:          fmt.Sprintf("0x%04x", intOpt.DomainSpecificID),
			RemainingHops:   intOpt.RemainingHopCount,
			Instructions:    intOpt.GetINTInstructionNames(),
			HopDataLength:   intOpt.HopML,
			Flags:           flags,
			NetworkIssues:   issues,
		}
		record.NetworkIssues = append(record.NetworkIssues, issues...)
	}
	
	// Extract enterprise context
	for _, ent := range result.EnterpriseOptions {
		context := EnterpriseContext{
			Vendor:      ent.VendorName,
			Class:       ent.GetOptionClassName(),
			Type:        ent.GetOptionTypeName(),
			Decoded:     ent.Decoded,
			DecodedData: ent.DecodedData,
		}
		record.EnterpriseData = append(record.EnterpriseData, context)
		
		// Add to policy context
		if ent.Decoded {
			for k, v := range ent.DecodedData {
				record.PolicyContext[fmt.Sprintf("%s_%s", ent.VendorName, k)] = v
			}
		}
	}
	
	// Extract VMware NSX context
	for _, vmw := range result.VMwareOptions {
		record.PolicyContext["vmware_vsid"] = fmt.Sprintf("0x%08x", vmw.VSID)
		record.PolicyContext["vmware_source_vni"] = fmt.Sprintf("0x%08x", vmw.SourceVNI)
		record.PolicyContext["vmware_policy_id"] = fmt.Sprintf("0x%04x", vmw.PolicyID)
		record.PolicyContext["vmware_flags"] = fmt.Sprintf("0x%04x", vmw.Flags)
	}
	
	// Extract Cisco ACI context
	for _, cisco := range result.CiscoOptions {
		record.PolicyContext["cisco_epg_id"] = fmt.Sprintf("0x%04x", cisco.EPGID)
		record.PolicyContext["cisco_bridge_domain"] = fmt.Sprintf("0x%04x", cisco.BridgeDomain)
		record.PolicyContext["cisco_vrf"] = fmt.Sprintf("0x%04x", cisco.VRF)
		record.PolicyContext["cisco_contract_id"] = fmt.Sprintf("0x%04x", cisco.ContractID)
		record.PolicyContext["cisco_tenant_id"] = fmt.Sprintf("0x%04x", cisco.TenantID)
	}
	
	return record
}

func displayTelemetrySummary(packetNum int, record *TelemetryRecord) {
	fmt.Printf("  Packet %d Summary:\n", packetNum)
	fmt.Printf("    VNI: 0x%06x (%s)\n", record.VNI, record.Protocol)
	
	if record.INTData != nil {
		fmt.Printf("    INT: %s, Domain: %s, Hops: %d\n", 
			record.INTData.Version, record.INTData.Domain, record.INTData.RemainingHops)
		if len(record.INTData.NetworkIssues) > 0 {
			fmt.Printf("    ⚠️  Issues: %v\n", record.INTData.NetworkIssues)
		}
	}
	
	if len(record.EnterpriseData) > 0 {
		fmt.Printf("    Enterprise: %d vendors detected\n", len(record.EnterpriseData))
		for _, ent := range record.EnterpriseData {
			fmt.Printf("      - %s (%s)\n", ent.Vendor, ent.Type)
		}
	}
	fmt.Println()
}

func generateMonitoringAlerts(records []TelemetryRecord) {
	alerts := []string{}
	
	for i, record := range records {
		packetID := fmt.Sprintf("Packet_%d", i+1)
		
		// Check for network issues
		if len(record.NetworkIssues) > 0 {
			for _, issue := range record.NetworkIssues {
				alerts = append(alerts, fmt.Sprintf("NETWORK_ISSUE: %s - %s", packetID, issue))
			}
		}
		
		// Check for high hop count
		if record.INTData != nil && record.INTData.RemainingHops > 10 {
			alerts = append(alerts, fmt.Sprintf("HIGH_LATENCY: %s - High hop count: %d", 
				packetID, record.INTData.RemainingHops))
		}
		
		// Check for policy violations (example logic)
		if vmwareVSID, exists := record.PolicyContext["vmware_vsid"]; exists {
			if vmwareVSID == "0x11111111" {
				alerts = append(alerts, fmt.Sprintf("SECURITY_POLICY: %s - Suspicious VMware VSID detected", packetID))
			}
		}
		
		// Check for enterprise context availability
		if len(record.EnterpriseData) == 0 && record.INTData != nil {
			alerts = append(alerts, fmt.Sprintf("MISSING_CONTEXT: %s - INT telemetry without enterprise context", packetID))
		}
	}
	
	if len(alerts) == 0 {
		fmt.Println("✅ No alerts generated - All telemetry data looks normal")
	} else {
		fmt.Printf("⚠️  Generated %d monitoring alerts:\n", len(alerts))
		for _, alert := range alerts {
			fmt.Printf("  - %s\n", alert)
		}
	}
	
	fmt.Printf("\n📊 Telemetry Summary:\n")
	fmt.Printf("  Total packets processed: %d\n", len(records))
	intCount := 0
	enterpriseCount := 0
	for _, record := range records {
		if record.INTData != nil {
			intCount++
		}
		enterpriseCount += len(record.EnterpriseData)
	}
	fmt.Printf("  Packets with INT data: %d\n", intCount)
	fmt.Printf("  Total enterprise options: %d\n", enterpriseCount)
	fmt.Printf("  Total alerts: %d\n", len(alerts))
}

func createVMwareINTPacket() []byte {
	// 48-byte packet with INT + VMware NSX
	packet := make([]byte, 48)
	packet[0] = 0x0A // Option length 10 (40 bytes)
	packet[1] = 0x00
	binary.BigEndian.PutUint16(packet[2:4], geneve.ProtocolTypeEthernet)
	binary.BigEndian.PutUint32(packet[4:8], 0xAABBCC)
	
	// INT option (16 bytes)
	binary.BigEndian.PutUint16(packet[8:10], geneve.OptionClassINT)
	packet[10] = geneve.INTTypeMetadata
	packet[11] = 0x03 // 12 bytes of data
	packet[12] = 0x42 // Version 4, Discard=true
	packet[13] = 0x05 // Hop ML 5
	packet[14] = 0x08 // Remaining hops 8
	packet[15] = 0x00
	binary.BigEndian.PutUint16(packet[16:18], 0x1000) // VMware domain
	binary.BigEndian.PutUint16(packet[18:20], 0x1234)
	binary.BigEndian.PutUint32(packet[20:24], 0x56789ABC)
	
	// VMware NSX option (24 bytes)
	binary.BigEndian.PutUint16(packet[24:26], geneve.OptionClassVMware)
	packet[26] = geneve.VMwareTypeNSXMetadata
	packet[27] = 0x05 // 20 bytes of data
	binary.BigEndian.PutUint32(packet[28:32], 0x11111111) // VSID
	binary.BigEndian.PutUint32(packet[32:36], 0x22222222) // Source VNI
	binary.BigEndian.PutUint16(packet[36:38], 0x3333)     // Flags
	binary.BigEndian.PutUint16(packet[38:40], 0x4444)     // Policy ID
	binary.BigEndian.PutUint32(packet[40:44], 0x55555555) // Source TEP
	binary.BigEndian.PutUint32(packet[44:48], 0x00000000) // Reserved
	
	return packet
}

func createCiscoINTPacket() []byte {
	// 48-byte packet with INT + Cisco ACI
	packet := make([]byte, 48)
	packet[0] = 0x0A // Option length 10 (40 bytes)
	packet[1] = 0x00
	binary.BigEndian.PutUint16(packet[2:4], geneve.ProtocolTypeIPv4)
	binary.BigEndian.PutUint32(packet[4:8], 0xDDEEFF)
	
	// INT option (16 bytes)
	binary.BigEndian.PutUint16(packet[8:10], geneve.OptionClassINT)
	packet[10] = geneve.INTTypeMetadata
	packet[11] = 0x03 // 12 bytes of data
	packet[12] = 0x20 // Version 2, MTU exceeded
	packet[13] = 0x03 // Hop ML 3
	packet[14] = 0x12 // Remaining hops 18 (high latency path)
	packet[15] = 0x00
	binary.BigEndian.PutUint16(packet[16:18], 0x2000) // Cisco domain
	binary.BigEndian.PutUint16(packet[18:20], 0x5678)
	binary.BigEndian.PutUint32(packet[20:24], 0x9ABCDEF0)
	
	// Cisco ACI option (24 bytes)
	binary.BigEndian.PutUint16(packet[24:26], geneve.OptionClassCisco)
	packet[26] = geneve.CiscoTypeACI
	packet[27] = 0x05 // 20 bytes of data
	binary.BigEndian.PutUint32(packet[28:32], 0x10012002) // EPG + BD
	binary.BigEndian.PutUint32(packet[32:36], 0x30034004) // VRF + Contract
	binary.BigEndian.PutUint32(packet[36:40], 0x80000001) // Flags
	binary.BigEndian.PutUint32(packet[40:44], 0x60067007) // Tenant + App
	binary.BigEndian.PutUint32(packet[44:48], 0x00000000) // Padding
	
	return packet
}

func createMultiVendorPacket() []byte {
	// 40-byte packet with Microsoft option only (no INT)
	packet := make([]byte, 40)
	packet[0] = 0x08 // Option length 8 (32 bytes)
	packet[1] = 0x00
	binary.BigEndian.PutUint16(packet[2:4], geneve.ProtocolTypeIPv6)
	binary.BigEndian.PutUint32(packet[4:8], 0x123ABC)
	
	// Microsoft option (16 bytes)
	binary.BigEndian.PutUint16(packet[8:10], geneve.OptionClassMicrosoft)
	packet[10] = geneve.MicrosoftTypeHyperV
	packet[11] = 0x03 // 12 bytes of data
	binary.BigEndian.PutUint64(packet[12:20], 0x123456789ABCDEF0)
	binary.BigEndian.PutUint32(packet[20:24], 0x12345678)
	
	// Linux Generic option (16 bytes)
	binary.BigEndian.PutUint16(packet[24:26], geneve.OptionClassLinuxGeneric)
	packet[26] = geneve.GenericTypeTimestamp
	packet[27] = 0x03 // 12 bytes of data
	binary.BigEndian.PutUint64(packet[28:36], 0xDEADBEEFCAFEBABE)
	binary.BigEndian.PutUint32(packet[36:40], 0xABCDEF00)
	
	return packet
}