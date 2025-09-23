package main

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/mkrygeri/libgeneve-go/geneve"
)

func main() {
	fmt.Println("=== GENEVE In-Band Telemetry (INT) Enterprise Example ===\n")
	
	parser := geneve.NewParser()
	
	// Demo 1: Standard INT with Enterprise Extensions
	fmt.Println("Demo 1: Standard INT Metadata with VMware NSX Context")
	fmt.Println("=" + strings.Repeat("=", 60))
	intWithVMwarePacket := createINTWithVMwarePacket()
	result1, err := parser.ParsePacket(intWithVMwarePacket)
	if err != nil {
		fmt.Printf("Error parsing packet: %v\n", err)
		return
	}
	
	fmt.Printf("Header: %s\n", result1.Header.String())
	fmt.Printf("Regular Options: %d, INT Options: %d, Enterprise Options: %d\n\n",
		len(result1.Options), len(result1.INTOptions), len(result1.EnterpriseOptions))
	
	// Display INT telemetry
	if len(result1.INTOptions) > 0 {
		intOpt := result1.INTOptions[0]
		fmt.Printf("📊 INT Telemetry Data:\n")
		fmt.Printf("  Version: %s\n", intOpt.GetVersionName())
		fmt.Printf("  Hop Count: %d remaining\n", intOpt.RemainingHopCount)
		fmt.Printf("  Domain: 0x%04x\n", intOpt.DomainSpecificID)
		fmt.Printf("  Flags: %s\n", intOpt.GetFlagsDescription())
		fmt.Printf("  Instructions: %s\n", strings.Join(intOpt.GetINTInstructionNames(), ", "))
		fmt.Printf("  Hop Data Length: %d words\n", intOpt.HopML)
		fmt.Printf("  String: %s\n\n", intOpt.String())
	}
	
	// Display enterprise context
	if len(result1.EnterpriseOptions) > 0 {
		ent := result1.EnterpriseOptions[0]
		fmt.Printf("🏢 Enterprise Context (VMware NSX):\n")
		fmt.Printf("  Vendor: %s\n", ent.VendorName)
		fmt.Printf("  Decoded: %t\n", ent.Decoded)
		if ent.Decoded {
			fmt.Printf("  NSX Context:\n")
			for k, v := range ent.DecodedData {
				fmt.Printf("    %s: %v\n", k, v)
			}
		}
		fmt.Printf("  String: %s\n\n", ent.String())
	}
	
	// Demo 2: Multi-vendor INT with Cisco ACI
	fmt.Println("Demo 2: INT Metadata with Cisco ACI Policy Context")
	fmt.Println("=" + strings.Repeat("=", 60))
	intWithCiscoPacket := createINTWithCiscoPacket()
	result2, err := parser.ParsePacket(intWithCiscoPacket)
	if err != nil {
		fmt.Printf("Error parsing packet: %v\n", err)
		return
	}
	
	fmt.Printf("Header: %s\n", result2.Header.String())
	fmt.Printf("Regular Options: %d, INT Options: %d, Enterprise Options: %d, Cisco Options: %d\n\n",
		len(result2.Options), len(result2.INTOptions), len(result2.EnterpriseOptions), len(result2.CiscoOptions))
	
	// Display INT telemetry
	if len(result2.INTOptions) > 0 {
		intOpt := result2.INTOptions[0]
		fmt.Printf("📊 INT Telemetry Data:\n")
		fmt.Printf("  Version: %s\n", intOpt.GetVersionName())
		fmt.Printf("  Domain: 0x%04x (Cisco ACI Fabric)\n", intOpt.DomainSpecificID)
		fmt.Printf("  Instructions: %s\n", strings.Join(intOpt.GetINTInstructionNames(), ", "))
		fmt.Printf("  Hop Latency Tracked: %t\n", (intOpt.DomainInstruction&0x0400) != 0)
		fmt.Printf("  Queue Occupancy Tracked: %t\n", (intOpt.DomainInstruction&0x0200) != 0)
		fmt.Printf("  String: %s\n\n", intOpt.String())
	}
	
	// Display Cisco ACI policy context
	if len(result2.CiscoOptions) > 0 {
		cisco := result2.CiscoOptions[0]
		fmt.Printf("🏢 Enterprise Policy Context (Cisco ACI):\n")
		fmt.Printf("  EPG ID: 0x%04x (Security Group)\n", cisco.EPGID)
		fmt.Printf("  Bridge Domain: 0x%04x (L2 Segment)\n", cisco.BridgeDomain)
		fmt.Printf("  VRF: 0x%04x (L3 Context)\n", cisco.VRF)
		fmt.Printf("  Contract ID: 0x%04x (Policy Rules)\n", cisco.ContractID)
		fmt.Printf("  Tenant: 0x%04x, Application: 0x%04x\n", cisco.TenantID, cisco.ApplicationID)
		fmt.Printf("  Policy Flags: 0x%08x\n", cisco.Flags)
		fmt.Printf("  String: %s\n\n", cisco.String())
	}
	
	// Demo 3: Custom Enterprise INT Decoder
	fmt.Println("Demo 3: Custom Enterprise INT Telemetry Extension")
	fmt.Println("=" + strings.Repeat("=", 60))
	
	// Register a custom decoder for enterprise INT extensions
	customINTClass := uint16(0x2000)
	parser.RegisterEnterpriseDecoder(customINTClass, func(data []byte) {
		if len(data) >= 16 {
			switchID := binary.BigEndian.Uint32(data[0:4])
			ingressPort := binary.BigEndian.Uint32(data[4:8])
			egressPort := binary.BigEndian.Uint32(data[8:12])
			latency := binary.BigEndian.Uint32(data[12:16])
			
			fmt.Printf("  🔧 Custom INT Decoder Results:\n")
			fmt.Printf("    Switch ID: 0x%08x\n", switchID)
			fmt.Printf("    Ingress Port: %d\n", ingressPort)
			fmt.Printf("    Egress Port: %d\n", egressPort)
			fmt.Printf("    Hop Latency: %d microseconds\n", latency)
		}
	})
	
	customINTPacket := createCustomINTPacket()
	result3, err := parser.ParsePacket(customINTPacket)
	if err != nil {
		fmt.Printf("Error parsing packet: %v\n", err)
		return
	}
	
	fmt.Printf("Header: %s\n", result3.Header.String())
	fmt.Printf("Regular Options: %d, INT Options: %d, Enterprise Options: %d\n\n",
		len(result3.Options), len(result3.INTOptions), len(result3.EnterpriseOptions))
	
	// Display standard INT
	if len(result3.INTOptions) > 0 {
		intOpt := result3.INTOptions[0]
		fmt.Printf("📊 Standard INT Telemetry:\n")
		fmt.Printf("  Version: %s\n", intOpt.GetVersionName())
		fmt.Printf("  Instructions: %s\n", strings.Join(intOpt.GetINTInstructionNames(), ", "))
		fmt.Printf("  String: %s\n\n", intOpt.String())
	}
	
	// Display custom enterprise INT
	if len(result3.EnterpriseOptions) > 0 {
		ent := result3.EnterpriseOptions[0]
		fmt.Printf("🏢 Custom Enterprise INT Extension:\n")
		fmt.Printf("  Vendor: %s\n", ent.VendorName)
		fmt.Printf("  Decoded: %t\n", ent.Decoded)
		fmt.Printf("  String: %s\n\n", ent.String())
	}
	
	// Demo 4: Telemetry Analysis and Recommendations
	fmt.Println("Demo 4: Telemetry Analysis & Network Insights")
	fmt.Println("=" + strings.Repeat("=", 60))
	
	analyzeTelemetry(result1, result2, result3)
	
	fmt.Println("=" + strings.Repeat("=", 70))
	fmt.Println("🎯 In-Band Telemetry Enterprise Integration Complete!")
	fmt.Println("✅ INT metadata extracted with enterprise context correlation")
	fmt.Println("✅ Multi-vendor policy contexts decoded and analyzed")
	fmt.Println("✅ Custom enterprise INT extensions demonstrated")
	fmt.Println("=" + strings.Repeat("=", 70))
}

func createINTWithVMwarePacket() []byte {
	// Packet with both INT and VMware NSX options (64 bytes)
	packet := make([]byte, 64)
	packet[0] = 0x0E // Version 0, Option length 14 (56 bytes of options)
	packet[1] = 0x00 // No flags
	binary.BigEndian.PutUint16(packet[2:4], geneve.ProtocolTypeEthernet)
	binary.BigEndian.PutUint32(packet[4:8], 0x123456) // VNI
	
	// INT Metadata option (20 bytes)
	binary.BigEndian.PutUint16(packet[8:10], geneve.OptionClassINT)
	packet[10] = geneve.INTTypeMetadata
	packet[11] = 0x04 // 16 bytes of data
	
	// INT metadata
	packet[12] = 0x42 // Version 4, Discard=true, No MTU exceeded, Max hops exceeded=false
	packet[13] = 0x08 // Hop metadata length 8
	packet[14] = 0x10 // Remaining hops 16
	packet[15] = 0x00 // Reserved
	binary.BigEndian.PutUint16(packet[16:18], 0x1000) // Domain ID (VMware domain)
	binary.BigEndian.PutUint16(packet[18:20], 0x5678) // Domain instruction
	binary.BigEndian.PutUint16(packet[20:22], 0x9ABC) // Domain flags
	binary.BigEndian.PutUint16(packet[22:24], 0x0000) // Reserved
	binary.BigEndian.PutUint32(packet[24:28], 0x12345678) // Hop data
	
	// VMware NSX option (24 bytes)
	binary.BigEndian.PutUint16(packet[28:30], geneve.OptionClassVMware)
	packet[30] = geneve.VMwareTypeNSXMetadata
	packet[31] = 0x05 // 20 bytes of data
	
	// NSX metadata
	binary.BigEndian.PutUint32(packet[32:36], 0x11111111) // VSID
	binary.BigEndian.PutUint32(packet[36:40], 0x22222222) // Source VNI
	binary.BigEndian.PutUint16(packet[40:42], 0x3333)     // Flags
	binary.BigEndian.PutUint16(packet[42:44], 0x4444)     // Policy ID
	binary.BigEndian.PutUint32(packet[44:48], 0x55555555) // Source TEP
	binary.BigEndian.PutUint32(packet[48:52], 0x00000000) // Reserved
	
	// Security tag option (12 bytes)
	binary.BigEndian.PutUint16(packet[52:54], geneve.OptionClassLinuxGeneric)
	packet[54] = geneve.GenericTypeSecurityTag
	packet[55] = 0x02 // 8 bytes of data
	binary.BigEndian.PutUint64(packet[56:64], 0x1234567890ABCDEF) // Security tag data
	
	return packet
}

func createINTWithCiscoPacket() []byte {
	// Packet with both INT and Cisco ACI options (64 bytes)
	packet := make([]byte, 64)
	packet[0] = 0x0E // Version 0, Option length 14 (56 bytes of options)
	packet[1] = 0x00 // No flags
	binary.BigEndian.PutUint16(packet[2:4], geneve.ProtocolTypeIPv4)
	binary.BigEndian.PutUint32(packet[4:8], 0xABC123) // VNI
	
	// INT Metadata option (20 bytes)
	binary.BigEndian.PutUint16(packet[8:10], geneve.OptionClassINT)
	packet[10] = geneve.INTTypeMetadata
	packet[11] = 0x04 // 16 bytes of data
	
	// INT metadata with Cisco ACI fabric context
	packet[12] = 0x42 // Version 4, flags
	packet[13] = 0x06 // Hop metadata length 6
	packet[14] = 0x08 // Remaining hops 8
	packet[15] = 0x00 // Reserved
	binary.BigEndian.PutUint16(packet[16:18], 0x2000) // Domain ID (Cisco ACI fabric)
	binary.BigEndian.PutUint16(packet[18:20], 0x0600) // Domain instruction (latency + queue)
	binary.BigEndian.PutUint16(packet[20:22], 0xACDC) // Domain flags (ACI specific)
	binary.BigEndian.PutUint16(packet[22:24], 0x0000) // Reserved
	binary.BigEndian.PutUint32(packet[24:28], 0xFABDEF00) // Hop data
	
	// Cisco ACI option (24 bytes)
	binary.BigEndian.PutUint16(packet[28:30], geneve.OptionClassCisco)
	packet[30] = geneve.CiscoTypeACI
	packet[31] = 0x05 // 20 bytes of data
	
	// ACI policy metadata
	binary.BigEndian.PutUint16(packet[32:34], 0x1001) // EPG ID (web tier)
	binary.BigEndian.PutUint16(packet[34:36], 0x2002) // Bridge Domain (BD-WEB)
	binary.BigEndian.PutUint16(packet[36:38], 0x3003) // VRF (VRF-PROD)
	binary.BigEndian.PutUint16(packet[38:40], 0x4004) // Contract ID (web-to-app)
	binary.BigEndian.PutUint32(packet[40:44], 0x80000001) // Flags (policy enforced)
	binary.BigEndian.PutUint16(packet[44:46], 0x6006) // Tenant ID (PROD-TENANT)
	binary.BigEndian.PutUint16(packet[46:48], 0x7007) // Application ID (WEB-APP)
	binary.BigEndian.PutUint32(packet[48:52], 0x00000000) // Padding
	
	// Quality of Service option (12 bytes)
	binary.BigEndian.PutUint16(packet[52:54], geneve.OptionClassLinuxGeneric)
	packet[54] = geneve.GenericTypeQoSMarking
	packet[55] = 0x02 // 8 bytes of data
	binary.BigEndian.PutUint32(packet[56:60], 0x12345678) // QoS data
	binary.BigEndian.PutUint32(packet[60:64], 0x9ABCDEF0) // More QoS data
	
	return packet
}

func createCustomINTPacket() []byte {
	// Packet with standard INT and custom enterprise INT extension (56 bytes)
	packet := make([]byte, 56)
	packet[0] = 0x0C // Version 0, Option length 12 (48 bytes of options)
	packet[1] = 0x00 // No flags
	binary.BigEndian.PutUint16(packet[2:4], geneve.ProtocolTypeIPv6)
	binary.BigEndian.PutUint32(packet[4:8], 0x999999) // VNI
	
	// Standard INT Metadata option (16 bytes)
	binary.BigEndian.PutUint16(packet[8:10], geneve.OptionClassINT)
	packet[10] = geneve.INTTypeMetadata
	packet[11] = 0x03 // 12 bytes of data
	
	// INT metadata
	packet[12] = 0x42 // Version 4, flags
	packet[13] = 0x04 // Hop metadata length 4
	packet[14] = 0x05 // Remaining hops 5
	packet[15] = 0x00 // Reserved
	binary.BigEndian.PutUint16(packet[16:18], 0x3000) // Domain ID
	binary.BigEndian.PutUint16(packet[18:20], 0x1234) // Domain instruction
	binary.BigEndian.PutUint32(packet[20:24], 0xDEADBEEF) // Domain flags + reserved
	
	// Custom Enterprise INT Extension (32 bytes)
	binary.BigEndian.PutUint16(packet[24:26], 0x2000) // Custom enterprise class
	packet[26] = 0x01 // Type
	packet[27] = 0x07 // 28 bytes of data
	
	// Custom INT telemetry data (28 bytes)
	binary.BigEndian.PutUint32(packet[28:32], 0x01020304) // Switch ID
	binary.BigEndian.PutUint32(packet[32:36], 0x00000010) // Ingress port 16
	binary.BigEndian.PutUint32(packet[36:40], 0x00000020) // Egress port 32
	binary.BigEndian.PutUint32(packet[40:44], 0x000003E8) // Latency 1000 microseconds
	binary.BigEndian.PutUint32(packet[44:48], 0x12345678) // Queue depth
	binary.BigEndian.PutUint32(packet[48:52], 0x87654321) // Bandwidth utilization
	binary.BigEndian.PutUint32(packet[52:56], 0xABCDEF00) // Custom metrics
	
	return packet
}

func analyzeTelemetry(results ...*geneve.ParseResult) {
	fmt.Printf("📈 Cross-Vendor Telemetry Analysis:\n\n")
	
	totalINTOptions := 0
	totalEnterpriseOptions := 0
	vendors := make(map[string]int)
	domains := make(map[uint16]string)
	
	for i, result := range results {
		fmt.Printf("Packet %d Analysis:\n", i+1)
		
		// Count INT options
		totalINTOptions += len(result.INTOptions)
		totalEnterpriseOptions += len(result.EnterpriseOptions)
		
		// Track vendors
		for _, ent := range result.EnterpriseOptions {
			vendors[ent.VendorName]++
		}
		
		// Track domains
		for _, intOpt := range result.INTOptions {
			switch intOpt.DomainSpecificID {
			case 0x1000:
				domains[intOpt.DomainSpecificID] = "VMware vSphere"
			case 0x2000:
				domains[intOpt.DomainSpecificID] = "Cisco ACI Fabric"
			case 0x3000:
				domains[intOpt.DomainSpecificID] = "Custom Network Domain"
			default:
				domains[intOpt.DomainSpecificID] = fmt.Sprintf("Domain 0x%04x", intOpt.DomainSpecificID)
			}
		}
		
		// Analyze telemetry quality
		if len(result.INTOptions) > 0 {
			intOpt := result.INTOptions[0]
			quality := "Good"
			if intOpt.RemainingHopCount < 5 {
				quality = "Excellent (Low latency path)"
			} else if intOpt.RemainingHopCount > 15 {
				quality = "Warning (High hop count)"
			}
			fmt.Printf("  📊 Telemetry Quality: %s\n", quality)
			
			// Check for network issues
			if intOpt.Discard {
				fmt.Printf("  ⚠️  Network Issue: Packet marked for discard\n")
			}
			if intOpt.MTUExceeded {
				fmt.Printf("  ⚠️  Network Issue: MTU exceeded detected\n")
			}
		}
		
		// Enterprise context insights
		for _, ent := range result.EnterpriseOptions {
			if ent.VendorName == "VMware Inc." && ent.Decoded {
				fmt.Printf("  🏢 VMware Context: NSX microsegmentation active\n")
			} else if ent.VendorName == "Cisco Systems Inc." && ent.Decoded {
				fmt.Printf("  🏢 Cisco Context: ACI policy enforcement active\n")
			}
		}
		fmt.Println()
	}
	
	// Summary statistics
	fmt.Printf("📊 Summary Statistics:\n")
	fmt.Printf("  Total INT Options: %d\n", totalINTOptions)
	fmt.Printf("  Total Enterprise Options: %d\n", totalEnterpriseOptions)
	fmt.Printf("  Vendor Distribution:\n")
	for vendor, count := range vendors {
		fmt.Printf("    %s: %d options\n", vendor, count)
	}
	fmt.Printf("  Domain Distribution:\n")
	for domainID, domainName := range domains {
		fmt.Printf("    0x%04x (%s): Active\n", domainID, domainName)
	}
	
	// Recommendations
	fmt.Printf("\n🎯 Network Recommendations:\n")
	if totalINTOptions > 0 && totalEnterpriseOptions > 0 {
		fmt.Printf("  ✅ Excellent: Multi-vendor telemetry correlation enabled\n")
		fmt.Printf("  ✅ Policy context available for enhanced troubleshooting\n")
		fmt.Printf("  💡 Consider: Centralized telemetry aggregation for cross-domain insights\n")
	}
	if len(domains) > 1 {
		fmt.Printf("  🔄 Multi-domain environment detected - enable cross-domain correlation\n")
	}
}