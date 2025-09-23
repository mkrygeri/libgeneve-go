// Enhanced demo showing human-friendly GENEVE parsing with enumerations
package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mkrygeri/libgeneve-go/geneve"
)

func main() {
	fmt.Println("=== Enhanced GENEVE Parser with Human-Friendly Output ===")
	fmt.Println()

	// Demo 1: Various option types with descriptive names
	fmt.Println("Demo 1: Option Types and Descriptions")
	fmt.Println(strings.Repeat("=", 50))
	demoOptionTypes()

	// Demo 2: INT metadata with detailed analysis  
	fmt.Println("\nDemo 2: INT Metadata Analysis")
	fmt.Println(strings.Repeat("=", 50))
	demoINTAnalysis()

	// Demo 3: Complex packet with multiple option types
	fmt.Println("\nDemo 3: Multi-Vendor Options Packet")
	fmt.Println(strings.Repeat("=", 50))
	demoMultiVendorOptions()

	// Demo 4: OAM packet analysis
	fmt.Println("\nDemo 4: OAM Packet Analysis")
	fmt.Println(strings.Repeat("=", 50))
	demoOAMPacket()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("All demos completed - Human-friendly parsing active!")
	fmt.Println(strings.Repeat("=", 60))
}

func demoOptionTypes() {
	parser := geneve.NewParser()

	// Create packet with various option types
	packet := geneve.NewPacketBuilder().
		SetVNI(0x123456).
		SetProtocolType(geneve.ProtocolTypeIPv4).
		AddOption(0x0001, geneve.GenericTypeTimestamp, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}). // Linux Generic - Timestamp
		AddOption(0x0002, 0x01, []byte{0xAA, 0xBB}). // Open vSwitch
		AddOption(0x0003, 0x02, []byte{0xCC, 0xDD, 0xEE, 0xFF}). // VMware
		SetPayload([]byte("Multi-option payload")).
		Build()

	result, err := parser.ParsePacket(packet)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	fmt.Printf("Packet: %s\n", result.Header.String())
	fmt.Printf("Options found: %d\n\n", len(result.Options))

	for i, opt := range result.Options {
		fmt.Printf("Option %d:\n", i+1)
		fmt.Printf("  Description: %s\n", opt.GetOptionDescription())
		fmt.Printf("  Details: %s\n", opt.String())
		fmt.Printf("  Critical: %t\n", opt.IsCritical())
		fmt.Printf("  Data: %s\n", hex.EncodeToString(opt.Data))
		fmt.Println()
	}
}

func demoINTAnalysis() {
	parser := geneve.NewParser()

	// Create INT metadata option with comprehensive telemetry
	intOpt := geneve.INTMetadataOption{
		Version:            4,
		Discard:            true,
		ExceededMaxHops:    false,
		MTUExceeded:        true,
		HopML:             8,
		RemainingHopCount:  12,
		InstructionBitmap:  geneve.INTInstrSwitchID | geneve.INTInstrIngressPort | geneve.INTInstrHopLatency | geneve.INTInstrQueueOccupancy | geneve.INTInstrIngressTimestamp,
		DomainSpecificID:   0x1234,
		DomainInstruction:  0x5678,
		DomainFlags:        0x9ABC,
	}

	packet := geneve.NewPacketBuilder().
		SetVNI(0xABCDEF).
		SetProtocolType(geneve.ProtocolTypeIPv6).
		AddINTMetadataOption(intOpt).
		SetPayload([]byte("INT telemetry data")).
		Build()

	result, err := parser.ParsePacket(packet)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	fmt.Printf("Header: %s\n", result.Header.String())
	fmt.Printf("INT Options: %d\n\n", len(result.INTOptions))

	for i, intOption := range result.INTOptions {
		fmt.Printf("INT Option %d:\n", i+1)
		fmt.Printf("  Summary: %s\n", intOption.String())
		fmt.Printf("  Version: %s\n", intOption.GetVersionName())
		fmt.Printf("  Status Flags: %s\n", intOption.GetFlagsDescription())
		fmt.Printf("  Hop Metadata Length: %d words\n", intOption.HopML)
		fmt.Printf("  Remaining Hop Count: %d\n", intOption.RemainingHopCount)
		fmt.Printf("  Domain Specific ID: 0x%04x\n", intOption.DomainSpecificID)
		fmt.Printf("  Domain Instruction: 0x%04x\n", intOption.DomainInstruction)
		fmt.Printf("  Domain Flags: 0x%04x\n", intOption.DomainFlags)
		
		instructions := intOption.GetINTInstructionNames()
		fmt.Printf("  Telemetry Instructions (%d active):\n", len(instructions))
		for j, instr := range instructions {
			fmt.Printf("    %d. %s\n", j+1, instr)
		}
		fmt.Println()
	}
}

func demoMultiVendorOptions() {
	parser := geneve.NewParser()

	// Create packet with options from different vendors
	packet := geneve.NewPacketBuilder().
		SetVNI(0x555555).
		SetProtocolType(geneve.ProtocolTypeEthernet).
		AddOption(0x0001, geneve.GenericTypeSecurityTag, []byte{0x01, 0x02, 0x03, 0x04}). // Linux - Security
		AddOption(0x0002, 0x10, []byte{0x11, 0x22}). // Open vSwitch - Custom
		AddOption(0x0003, 0x20, []byte{0x33, 0x44, 0x55, 0x66}). // VMware - Custom  
		AddOption(0x0004, 0x30, []byte{0x77, 0x88}). // Cisco - Custom
		AddOption(0xFFFF, 0x01, []byte{0x99, 0xAA, 0xBB, 0xCC}). // Platform specific
		SetPayload([]byte("Multi-vendor options")).
		Build()

	result, err := parser.ParsePacket(packet)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	fmt.Printf("Multi-Vendor Packet Analysis:\n")
	fmt.Printf("Header: %s\n", result.Header.String())
	fmt.Printf("Total Options: %d\n\n", len(result.Options))

	vendorCounts := make(map[string]int)
	criticalCount := 0

	for i, opt := range result.Options {
		className := opt.GetOptionClassName()
		vendorCounts[className]++
		
		fmt.Printf("Option %d: %s\n", i+1, opt.String())
		fmt.Printf("  Class: 0x%04x (%s)\n", opt.Class, className)
		fmt.Printf("  Type: 0x%02x (%s)\n", opt.Type, opt.GetOptionTypeName())
		fmt.Printf("  Critical: %t\n", opt.IsCritical())
		fmt.Printf("  Data Length: %d bytes\n", len(opt.Data))
		
		if opt.IsCritical() {
			criticalCount++
			fmt.Printf("  ⚠️  CRITICAL OPTION - Must be processed\n")
		}
		fmt.Println()
	}

	fmt.Printf("Vendor Summary:\n")
	for vendor, count := range vendorCounts {
		fmt.Printf("  %s: %d options\n", vendor, count)
	}
	fmt.Printf("  Critical options: %d\n", criticalCount)
}

func demoOAMPacket() {
	parser := geneve.NewParser()

	// Create OAM packet for network diagnostics
	packet := geneve.NewPacketBuilder().
		SetVNI(0x999999).
		SetProtocolType(geneve.ProtocolTypeIPv4).
		SetOAMFlag(true). // Mark as OAM packet
		SetCriticalFlag(true). // Has critical options
		AddOption(0x0000, geneve.OAMTypeEcho, []byte{0x01, 0x23, 0x45, 0x67}). // OAM Echo
		AddOption(0x0001, geneve.GenericTypeDebugInfo, []byte("DEBUG:OAM_TEST")). // Debug info
		SetPayload([]byte("OAM echo request payload")).
		Build()

	result, err := parser.ParsePacket(packet)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	fmt.Printf("OAM Packet Analysis:\n")
	fmt.Printf("Header: %s\n", result.Header.String())
	
	// Analyze OAM characteristics
	fmt.Printf("\nOAM Characteristics:\n")
	fmt.Printf("  OAM Packet: %t\n", result.Header.IsOAMPacket())
	fmt.Printf("  Critical Options: %t\n", result.Header.HasCriticalOptions())
	fmt.Printf("  VNI: 0x%06x (%d)\n", result.Header.VNI, result.Header.VNI)
	fmt.Printf("  Inner Protocol: %s\n", result.Header.GetProtocolName())
	
	fmt.Printf("\nOAM Options:\n")
	oamCount := 0
	debugCount := 0
	
	for i, opt := range result.Options {
		fmt.Printf("  Option %d: %s\n", i+1, opt.GetOptionDescription())
		
		if opt.Class == 0x0000 && opt.Type == geneve.OAMTypeEcho {
			oamCount++
			fmt.Printf("    🔍 OAM Echo - Sequence: %s\n", hex.EncodeToString(opt.Data))
		} else if opt.Type == geneve.GenericTypeDebugInfo {
			debugCount++
			fmt.Printf("    🐛 Debug Info: %s\n", string(opt.Data))
		}
	}
	
	fmt.Printf("\nOAM Summary:\n")
	fmt.Printf("  OAM operations: %d\n", oamCount)
	fmt.Printf("  Debug options: %d\n", debugCount)
	fmt.Printf("  Payload size: %d bytes\n", len(result.Payload))
	
	if result.Header.IsOAMPacket() {
		fmt.Printf("  📋 Recommendation: Process as network diagnostic packet\n")
	}
}