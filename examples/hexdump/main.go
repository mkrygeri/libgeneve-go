// Example program demonstrating GENEVE parsing from raw network data
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/mkrygeri/libgeneve-go/geneve"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("GENEVE Raw Packet Parser")
		fmt.Println("Usage: go run main.go <hex_string>")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  Basic packet:")
		fmt.Println("    go run main.go \"000008001234560048656c6c6f2c2047454e45564521\"")
		fmt.Println()
		fmt.Println("  Packet with options:")
		fmt.Println("    go run main.go \"010008001234560000010201234000\"")
		fmt.Println()
		showSamplePackets()
		os.Exit(1)
	}

	hexString := strings.ReplaceAll(os.Args[1], " ", "")
	hexString = strings.ReplaceAll(hexString, ":", "")
	hexString = strings.ReplaceAll(hexString, "-", "")

	// Decode hex string to bytes
	packet, err := hex.DecodeString(hexString)
	if err != nil {
		log.Fatalf("Invalid hex string: %v", err)
	}

	fmt.Printf("Raw packet (%d bytes): %s\n", len(packet), hex.EncodeToString(packet))
	fmt.Println()

	// Parse with detailed output
	parseWithDetails(packet)
}

func parseWithDetails(packet []byte) {
	parser := geneve.NewParser()
	parser.ParseNestedLayers = true
	
	result, err := parser.ParsePacket(packet)
	if err != nil {
		log.Fatalf("Failed to parse packet: %v", err)
	}

	printParseResult(result, 0)

	// Validate packet
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("PACKET VALIDATION")
	fmt.Println(strings.Repeat("=", 50))
	
	validator := geneve.NewValidator()
	violations := validator.ValidatePacket(result)
	
	if len(violations) == 0 {
		fmt.Println("✓ Packet is valid")
	} else {
		fmt.Printf("✗ Found %d validation issues:\n", len(violations))
		for i, violation := range violations {
			fmt.Printf("  %d. %s\n", i+1, violation)
		}
	}
}

func printParseResult(result *geneve.ParseResult, depth int) {
	indent := strings.Repeat("  ", depth)
	
	fmt.Printf("%s%s\n", indent, strings.Repeat("=", 50-depth*2))
	fmt.Printf("%sGENEVE LAYER %d\n", indent, depth+1)
	fmt.Printf("%s%s\n", indent, strings.Repeat("=", 50-depth*2))
	
	// Header information
	fmt.Printf("%sHeader Information:\n", indent)
	fmt.Printf("%s  Version: %d\n", indent, result.Header.Version)
	fmt.Printf("%s  VNI: %d (0x%06x)\n", indent, result.Header.VNI, result.Header.VNI)
	fmt.Printf("%s  Protocol Type: %s (0x%04x)\n", indent, 
		result.Header.GetProtocolName(), result.Header.ProtocolType)
	fmt.Printf("%s  Option Length: %d bytes\n", indent, result.Header.OptionLength*4)
	fmt.Printf("%s  Flags: OAM=%t, Critical=%t\n", indent, 
		result.Header.OFlag, result.Header.CFlag)
	fmt.Printf("%s  Reserved1: 0x%02x\n", indent, result.Header.Reserved1)
	fmt.Printf("%s  Reserved2: 0x%02x\n", indent, result.Header.Reserved2)

	// Options
	if len(result.Options) > 0 {
		fmt.Printf("%s\nOptions (%d found):\n", indent, len(result.Options))
		for i, opt := range result.Options {
			fmt.Printf("%s  Option %d:\n", indent, i+1)
			fmt.Printf("%s    Description: %s\n", indent, opt.GetOptionDescription())
			fmt.Printf("%s    Class: 0x%04x (%s)\n", indent, opt.Class, opt.GetOptionClassName())
			fmt.Printf("%s    Type: 0x%02x (%s)\n", indent, opt.Type, opt.GetOptionTypeName())
			fmt.Printf("%s    Length: %d bytes\n", indent, opt.Length*4)
			fmt.Printf("%s    Critical: %t\n", indent, opt.IsCritical())
			fmt.Printf("%s    Reserved: 0x%x\n", indent, opt.Reserved)
			if len(opt.Data) > 0 {
				fmt.Printf("%s    Data: %s\n", indent, hex.EncodeToString(opt.Data))
				printOptionData(opt, indent+"      ")
			}
		}
	}

	// INT Options
	if len(result.INTOptions) > 0 {
		fmt.Printf("%s\nINT Options (%d found):\n", indent, len(result.INTOptions))
		for i, intOpt := range result.INTOptions {
			fmt.Printf("%s  INT Option %d:\n", indent, i+1)
			fmt.Printf("%s    Summary: %s\n", indent, intOpt.String())
			fmt.Printf("%s    Version: %s\n", indent, intOpt.GetVersionName())
			fmt.Printf("%s    Status Flags: %s\n", indent, intOpt.GetFlagsDescription())
			fmt.Printf("%s    Hop ML: %d\n", indent, intOpt.HopML)
			fmt.Printf("%s    Remaining Hop Count: %d\n", indent, intOpt.RemainingHopCount)
			fmt.Printf("%s    Instruction Bitmap: 0x%04x\n", indent, intOpt.InstructionBitmap)
			
			instructions := intOpt.GetINTInstructionNames()
			fmt.Printf("%s    Telemetry Instructions:\n", indent)
			for j, instr := range instructions {
				fmt.Printf("%s      %d. %s\n", indent, j+1, instr)
			}
			
			fmt.Printf("%s    Domain Specific ID: 0x%04x\n", indent, intOpt.DomainSpecificID)
			fmt.Printf("%s    Domain Instruction: 0x%04x\n", indent, intOpt.DomainInstruction)
			fmt.Printf("%s    Domain Flags: 0x%04x\n", indent, intOpt.DomainFlags)
		}
	}

	// Payload
	if len(result.Payload) > 0 {
		fmt.Printf("%s\nPayload (%d bytes at offset %d):\n", indent, 
			len(result.Payload), result.PayloadOffset)
		
		// Show first 64 bytes of payload
		displayLen := len(result.Payload)
		if displayLen > 64 {
			displayLen = 64
		}
		
		fmt.Printf("%s  Hex: %s", indent, hex.EncodeToString(result.Payload[:displayLen]))
		if len(result.Payload) > 64 {
			fmt.Printf("... (%d more bytes)", len(result.Payload)-64)
		}
		fmt.Println()
		
		// Try to show as ASCII if printable
		ascii := make([]byte, displayLen)
		for i, b := range result.Payload[:displayLen] {
			if b >= 32 && b <= 126 {
				ascii[i] = b
			} else {
				ascii[i] = '.'
			}
		}
		fmt.Printf("%s  ASCII: %s\n", indent, string(ascii))
		
		// Analyze payload for known protocols
		analyzePayload(result.Payload, result.Header.ProtocolType, indent+"  ")
	}

	// Nested layers
	if len(result.InnerLayers) > 0 {
		fmt.Printf("%s\nNested GENEVE Layers (%d found):\n", indent, len(result.InnerLayers))
		for i, inner := range result.InnerLayers {
			fmt.Printf("%s\nNested Layer %d:\n", indent, i+1)
			printParseResult(&inner, depth+1)
		}
	}
}

func printOptionData(opt geneve.Option, indent string) {
	classType := (uint32(opt.Class) << 8) | uint32(opt.Type)
	
	switch classType {
	case geneve.OptionClassINTMetadata:
		fmt.Printf("%sType: INT Metadata Option\n", indent)
	case geneve.OptionClassINTDestination:
		fmt.Printf("%sType: INT Destination Option\n", indent)
	case geneve.OptionClassINTMX:
		fmt.Printf("%sType: INT MX Option\n", indent)
	default:
		fmt.Printf("%sType: Custom Option (Class:0x%04x, Type:0x%02x)\n", 
			indent, opt.Class, opt.Type)
	}
}

func analyzePayload(payload []byte, protocolType uint16, indent string) {
	fmt.Printf("%sPayload Analysis:\n", indent)
	fmt.Printf("%s  Expected Protocol: %s\n", indent, getProtocolName(protocolType))
	
	if len(payload) < 4 {
		fmt.Printf("%s  Payload too short for detailed analysis\n", indent)
		return
	}
	
	switch protocolType {
	case geneve.ProtocolTypeIPv4:
		if len(payload) >= 20 {
			version := (payload[0] >> 4) & 0xF
			headerLen := (payload[0] & 0xF) * 4
			fmt.Printf("%s  IPv4 Version: %d\n", indent, version)
			fmt.Printf("%s  IPv4 Header Length: %d bytes\n", indent, headerLen)
			if len(payload) >= 16 {
				srcIP := fmt.Sprintf("%d.%d.%d.%d", payload[12], payload[13], payload[14], payload[15])
				dstIP := fmt.Sprintf("%d.%d.%d.%d", payload[16], payload[17], payload[18], payload[19])
				fmt.Printf("%s  Source IP: %s\n", indent, srcIP)
				fmt.Printf("%s  Destination IP: %s\n", indent, dstIP)
			}
		}
	case geneve.ProtocolTypeIPv6:
		if len(payload) >= 40 {
			version := (payload[0] >> 4) & 0xF
			fmt.Printf("%s  IPv6 Version: %d\n", indent, version)
			// Could parse more IPv6 fields here
		}
	case geneve.ProtocolTypeEthernet:
		if len(payload) >= 14 {
			fmt.Printf("%s  Ethernet Destination: %02x:%02x:%02x:%02x:%02x:%02x\n", 
				indent, payload[0], payload[1], payload[2], payload[3], payload[4], payload[5])
			fmt.Printf("%s  Ethernet Source: %02x:%02x:%02x:%02x:%02x:%02x\n", 
				indent, payload[6], payload[7], payload[8], payload[9], payload[10], payload[11])
			etherType := (uint16(payload[12]) << 8) | uint16(payload[13])
			fmt.Printf("%s  EtherType: 0x%04x (%s)\n", indent, etherType, getProtocolName(etherType))
		}
	}

	// Check if this might be another GENEVE packet
	if len(payload) >= 8 {
		version := (payload[0] >> 6) & 0x3
		if version == 0 { // GENEVE version
			fmt.Printf("%s  Possible nested GENEVE detected (version=%d)\n", indent, version)
		}
	}
}

func getProtocolName(protocolType uint16) string {
	switch protocolType {
	case geneve.ProtocolTypeIPv4:
		return "IPv4"
	case geneve.ProtocolTypeIPv6:
		return "IPv6"
	case geneve.ProtocolTypeEthernet:
		return "Ethernet"
	case geneve.ProtocolTypeARP:
		return "ARP"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", protocolType)
	}
}

func showSamplePackets() {
	fmt.Println("Sample GENEVE packets:")
	fmt.Println()
	
	// Basic packet
	basic := geneve.NewPacketBuilder().
		SetVNI(0x123456).
		SetProtocolType(geneve.ProtocolTypeIPv4).
		SetPayload([]byte("Hello, GENEVE!")).
		Build()
	fmt.Printf("Basic packet: %s\n", hex.EncodeToString(basic))
	
	// Packet with options
	withOptions := geneve.NewPacketBuilder().
		SetVNI(0xABCDEF).
		AddOption(0x0001, 0x02, []byte{0x12, 0x34}).
		SetPayload([]byte("With options")).
		Build()
	fmt.Printf("With options: %s\n", hex.EncodeToString(withOptions))
	
	// INT packet
	intOpt := geneve.INTMetadataOption{
		Version:           4,
		Discard:          true,
		RemainingHopCount: 10,
		InstructionBitmap: 0x1234,
		DomainSpecificID:  0x0100,
	}
	intPacket := geneve.NewPacketBuilder().
		SetVNI(0x112233).
		AddINTMetadataOption(intOpt).
		SetPayload([]byte("INT packet")).
		Build()
	fmt.Printf("INT metadata: %s\n", hex.EncodeToString(intPacket))
}