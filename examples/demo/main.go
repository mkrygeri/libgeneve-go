package main

import (
	"encoding/hex"
	"fmt"

	"github.com/mkrygeri/libgeneve-go/geneve"
)

func main() {
	fmt.Println("Creating and parsing a comprehensive GENEVE packet:")
	fmt.Println()

	// Create a packet with INT metadata option
	intOpt := geneve.INTMetadataOption{
		Version:            4,
		Discard:            true,
		ExceededMaxHops:    false,
		MTUExceeded:        false,
		HopML:             5,
		RemainingHopCount:  10,
		InstructionBitmap:  0x1234,
		DomainSpecificID:   0x0100,
		DomainInstruction:  0x5678,
		DomainFlags:        0x9ABC,
	}

	packet := geneve.NewPacketBuilder().
		SetVNI(0x123456).
		SetProtocolType(geneve.ProtocolTypeIPv4).
		SetOAMFlag(false).
		SetCriticalFlag(false).
		AddOption(0x0001, 0x02, []byte{0xDE, 0xAD, 0xBE, 0xEF}).
		AddINTMetadataOption(intOpt).
		AddOption(0x0002, 0x03, []byte{0xCA, 0xFE}).
		SetPayload([]byte("GENEVE payload with metadata")).
		Build()

	fmt.Printf("Built packet (%d bytes):\n", len(packet))
	fmt.Printf("Hex: %s\n", hex.EncodeToString(packet))
	fmt.Println()

	// Parse the packet
	parser := geneve.NewParser()
	result, err := parser.ParsePacket(packet)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	// Display comprehensive results
	fmt.Println("Parse Results:")
	fmt.Printf("  VNI: %d (0x%06x)\n", result.Header.VNI, result.Header.VNI)
	fmt.Printf("  Protocol: %s\n", result.Header.GetProtocolName())
	fmt.Printf("  Options: %d total\n", len(result.Options))
	fmt.Printf("  INT Options: %d\n", len(result.INTOptions))
	fmt.Printf("  Payload: %s\n", string(result.Payload))
	fmt.Println()

	// Show detailed option analysis
	for i, opt := range result.Options {
		fmt.Printf("  Option %d:\n", i+1)
		fmt.Printf("    Class: 0x%04x\n", opt.Class)
		fmt.Printf("    Type: 0x%02x\n", opt.Type)
		fmt.Printf("    Data: %s\n", hex.EncodeToString(opt.Data))
	}

	if len(result.INTOptions) > 0 {
		fmt.Println("  INT Metadata:")
		int := result.INTOptions[0]
		fmt.Printf("    Version: %d\n", int.Version)
		fmt.Printf("    Flags: Discard=%t, MaxHops=%t, MTU=%t\n", 
			int.Discard, int.ExceededMaxHops, int.MTUExceeded)
		fmt.Printf("    Hops Remaining: %d\n", int.RemainingHopCount)
		fmt.Printf("    Domain ID: 0x%04x\n", int.DomainSpecificID)
		fmt.Printf("    Instruction: 0x%04x\n", int.DomainInstruction)
		fmt.Printf("    Flags: 0x%04x\n", int.DomainFlags)
	}

	// Validate packet
	validator := geneve.NewValidator()
	violations := validator.ValidatePacket(result)
	fmt.Printf("\nValidation: ")
	if len(violations) == 0 {
		fmt.Println("✓ PASS - Packet is RFC 8926 compliant")
	} else {
		fmt.Printf("✗ FAIL - %d issues found\n", len(violations))
		for _, v := range violations {
			fmt.Printf("    - %s\n", v)
		}
	}
}