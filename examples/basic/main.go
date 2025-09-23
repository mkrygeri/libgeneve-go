// Example program demonstrating basic GENEVE packet parsing
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/mkrygeri/libgeneve-go/geneve"
)

func main() {
	fmt.Println("GENEVE Protocol Parser Example")
	fmt.Println("==============================")

	// Example 1: Parse a basic GENEVE packet
	fmt.Println("\n1. Basic GENEVE Packet Parsing:")
	parseBasicPacket()

	// Example 2: Parse packet with options
	fmt.Println("\n2. GENEVE Packet with Options:")
	parsePacketWithOptions()

	// Example 3: Parse packet with INT metadata
	fmt.Println("\n3. GENEVE Packet with INT Metadata:")
	parsePacketWithINT()

	// Example 4: Parse nested GENEVE packets
	fmt.Println("\n4. Nested GENEVE Packets:")
	parseNestedPackets()

	// Example 5: Batch processing with statistics
	fmt.Println("\n5. Batch Processing with Statistics:")
	batchProcessing()

	// Example 6: Packet validation
	fmt.Println("\n6. Packet Validation:")
	packetValidation()
}

func parseBasicPacket() {
	// Create a simple GENEVE packet using the builder
	builder := geneve.NewPacketBuilder()
	payload := []byte("Hello, GENEVE!")
	
	packet := builder.
		SetVNI(0x123456).
		SetProtocolType(geneve.ProtocolTypeIPv4).
		SetPayload(payload).
		Build()

	fmt.Printf("Created packet (%d bytes): %s\n", len(packet), hex.EncodeToString(packet))

	// Parse the packet
	parser := geneve.NewParser()
	result, err := parser.ParsePacket(packet)
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}

	// Display results
	fmt.Printf("Header: %s\n", result.Header.String())
	fmt.Printf("VNI: %d (0x%06x)\n", result.Header.VNI, result.Header.VNI)
	fmt.Printf("Protocol: %s\n", result.Header.GetProtocolName())
	fmt.Printf("Payload: %s\n", string(result.Payload))
}

func parsePacketWithOptions() {
	// Create packet with custom options
	builder := geneve.NewPacketBuilder()
	
	packet := builder.
		SetVNI(0xABCDEF).
		SetProtocolType(geneve.ProtocolTypeEthernet).
		AddOption(0x0001, 0x02, []byte{0x12, 0x34, 0x56, 0x78}).
		AddOption(0x0002, 0x03, []byte{0xAA, 0xBB}).
		SetPayload([]byte("Packet with options")).
		Build()

	parser := geneve.NewParser()
	result, err := parser.ParsePacket(packet)
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}

	fmt.Printf("Header: %s\n", result.Header.String())
	fmt.Printf("Options found: %d\n", len(result.Options))
	
	for i, opt := range result.Options {
		fmt.Printf("  Option %d: Class=0x%04x, Type=0x%02x, Length=%d, Data=%s\n",
			i+1, opt.Class, opt.Type, opt.Length, hex.EncodeToString(opt.Data))
	}
	
	fmt.Printf("Payload: %s\n", string(result.Payload))
}

func parsePacketWithINT() {
	// Create packet with INT (In-band Network Telemetry) metadata
	builder := geneve.NewPacketBuilder()
	
	intOpt := geneve.INTMetadataOption{
		Version:            4,
		Discard:            true,
		ExceededMaxHops:    false,
		MTUExceeded:        false,
		HopML:             8,
		RemainingHopCount:  15,
		InstructionBitmap:  0x1234,
		DomainSpecificID:   0x0100,
		DomainInstruction:  0x5678,
		DomainFlags:        0x9ABC,
	}

	packet := builder.
		SetVNI(0x112233).
		SetProtocolType(geneve.ProtocolTypeIPv6).
		AddINTMetadataOption(intOpt).
		SetPayload([]byte("INT telemetry packet")).
		Build()

	parser := geneve.NewParser()
	result, err := parser.ParsePacket(packet)
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}

	fmt.Printf("Header: %s\n", result.Header.String())
	fmt.Printf("Regular options: %d\n", len(result.Options))
	fmt.Printf("INT options: %d\n", len(result.INTOptions))
	
	if len(result.INTOptions) > 0 {
		int := result.INTOptions[0]
		fmt.Printf("  INT Version: %d\n", int.Version)
		fmt.Printf("  Discard: %t\n", int.Discard)
		fmt.Printf("  Hop ML: %d\n", int.HopML)
		fmt.Printf("  Remaining Hops: %d\n", int.RemainingHopCount)
		fmt.Printf("  Instruction Bitmap: 0x%04x\n", int.InstructionBitmap)
		fmt.Printf("  Domain ID: 0x%04x\n", int.DomainSpecificID)
	}
}

func parseNestedPackets() {
	// Create nested GENEVE packets (GENEVE in GENEVE)
	innerPayload := []byte("Inner packet payload")
	
	// Build inner GENEVE packet
	innerPacket := geneve.NewPacketBuilder().
		SetVNI(0x654321).
		SetProtocolType(geneve.ProtocolTypeEthernet).
		AddOption(0x0001, 0x01, []byte{0xFF}).
		SetPayload(innerPayload).
		Build()

	// Build outer GENEVE packet with inner packet as payload
	outerPacket := geneve.NewPacketBuilder().
		SetVNI(0x123456).
		SetProtocolType(geneve.ProtocolTypeIPv4).
		SetPayload(innerPacket).
		Build()

	// Parse with nested layer support
	parser := geneve.NewParser()
	parser.ParseNestedLayers = true
	
	result, err := parser.ParsePacket(outerPacket)
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}

	fmt.Printf("Outer Header: %s\n", result.Header.String())
	fmt.Printf("Nested layers found: %d\n", len(result.InnerLayers))
	
	if len(result.InnerLayers) > 0 {
		inner := result.InnerLayers[0]
		fmt.Printf("Inner Header: %s\n", inner.Header.String())
		fmt.Printf("Inner Options: %d\n", len(inner.Options))
		fmt.Printf("Inner Payload: %s\n", string(inner.Payload))
	}
}

func batchProcessing() {
	// Simulate processing multiple packets with statistics
	parser := geneve.NewParser()
	stats := geneve.NewStatistics()

	// Create various test packets
	packets := [][]byte{
		// Valid packet with IPv4
		geneve.NewPacketBuilder().SetVNI(0x111111).SetProtocolType(geneve.ProtocolTypeIPv4).Build(),
		// Valid packet with IPv6
		geneve.NewPacketBuilder().SetVNI(0x222222).SetProtocolType(geneve.ProtocolTypeIPv6).Build(),
		// Valid packet with options
		geneve.NewPacketBuilder().SetVNI(0x333333).AddOption(0x0001, 0x02, []byte{0x12, 0x34}).Build(),
		// Invalid packet (too short)
		{0x01, 0x02, 0x03},
		// Another valid packet
		geneve.NewPacketBuilder().SetVNI(0x111111).SetProtocolType(geneve.ProtocolTypeEthernet).Build(),
	}

	fmt.Printf("Processing %d packets...\n", len(packets))
	
	for i, packet := range packets {
		result, err := parser.ParsePacket(packet)
		stats.UpdateFromResult(result, err)
		
		if err != nil {
			fmt.Printf("Packet %d: ERROR - %v\n", i+1, err)
		} else {
			fmt.Printf("Packet %d: OK - VNI=%d, Proto=%s\n", 
				i+1, result.Header.VNI, result.Header.GetProtocolName())
		}
	}

	fmt.Printf("\n%s", stats.String())
}

func packetValidation() {
	// Create packets with various validation issues
	validator := geneve.NewValidator()
	parser := geneve.NewParser()

	// Valid packet
	validPacket := geneve.NewPacketBuilder().
		SetVNI(0x123456).
		SetProtocolType(geneve.ProtocolTypeIPv4).
		Build()

	result, err := parser.ParsePacket(validPacket)
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}

	violations := validator.ValidatePacket(result)
	fmt.Printf("Valid packet violations: %d\n", len(violations))
	fmt.Printf("Is valid: %t\n", validator.IsValid(result))

	// Test with modified reserved field
	result.Header.Reserved1 = 0x01 // Should be zero
	violations = validator.ValidatePacket(result)
	fmt.Printf("After modifying reserved field violations: %d\n", len(violations))
	if len(violations) > 0 {
		fmt.Printf("Violation: %s\n", violations[0])
	}

	// Test option count limit
	validator.MaxAllowedOptions = 1
	manyOptionsPacket := geneve.NewPacketBuilder().
		AddOption(0x0001, 0x01, []byte{0x01}).
		AddOption(0x0002, 0x02, []byte{0x02}).
		Build()

	result2, err := parser.ParsePacket(manyOptionsPacket)
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}

	violations = validator.ValidatePacket(result2)
	fmt.Printf("Too many options violations: %d\n", len(violations))
	if len(violations) > 0 {
		fmt.Printf("Violation: %s\n", violations[0])
	}
}