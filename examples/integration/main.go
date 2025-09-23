// Integration test demonstrating complete GENEVE parsing workflow
package main

import (
	"fmt"
	"log"

	"github.com/mkrygeri/libgeneve-go/geneve"
)

func main() {
	fmt.Println("=== GENEVE Protocol Parser Integration Test ===")
	fmt.Println()

	// Test 1: Parse sample packet with multiple VNIs
	fmt.Println("Test 1: Multiple VNI Detection")
	fmt.Println("-------------------------------")
	testMultipleVNIs()

	// Test 2: Complex nested parsing
	fmt.Println("\nTest 2: Complex Nested Parsing")
	fmt.Println("-------------------------------")
	testComplexNested()

	// Test 3: Performance test with large batch
	fmt.Println("\nTest 3: Batch Performance")
	fmt.Println("-------------------------")
	testBatchPerformance()

	// Test 4: All option types
	fmt.Println("\nTest 4: All Option Types")
	fmt.Println("------------------------")
	testAllOptionTypes()

	fmt.Println("\n=== All tests completed successfully! ===")
}

func testMultipleVNIs() {
	parser := geneve.NewParser()
	stats := geneve.NewStatistics()

	vnis := []uint32{0x123456, 0xABCDEF, 0x000001, 0xFFFFFF, 0x555555}

	for i, vni := range vnis {
		packet := geneve.NewPacketBuilder().
			SetVNI(vni).
			SetProtocolType(geneve.ProtocolTypeIPv4).
			SetPayload([]byte(fmt.Sprintf("Payload for VNI %d", i+1))).
			Build()

		result, err := parser.ParsePacket(packet)
		if err != nil {
			log.Fatalf("Failed to parse VNI %d: %v", i+1, err)
		}

		stats.UpdateFromResult(result, nil)
		fmt.Printf("VNI %d: 0x%06x (%d) - %s\n", i+1, result.Header.VNI, 
			result.Header.VNI, string(result.Payload))
	}

	fmt.Printf("Processed %d unique VNIs\n", len(stats.VNICounts))
}

func testComplexNested() {
	// Create a 3-layer nested GENEVE packet
	level3Payload := []byte("Level 3 payload - deepest layer")
	level3Packet := geneve.NewPacketBuilder().
		SetVNI(0x333333).
		SetProtocolType(geneve.ProtocolTypeEthernet).
		AddOption(0x0003, 0x03, []byte{0x33, 0x33}).
		SetPayload(level3Payload).
		Build()

	level2Packet := geneve.NewPacketBuilder().
		SetVNI(0x222222).
		SetProtocolType(geneve.ProtocolTypeIPv6).
		AddOption(0x0002, 0x02, []byte{0x22, 0x22}).
		SetPayload(level3Packet).
		Build()

	level1Packet := geneve.NewPacketBuilder().
		SetVNI(0x111111).
		SetProtocolType(geneve.ProtocolTypeIPv4).
		AddOption(0x0001, 0x01, []byte{0x11}).
		SetPayload(level2Packet).
		Build()

	parser := geneve.NewParser()
	parser.MaxNestedDepth = 3

	result, err := parser.ParsePacket(level1Packet)
	if err != nil {
		log.Fatalf("Failed to parse nested packet: %v", err)
	}

	fmt.Printf("Layer 1: VNI=0x%06x, Proto=%s, Options=%d\n", 
		result.Header.VNI, result.Header.GetProtocolName(), len(result.Options))

	if len(result.InnerLayers) > 0 {
		inner1 := result.InnerLayers[0]
		fmt.Printf("Layer 2: VNI=0x%06x, Proto=%s, Options=%d\n", 
			inner1.Header.VNI, inner1.Header.GetProtocolName(), len(inner1.Options))

		if len(inner1.InnerLayers) > 0 {
			inner2 := inner1.InnerLayers[0]
			fmt.Printf("Layer 3: VNI=0x%06x, Proto=%s, Options=%d\n", 
				inner2.Header.VNI, inner2.Header.GetProtocolName(), len(inner2.Options))
			fmt.Printf("Final payload: %s\n", string(inner2.Payload))
		}
	}
}

func testBatchPerformance() {
	parser := geneve.NewParser()
	stats := geneve.NewStatistics()

	batchSize := 1000
	fmt.Printf("Processing batch of %d packets...\n", batchSize)

	for i := 0; i < batchSize; i++ {
		vni := uint32(i % 0xFFFFFF)
		protocol := []uint16{
			geneve.ProtocolTypeIPv4,
			geneve.ProtocolTypeIPv6,
			geneve.ProtocolTypeEthernet,
		}[i%3]

		var packet []byte
		if i%10 == 0 {
			// Add options to every 10th packet
			packet = geneve.NewPacketBuilder().
				SetVNI(vni).
				SetProtocolType(protocol).
				AddOption(0x0001, uint8(i%256), []byte{uint8(i), uint8(i >> 8)}).
				SetPayload([]byte(fmt.Sprintf("Batch payload %d", i))).
				Build()
		} else {
			packet = geneve.NewPacketBuilder().
				SetVNI(vni).
				SetProtocolType(protocol).
				SetPayload([]byte(fmt.Sprintf("Batch payload %d", i))).
				Build()
		}

		result, err := parser.ParsePacket(packet)
		stats.UpdateFromResult(result, err)
	}

	fmt.Printf("Batch processing complete:\n")
	fmt.Printf("  Success rate: %.1f%%\n", 
		float64(stats.SuccessfulParse)/float64(stats.TotalPackets)*100)
	fmt.Printf("  Unique VNIs: %d\n", len(stats.VNICounts))
	fmt.Printf("  Unique protocols: %d\n", len(stats.ProtocolCounts))
	fmt.Printf("  Total options: %d\n", len(stats.OptionCounts))
}

func testAllOptionTypes() {
	parser := geneve.NewParser()

	// Test standard option
	standardOpt := geneve.NewPacketBuilder().
		SetVNI(0x111111).
		AddOption(0x0001, 0x02, []byte{0x12, 0x34, 0x56, 0x78}).
		Build()

	// Test INT metadata option
	intOpt := geneve.INTMetadataOption{
		Version:            4,
		Discard:            true,
		ExceededMaxHops:    false,
		MTUExceeded:        true,
		HopML:             10,
		RemainingHopCount:  5,
		InstructionBitmap:  0xABCD,
		DomainSpecificID:   0x1234,
		DomainInstruction:  0x5678,
		DomainFlags:        0x9ABC,
	}

	intPacket := geneve.NewPacketBuilder().
		SetVNI(0x222222).
		AddINTMetadataOption(intOpt).
		Build()

	// Test multiple options
	multiOptPacket := geneve.NewPacketBuilder().
		SetVNI(0x333333).
		AddOption(0x0001, 0x01, []byte{0x11}).
		AddOption(0x0002, 0x02, []byte{0x22, 0x22}).
		AddINTMetadataOption(intOpt).
		AddOption(0x0003, 0x03, []byte{0x33, 0x33, 0x33}).
		Build()

	packets := [][]byte{standardOpt, intPacket, multiOptPacket}
	names := []string{"Standard Option", "INT Metadata", "Multiple Options"}

	for i, packet := range packets {
		result, err := parser.ParsePacket(packet)
		if err != nil {
			log.Fatalf("Failed to parse %s: %v", names[i], err)
		}

		fmt.Printf("%s:\n", names[i])
		fmt.Printf("  VNI: 0x%06x\n", result.Header.VNI)
		fmt.Printf("  Regular options: %d\n", len(result.Options))
		fmt.Printf("  INT options: %d\n", len(result.INTOptions))

		for j, opt := range result.Options {
			fmt.Printf("  Option %d: Class=0x%04x, Type=0x%02x\n", 
				j+1, opt.Class, opt.Type)
		}

		for j, intOption := range result.INTOptions {
			fmt.Printf("  INT %d: Version=%d, Discard=%t, Hops=%d\n", 
				j+1, intOption.Version, intOption.Discard, intOption.RemainingHopCount)
		}

		// Validate the packet
		validator := geneve.NewValidator()
		if validator.IsValid(result) {
			fmt.Printf("  Validation: ✓ PASS\n")
		} else {
			violations := validator.ValidatePacket(result)
			fmt.Printf("  Validation: ✗ FAIL (%d issues)\n", len(violations))
		}
		fmt.Println()
	}
}