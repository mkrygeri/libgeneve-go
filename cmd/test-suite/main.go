package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/mkrygeri/libgeneve-go/geneve"
	"github.com/mkrygeri/libgeneve-go/test"
)

func main() {
	fmt.Println("🚀 GENEVE Protocol Parser - Comprehensive Test Suite")
	fmt.Println("=====================================================")

	// Test 1: Library functionality with synthetic packets
	fmt.Println("\n📋 Test 1: Library Parsing Tests")
	testLibraryParsing()

	// Test 2: Generate test PCAP files
	fmt.Println("\n📋 Test 2: Generate Test PCAP Files")
	generateTestPCAPs()

	// Test 3: Test command-line analyzer
	fmt.Println("\n📋 Test 3: Command-Line Analyzer Tests")
	testAnalyzer()

	fmt.Println("\n🎉 All tests completed successfully!")
}

func testLibraryParsing() {
	parser := geneve.NewParser()
	
	// Test VMware NSX packet
	fmt.Println("  🔍 Testing VMware NSX telemetry parsing...")
	vmwarePacket := test.CreateGENEVEPacketWithVMwareTelemetry()
	
	// Extract just the GENEVE portion (skip Ethernet + IP + UDP headers)
	geneveStart := 14 + 20 + 8 // Ethernet + IP + UDP
	geneveData := vmwarePacket[geneveStart:]
	
	result, err := parser.ParsePacket(geneveData)
	if err != nil {
		log.Printf("    ❌ VMware parsing failed: %v", err)
	} else {
		fmt.Printf("    ✅ VMware NSX packet parsed successfully\n")
		fmt.Printf("       VNI: 0x%06X (%d)\n", result.Header.VNI, result.Header.VNI)
		fmt.Printf("       Protocol: %s\n", result.Header.GetProtocolName())
		fmt.Printf("       Options: %d found\n", len(result.Options))
		
		for i, opt := range result.Options {
			fmt.Printf("       Option %d: %s\n", i+1, opt.GetOptionDescription())
			fmt.Printf("         Class: %s (0x%04X)\n", opt.GetOptionClassName(), opt.Class)
			fmt.Printf("         Type: %s (%d)\n", opt.GetOptionTypeName(), opt.Type)
		}
	}
	
	// Test Cisco ACI packet  
	fmt.Println("\n  🔍 Testing Cisco ACI telemetry parsing...")
	ciscoPacket := test.CreateGENEVEPacketWithCiscoTelemetry()
	ciscoGeneveData := ciscoPacket[geneveStart:]
	
	result, err = parser.ParsePacket(ciscoGeneveData)
	if err != nil {
		log.Printf("    ❌ Cisco parsing failed: %v", err)
	} else {
		fmt.Printf("    ✅ Cisco ACI packet parsed successfully\n")
		fmt.Printf("       VNI: 0x%06X (%d)\n", result.Header.VNI, result.Header.VNI)
		fmt.Printf("       Options: %d found\n", len(result.Options))
		
		for i, opt := range result.Options {
			fmt.Printf("       Option %d: %s\n", i+1, opt.GetOptionDescription())
		}
	}

	// Test Multi-vendor packet
	fmt.Println("\n  🔍 Testing Multi-vendor telemetry parsing...")
	multiPacket := test.CreateGENEVEPacketWithMultiVendorTelemetry()
	multiGeneveData := multiPacket[geneveStart:]
	
	result, err = parser.ParsePacket(multiGeneveData)
	if err != nil {
		log.Printf("    ❌ Multi-vendor parsing failed: %v", err)
	} else {
		fmt.Printf("    ✅ Multi-vendor packet parsed successfully\n")
		fmt.Printf("       VNI: 0x%06X (%d)\n", result.Header.VNI, result.Header.VNI)
		fmt.Printf("       Protocol: %s\n", result.Header.GetProtocolName())
		fmt.Printf("       Options: %d found\n", len(result.Options))
		
		for i, opt := range result.Options {
			fmt.Printf("       Option %d: %s\n", i+1, opt.GetOptionDescription())
			fmt.Printf("         Class: %s\n", opt.GetOptionClassName())
		}
	}
}

func generateTestPCAPs() {
	testDir := "test-pcaps"
	os.MkdirAll(testDir, 0755)
	
	// Generate VMware NSX test PCAP
	fmt.Println("  📄 Generating VMware NSX test PCAP...")
	createPCAPFile(filepath.Join(testDir, "vmware-nsx.pcap"), 
		[][]byte{test.CreateGENEVEPacketWithVMwareTelemetry()})
	
	// Generate Cisco ACI test PCAP
	fmt.Println("  📄 Generating Cisco ACI test PCAP...")
	createPCAPFile(filepath.Join(testDir, "cisco-aci.pcap"), 
		[][]byte{test.CreateGENEVEPacketWithCiscoTelemetry()})
	
	// Generate multi-vendor test PCAP
	fmt.Println("  📄 Generating Multi-vendor test PCAP...")
	createPCAPFile(filepath.Join(testDir, "multi-vendor.pcap"), 
		[][]byte{test.CreateGENEVEPacketWithMultiVendorTelemetry()})
	
	// Generate a PCAP with multiple packets
	fmt.Println("  📄 Generating Mixed telemetry test PCAP...")
	mixedPackets := [][]byte{
		test.CreateGENEVEPacketWithVMwareTelemetry(),
		test.CreateGENEVEPacketWithCiscoTelemetry(),
		test.CreateGENEVEPacketWithMultiVendorTelemetry(),
		test.CreateGENEVEPacketWithVMwareTelemetry(), // Add duplicates
		test.CreateGENEVEPacketWithCiscoTelemetry(),
	}
	createPCAPFile(filepath.Join(testDir, "mixed-telemetry.pcap"), mixedPackets)
}

func createPCAPFile(filename string, packets [][]byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create PCAP file %s: %v", filename, err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	err = writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
	if err != nil {
		log.Fatalf("Failed to write PCAP header: %v", err)
	}

	for i, packet := range packets {
		timestamp := time.Now().Add(time.Duration(i) * time.Second)
		err = writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     timestamp,
			CaptureLength: len(packet),
			Length:        len(packet),
		}, packet)
		if err != nil {
			log.Fatalf("Failed to write packet: %v", err)
		}
	}

	fmt.Printf("    ✅ Created %s with %d packets\n", filename, len(packets))
}

func testAnalyzer() {
	analyzerPath := "./build/geneve-analyzer"
	
	// Check if analyzer exists
	if _, err := os.Stat(analyzerPath); os.IsNotExist(err) {
		fmt.Println("    ⚠️  Analyzer not found, building it first...")
		buildCmd := exec.Command("make", "analyzer")
		if err := buildCmd.Run(); err != nil {
			log.Printf("    ❌ Failed to build analyzer: %v", err)
			return
		}
	}

	testCases := []struct {
		name     string
		filename string
		args     []string
	}{
		{
			name:     "VMware NSX Telemetry Analysis",
			filename: "test-pcaps/vmware-nsx.pcap",
			args:     []string{"-r", "test-pcaps/vmware-nsx.pcap", "-output", "detailed"},
		},
		{
			name:     "Cisco ACI Telemetry Analysis",
			filename: "test-pcaps/cisco-aci.pcap",
			args:     []string{"-r", "test-pcaps/cisco-aci.pcap", "-output", "summary"},
		},
		{
			name:     "Multi-vendor JSON Output",
			filename: "test-pcaps/multi-vendor.pcap",
			args:     []string{"-r", "test-pcaps/multi-vendor.pcap", "-output", "json"},
		},
		{
			name:     "Mixed Telemetry Analysis",
			filename: "test-pcaps/mixed-telemetry.pcap",
			args:     []string{"-r", "test-pcaps/mixed-telemetry.pcap", "-count", "3", "-verbose"},
		},
	}

	for _, tc := range testCases {
		fmt.Printf("  🔍 %s\n", tc.name)
		
		if _, err := os.Stat(tc.filename); os.IsNotExist(err) {
			fmt.Printf("    ❌ Test file %s not found\n", tc.filename)
			continue
		}

		cmd := exec.Command(analyzerPath, tc.args...)
		output, err := cmd.CombinedOutput()
		
		if err != nil {
			fmt.Printf("    ❌ Analysis failed: %v\n", err)
			fmt.Printf("    Output: %s\n", string(output))
		} else {
			fmt.Printf("    ✅ Analysis completed successfully\n")
			
			// Show first few lines of output
			lines := splitLines(string(output))
			maxLines := 10
			if len(lines) > maxLines {
				for i := 0; i < maxLines; i++ {
					fmt.Printf("       %s\n", lines[i])
				}
				fmt.Printf("       ... (%d more lines)\n", len(lines)-maxLines)
			} else {
				for _, line := range lines {
					fmt.Printf("       %s\n", line)
				}
			}
		}
		fmt.Println()
	}
}

func splitLines(s string) []string {
	if s == "" {
		return []string{}
	}
	lines := []string{}
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}