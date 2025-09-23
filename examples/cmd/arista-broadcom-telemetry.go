package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"

	"github.com/mkrygeri/libgeneve-go/geneve"
)

func main() {
	// Create a parser with enterprise extensions enabled
	parser := geneve.NewParser()
	parser.EnableEnterpriseExtensions()

	// Create sample Arista TAP telemetry data
	aristaTAPData := createAristaTAPPacket()
	fmt.Println("=== Parsing Arista TAP Telemetry ===")
	result, err := parser.ParsePacket(aristaTAPData)
	if err != nil {
		log.Fatalf("Failed to parse Arista TAP packet: %v", err)
	}
	printTelemetryResults(result)

	// Create sample Arista Latency telemetry data
	aristaLatencyData := createAristaLatencyPacket()
	fmt.Println("\n=== Parsing Arista Latency Telemetry ===")
	result, err = parser.ParsePacket(aristaLatencyData)
	if err != nil {
		log.Fatalf("Failed to parse Arista latency packet: %v", err)
	}
	printTelemetryResults(result)

	// Create sample Broadcom switch telemetry data
	broadcomSwitchData := createBroadcomSwitchPacket()
	fmt.Println("\n=== Parsing Broadcom Switch Telemetry ===")
	result, err = parser.ParsePacket(broadcomSwitchData)
	if err != nil {
		log.Fatalf("Failed to parse Broadcom switch packet: %v", err)
	}
	printTelemetryResults(result)

	// Create sample Broadcom latency histogram data
	broadcomLatencyData := createBroadcomLatencyPacket()
	fmt.Println("\n=== Parsing Broadcom Latency Histogram ===")
	result, err = parser.ParsePacket(broadcomLatencyData)
	if err != nil {
		log.Fatalf("Failed to parse Broadcom latency packet: %v", err)
	}
	printTelemetryResults(result)
}

// createAristaTAPPacket creates a sample GENEVE packet with Arista TAP telemetry
func createAristaTAPPacket() []byte {
	packet := make([]byte, 0, 100)
	
	// GENEVE header (8 bytes) - options length is in 4-byte units
	header := []byte{
		0x06,       // Version (2 bits) = 0, OptionsLength (6 bits) = 6 (24 bytes of options = 6 * 4)
		0x00,       // Reserved + Flags
		0x65, 0x58, // Protocol Type (Ethernet)
		0x00, 0x12, 0x34, // VNI
		0x00,       // Reserved
	}
	packet = append(packet, header...)

	// Arista TAP option (24 bytes total: 4 header + 20 data)
	option := make([]byte, 24)
	binary.BigEndian.PutUint16(option[0:2], geneve.OptionClassArista) // Class
	option[2] = geneve.AristaTypeTAP                                 // Type
	option[3] = 5                                                    // Length = 5 * 4 = 20 bytes data
	
	// TAP telemetry data (20 bytes)
	binary.BigEndian.PutUint32(option[4:8], 0x12345678)     // FlowID
	binary.BigEndian.PutUint32(option[8:12], 10)            // IngressPort
	binary.BigEndian.PutUint32(option[12:16], 20)           // EgressPort
	binary.BigEndian.PutUint64(option[16:24], 1634567890123) // Timestamp
	
	packet = append(packet, option...)

	// Dummy payload
	payload := []byte("Arista TAP telemetry test payload")
	packet = append(packet, payload...)

	return packet
}

// createAristaLatencyPacket creates a sample GENEVE packet with Arista latency telemetry
func createAristaLatencyPacket() []byte {
	packet := make([]byte, 0, 100)
	
	// GENEVE header (8 bytes) - options length is in 4-byte units
	header := []byte{
		0x06,       // Version (2 bits) = 0, OptionsLength (6 bits) = 6 (24 bytes of options = 6 * 4)
		0x00,       // Reserved + Flags
		0x65, 0x58, // Protocol Type (Ethernet)
		0x00, 0x56, 0x78, // VNI
		0x00,       // Reserved
	}
	packet = append(packet, header...)

	// Arista Latency option (24 bytes total: 4 header + 20 data)
	option := make([]byte, 24)
	binary.BigEndian.PutUint16(option[0:2], geneve.OptionClassArista) // Class
	option[2] = geneve.AristaTypeLatency                             // Type
	option[3] = 5                                                    // Length = 5 * 4 = 20 bytes data
	
	// Latency telemetry data (20 bytes)
	binary.BigEndian.PutUint32(option[4:8], 0xABCDEF00)         // FlowHash
	binary.BigEndian.PutUint64(option[8:16], 1634567890123456)   // IngressTS (nanoseconds)
	binary.BigEndian.PutUint64(option[16:24], 1634567890125678)  // EgressTS (nanoseconds)
	
	packet = append(packet, option...)

	// Dummy payload
	payload := []byte("Arista latency telemetry test payload")
	packet = append(packet, payload...)

	return packet
}

// createBroadcomSwitchPacket creates a sample GENEVE packet with Broadcom switch telemetry
func createBroadcomSwitchPacket() []byte {
	packet := make([]byte, 0, 100)
	
	// GENEVE header (8 bytes) - options length is in 4-byte units
	header := []byte{
		0x08,       // Version (2 bits) = 0, OptionsLength (6 bits) = 8 (32 bytes of options = 8 * 4)
		0x00,       // Reserved + Flags
		0x65, 0x58, // Protocol Type (Ethernet)
		0x00, 0x9A, 0xBC, // VNI
		0x00,       // Reserved
	}
	packet = append(packet, header...)

	// Broadcom switch telemetry option (32 bytes total: 4 header + 28 data)
	option := make([]byte, 32)
	binary.BigEndian.PutUint16(option[0:2], geneve.OptionClassBroadcom) // Class
	option[2] = geneve.BroadcomTypeSwitchTelem                          // Type
	option[3] = 7                                                       // Length = 7 * 4 = 28 bytes data
	
	// Switch telemetry data (28 bytes)
	binary.BigEndian.PutUint32(option[4:8], 1)              // SwitchID
	binary.BigEndian.PutUint16(option[8:10], 2)             // ChipID
	binary.BigEndian.PutUint16(option[10:12], 3)            // PipelineID
	binary.BigEndian.PutUint32(option[12:16], 7500)         // BufferUtil (75.00%)
	binary.BigEndian.PutUint64(option[16:24], 1000000)      // PacketRate (1M pps)
	binary.BigEndian.PutUint64(option[24:32], 8000000000)   // ByteRate (8 Gbps)
	
	packet = append(packet, option...)

	// Dummy payload
	payload := []byte("Broadcom switch telemetry test payload")
	packet = append(packet, payload...)

	return packet
}

// createBroadcomLatencyPacket creates a sample GENEVE packet with Broadcom latency histogram
func createBroadcomLatencyPacket() []byte {
	packet := make([]byte, 0, 100)
	
	// GENEVE header (8 bytes) - options length is in 4-byte units
	header := []byte{
		0x0A,       // Version (2 bits) = 0, OptionsLength (6 bits) = 10 (40 bytes of options = 10 * 4)
		0x00,       // Reserved + Flags
		0x65, 0x58, // Protocol Type (Ethernet)
		0x00, 0xDE, 0xF0, // VNI
		0x00,       // Reserved
	}
	packet = append(packet, header...)

	// Broadcom latency histogram option (40 bytes total: 4 header + 36 data)
	option := make([]byte, 40)
	binary.BigEndian.PutUint16(option[0:2], geneve.OptionClassBroadcom) // Class
	option[2] = geneve.BroadcomTypeLatencyHist                          // Type
	option[3] = 9                                                       // Length = 9 * 4 = 36 bytes data
	
	// Latency histogram data (36 bytes)
	binary.BigEndian.PutUint32(option[4:8], 10)     // PortID
	binary.BigEndian.PutUint32(option[8:12], 1000)  // Bucket0_1us
	binary.BigEndian.PutUint32(option[12:16], 500)  // Bucket1_10us
	binary.BigEndian.PutUint32(option[16:20], 200)  // Bucket10_100us
	binary.BigEndian.PutUint32(option[20:24], 50)   // Bucket100us_1ms
	binary.BigEndian.PutUint32(option[24:28], 10)   // Bucket1ms_10ms
	binary.BigEndian.PutUint32(option[28:32], 2)    // BucketOver10ms
	binary.BigEndian.PutUint32(option[32:36], 15000) // MaxLatency (microseconds)
	binary.BigEndian.PutUint32(option[36:40], 100)   // MinLatency (microseconds)
	
	packet = append(packet, option...)

	// Dummy payload
	payload := []byte("Broadcom latency histogram test payload")
	packet = append(packet, payload...)

	return packet
}

// printTelemetryResults prints the parsed telemetry results
func printTelemetryResults(result *geneve.ParseResult) {
	fmt.Printf("VNI: %d, Protocol: 0x%04x, Options: %d\n",
		result.Header.VNI, result.Header.ProtocolType, len(result.Options))

	// Print Arista telemetry
	if len(result.AristaOptions) > 0 {
		fmt.Printf("Found %d Arista TAP options:\n", len(result.AristaOptions))
		for i, opt := range result.AristaOptions {
			data, _ := json.MarshalIndent(map[string]interface{}{
				"flow_id":      opt.FlowID,
				"ingress_port": opt.IngressPort,
				"egress_port":  opt.EgressPort,
				"timestamp":    opt.Timestamp,
				"queue_depth":  opt.QueueDepth,
				"latency":      opt.Latency,
			}, "  ", "  ")
			fmt.Printf("  [%d] %s\n", i, string(data))
		}
	}

	if len(result.AristaLatencyOptions) > 0 {
		fmt.Printf("Found %d Arista Latency options:\n", len(result.AristaLatencyOptions))
		for i, opt := range result.AristaLatencyOptions {
			latencyNs := opt.EgressTS - opt.IngressTS
			data, _ := json.MarshalIndent(map[string]interface{}{
				"flow_hash":       fmt.Sprintf("0x%08x", opt.FlowHash),
				"ingress_ts":      opt.IngressTS,
				"egress_ts":       opt.EgressTS,
				"latency_ns":      latencyNs,
				"queue_wait_time": opt.QueueWaitTime,
			}, "  ", "  ")
			fmt.Printf("  [%d] %s\n", i, string(data))
		}
	}

	// Print Broadcom telemetry
	if len(result.BroadcomOptions) > 0 {
		fmt.Printf("Found %d Broadcom Switch options:\n", len(result.BroadcomOptions))
		for i, opt := range result.BroadcomOptions {
			data, _ := json.MarshalIndent(map[string]interface{}{
				"switch_id":   opt.SwitchID,
				"chip_id":     opt.ChipID,
				"pipeline_id": opt.PipelineID,
				"buffer_util": fmt.Sprintf("%.2f%%", float64(opt.BufferUtil)/100.0),
				"packet_rate": fmt.Sprintf("%d pps", opt.PacketRate),
				"byte_rate":   fmt.Sprintf("%.2f Gbps", float64(opt.ByteRate)*8/1e9),
				"drop_count":  opt.DropCount,
				"error_count": opt.ErrorCount,
			}, "  ", "  ")
			fmt.Printf("  [%d] %s\n", i, string(data))
		}
	}

	if len(result.BroadcomLatencyOptions) > 0 {
		fmt.Printf("Found %d Broadcom Latency options:\n", len(result.BroadcomLatencyOptions))
		for i, opt := range result.BroadcomLatencyOptions {
			data, _ := json.MarshalIndent(map[string]interface{}{
				"port_id":          opt.PortID,
				"bucket_0_1us":     opt.Bucket0_1us,
				"bucket_1_10us":    opt.Bucket1_10us,
				"bucket_10_100us":  opt.Bucket10_100us,
				"bucket_100us_1ms": opt.Bucket100us_1ms,
				"bucket_1ms_10ms":  opt.Bucket1ms_10ms,
				"bucket_over_10ms": opt.BucketOver10ms,
				"max_latency_us":   opt.MaxLatency,
				"min_latency_us":   opt.MinLatency,
				"avg_latency_us":   opt.AvgLatency,
			}, "  ", "  ")
			fmt.Printf("  [%d] %s\n", i, string(data))
		}
	}

	// Print enterprise context
	if len(result.EnterpriseOptions) > 0 {
		fmt.Printf("Enterprise context: %d decoded options\n", len(result.EnterpriseOptions))
		for _, opt := range result.EnterpriseOptions {
			if opt.Decoded {
				fmt.Printf("  %s: %v\n", opt.VendorName, opt.DecodedData)
			}
		}
	}
}