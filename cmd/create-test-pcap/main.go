package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <ethernet-output.pcap> <cooked-output.pcap>\n", os.Args[0])
		os.Exit(1)
	}

	ethernetFile := os.Args[1]
	cookedFile := os.Args[2]

	fmt.Printf("Creating test PCAP files with GENEVE packets...\n")
	fmt.Printf("Ethernet format: %s\n", ethernetFile)
	fmt.Printf("Linux SLL format: %s\n", cookedFile)

	// Create synthetic GENEVE packet data
	genevePackets := createGeneveTestPackets()

	// Create Ethernet format PCAP
	if err := createEthernetPCAP(ethernetFile, genevePackets); err != nil {
		log.Fatalf("Error creating Ethernet PCAP: %v", err)
	}

	// Create Linux SLL format PCAP
	if err := createLinuxSLLPCAP(cookedFile, genevePackets); err != nil {
		log.Fatalf("Error creating Linux SLL PCAP: %v", err)
	}

	fmt.Printf("\nTest files created successfully!\n")
	fmt.Printf("\nTo test:\n")
	fmt.Printf("1. Ethernet format: ./build/geneve-analyzer -pcap-file %s -verbose\n", ethernetFile)
	fmt.Printf("2. Linux SLL format: ./build/geneve-analyzer -pcap-file %s -verbose\n", cookedFile)
}

type GeneveTestPacket struct {
	VNI     uint32
	Options []GeneveOption
	Payload []byte
}

type GeneveOption struct {
	Class    uint16
	Type     uint8
	Critical bool
	Data     []byte
}

func createGeneveTestPackets() []GeneveTestPacket {
	return []GeneveTestPacket{
		{
			VNI: 12345,
			Options: []GeneveOption{
				{Class: 0x0102, Type: 0x01, Critical: false, Data: []byte{0x12, 0x34, 0x56, 0x78}}, // VMware-like
			},
			Payload: []byte("Test GENEVE payload #1"),
		},
		{
			VNI: 67890,
			Options: []GeneveOption{
				{Class: 0x0103, Type: 0x02, Critical: true, Data: []byte{0xAB, 0xCD, 0xEF, 0x00}}, // Cisco-like
			},
			Payload: []byte("Test GENEVE payload #2"),
		},
		{
			VNI: 11111,
			Options: []GeneveOption{
				{Class: 0x000B, Type: 0x01, Critical: false, Data: []byte{0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00}}, // NVIDIA/Mellanox-like
				{Class: 0x000D, Type: 0x03, Critical: false, Data: []byte{0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00}}, // Cumulus-like
			},
			Payload: []byte("Multi-vendor GENEVE packet"),
		},
	}
}

func createEthernetPCAP(filename string, packets []GeneveTestPacket) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		return err
	}

	baseTime := time.Now()

	for i, genevePacket := range packets {
		packetData := buildEthernetPacket(genevePacket)
		
		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(i) * time.Second),
			CaptureLength: len(packetData),
			Length:        len(packetData),
		}

		if err := writer.WritePacket(ci, packetData); err != nil {
			return err
		}
	}

	return nil
}

func createLinuxSLLPCAP(filename string, packets []GeneveTestPacket) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(1600, layers.LinkTypeLinuxSLL); err != nil {
		return err
	}

	baseTime := time.Now()

	for i, genevePacket := range packets {
		packetData := buildLinuxSLLPacket(genevePacket)
		
		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(i) * time.Second),
			CaptureLength: len(packetData),
			Length:        len(packetData),
		}

		if err := writer.WritePacket(ci, packetData); err != nil {
			return err
		}
	}

	return nil
}

func buildEthernetPacket(genevePacket GeneveTestPacket) []byte {
	// Ethernet header
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IPv4 header
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{10, 0, 0, 2},
	}

	// UDP header
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 6081, // GENEVE port
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Build GENEVE payload
	geneveData := buildGenevePacket(genevePacket)

	// Serialize packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, opts,
		eth,
		ip,
		udp,
		gopacket.Payload(geneveData),
	); err != nil {
		log.Printf("Error serializing Ethernet packet: %v", err)
		return nil
	}

	return buffer.Bytes()
}

func buildLinuxSLLPacket(genevePacket GeneveTestPacket) []byte {
	var packet []byte

	// Linux SLL header (16 bytes)
	// Packet type (2 bytes) - 0 = packet sent to us
	packet = append(packet, 0x00, 0x00)
	
	// ARPHRD type (2 bytes) - 1 = Ethernet
	packet = append(packet, 0x00, 0x01)
	
	// Link layer address length (2 bytes) - 6 = MAC address length
	packet = append(packet, 0x00, 0x06)
	
	// Link layer address (8 bytes) - source MAC address + padding
	packet = append(packet, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00)
	
	// Protocol type (2 bytes) - 0x0800 = IPv4
	packet = append(packet, 0x08, 0x00)

	// IPv4 header (20 bytes minimum)
	ipHeader := buildIPv4Header()
	packet = append(packet, ipHeader...)

	// UDP header (8 bytes)
	udpHeader := buildUDPHeader()
	packet = append(packet, udpHeader...)

	// GENEVE payload
	geneveData := buildGenevePacket(genevePacket)
	packet = append(packet, geneveData...)

	// Update UDP length in header
	udpLength := uint16(8 + len(geneveData))
	binary.BigEndian.PutUint16(packet[16+20+4:16+20+4+2], udpLength) // SLL(16) + IP(20) + UDP offset 4-6

	// Update IP total length
	ipLength := uint16(20 + 8 + len(geneveData))
	binary.BigEndian.PutUint16(packet[16+2:16+2+2], ipLength) // SLL(16) + IP offset 2-4

	return packet
}

func buildIPv4Header() []byte {
	header := make([]byte, 20)
	
	// Version (4) + IHL (4) = 0x45
	header[0] = 0x45
	
	// Type of Service
	header[1] = 0x00
	
	// Total Length (will be updated later)
	binary.BigEndian.PutUint16(header[2:4], 0)
	
	// Identification
	binary.BigEndian.PutUint16(header[4:6], 0x1234)
	
	// Flags + Fragment Offset
	binary.BigEndian.PutUint16(header[6:8], 0x4000) // Don't fragment
	
	// TTL
	header[8] = 64
	
	// Protocol (UDP)
	header[9] = 17
	
	// Header Checksum (will be calculated)
	binary.BigEndian.PutUint16(header[10:12], 0)
	
	// Source IP (10.0.0.1)
	header[12] = 10
	header[13] = 0
	header[14] = 0
	header[15] = 1
	
	// Destination IP (10.0.0.2)
	header[16] = 10
	header[17] = 0
	header[18] = 0
	header[19] = 2
	
	// Calculate checksum
	checksum := calculateIPChecksum(header)
	binary.BigEndian.PutUint16(header[10:12], checksum)
	
	return header
}

func buildUDPHeader() []byte {
	header := make([]byte, 8)
	
	// Source port
	binary.BigEndian.PutUint16(header[0:2], 12345)
	
	// Destination port (GENEVE)
	binary.BigEndian.PutUint16(header[2:4], 6081)
	
	// Length (will be updated later)
	binary.BigEndian.PutUint16(header[4:6], 0)
	
	// Checksum (set to 0 for simplicity)
	binary.BigEndian.PutUint16(header[6:8], 0)
	
	return header
}

func calculateIPChecksum(header []byte) uint16 {
	var sum uint32
	
	// Sum all 16-bit words
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	
	// Add carry
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	
	// One's complement
	return uint16(^sum)
}

func buildGenevePacket(packet GeneveTestPacket) []byte {
	// GENEVE header format:
	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |Ver|  Opt Len |O|C|    Rsvd   |          Protocol Type        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |        Virtual Network Identifier (VNI)      |    Reserved   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Variable Length Options                    |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	var geneveData []byte

	// Calculate options length (in 4-byte units)
	optionBytes := 0
	for _, opt := range packet.Options {
		optionBytes += 4 + len(opt.Data) // 4-byte header + data
		// Pad to 4-byte boundary
		if len(opt.Data)%4 != 0 {
			optionBytes += 4 - (len(opt.Data) % 4)
		}
	}
	optionLength := uint8(optionBytes / 4)

	// First 4 bytes: Version(2) + OptLen(6) + O(1) + C(1) + Rsvd(6) + Protocol(16)
	firstWord := uint32(0)
	firstWord |= 0 << 30           // Version = 0
	firstWord |= uint32(optionLength) << 24 // Option Length
	firstWord |= 0 << 23           // O bit = 0
	firstWord |= 0 << 22           // C bit = 0
	firstWord |= 0 << 16           // Reserved = 0
	firstWord |= 0x0800            // Protocol Type = IPv4

	// Second 4 bytes: VNI(24) + Reserved(8)
	secondWord := (packet.VNI << 8) | 0 // VNI + Reserved

	// Write header
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], firstWord)
	binary.BigEndian.PutUint32(header[4:8], secondWord)
	geneveData = append(geneveData, header...)

	// Write options
	for _, opt := range packet.Options {
		// Option header: Class(16) + Type(8) + R+C+R+Length(8)
		optHeader := make([]byte, 4)
		binary.BigEndian.PutUint16(optHeader[0:2], opt.Class)
		optHeader[2] = opt.Type

		// Length field includes the option header (4 bytes) + data
		totalOptLen := 4 + len(opt.Data)
		flags := uint8(0)
		if opt.Critical {
			flags |= 0x80 // Set critical bit
		}
		optHeader[3] = flags | uint8((totalOptLen/4)-1) // Length in 4-byte units - 1

		geneveData = append(geneveData, optHeader...)
		geneveData = append(geneveData, opt.Data...)

		// Pad to 4-byte boundary
		for len(opt.Data)%4 != 0 {
			geneveData = append(geneveData, 0)
		}
	}

	// Add payload
	geneveData = append(geneveData, packet.Payload...)

	return geneveData
}