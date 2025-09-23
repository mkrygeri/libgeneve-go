package test

import (
	"bytes"
	"encoding/binary"
)

// CreateGENEVEPacketWithVMwareTelemetry creates a synthetic GENEVE packet with VMware NSX telemetry
func CreateGENEVEPacketWithVMwareTelemetry() []byte {
	var buf bytes.Buffer
	
	// Ethernet header (14 bytes)
	ethHeader := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dst MAC
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Src MAC
		0x08, 0x00, // EtherType (IPv4)
	}
	buf.Write(ethHeader)
	
	// IP header (20 bytes)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45  // Version + IHL
	ipHeader[1] = 0x00  // TOS
	binary.BigEndian.PutUint16(ipHeader[2:4], 80) // Total Length
	binary.BigEndian.PutUint16(ipHeader[4:6], 1234) // ID
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000) // Flags + Fragment
	ipHeader[8] = 64    // TTL
	ipHeader[9] = 17    // Protocol (UDP)
	// Skip checksum for simplicity
	ipHeader[12] = 192  // Src IP: 192.168.1.100
	ipHeader[13] = 168
	ipHeader[14] = 1
	ipHeader[15] = 100
	ipHeader[16] = 10   // Dst IP: 10.0.0.50
	ipHeader[17] = 0
	ipHeader[18] = 0
	ipHeader[19] = 50
	buf.Write(ipHeader)
	
	// UDP header (8 bytes)
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], 54321) // Src Port
	binary.BigEndian.PutUint16(udpHeader[2:4], 6081)  // Dst Port (GENEVE)
	binary.BigEndian.PutUint16(udpHeader[4:6], 52)    // Length
	// Skip checksum
	buf.Write(udpHeader)
	
	// GENEVE header with VMware NSX option
	geneveHeader := make([]byte, 8)
	geneveHeader[0] = 0x02  // Ver(0) + Opt Len(2) - 8 bytes of options
	geneveHeader[1] = 0x00  // O + C + Rsvd
	binary.BigEndian.PutUint16(geneveHeader[2:4], 0x0800) // Protocol Type (IPv4)
	// VNI (24 bits) = 0x123456 (VMware NSX segment)
	geneveHeader[4] = 0x12
	geneveHeader[5] = 0x34
	geneveHeader[6] = 0x56
	geneveHeader[7] = 0x00  // Reserved
	buf.Write(geneveHeader)
	
	// VMware NSX Option (8 bytes) - properly formatted
	vmwareOption := make([]byte, 8)
	binary.BigEndian.PutUint16(vmwareOption[0:2], 0x0008) // Class: VMware (0x0008)
	vmwareOption[2] = 0x81  // Type: NSX Segment ID (with C=1, critical)
	vmwareOption[3] = 0x01  // Length: 1 * 4 = 4 bytes
	binary.BigEndian.PutUint32(vmwareOption[4:8], 4096) // Segment ID: 4096
	buf.Write(vmwareOption)
	
	// Inner IPv4 packet
	innerIP := make([]byte, 20)
	innerIP[0] = 0x45    // Version + IHL
	innerIP[1] = 0x00    // TOS
	binary.BigEndian.PutUint16(innerIP[2:4], 28) // Total Length
	binary.BigEndian.PutUint16(innerIP[4:6], 5678) // ID
	binary.BigEndian.PutUint16(innerIP[6:8], 0x4000) // Flags
	innerIP[8] = 64      // TTL
	innerIP[9] = 1       // Protocol (ICMP)
	innerIP[12] = 172    // Src IP: 172.16.1.10
	innerIP[13] = 16
	innerIP[14] = 1
	innerIP[15] = 10
	innerIP[16] = 172    // Dst IP: 172.16.2.20
	innerIP[17] = 16
	innerIP[18] = 2
	innerIP[19] = 20
	buf.Write(innerIP)
	
	// Simple ICMP payload
	icmpPayload := []byte{0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78}
	buf.Write(icmpPayload)
	
	return buf.Bytes()
}

// CreateGENEVEPacketWithCiscoTelemetry creates a synthetic GENEVE packet with Cisco ACI telemetry
func CreateGENEVEPacketWithCiscoTelemetry() []byte {
	var buf bytes.Buffer
	
	// Ethernet header
	ethHeader := []byte{
		0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
	}
	buf.Write(ethHeader)
	
	// IP header
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	ipHeader[1] = 0x00
	binary.BigEndian.PutUint16(ipHeader[2:4], 88)
	binary.BigEndian.PutUint16(ipHeader[4:6], 9999)
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000)
	ipHeader[8] = 64
	ipHeader[9] = 17
	ipHeader[12] = 10    // Src IP: 10.1.1.1
	ipHeader[13] = 1
	ipHeader[14] = 1
	ipHeader[15] = 1
	ipHeader[16] = 10    // Dst IP: 10.2.2.2
	ipHeader[17] = 2
	ipHeader[18] = 2
	ipHeader[19] = 2
	buf.Write(ipHeader)
	
	// UDP header
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], 45678)
	binary.BigEndian.PutUint16(udpHeader[2:4], 6081)
	binary.BigEndian.PutUint16(udpHeader[4:6], 60)
	buf.Write(udpHeader)
	
	// GENEVE header with Cisco ACI options
	geneveHeader := make([]byte, 8)
	geneveHeader[0] = 0x04  // Ver(0) + Opt Len(4) - 16 bytes of options
	geneveHeader[1] = 0x00
	binary.BigEndian.PutUint16(geneveHeader[2:4], 0x0800)
	// VNI for ACI tenant
	geneveHeader[4] = 0x78
	geneveHeader[5] = 0x9A
	geneveHeader[6] = 0xBC
	geneveHeader[7] = 0x00
	buf.Write(geneveHeader)
	
	// Cisco ACI EPG Option (8 bytes) - properly formatted
	ciscoOption1 := make([]byte, 8)
	binary.BigEndian.PutUint16(ciscoOption1[0:2], 0x0009) // Class: Cisco (0x0009)
	ciscoOption1[2] = 0x81  // Type: ACI EPG ID (with C=1, critical)
	ciscoOption1[3] = 0x01  // Length: 1 * 4 = 4 bytes
	binary.BigEndian.PutUint32(ciscoOption1[4:8], 12345) // EPG ID
	buf.Write(ciscoOption1)
	
	// Cisco ACI Contract Option (8 bytes) - properly formatted
	ciscoOption2 := make([]byte, 8)
	binary.BigEndian.PutUint16(ciscoOption2[0:2], 0x0009) // Class: Cisco
	ciscoOption2[2] = 0x83  // Type: Contract ID (with C=1, critical)
	ciscoOption2[3] = 0x01  // Length: 1 * 4 = 4 bytes
	binary.BigEndian.PutUint32(ciscoOption2[4:8], 98765) // Contract ID
	buf.Write(ciscoOption2)
	
	// Inner payload
	payload := []byte("Cisco ACI GENEVE payload data")
	buf.Write(payload)
	
	return buf.Bytes()
}

// CreateGENEVEPacketWithMultiVendorTelemetry creates a complex packet with multiple vendor telemetries
func CreateGENEVEPacketWithMultiVendorTelemetry() []byte {
	var buf bytes.Buffer
	
	// Ethernet header
	ethHeader := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x08, 0x00,
	}
	buf.Write(ethHeader)
	
	// IP header
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	ipHeader[1] = 0x00
	binary.BigEndian.PutUint16(ipHeader[2:4], 120) // Larger packet
	binary.BigEndian.PutUint16(ipHeader[4:6], 7777)
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000)
	ipHeader[8] = 64
	ipHeader[9] = 17
	ipHeader[12] = 203   // Src IP: 203.0.113.1
	ipHeader[13] = 0
	ipHeader[14] = 113
	ipHeader[15] = 1
	ipHeader[16] = 198   // Dst IP: 198.51.100.1
	ipHeader[17] = 51
	ipHeader[18] = 100
	ipHeader[19] = 1
	buf.Write(ipHeader)
	
	// UDP header
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], 33445)
	binary.BigEndian.PutUint16(udpHeader[2:4], 6081)
	binary.BigEndian.PutUint16(udpHeader[4:6], 92)
	buf.Write(udpHeader)
	
	// GENEVE header with multiple options
	geneveHeader := make([]byte, 8)
	geneveHeader[0] = 0x06  // Ver(0) + Opt Len(6) - 24 bytes of options
	geneveHeader[1] = 0x00
	binary.BigEndian.PutUint16(geneveHeader[2:4], 0x86DD) // IPv6 inner
	// Multi-tenant VNI
	geneveHeader[4] = 0xFF
	geneveHeader[5] = 0xAA
	geneveHeader[6] = 0x55
	geneveHeader[7] = 0x00
	buf.Write(geneveHeader)
	
	// VMware NSX Option - properly formatted
	vmwareOpt := make([]byte, 8)
	binary.BigEndian.PutUint16(vmwareOpt[0:2], 0x0008) // VMware
	vmwareOpt[2] = 0x82  // Type: Service Chain (with C=1, critical)
	vmwareOpt[3] = 0x01  // Length: 1 * 4 = 4 bytes
	binary.BigEndian.PutUint32(vmwareOpt[4:8], 8192) // Service Chain ID
	buf.Write(vmwareOpt)
	
	// Microsoft Azure Option - properly formatted
	azureOpt := make([]byte, 8)
	binary.BigEndian.PutUint16(azureOpt[0:2], 0x0137) // Microsoft
	azureOpt[2] = 0x81  // Type: Virtual Network (with C=1, critical)
	azureOpt[3] = 0x01  // Length: 1 * 4 = 4 bytes
	binary.BigEndian.PutUint32(azureOpt[4:8], 5678) // VNet ID
	buf.Write(azureOpt)
	
	// Arista Networks Option - properly formatted
	aristaOpt := make([]byte, 8)
	binary.BigEndian.PutUint16(aristaOpt[0:2], 0xF000) // Arista (experimental range)
	aristaOpt[2] = 0x90  // Type: Flow Monitoring (with C=1, critical)
	aristaOpt[3] = 0x01  // Length: 1 * 4 = 4 bytes
	binary.BigEndian.PutUint32(aristaOpt[4:8], 0x1234ABCD) // Flow ID
	buf.Write(aristaOpt)
	
	// Simple IPv6 inner header (40 bytes)
	ipv6Header := make([]byte, 40)
	binary.BigEndian.PutUint32(ipv6Header[0:4], 0x60000000) // Version + Traffic Class + Flow Label
	binary.BigEndian.PutUint16(ipv6Header[4:6], 24) // Payload Length
	ipv6Header[6] = 58  // Next Header (ICMPv6)
	ipv6Header[7] = 64  // Hop Limit
	// Src: 2001:db8::1
	binary.BigEndian.PutUint64(ipv6Header[8:16], 0x20010db800000000)
	binary.BigEndian.PutUint64(ipv6Header[16:24], 0x0000000000000001)
	// Dst: 2001:db8::2
	binary.BigEndian.PutUint64(ipv6Header[24:32], 0x20010db800000000)
	binary.BigEndian.PutUint64(ipv6Header[32:40], 0x0000000000000002)
	buf.Write(ipv6Header)
	
	// ICMPv6 payload
	icmpv6 := []byte("Multi-vendor GENEVE test packet")
	buf.Write(icmpv6)
	
	return buf.Bytes()
}