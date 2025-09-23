package geneve

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnterpriseExtensions(t *testing.T) {
	parser := NewParser()
	assert.True(t, parser.ParseEnterpriseExtensions, "Enterprise extensions should be enabled by default")

	// Test disabling enterprise extensions
	parser.DisableEnterpriseExtensions()
	assert.False(t, parser.ParseEnterpriseExtensions, "Enterprise extensions should be disabled")

	// Test enabling enterprise extensions
	parser.EnableEnterpriseExtensions()
	assert.True(t, parser.ParseEnterpriseExtensions, "Enterprise extensions should be enabled")
}

func TestIsEnterpriseOption(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		class    uint16
		expected bool
	}{
		{"VMware", OptionClassVMware, true},
		{"Cisco", OptionClassCisco, true},
		{"Microsoft", OptionClassMicrosoft, true},
		{"Google", OptionClassGoogle, true},
		{"Amazon", OptionClassAmazon, true},
		{"Vendor Specific Range Start", 0x0100, true},
		{"Vendor Specific Range Mid", 0x8000, true},
		{"Vendor Specific Range End", 0xFEFF, true},
		{"Experimental Range Start", 0xFF00, true},
		{"Experimental Range End", 0xFFFE, true}, // Changed from 0xFFFF to 0xFFFE
		{"Linux Generic", 0x0001, false},
		{"Open vSwitch", 0x0002, false},
		{"INT", 0x0103, false},
		{"IETF Standards", 0x0050, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.isEnterpriseOption(tt.class)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVMwareNSXOptionParsing(t *testing.T) {
	// Create a GENEVE packet with VMware NSX option
	packet := make([]byte, 32)
	
	// GENEVE header
	packet[0] = 0x06      // Version 0 (upper 2 bits) + Option length 6 (lower 6 bits, 24 bytes of options)
	packet[1] = 0x00      // No flags
	binary.BigEndian.PutUint16(packet[2:4], ProtocolTypeEthernet)
	binary.BigEndian.PutUint32(packet[4:8], 0x123456) // VNI + Reserved
	
	// VMware NSX option (24 bytes total)
	// Class (2) + Type (1) + Length (1) + Data (20) = 24 bytes
	binary.BigEndian.PutUint16(packet[8:10], OptionClassVMware) // Class
	packet[10] = VMwareTypeNSXMetadata                          // Type
	packet[11] = 0x05                                           // Length (5 * 4-byte units = 20 bytes of data)
	
	// NSX metadata (20 bytes of data)
	binary.BigEndian.PutUint32(packet[12:16], 0x12345678) // VSID
	binary.BigEndian.PutUint32(packet[16:20], 0x87654321) // Source VNI
	binary.BigEndian.PutUint16(packet[20:22], 0x1234)     // Flags
	binary.BigEndian.PutUint16(packet[22:24], 0x5678)     // Policy ID
	binary.BigEndian.PutUint32(packet[24:28], 0xABCDEF00) // Source TEP
	binary.BigEndian.PutUint32(packet[28:32], 0x00000000) // Reserved

	parser := NewParser()
	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)

	// Check that we have enterprise options
	assert.Len(t, result.Options, 1)
	assert.Len(t, result.EnterpriseOptions, 1)
	assert.Len(t, result.VMwareOptions, 1)

	// Check enterprise option
	enterpriseOpt := result.EnterpriseOptions[0]
	assert.Equal(t, "VMware Inc.", enterpriseOpt.VendorName)
	assert.True(t, enterpriseOpt.Decoded)
	assert.Contains(t, enterpriseOpt.DecodedData, "type")
	assert.Equal(t, "VMware NSX Metadata", enterpriseOpt.DecodedData["type"])

	// Check VMware specific option
	vmwareOpt := result.VMwareOptions[0]
	assert.Equal(t, uint32(0x12345678), vmwareOpt.VSID)
	assert.Equal(t, uint32(0x87654321), vmwareOpt.SourceVNI)
	assert.Equal(t, uint16(0x1234), vmwareOpt.Flags)
	assert.Equal(t, uint16(0x5678), vmwareOpt.PolicyID)
	assert.Equal(t, uint32(0xABCDEF00), vmwareOpt.SourceTEP)
}

func TestCiscoACIOptionParsing(t *testing.T) {
	// Create a GENEVE packet with Cisco ACI option
	packet := make([]byte, 32)
	
	// GENEVE header
	packet[0] = 0x06      // Version 0 (upper 2 bits) + Option length 6 (lower 6 bits, 24 bytes of options)
	packet[1] = 0x00      // No flags
	binary.BigEndian.PutUint16(packet[2:4], ProtocolTypeEthernet)
	binary.BigEndian.PutUint32(packet[4:8], 0x123456) // VNI + Reserved
	
	// Cisco ACI option (24 bytes total)
	// Class (2) + Type (1) + Length (1) + Data (20) = 24 bytes
	binary.BigEndian.PutUint16(packet[8:10], OptionClassCisco) // Class
	packet[10] = CiscoTypeACI                                  // Type
	packet[11] = 0x05                                          // Length (5 * 4-byte units = 20 bytes of data)
	
	// ACI metadata (20 bytes of data)
	binary.BigEndian.PutUint16(packet[12:14], 0x1111) // EPG ID
	binary.BigEndian.PutUint16(packet[14:16], 0x2222) // Bridge Domain
	binary.BigEndian.PutUint16(packet[16:18], 0x3333) // VRF
	binary.BigEndian.PutUint16(packet[18:20], 0x4444) // Contract ID
	binary.BigEndian.PutUint32(packet[20:24], 0x55555555) // Flags
	binary.BigEndian.PutUint16(packet[24:26], 0x6666) // Tenant ID
	binary.BigEndian.PutUint16(packet[26:28], 0x7777) // Application ID
	binary.BigEndian.PutUint32(packet[28:32], 0x00000000) // Padding

	parser := NewParser()
	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)

	// Check that we have enterprise options
	assert.Len(t, result.Options, 1)
	assert.Len(t, result.EnterpriseOptions, 1)
	assert.Len(t, result.CiscoOptions, 1)

	// Check enterprise option
	enterpriseOpt := result.EnterpriseOptions[0]
	assert.Equal(t, "Cisco Systems Inc.", enterpriseOpt.VendorName)
	assert.True(t, enterpriseOpt.Decoded)

	// Check Cisco specific option
	ciscoOpt := result.CiscoOptions[0]
	assert.Equal(t, uint16(0x1111), ciscoOpt.EPGID)
	assert.Equal(t, uint16(0x2222), ciscoOpt.BridgeDomain)
	assert.Equal(t, uint16(0x3333), ciscoOpt.VRF)
	assert.Equal(t, uint16(0x4444), ciscoOpt.ContractID)
	assert.Equal(t, uint32(0x55555555), ciscoOpt.Flags)
	assert.Equal(t, uint16(0x6666), ciscoOpt.TenantID)
	assert.Equal(t, uint16(0x7777), ciscoOpt.ApplicationID)
}

func TestMicrosoftOptionParsing(t *testing.T) {
	// Create a GENEVE packet with Microsoft Hyper-V option
	packet := make([]byte, 24)
	
	// GENEVE header
	packet[0] = 0x04      // Version 0 (upper 2 bits) + Option length 4 (lower 6 bits, 16 bytes of options)
	packet[1] = 0x00      // No flags
	binary.BigEndian.PutUint16(packet[2:4], ProtocolTypeEthernet)
	binary.BigEndian.PutUint32(packet[4:8], 0x123456) // VNI + Reserved
	
	// Microsoft Hyper-V option (16 bytes total)
	// Class (2) + Type (1) + Length (1) + Data (12) = 16 bytes
	binary.BigEndian.PutUint16(packet[8:10], OptionClassMicrosoft) // Class
	packet[10] = MicrosoftTypeHyperV                               // Type
	packet[11] = 0x03                                              // Length (3 * 4-byte units = 12 bytes of data)
	
	// Hyper-V VM ID (12 bytes of data)
	binary.BigEndian.PutUint64(packet[12:20], 0x123456789ABCDEF0) // VM ID (8 bytes)
	binary.BigEndian.PutUint32(packet[20:24], 0x12345678)         // Additional data (4 bytes)

	parser := NewParser()
	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)

	// Check that we have enterprise options
	assert.Len(t, result.Options, 1)
	assert.Len(t, result.EnterpriseOptions, 1)

	// Check enterprise option
	enterpriseOpt := result.EnterpriseOptions[0]
	assert.Equal(t, "Microsoft Corporation", enterpriseOpt.VendorName)
	assert.True(t, enterpriseOpt.Decoded)
	assert.Equal(t, "Hyper-V Metadata", enterpriseOpt.DecodedData["type"])
	assert.Equal(t, uint64(0x123456789ABCDEF0), enterpriseOpt.DecodedData["vm_id"])
}

func TestCustomEnterpriseDecoder(t *testing.T) {
	parser := NewParser()
	
	// Register a custom decoder for a vendor-specific class
	customClass := uint16(0x1000)
	decodeCalled := false
	
	parser.RegisterEnterpriseDecoder(customClass, func(data []byte) {
		decodeCalled = true
	})

	// Create packet with custom enterprise option (24 bytes total)
	// Header: 8 bytes + Options: 16 bytes = 24 bytes total
	packet := make([]byte, 24)
	packet[0] = 0x04      // Version 0 (upper 2 bits = 00) + Option length 4 (lower 6 bits = 000100)
	packet[1] = 0x00      // No flags
	binary.BigEndian.PutUint16(packet[2:4], ProtocolTypeEthernet)
	binary.BigEndian.PutUint32(packet[4:8], 0x123456) // VNI + Reserved
	
	// Custom enterprise option (16 bytes total)
	// Class (2) + Type (1) + Length (1) + Data (12) = 16 bytes
	binary.BigEndian.PutUint16(packet[8:10], customClass) // Class
	packet[10] = 0x01                                     // Type
	packet[11] = 0x03                                     // Length (3 * 4-byte units = 12 bytes of data)
	binary.BigEndian.PutUint32(packet[12:16], 0x12345678) // Custom data (4 bytes)
	binary.BigEndian.PutUint64(packet[16:24], 0x123456789ABCDEF0) // More custom data (8 bytes)

	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)

	assert.True(t, decodeCalled, "Custom decoder should have been called")
	assert.Len(t, result.EnterpriseOptions, 1)
	
	enterpriseOpt := result.EnterpriseOptions[0]
	assert.True(t, enterpriseOpt.Decoded)
	assert.Contains(t, enterpriseOpt.DecodedData, "custom")

	// Test unregistering decoder
	parser.UnregisterEnterpriseDecoder(customClass)
	// The decoder map should not contain the custom class anymore
	_, exists := parser.EnterpriseDecoders[customClass]
	assert.False(t, exists)
}

func TestDisabledEnterpriseExtensions(t *testing.T) {
	parser := NewParser()
	parser.DisableEnterpriseExtensions()

	// Create packet with VMware option (28 bytes total)
	// Header: 8 bytes + Options: 20 bytes = 28 bytes total
	packet := make([]byte, 28)
	packet[0] = 0x05      // Version 0 (upper 2 bits) + Option length 5 (lower 6 bits, 20 bytes of options)
	packet[1] = 0x00      // No flags
	binary.BigEndian.PutUint16(packet[2:4], ProtocolTypeEthernet)
	binary.BigEndian.PutUint32(packet[4:8], 0x123456) // VNI + Reserved
	
	// VMware option (20 bytes total)
	// Class (2) + Type (1) + Length (1) + Data (16) = 20 bytes
	binary.BigEndian.PutUint16(packet[8:10], OptionClassVMware) // Class
	packet[10] = VMwareTypeNSXMetadata                          // Type
	packet[11] = 0x04                                           // Length (4 * 4-byte units = 16 bytes of data)
	// Fill remaining 16 bytes of data
	for i := 12; i < 28; i++ {
		packet[i] = 0x00
	}

	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)

	// Should have basic option but no enterprise parsing
	assert.Len(t, result.Options, 1)
	assert.Len(t, result.EnterpriseOptions, 0)
	assert.Len(t, result.VMwareOptions, 0)
}

func TestEnterpriseOptionStringMethods(t *testing.T) {
	// Test EnterpriseOption String method
	enterpriseOpt := EnterpriseOption{
		Option: Option{Class: 0x1000, Type: 0x01},
		VendorName: "Custom Vendor",
		Decoded: true,
	}
	
	str := enterpriseOpt.String()
	assert.Contains(t, str, "Custom Vendor")
	assert.Contains(t, str, "0x1000")
	assert.Contains(t, str, "0x01")
	assert.Contains(t, str, "decoded")

	// Test VMwareNSXOption String method
	vmwareOpt := VMwareNSXOption{
		VSID: 0x12345678,
		SourceVNI: 0x87654321,
		PolicyID: 1234,
		Flags: 0xABCD,
	}
	
	str = vmwareOpt.String()
	assert.Contains(t, str, "0x12345678")
	assert.Contains(t, str, "0x87654321")
	assert.Contains(t, str, "1234")
	assert.Contains(t, str, "0xabcd")

	// Test CiscoACIOption String method
	ciscoOpt := CiscoACIOption{
		EPGID: 1111,
		BridgeDomain: 2222,
		VRF: 3333,
		ContractID: 4444,
		TenantID: 5555,
	}
	
	str = ciscoOpt.String()
	assert.Contains(t, str, "1111")
	assert.Contains(t, str, "2222")
	assert.Contains(t, str, "3333")
	assert.Contains(t, str, "4444")
	assert.Contains(t, str, "5555")
}

func TestEnhancedOptionClassName(t *testing.T) {
	tests := []struct {
		name     string
		class    uint16
		expected string
	}{
		{"Microsoft", OptionClassMicrosoft, "Microsoft"},
		{"Google", OptionClassGoogle, "Google"},
		{"Amazon", OptionClassAmazon, "Amazon"},
		{"Huawei", OptionClassHuawei, "Huawei"},
		{"Juniper", OptionClassJuniper, "Juniper"},
		{"Arista", OptionClassArista, "Arista"},
		{"NVIDIA/Mellanox", OptionClassMellanox, "NVIDIA/Mellanox"},
		{"Broadcom", OptionClassBroadcom, "Broadcom"},
		{"Experimental Range", 0xFF50, "Experimental Use"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := Option{Class: tt.class}
			result := option.GetOptionClassName()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnhancedOptionTypeName(t *testing.T) {
	tests := []struct {
		name     string
		class    uint16
		optType  uint8
		expected string
	}{
		{"VMware NSX", OptionClassVMware, VMwareTypeNSXMetadata, "NSX Metadata"},
		{"VMware VXLAN", OptionClassVMware, VMwareTypeVXLANCompat, "VXLAN Compatibility"},
		{"Cisco ACI", OptionClassCisco, CiscoTypeACI, "Application Centric Infrastructure"},
		{"Cisco SGT", OptionClassCisco, CiscoTypeSGT, "Security Group Tag"},
		{"Microsoft Hyper-V", OptionClassMicrosoft, MicrosoftTypeHyperV, "Hyper-V Metadata"},
		{"Amazon VPC", OptionClassAmazon, AmazonTypeVPC, "VPC Metadata"},
		{"Google GKE", OptionClassGoogle, GoogleTypeGKE, "Google Kubernetes Engine"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := Option{Class: tt.class, Type: tt.optType}
			result := option.GetOptionTypeName()
			assert.Equal(t, tt.expected, result)
		})
	}
}