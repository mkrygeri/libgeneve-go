package geneve

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestGenevePacket creates a test GENEVE packet with specified parameters
func createTestGenevePacket(vni uint32, protocolType uint16, options []byte, payload []byte) []byte {
	optionLength := len(options) / 4 // Option length in 4-byte units
	if len(options)%4 != 0 {
		optionLength++
	}

	packet := make([]byte, 8+len(options)+len(payload))
	
	// First byte: Version (2 bits) + Option Length (6 bits)
	packet[0] = (GeneveVersion << 6) | uint8(optionLength&0x3F)
	
	// Second byte: O flag (1 bit) + C flag (1 bit) + Reserved (6 bits)
	packet[1] = 0x00 // No flags set
	
	// Protocol type (2 bytes)
	binary.BigEndian.PutUint16(packet[2:4], protocolType)
	
	// VNI (24 bits) + Reserved (8 bits)
	vniReserved := (vni << 8) | 0x00
	binary.BigEndian.PutUint32(packet[4:8], vniReserved)
	
	// Copy options
	if len(options) > 0 {
		copy(packet[8:8+len(options)], options)
	}
	
	// Copy payload
	if len(payload) > 0 {
		copy(packet[8+len(options):], payload)
	}
	
	return packet
}

// createTestOption creates a test GENEVE option
func createTestOption(class uint16, optionType uint8, data []byte) []byte {
	// Pad data to 4-byte boundary
	paddedData := make([]byte, ((len(data)+3)/4)*4)
	copy(paddedData, data)
	
	length := len(paddedData) / 4
	option := make([]byte, 4+len(paddedData))
	
	// Class (16 bits)
	binary.BigEndian.PutUint16(option[0:2], class)
	
	// Type (8 bits)
	option[2] = optionType
	
	// Reserved (3 bits) + Length (5 bits)
	option[3] = uint8(length & 0x1F)
	
	// Data
	copy(option[4:], paddedData)
	
	return option
}

// createTestINTMetadataOption creates a test INT metadata option
func createTestINTMetadataOption() []byte {
	data := make([]byte, 16)
	
	// Version (4) + Discard (1) + ExceededMaxHops (1) + MTUExceeded (1) + Reserved (1)
	data[0] = (4 << 4) | 0x08 // Version 4, Discard=true (bit 3)
	
	// Reserved (12) + HopML (5)
	binary.BigEndian.PutUint16(data[1:3], 0x0005) // HopML = 5
	
	// Remaining hop count
	data[3] = 10
	
	// Instruction bitmap
	binary.BigEndian.PutUint16(data[4:6], 0x1234)
	
	// Domain specific ID
	binary.BigEndian.PutUint16(data[6:8], 0x0100)
	
	// Domain instruction
	binary.BigEndian.PutUint16(data[8:10], 0x5678)
	
	// Domain flags
	binary.BigEndian.PutUint16(data[10:12], 0x9ABC)
	
	return createTestOption(0x0103, 0x01, data)
}

func TestParseBasicHeader(t *testing.T) {
	tests := []struct {
		name     string
		vni      uint32
		protocol uint16
	}{
		{"IPv4 payload", 0x123456, ProtocolTypeIPv4},
		{"IPv6 payload", 0xABCDEF, ProtocolTypeIPv6},
		{"Ethernet payload", 0x000001, ProtocolTypeEthernet},
		{"Zero VNI", 0x000000, ProtocolTypeIPv4},
		{"Max VNI", 0xFFFFFF, ProtocolTypeIPv4},
	}

	parser := NewParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte("test payload")
			packet := createTestGenevePacket(tt.vni, tt.protocol, nil, payload)

			result, err := parser.ParsePacket(packet)
			require.NoError(t, err)
			assert.NotNil(t, result)

			// Check header
			assert.Equal(t, GeneveVersion, int(result.Header.Version))
			assert.Equal(t, tt.vni, result.Header.VNI)
			assert.Equal(t, tt.protocol, result.Header.ProtocolType)
			assert.Equal(t, uint8(0), result.Header.OptionLength)
			assert.False(t, result.Header.OFlag)
			assert.False(t, result.Header.CFlag)

			// Check payload
			assert.Equal(t, payload, result.Payload)
			assert.Equal(t, GeneveHeaderSize, result.PayloadOffset)
			assert.Empty(t, result.Options)
		})
	}
}

func TestParseWithOptions(t *testing.T) {
	parser := NewParser()

	// Create a simple option
	optionData := []byte{0x12, 0x34, 0x56, 0x78}
	option := createTestOption(0x0001, 0x02, optionData)
	payload := []byte("test payload")
	packet := createTestGenevePacket(0x123456, ProtocolTypeIPv4, option, payload)

	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Check header
	assert.Equal(t, uint8(2), result.Header.OptionLength) // 8 bytes = 2 * 4-byte units
	assert.Equal(t, uint32(0x123456), result.Header.VNI)

	// Check options
	assert.Len(t, result.Options, 1)
	assert.Equal(t, uint16(0x0001), result.Options[0].Class)
	assert.Equal(t, uint8(0x02), result.Options[0].Type)
	assert.Equal(t, uint8(1), result.Options[0].Length) // 4 bytes = 1 * 4-byte unit
	assert.Equal(t, optionData, result.Options[0].Data)

	// Check payload
	assert.Equal(t, payload, result.Payload)
	assert.Equal(t, GeneveHeaderSize+len(option), result.PayloadOffset)
}

func TestParseINTMetadataOption(t *testing.T) {
	parser := NewParser()

	// Create INT metadata option
	intOption := createTestINTMetadataOption()
	payload := []byte("test payload")
	packet := createTestGenevePacket(0x123456, ProtocolTypeIPv4, intOption, payload)

	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Check that we have both regular option and INT option
	assert.Len(t, result.Options, 1)
	assert.Len(t, result.INTOptions, 1)

	// Check INT option details
	intOpt := result.INTOptions[0]
	assert.Equal(t, uint8(4), intOpt.Version)
	assert.True(t, intOpt.Discard)
	assert.False(t, intOpt.ExceededMaxHops)
	assert.False(t, intOpt.MTUExceeded)
	assert.Equal(t, uint8(5), intOpt.HopML)
	assert.Equal(t, uint8(10), intOpt.RemainingHopCount)
	assert.Equal(t, uint16(0x1234), intOpt.InstructionBitmap)
	assert.Equal(t, uint16(0x0100), intOpt.DomainSpecificID)
	assert.Equal(t, uint16(0x5678), intOpt.DomainInstruction)
	assert.Equal(t, uint16(0x9ABC), intOpt.DomainFlags)
}

func TestParseMultipleOptions(t *testing.T) {
	parser := NewParser()

	// Create multiple options
	option1 := createTestOption(0x0001, 0x02, []byte{0x12, 0x34})
	option2 := createTestOption(0x0002, 0x03, []byte{0x56, 0x78, 0x9A, 0xBC})
	intOption := createTestINTMetadataOption()

	allOptions := append(append(option1, option2...), intOption...)
	payload := []byte("test payload")
	packet := createTestGenevePacket(0x123456, ProtocolTypeIPv4, allOptions, payload)

	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Check options
	assert.Len(t, result.Options, 3)
	assert.Len(t, result.INTOptions, 1)

	// Check first option
	assert.Equal(t, uint16(0x0001), result.Options[0].Class)
	assert.Equal(t, uint8(0x02), result.Options[0].Type)

	// Check second option
	assert.Equal(t, uint16(0x0002), result.Options[1].Class)
	assert.Equal(t, uint8(0x03), result.Options[1].Type)

	// Check third option (INT)
	assert.Equal(t, uint16(0x0103), result.Options[2].Class)
	assert.Equal(t, uint8(0x01), result.Options[2].Type)
}

func TestParseNestedGENEVE(t *testing.T) {
	parser := NewParser()
	parser.ParseNestedLayers = true

	// Create inner GENEVE packet
	innerPayload := []byte("inner payload")
	innerPacket := createTestGenevePacket(0x654321, ProtocolTypeEthernet, nil, innerPayload)

	// Create outer GENEVE packet with inner packet as payload
	outerPacket := createTestGenevePacket(0x123456, ProtocolTypeIPv4, nil, innerPacket)

	result, err := parser.ParsePacket(outerPacket)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Check outer layer
	assert.Equal(t, uint32(0x123456), result.Header.VNI)
	assert.Equal(t, uint16(ProtocolTypeIPv4), result.Header.ProtocolType)

	// Check nested layer
	assert.Len(t, result.InnerLayers, 1)
	innerResult := result.InnerLayers[0]
	assert.Equal(t, uint32(0x654321), innerResult.Header.VNI)
	assert.Equal(t, uint16(ProtocolTypeEthernet), innerResult.Header.ProtocolType)
	assert.Equal(t, innerPayload, innerResult.Payload)
}

func TestParseErrors(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name   string
		packet []byte
		errMsg string
	}{
		{
			name:   "Too short packet",
			packet: []byte{0x01, 0x02, 0x03},
			errMsg: "packet too short",
		},
		{
			name:   "Invalid version",
			packet: []byte{0x40, 0x00, 0x08, 0x00, 0x12, 0x34, 0x56, 0x00}, // Version 1
			errMsg: "unsupported GENEVE version",
		},
		{
			name:   "Options too short",
			packet: []byte{0x01, 0x00, 0x08, 0x00, 0x12, 0x34, 0x56, 0x00}, // Option length = 1 but no options
			errMsg: "packet too short for options",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParsePacket(tt.packet)
			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestHeaderMethods(t *testing.T) {
	header := &Header{
		Version:      0,
		VNI:          0x123456,
		ProtocolType: ProtocolTypeIPv4,
		OFlag:        true,
		CFlag:        false,
	}

	assert.Equal(t, uint32(0x123456), header.GetVNI())
	assert.True(t, header.IsOAMPacket())
	assert.False(t, header.HasCriticalOptions())
	assert.Equal(t, "IPv4", header.GetProtocolName())

	// Test unknown protocol
	header.ProtocolType = 0x9999
	assert.Equal(t, "Unknown(0x9999)", header.GetProtocolName())

	// Test string representation
	str := header.String()
	assert.Contains(t, str, "GENEVE")
	assert.Contains(t, str, "VNI:1193046")
	assert.Contains(t, str, "O=true")
	assert.Contains(t, str, "C=false")
}

func TestParserConfiguration(t *testing.T) {
	parser := NewParser()

	// Test default configuration
	assert.Equal(t, uint8(63), parser.MaxOptionLength)
	assert.True(t, parser.ParseNestedLayers)
	assert.Equal(t, 3, parser.MaxNestedDepth)

	// Test custom configuration
	parser.MaxOptionLength = 10
	parser.ParseNestedLayers = false
	parser.MaxNestedDepth = 1

	// Create packet with option length exceeding limit
	packet := make([]byte, 8)
	packet[0] = 0x0B // Version 0, Option length 11 (exceeds limit of 10)
	binary.BigEndian.PutUint16(packet[2:4], ProtocolTypeIPv4)

	result, err := parser.ParsePacket(packet)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "option length too large")
}

func TestMaxNestedDepth(t *testing.T) {
	parser := NewParser()
	parser.MaxNestedDepth = 1

	// Create deeply nested GENEVE packets
	level3 := createTestGenevePacket(3, ProtocolTypeEthernet, nil, []byte("level3"))
	level2 := createTestGenevePacket(2, ProtocolTypeIPv4, nil, level3)
	level1 := createTestGenevePacket(1, ProtocolTypeIPv4, nil, level2)

	result, err := parser.ParsePacket(level1)
	require.NoError(t, err)

	// Should only parse to depth 1
	assert.Len(t, result.InnerLayers, 1)
	assert.Equal(t, uint32(2), result.InnerLayers[0].Header.VNI)
	
	// Level 2 should not have inner layers due to depth limit
	assert.Len(t, result.InnerLayers[0].InnerLayers, 0)
}

// Benchmark tests
func BenchmarkParseBasicPacket(b *testing.B) {
	parser := NewParser()
	payload := []byte("benchmark payload data")
	packet := createTestGenevePacket(0x123456, ProtocolTypeIPv4, nil, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.ParsePacket(packet)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseWithOptions(b *testing.B) {
	parser := NewParser()
	option := createTestOption(0x0001, 0x02, []byte{0x12, 0x34, 0x56, 0x78})
	payload := []byte("benchmark payload data")
	packet := createTestGenevePacket(0x123456, ProtocolTypeIPv4, option, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.ParsePacket(packet)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseINTOption(b *testing.B) {
	parser := NewParser()
	intOption := createTestINTMetadataOption()
	payload := []byte("benchmark payload data")
	packet := createTestGenevePacket(0x123456, ProtocolTypeIPv4, intOption, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.ParsePacket(packet)
		if err != nil {
			b.Fatal(err)
		}
	}
}