package geneve

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketBuilder(t *testing.T) {
	builder := NewPacketBuilder()
	payload := []byte("test payload")

	packet := builder.
		SetVNI(0x123456).
		SetProtocolType(ProtocolTypeIPv4).
		SetOAMFlag(true).
		SetCriticalFlag(false).
		AddOption(0x0001, 0x02, []byte{0x12, 0x34}).
		SetPayload(payload).
		Build()

	// Parse the built packet to verify
	parser := NewParser()
	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)

	// Verify header
	assert.Equal(t, uint32(0x123456), result.Header.VNI)
	assert.Equal(t, uint16(ProtocolTypeIPv4), result.Header.ProtocolType)
	assert.True(t, result.Header.OFlag)
	assert.False(t, result.Header.CFlag)

	// Verify options
	assert.Len(t, result.Options, 1)
	assert.Equal(t, uint16(0x0001), result.Options[0].Class)
	assert.Equal(t, uint8(0x02), result.Options[0].Type)

	// Verify payload
	assert.Equal(t, payload, result.Payload)
}

func TestPacketBuilderINTOption(t *testing.T) {
	builder := NewPacketBuilder()
	
	intOpt := INTMetadataOption{
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

	packet := builder.
		SetVNI(0x654321).
		AddINTMetadataOption(intOpt).
		Build()

	// Parse and verify
	parser := NewParser()
	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)

	assert.Len(t, result.INTOptions, 1)
	parsedINT := result.INTOptions[0]
	
	assert.Equal(t, uint8(4), parsedINT.Version)
	assert.True(t, parsedINT.Discard)
	assert.False(t, parsedINT.ExceededMaxHops)
	assert.False(t, parsedINT.MTUExceeded)
	assert.Equal(t, uint8(5), parsedINT.HopML)
	assert.Equal(t, uint8(10), parsedINT.RemainingHopCount)
	assert.Equal(t, uint16(0x1234), parsedINT.InstructionBitmap)
	assert.Equal(t, uint16(0x0100), parsedINT.DomainSpecificID)
	assert.Equal(t, uint16(0x5678), parsedINT.DomainInstruction)
	assert.Equal(t, uint16(0x9ABC), parsedINT.DomainFlags)
}

func TestStatistics(t *testing.T) {
	stats := NewStatistics()
	parser := NewParser()

	// Create test packets
	packet1 := NewPacketBuilder().SetVNI(0x123456).SetProtocolType(ProtocolTypeIPv4).Build()
	packet2 := NewPacketBuilder().SetVNI(0x654321).SetProtocolType(ProtocolTypeIPv6).Build()
	invalidPacket := []byte{0x01, 0x02} // Too short

	// Parse and update statistics
	result1, err1 := parser.ParsePacket(packet1)
	stats.UpdateFromResult(result1, err1)

	result2, err2 := parser.ParsePacket(packet2)
	stats.UpdateFromResult(result2, err2)

	result3, err3 := parser.ParsePacket(invalidPacket)
	stats.UpdateFromResult(result3, err3)

	// Check statistics
	assert.Equal(t, 3, stats.TotalPackets)
	assert.Equal(t, 2, stats.SuccessfulParse)
	assert.Equal(t, 1, stats.FailedParse)
	assert.Equal(t, 1, stats.ProtocolCounts[ProtocolTypeIPv4])
	assert.Equal(t, 1, stats.ProtocolCounts[ProtocolTypeIPv6])
	assert.Equal(t, 1, stats.VNICounts[0x123456])
	assert.Equal(t, 1, stats.VNICounts[0x654321])

	// Check string representation
	str := stats.String()
	assert.Contains(t, str, "Total Packets: 3")
	assert.Contains(t, str, "Successful: 2")
	assert.Contains(t, str, "Failed: 1")
}

func TestValidator(t *testing.T) {
	validator := NewValidator()
	parser := NewParser()

	// Create valid packet
	validPacket := NewPacketBuilder().SetVNI(0x123456).Build()
	result, err := parser.ParsePacket(validPacket)
	require.NoError(t, err)

	violations := validator.ValidatePacket(result)
	assert.Empty(t, violations)
	assert.True(t, validator.IsValid(result))

	// Test with invalid version
	validator.EnforceStrictVersion = true
	result.Header.Version = 1 // Invalid version
	violations = validator.ValidatePacket(result)
	assert.NotEmpty(t, violations)
	assert.False(t, validator.IsValid(result))
	assert.Contains(t, violations[0], "Invalid version")

	// Reset and test reserved fields
	result.Header.Version = 0
	validator.ValidateReservedFields = true
	result.Header.Reserved1 = 0x01 // Should be zero
	violations = validator.ValidatePacket(result)
	assert.NotEmpty(t, violations)
	assert.Contains(t, violations[0], "Reserved1 field not zero")
}

func TestValidatorMaxOptions(t *testing.T) {
	validator := NewValidator()
	validator.MaxAllowedOptions = 2

	builder := NewPacketBuilder()
	// Add 3 options (exceeds limit of 2)
	packet := builder.
		AddOption(0x0001, 0x01, []byte{0x01}).
		AddOption(0x0002, 0x02, []byte{0x02}).
		AddOption(0x0003, 0x03, []byte{0x03}).
		Build()

	parser := NewParser()
	result, err := parser.ParsePacket(packet)
	require.NoError(t, err)

	violations := validator.ValidatePacket(result)
	assert.NotEmpty(t, violations)
	assert.Contains(t, violations[0], "Too many options")
}

func TestValidatorNestedLayers(t *testing.T) {
	validator := NewValidator()
	validator.EnforceStrictVersion = true

	// Create nested packet with invalid inner version
	innerPacket := NewPacketBuilder().SetVNI(0x654321).Build()
	outerPacket := NewPacketBuilder().SetVNI(0x123456).SetPayload(innerPacket).Build()

	parser := NewParser()
	result, err := parser.ParsePacket(outerPacket)
	require.NoError(t, err)

	// Manually set invalid version in nested layer for testing
	if len(result.InnerLayers) > 0 {
		result.InnerLayers[0].Header.Version = 1
	}

	violations := validator.ValidatePacket(result)
	if len(result.InnerLayers) > 0 {
		assert.NotEmpty(t, violations)
		assert.Contains(t, violations[0], "Nested layer")
	}
}

// Benchmark tests for utilities
func BenchmarkPacketBuilder(b *testing.B) {
	payload := []byte("benchmark payload")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder := NewPacketBuilder()
		_ = builder.
			SetVNI(0x123456).
			SetProtocolType(ProtocolTypeIPv4).
			AddOption(0x0001, 0x02, []byte{0x12, 0x34}).
			SetPayload(payload).
			Build()
	}
}

func BenchmarkStatisticsUpdate(b *testing.B) {
	stats := NewStatistics()
	parser := NewParser()
	packet := NewPacketBuilder().SetVNI(0x123456).Build()
	result, _ := parser.ParsePacket(packet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.UpdateFromResult(result, nil)
	}
}

func BenchmarkValidator(b *testing.B) {
	validator := NewValidator()
	parser := NewParser()
	packet := NewPacketBuilder().SetVNI(0x123456).Build()
	result, _ := parser.ParsePacket(packet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidatePacket(result)
	}
}