package geneve

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionClassName(t *testing.T) {
	tests := []struct {
		name     string
		class    uint16
		expected string
	}{
		{"Experimental", 0x0000, "Experimental"},
		{"Linux Generic", 0x0001, "Linux Generic"},
		{"Open vSwitch", 0x0002, "Open vSwitch"},
		{"VMware", 0x0003, "VMware"},
		{"Cisco", 0x0004, "Cisco"},
		{"INT", 0x0103, "INT (In-band Network Telemetry)"},
		{"Platform Specific", 0xFFFF, "Platform Specific"},
		{"IETF Standards", 0x0055, "IETF Standards"},
		{"Vendor Specific", 0x1000, "Vendor Specific"},
		{"Vendor Specific 2", 0x9999, "Vendor Specific"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := Option{Class: tt.class}
			result := opt.GetOptionClassName()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOptionTypeName(t *testing.T) {
	tests := []struct {
		name     string
		class    uint16
		optType  uint8
		expected string
	}{
		{"INT Metadata", 0x0103, INTTypeMetadata, "INT Metadata"},
		{"INT Destination", 0x0103, INTTypeDestination, "INT Destination"},
		{"INT MX", 0x0103, INTTypeMX, "INT Monitoring & Export"},
		{"INT Source", 0x0103, INTTypeSource, "INT Source"},
		{"INT Sink", 0x0103, INTTypeSink, "INT Sink"},
		{"Generic Timestamp", 0x0001, GenericTypeTimestamp, "Timestamp"},
		{"Security Tag", 0x0001, GenericTypeSecurityTag, "Security Tag"},
		{"QoS Marking", 0x0001, GenericTypeQoSMarking, "QoS Marking"},
		{"OAM Echo", 0x0000, OAMTypeEcho, "OAM Echo"},
		{"OAM Trace", 0x0000, OAMTypeTrace, "OAM Trace"},
		{"Unknown Type", 0x0001, 0x99, "Generic Type 0x99"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := Option{Class: tt.class, Type: tt.optType}
			result := opt.GetOptionTypeName()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOptionDescription(t *testing.T) {
	opt := Option{Class: 0x0103, Type: INTTypeMetadata}
	desc := opt.GetOptionDescription()
	assert.Equal(t, "INT (In-band Network Telemetry) - INT Metadata", desc)
}

func TestOptionStringRepresentation(t *testing.T) {
	opt := Option{Class: 0x0001, Type: GenericTypeTimestamp, Length: 2}
	str := opt.String()
	expected := "Option(Class:Linux Generic, Type:Timestamp, Length:8 bytes)"
	assert.Equal(t, expected, str)
}

func TestIsINTOption(t *testing.T) {
	tests := []struct {
		name     string
		class    uint16
		expected bool
	}{
		{"INT Option", 0x0103, true},
		{"Non-INT Option", 0x0001, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := Option{Class: tt.class}
			assert.Equal(t, tt.expected, opt.IsINTOption())
		})
	}
}

func TestIsCritical(t *testing.T) {
	tests := []struct {
		name     string
		class    uint16
		optType  uint8
		expected bool
	}{
		{"INT Option", 0x0103, INTTypeMetadata, true},
		{"Security Tag", 0x0001, GenericTypeSecurityTag, true},
		{"Regular Option", 0x0001, GenericTypeTimestamp, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := Option{Class: tt.class, Type: tt.optType}
			assert.Equal(t, tt.expected, opt.IsCritical())
		})
	}
}

func TestINTInstructionNames(t *testing.T) {
	intOpt := INTMetadataOption{
		InstructionBitmap: INTInstrSwitchID | INTInstrIngressPort | INTInstrHopLatency,
	}

	instructions := intOpt.GetINTInstructionNames()
	expected := []string{"Switch ID", "Ingress Port", "Hop Latency"}
	assert.Equal(t, expected, instructions)

	// Test empty bitmap
	intOpt.InstructionBitmap = 0x0000
	instructions = intOpt.GetINTInstructionNames()
	assert.Len(t, instructions, 1)
	assert.Contains(t, instructions[0], "Custom")
}

func TestINTVersionName(t *testing.T) {
	tests := []struct {
		version  uint8
		expected string
	}{
		{INTVersion1, "INT v1.0"},
		{INTVersion2, "INT v2.0"},
		{INTVersion3, "INT v2.1"},
		{INTVersion4, "INT v2.1+ (Current)"},
		{99, "INT v99 (Unknown)"},
	}

	for _, tt := range tests {
		intOpt := INTMetadataOption{Version: tt.version}
		result := intOpt.GetVersionName()
		assert.Equal(t, tt.expected, result)
	}
}

func TestINTFlagsDescription(t *testing.T) {
	tests := []struct {
		name             string
		discard          bool
		exceededMaxHops  bool
		mtuExceeded      bool
		expected         string
	}{
		{"No flags", false, false, false, "None"},
		{"Discard only", true, false, false, "[DISCARD]"},
		{"All flags", true, true, true, "[DISCARD, MAX_HOPS_EXCEEDED, MTU_EXCEEDED]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intOpt := INTMetadataOption{
				Discard:         tt.discard,
				ExceededMaxHops: tt.exceededMaxHops,
				MTUExceeded:     tt.mtuExceeded,
			}
			result := intOpt.GetFlagsDescription()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestINTStringRepresentation(t *testing.T) {
	intOpt := INTMetadataOption{
		Version:            4,
		RemainingHopCount:  10,
		DomainSpecificID:   0x1234,
		Discard:            true,
		InstructionBitmap:  INTInstrSwitchID | INTInstrHopLatency,
	}

	str := intOpt.String()
	
	// Check that all key components are present
	assert.Contains(t, str, "INT v2.1+ (Current)")
	assert.Contains(t, str, "Hops:10")
	assert.Contains(t, str, "Domain:0x1234")
	assert.Contains(t, str, "[DISCARD]")
	assert.Contains(t, str, "Switch ID")
	assert.Contains(t, str, "Hop Latency")
}

func TestINTStringTruncation(t *testing.T) {
	// Create INT option with many instructions to test truncation
	intOpt := INTMetadataOption{
		Version:            4,
		RemainingHopCount:  10,
		DomainSpecificID:   0x1234,
		InstructionBitmap:  0xFFFF, // All bits set
	}

	str := intOpt.String()
	
	// Should contain truncation indicator if instruction list is long
	if len(str) > 100 {
		// Instruction part should be truncated if too long
		instructions := intOpt.GetINTInstructionNames()
		instructStr := strings.Join(instructions, ", ")
		if len(instructStr) > 50 {
			assert.Contains(t, str, "...")
		}
	}
}

func TestAllINTInstructionBits(t *testing.T) {
	// Test all individual instruction bits
	instructionTests := []struct {
		bit      uint16
		expected string
	}{
		{INTInstrSwitchID, "Switch ID"},
		{INTInstrIngressPort, "Ingress Port"},
		{INTInstrEgressPort, "Egress Port"},
		{INTInstrHopLatency, "Hop Latency"},
		{INTInstrQueueOccupancy, "Queue Occupancy"},
		{INTInstrIngressTimestamp, "Ingress Timestamp"},
		{INTInstrEgressTimestamp, "Egress Timestamp"},
		{INTInstrLevel2Port, "Level 2 Port"},
		{INTInstrEgressTXUtil, "Egress TX Utilization"},
		{INTInstrBufferPool, "Buffer Pool"},
		{INTInstrChecksumComplement, "Checksum Complement"},
	}

	for _, tt := range instructionTests {
		intOpt := INTMetadataOption{InstructionBitmap: tt.bit}
		instructions := intOpt.GetINTInstructionNames()
		assert.Contains(t, instructions, tt.expected)
	}
}

// Benchmark the new string methods
func BenchmarkOptionClassName(b *testing.B) {
	opt := Option{Class: 0x0103}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = opt.GetOptionClassName()
	}
}

func BenchmarkOptionTypeName(b *testing.B) {
	opt := Option{Class: 0x0103, Type: INTTypeMetadata}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = opt.GetOptionTypeName()
	}
}

func BenchmarkINTInstructionNames(b *testing.B) {
	intOpt := INTMetadataOption{InstructionBitmap: INTInstrSwitchID | INTInstrIngressPort | INTInstrHopLatency}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = intOpt.GetINTInstructionNames()
	}
}

func BenchmarkINTString(b *testing.B) {
	intOpt := INTMetadataOption{
		Version:           4,
		RemainingHopCount: 10,
		DomainSpecificID:  0x1234,
		Discard:           true,
		InstructionBitmap: INTInstrSwitchID | INTInstrHopLatency,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = intOpt.String()
	}
}