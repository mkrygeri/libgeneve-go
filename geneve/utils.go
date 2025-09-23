package geneve

import (
	"encoding/binary"
	"fmt"
)

// PacketBuilder helps construct GENEVE packets for testing and simulation
type PacketBuilder struct {
	header  Header
	options []Option
	payload []byte
}

// NewPacketBuilder creates a new packet builder with default header values
func NewPacketBuilder() *PacketBuilder {
	return &PacketBuilder{
		header: Header{
			Version:      GeneveVersion,
			ProtocolType: ProtocolTypeEthernet,
		},
	}
}

// SetVNI sets the Virtual Network Identifier
func (pb *PacketBuilder) SetVNI(vni uint32) *PacketBuilder {
	pb.header.VNI = vni & 0xFFFFFF // Ensure only 24 bits
	return pb
}

// SetProtocolType sets the protocol type of the inner payload
func (pb *PacketBuilder) SetProtocolType(protocolType uint16) *PacketBuilder {
	pb.header.ProtocolType = protocolType
	return pb
}

// SetOAMFlag sets the OAM flag
func (pb *PacketBuilder) SetOAMFlag(oam bool) *PacketBuilder {
	pb.header.OFlag = oam
	return pb
}

// SetCriticalFlag sets the critical options flag
func (pb *PacketBuilder) SetCriticalFlag(critical bool) *PacketBuilder {
	pb.header.CFlag = critical
	return pb
}

// AddOption adds a custom option to the packet
func (pb *PacketBuilder) AddOption(class uint16, optionType uint8, data []byte) *PacketBuilder {
	// Pad data to 4-byte boundary
	paddedData := make([]byte, ((len(data)+3)/4)*4)
	copy(paddedData, data)

	option := Option{
		Class:  class,
		Type:   optionType,
		Length: uint8(len(paddedData) / 4),
		Data:   paddedData,
	}
	pb.options = append(pb.options, option)
	return pb
}

// AddINTMetadataOption adds an INT metadata option
func (pb *PacketBuilder) AddINTMetadataOption(intOpt INTMetadataOption) *PacketBuilder {
	// Serialize INT metadata to bytes
	data := make([]byte, 16)
	
	// Version (4) + Discard (1) + ExceededMaxHops (1) + MTUExceeded (1) + Reserved (1)
	data[0] = (intOpt.Version << 4)
	if intOpt.Discard {
		data[0] |= 0x08
	}
	if intOpt.ExceededMaxHops {
		data[0] |= 0x04
	}
	if intOpt.MTUExceeded {
		data[0] |= 0x02
	}
	
	// Reserved (12) + HopML (5)
	reservedHopML := (intOpt.Reserved << 5) | uint16(intOpt.HopML&0x1F)
	binary.BigEndian.PutUint16(data[1:3], reservedHopML)
	
	// Remaining hop count
	data[3] = intOpt.RemainingHopCount
	
	// Instruction bitmap
	binary.BigEndian.PutUint16(data[4:6], intOpt.InstructionBitmap)
	
	// Domain specific ID
	binary.BigEndian.PutUint16(data[6:8], intOpt.DomainSpecificID)
	
	// Domain instruction
	binary.BigEndian.PutUint16(data[8:10], intOpt.DomainInstruction)
	
	// Domain flags
	binary.BigEndian.PutUint16(data[10:12], intOpt.DomainFlags)

	return pb.AddOption(0x0103, 0x01, data)
}

// SetPayload sets the inner payload
func (pb *PacketBuilder) SetPayload(payload []byte) *PacketBuilder {
	pb.payload = payload
	return pb
}

// Build constructs the final packet bytes
func (pb *PacketBuilder) Build() []byte {
	// Calculate total options length
	totalOptionsLen := 0
	for _, opt := range pb.options {
		totalOptionsLen += 4 + int(opt.Length)*4 // Header + data
	}

	// Update option length in header
	pb.header.OptionLength = uint8(totalOptionsLen / 4)

	// Allocate packet buffer
	packet := make([]byte, GeneveHeaderSize+totalOptionsLen+len(pb.payload))
	offset := 0

	// Write header
	packet[0] = (pb.header.Version << 6) | (pb.header.OptionLength & 0x3F)
	packet[1] = 0
	if pb.header.OFlag {
		packet[1] |= 0x80
	}
	if pb.header.CFlag {
		packet[1] |= 0x40
	}
	packet[1] |= pb.header.Reserved1 & 0x3F

	binary.BigEndian.PutUint16(packet[2:4], pb.header.ProtocolType)
	
	vniReserved := (pb.header.VNI << 8) | uint32(pb.header.Reserved2)
	binary.BigEndian.PutUint32(packet[4:8], vniReserved)
	
	offset = GeneveHeaderSize

	// Write options
	for _, opt := range pb.options {
		binary.BigEndian.PutUint16(packet[offset:offset+2], opt.Class)
		packet[offset+2] = opt.Type
		packet[offset+3] = (opt.Reserved << 5) | (opt.Length & 0x1F)
		copy(packet[offset+4:offset+4+len(opt.Data)], opt.Data)
		offset += 4 + len(opt.Data)
	}

	// Write payload
	if len(pb.payload) > 0 {
		copy(packet[offset:], pb.payload)
	}

	return packet
}

// Statistics contains parsing statistics
type Statistics struct {
	TotalPackets    int
	SuccessfulParse int
	FailedParse     int
	OptionCounts    map[uint32]int // Class-Type combination -> count
	ProtocolCounts  map[uint16]int // Protocol type -> count
	VNICounts       map[uint32]int // VNI -> count
	NestedLayers    int
}

// NewStatistics creates a new statistics collector
func NewStatistics() *Statistics {
	return &Statistics{
		OptionCounts:   make(map[uint32]int),
		ProtocolCounts: make(map[uint16]int),
		VNICounts:      make(map[uint32]int),
	}
}

// UpdateFromResult updates statistics from a parse result
func (s *Statistics) UpdateFromResult(result *ParseResult, err error) {
	s.TotalPackets++
	
	if err != nil {
		s.FailedParse++
		return
	}
	
	s.SuccessfulParse++
	
	// Count protocol types
	s.ProtocolCounts[result.Header.ProtocolType]++
	
	// Count VNIs
	s.VNICounts[result.Header.VNI]++
	
	// Count options
	for _, opt := range result.Options {
		classType := (uint32(opt.Class) << 8) | uint32(opt.Type)
		s.OptionCounts[classType]++
	}
	
	// Count nested layers
	s.NestedLayers += len(result.InnerLayers)
	for _, inner := range result.InnerLayers {
		s.UpdateFromResult(&inner, nil)
	}
}

// String returns a string representation of the statistics
func (s *Statistics) String() string {
	result := fmt.Sprintf("GENEVE Parse Statistics:\n")
	result += fmt.Sprintf("  Total Packets: %d\n", s.TotalPackets)
	result += fmt.Sprintf("  Successful: %d (%.1f%%)\n", s.SuccessfulParse, 
		float64(s.SuccessfulParse)/float64(s.TotalPackets)*100)
	result += fmt.Sprintf("  Failed: %d (%.1f%%)\n", s.FailedParse,
		float64(s.FailedParse)/float64(s.TotalPackets)*100)
	result += fmt.Sprintf("  Nested Layers: %d\n", s.NestedLayers)
	
	if len(s.ProtocolCounts) > 0 {
		result += "  Protocol Types:\n"
		for proto, count := range s.ProtocolCounts {
			var name string
			switch proto {
			case ProtocolTypeIPv4:
				name = "IPv4"
			case ProtocolTypeIPv6:
				name = "IPv6"
			case ProtocolTypeEthernet:
				name = "Ethernet"
			case ProtocolTypeARP:
				name = "ARP"
			default:
				name = fmt.Sprintf("0x%04x", proto)
			}
			result += fmt.Sprintf("    %s: %d\n", name, count)
		}
	}
	
	if len(s.OptionCounts) > 0 {
		result += "  Option Types:\n"
		for classType, count := range s.OptionCounts {
			class := uint16(classType >> 8)
			optType := uint8(classType & 0xFF)
			result += fmt.Sprintf("    Class:0x%04x Type:0x%02x: %d\n", class, optType, count)
		}
	}
	
	return result
}

// Validator provides packet validation functionality
type Validator struct {
	EnforceStrictVersion    bool // Enforce exact version match
	ValidateOptionPadding   bool // Validate option padding
	ValidateReservedFields  bool // Validate reserved fields are zero
	MaxAllowedOptions       int  // Maximum number of options allowed
}

// NewValidator creates a new packet validator with strict settings
func NewValidator() *Validator {
	return &Validator{
		EnforceStrictVersion:   true,
		ValidateOptionPadding:  true,
		ValidateReservedFields: true,
		MaxAllowedOptions:      16,
	}
}

// ValidatePacket validates a parsed GENEVE packet
func (v *Validator) ValidatePacket(result *ParseResult) []string {
	var violations []string
	
	// Check version
	if v.EnforceStrictVersion && result.Header.Version != GeneveVersion {
		violations = append(violations, fmt.Sprintf("Invalid version: %d (expected %d)", 
			result.Header.Version, GeneveVersion))
	}
	
	// Check reserved fields
	if v.ValidateReservedFields {
		if result.Header.Reserved1 != 0 {
			violations = append(violations, fmt.Sprintf("Reserved1 field not zero: 0x%02x", 
				result.Header.Reserved1))
		}
		if result.Header.Reserved2 != 0 {
			violations = append(violations, fmt.Sprintf("Reserved2 field not zero: 0x%02x", 
				result.Header.Reserved2))
		}
	}
	
	// Check option count
	if v.MaxAllowedOptions > 0 && len(result.Options) > v.MaxAllowedOptions {
		violations = append(violations, fmt.Sprintf("Too many options: %d (max %d)", 
			len(result.Options), v.MaxAllowedOptions))
	}
	
	// Validate options
	if v.ValidateOptionPadding {
		for i, opt := range result.Options {
			expectedLen := ((len(opt.Data) + 3) / 4) * 4
			if len(opt.Data) != expectedLen {
				violations = append(violations, fmt.Sprintf("Option %d has invalid padding", i))
			}
		}
	}
	
	// Validate nested layers recursively
	for i, inner := range result.InnerLayers {
		innerViolations := v.ValidatePacket(&inner)
		for _, violation := range innerViolations {
			violations = append(violations, fmt.Sprintf("Nested layer %d: %s", i, violation))
		}
	}
	
	return violations
}

// IsValid returns true if the packet has no validation violations
func (v *Validator) IsValid(result *ParseResult) bool {
	return len(v.ValidatePacket(result)) == 0
}