// Package geneve provides a high-performance GENEVE protocol packet parser
// implementing RFC 8926 - Generic Network Virtualization Encapsulation (GENEVE)
//
// GENEVE Header Format (RFC 8926):
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Ver|  Opt Len  |O|C|    Rsvd   |          Protocol Type        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Virtual Network Identifier (VNI)      |    Reserved     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Variable Length Options                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
package geneve

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Protocol constants
const (
	// GENEVE UDP port as defined in RFC 8926
	GenevePort = 6082

	// GENEVE header minimum size (8 bytes)
	GeneveHeaderSize = 8

	// GENEVE version (currently 0)
	GeneveVersion = 0

	// Protocol types (Ethertype values)
	ProtocolTypeIPv4     = 0x0800
	ProtocolTypeIPv6     = 0x86DD
	ProtocolTypeEthernet = 0x6558
	ProtocolTypeARP      = 0x0806

	// Option class types (from P4 example and RFC drafts)
	OptionClassINTMetadata    = 0x010301
	OptionClassINTDestination = 0x010302
	OptionClassINTMX          = 0x010303

	// Standard option classes
	OptionClassExperimental  = 0x0000 // Experimental use
	OptionClassLinuxGeneric  = 0x0001 // Linux generic
	OptionClassOpenVSwitch   = 0x0002 // Open vSwitch
	OptionClassVMware        = 0x0003 // VMware
	OptionClassCisco         = 0x0004 // Cisco
	OptionClassINT           = 0x0103 // In-band Network Telemetry
	OptionClassPlatform      = 0xFFFF // Platform specific

	// INT option types
	INTTypeMetadata    = 0x01 // INT metadata
	INTTypeDestination = 0x02 // INT destination
	INTTypeMX          = 0x03 // INT MX (monitoring and export)
	INTTypeSource      = 0x04 // INT source
	INTTypeSink        = 0x05 // INT sink

	// Common generic option types
	GenericTypeReserved    = 0x00 // Reserved
	GenericTypeTimestamp   = 0x01 // Timestamp
	GenericTypeSecurityTag = 0x02 // Security tag
	GenericTypeQoSMarking  = 0x03 // QoS marking
	GenericTypeLoadBalance = 0x04 // Load balancing hint
	GenericTypeDebugInfo   = 0x05 // Debug information

	// OAM (Operations, Administration, and Maintenance) types
	OAMTypeEcho        = 0x01 // OAM echo request/reply
	OAMTypeTrace       = 0x02 // OAM trace
	OAMTypeConnectivity = 0x03 // Connectivity verification

	// GENEVE header flags
	FlagOAM      = 0x80 // OAM packet flag (O bit)
	FlagCritical = 0x40 // Critical options present flag (C bit)

	// INT version values
	INTVersion1 = 1 // INT specification version 1.0
	INTVersion2 = 2 // INT specification version 2.0  
	INTVersion3 = 3 // INT specification version 2.1
	INTVersion4 = 4 // Current INT specification version

	// INT hop metadata instruction bits (from INT spec v2.1)
	INTInstrSwitchID          = 0x8000 // Switch identifier
	INTInstrIngressPort       = 0x4000 // Ingress port ID
	INTInstrEgressPort        = 0x2000 // Egress port ID
	INTInstrHopLatency        = 0x1000 // Hop latency
	INTInstrQueueOccupancy    = 0x0800 // Queue occupancy
	INTInstrIngressTimestamp  = 0x0400 // Ingress timestamp
	INTInstrEgressTimestamp   = 0x0200 // Egress timestamp
	INTInstrLevel2Port        = 0x0100 // Level 2 port ID
	INTInstrEgressTXUtil      = 0x0080 // Egress TX utilization
	INTInstrBufferPool        = 0x0040 // Buffer pool occupancy
	INTInstrChecksumComplement = 0x0020 // Checksum complement
	
	// Enterprise-specific option classes (from IANA registry and vendor implementations)
	OptionClassMicrosoft     = 0x0005 // Microsoft Corporation
	OptionClassGoogle        = 0x0006 // Google Inc.
	OptionClassAmazon        = 0x0007 // Amazon.com Inc.
	OptionClassHuawei        = 0x0008 // Huawei Technologies
	OptionClassJuniper       = 0x0009 // Juniper Networks
	OptionClassArista        = 0x000A // Arista Networks
	OptionClassMellanox      = 0x000B // NVIDIA/Mellanox
	OptionClassBroadcom      = 0x000C // Broadcom Inc.
	
	// VMware specific option types
	VMwareTypeNSXMetadata    = 0x01 // NSX metadata
	VMwareTypeVXLANCompat    = 0x02 // VXLAN compatibility
	VMwareTypeVDSMetadata    = 0x03 // vSphere Distributed Switch metadata
	VMwareTypeDVSExtension   = 0x04 // DVS extension
	
	// Cisco specific option types  
	CiscoTypeACI             = 0x01 // Application Centric Infrastructure
	CiscoTypeSDAccess        = 0x02 // Software-Defined Access
	CiscoTypeVXLANGPO        = 0x03 // VXLAN Group Policy Option
	CiscoTypeSGT             = 0x04 // Security Group Tag
	CiscoTypePathTrace       = 0x05 // Path trace information
	
	// Microsoft specific option types
	MicrosoftTypeHyperV      = 0x01 // Hyper-V metadata
	MicrosoftTypeAzure       = 0x02 // Azure specific
	MicrosoftTypeSDN         = 0x03 // Software Defined Networking
	
	// Amazon specific option types
	AmazonTypeVPC            = 0x01 // VPC metadata
	AmazonTypeECS            = 0x02 // Elastic Container Service
	AmazonTypeEKS            = 0x03 // Elastic Kubernetes Service
	
	// Google specific option types
	GoogleTypeGKE            = 0x01 // Google Kubernetes Engine
	GoogleTypeGCE            = 0x02 // Google Compute Engine
	GoogleTypeCloudArmor     = 0x03 // Cloud Armor metadata
	
	// Arista specific option types
	AristaTypeTAP            = 0x01 // Traffic Analysis Platform
	AristaTypeLatency        = 0x02 // Advanced latency measurement
	AristaTypeFlowTracker    = 0x03 // Flow tracking telemetry
	AristaTypeCongestion     = 0x04 // Congestion telemetry
	AristaTypeECN            = 0x05 // Explicit Congestion Notification
	AristaTypeQueueDepth     = 0x06 // Queue depth telemetry
	
	// Broadcom specific option types
	BroadcomTypeSwitchTelem  = 0x01 // Switch telemetry
	BroadcomTypePortStats    = 0x02 // Port statistics
	BroadcomTypeBufferUtil   = 0x03 // Buffer utilization
	BroadcomTypeFlowletHash  = 0x04 // Flowlet load balancing
	BroadcomTypeLatencyHist  = 0x05 // Latency histogram
	BroadcomTypeDropReason   = 0x06 // Packet drop analysis
)

// Header represents the GENEVE fixed header
type Header struct {
	Version      uint8  // 2 bits - GENEVE version (0)
	OptionLength uint8  // 6 bits - Length of options in 4-byte units
	OFlag        bool   // 1 bit - OAM packet flag
	CFlag        bool   // 1 bit - Critical options present flag
	Reserved1    uint8  // 6 bits - Reserved
	ProtocolType uint16 // 16 bits - Protocol type of inner frame
	VNI          uint32 // 24 bits - Virtual Network Identifier
	Reserved2    uint8  // 8 bits - Reserved
}

// Option represents a GENEVE TLV option
type Option struct {
	Class    uint16 // 16 bits - Option class
	Type     uint8  // 8 bits - Option type  
	Reserved uint8  // 3 bits - Reserved
	Length   uint8  // 5 bits - Length in 4-byte units
	Data     []byte // Variable length data
}

// INTMetadataOption represents INT (In-band Network Telemetry) metadata option
type INTMetadataOption struct {
	Option
	Version            uint8  // 4 bits - INT version
	Discard            bool   // 1 bit - Discard flag
	ExceededMaxHops    bool   // 1 bit - Exceeded max hops flag
	MTUExceeded        bool   // 1 bit - MTU exceeded flag
	Reserved           uint16 // 12 bits - Reserved
	HopML             uint8  // 5 bits - Hop metadata length
	RemainingHopCount  uint8  // 8 bits - Remaining hop count
	InstructionBitmap  uint16 // 16 bits - Instruction bitmap
	DomainSpecificID   uint16 // 16 bits - Domain specific ID
	DomainInstruction  uint16 // 16 bits - Domain instruction
	DomainFlags        uint16 // 16 bits - Domain flags
}

// EnterpriseOption represents a parsed enterprise-specific option
type EnterpriseOption struct {
	Option
	VendorName    string                 // Human-readable vendor name
	Decoded       bool                   // Whether additional decoding was performed
	DecodedData   map[string]interface{} // Decoded enterprise-specific data
	ParseError    error                  // Error during enterprise-specific parsing
}

// VMwareNSXOption represents VMware NSX metadata option
type VMwareNSXOption struct {
	Option
	VSID          uint32 // Virtual Segment ID
	SourceVNI     uint32 // Source VNI  
	Flags         uint16 // NSX flags
	PolicyID      uint16 // Security policy ID
	SourceTEP     uint32 // Source Tunnel Endpoint
	Reserved      uint32 // Reserved fields
}

// CiscoACIOption represents Cisco ACI metadata option
type CiscoACIOption struct {
	Option
	EPGID         uint16 // Endpoint Group ID
	BridgeDomain  uint16 // Bridge Domain ID
	VRF           uint16 // VRF ID
	ContractID    uint16 // Contract ID
	Flags         uint32 // ACI flags
	TenantID      uint16 // Tenant ID
	ApplicationID uint16 // Application Profile ID
}

// AristaTAPOption represents Arista Traffic Analysis Platform telemetry
type AristaTAPOption struct {
	Option
	FlowID        uint32 // Flow identifier
	IngressPort   uint32 // Ingress port number
	EgressPort    uint32 // Egress port number
	Timestamp     uint64 // High-precision timestamp
	PacketSize    uint16 // Original packet size
	Flags         uint16 // TAP specific flags
	QueueDepth    uint32 // Queue depth at egress
	Latency       uint32 // Microsecond latency
}

// AristaLatencyOption represents Arista advanced latency measurement
type AristaLatencyOption struct {
	Option
	FlowHash      uint32 // Flow hash identifier
	IngressTS     uint64 // Ingress timestamp (nanoseconds)
	EgressTS      uint64 // Egress timestamp (nanoseconds)
	QueueWaitTime uint32 // Time spent in queue (nanoseconds)
	ProcessTime   uint32 // Processing time (nanoseconds)
	Jitter        uint32 // Jitter measurement (nanoseconds)
	PathID        uint16 // Path identifier for ECMP
	Reserved      uint16 // Reserved for future use
}

// BroadcomSwitchTelemetryOption represents Broadcom switch telemetry
type BroadcomSwitchTelemetryOption struct {
	Option
	SwitchID      uint32 // Switch identifier
	ChipID        uint16 // ASIC chip identifier
	PipelineID    uint16 // Pipeline identifier
	BufferUtil    uint32 // Buffer utilization percentage (scaled by 100)
	PacketRate    uint64 // Packets per second
	ByteRate      uint64 // Bytes per second
	DropCount     uint32 // Packets dropped
	ErrorCount    uint32 // Error count
}

// BroadcomLatencyHistOption represents Broadcom latency histogram telemetry
type BroadcomLatencyHistOption struct {
	Option
	PortID        uint32 // Port identifier
	Bucket0_1us   uint32 // 0-1 microsecond bucket count
	Bucket1_10us  uint32 // 1-10 microsecond bucket count
	Bucket10_100us uint32 // 10-100 microsecond bucket count  
	Bucket100us_1ms uint32 // 100us-1ms bucket count
	Bucket1ms_10ms  uint32 // 1ms-10ms bucket count
	BucketOver10ms  uint32 // >10ms bucket count
	MaxLatency      uint32 // Maximum observed latency (microseconds)
	MinLatency      uint32 // Minimum observed latency (microseconds)
	AvgLatency      uint32 // Average latency (microseconds)
}

// ParseResult contains the parsed GENEVE packet information
type ParseResult struct {
	Header            Header
	Options           []Option
	INTOptions        []INTMetadataOption
	EnterpriseOptions []EnterpriseOption       // Parsed enterprise-specific options
	VMwareOptions     []VMwareNSXOption        // VMware NSX options
	CiscoOptions      []CiscoACIOption         // Cisco ACI options
	AristaOptions     []AristaTAPOption        // Arista TAP options
	AristaLatencyOptions []AristaLatencyOption  // Arista latency options
	BroadcomOptions   []BroadcomSwitchTelemetryOption // Broadcom switch telemetry
	BroadcomLatencyOptions []BroadcomLatencyHistOption // Broadcom latency histogram
	Payload           []byte
	InnerLayers       []ParseResult // For nested GENEVE layers
	PayloadOffset     int           // Offset where payload starts
}

// Parser provides GENEVE packet parsing functionality
type Parser struct {
	// Configuration options
	MaxOptionLength   uint8 // Maximum option length to parse (prevents DoS)
	ParseNestedLayers bool  // Whether to parse nested GENEVE layers
	MaxNestedDepth    int   // Maximum depth for nested parsing
	
	// Enterprise extension parsing options
	ParseEnterpriseExtensions bool                    // Whether to decode enterprise-specific options
	EnterpriseDecoders        map[uint16]func([]byte) // Custom decoders for enterprise option classes
}

// NewParser creates a new GENEVE parser with default configuration
func NewParser() *Parser {
	return &Parser{
		MaxOptionLength:           63,   // 6 bits max value
		ParseNestedLayers:         true,
		MaxNestedDepth:            3,    // Reasonable default to prevent infinite recursion
		ParseEnterpriseExtensions: true, // Enable enterprise extension parsing by default
		EnterpriseDecoders:        make(map[uint16]func([]byte)), // Initialize decoder map
	}
}

// ParsePacket parses a complete GENEVE packet starting from the GENEVE header
func (p *Parser) ParsePacket(data []byte) (*ParseResult, error) {
	return p.parsePacketRecursive(data, 0)
}

// parsePacketRecursive handles recursive parsing of nested GENEVE layers
func (p *Parser) parsePacketRecursive(data []byte, depth int) (*ParseResult, error) {
	if depth > p.MaxNestedDepth {
		return nil, errors.New("maximum nested depth exceeded")
	}

	if len(data) < GeneveHeaderSize {
		return nil, fmt.Errorf("packet too short: need at least %d bytes, got %d", GeneveHeaderSize, len(data))
	}

	result := &ParseResult{}

	// Parse fixed header
	header, err := p.parseHeader(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}
	result.Header = *header

	offset := GeneveHeaderSize

	// Parse options if present
	if header.OptionLength > 0 {
		optionsLength := int(header.OptionLength) * 4 // Convert from 4-byte units to bytes
		if len(data) < offset+optionsLength {
			return nil, fmt.Errorf("packet too short for options: need %d bytes, got %d", offset+optionsLength, len(data))
		}

		options, intOptions, enterpriseOptions, vmwareOptions, ciscoOptions, aristaOptions, aristaLatencyOptions, broadcomOptions, broadcomLatencyOptions, err := p.parseOptions(data[offset:offset+optionsLength])
		if err != nil {
			return nil, fmt.Errorf("failed to parse options: %w", err)
		}
		result.Options = options
		result.INTOptions = intOptions
		result.EnterpriseOptions = enterpriseOptions
		result.VMwareOptions = vmwareOptions
		result.CiscoOptions = ciscoOptions
		result.AristaOptions = aristaOptions
		result.AristaLatencyOptions = aristaLatencyOptions
		result.BroadcomOptions = broadcomOptions
		result.BroadcomLatencyOptions = broadcomLatencyOptions
		offset += optionsLength
	}

	// Extract payload
	if offset < len(data) {
		result.Payload = data[offset:]
		result.PayloadOffset = offset

		// Check for nested GENEVE layers if enabled
		if p.ParseNestedLayers && p.isGenevePayload(result.Payload, header.ProtocolType) {
			innerResult, err := p.parsePacketRecursive(result.Payload, depth+1)
			if err == nil {
				result.InnerLayers = append(result.InnerLayers, *innerResult)
			}
			// Don't fail if inner parsing fails, just skip nested layer
		}
	}

	return result, nil
}

// parseHeader parses the GENEVE fixed header
func (p *Parser) parseHeader(data []byte) (*Header, error) {
	if len(data) < GeneveHeaderSize {
		return nil, errors.New("insufficient data for GENEVE header")
	}

	header := &Header{}

	// First byte: Ver(2) + OptLen(6)
	firstByte := data[0]
	header.Version = (firstByte >> 6) & 0x3
	header.OptionLength = firstByte & 0x3F

	// Second byte: O(1) + C(1) + Rsvd(6)
	secondByte := data[1]
	header.OFlag = (secondByte & 0x80) != 0
	header.CFlag = (secondByte & 0x40) != 0
	header.Reserved1 = secondByte & 0x3F

	// Validate version
	if header.Version != GeneveVersion {
		return nil, fmt.Errorf("unsupported GENEVE version: %d", header.Version)
	}

	// Validate option length
	if header.OptionLength > p.MaxOptionLength {
		return nil, fmt.Errorf("option length too large: %d", header.OptionLength)
	}

	// Protocol type (bytes 2-3)
	header.ProtocolType = binary.BigEndian.Uint16(data[2:4])

	// VNI (bytes 4-6, 24 bits) + Reserved2 (byte 7)
	vniBytes := binary.BigEndian.Uint32(data[4:8])
	header.VNI = (vniBytes >> 8) & 0xFFFFFF
	header.Reserved2 = uint8(vniBytes & 0xFF)

	return header, nil
}

// parseOptions parses GENEVE TLV options including enterprise extensions
func (p *Parser) parseOptions(data []byte) ([]Option, []INTMetadataOption, []EnterpriseOption, []VMwareNSXOption, []CiscoACIOption, []AristaTAPOption, []AristaLatencyOption, []BroadcomSwitchTelemetryOption, []BroadcomLatencyHistOption, error) {
	var options []Option
	var intOptions []INTMetadataOption
	var enterpriseOptions []EnterpriseOption
	var vmwareOptions []VMwareNSXOption
	var ciscoOptions []CiscoACIOption
	var aristaOptions []AristaTAPOption
	var aristaLatencyOptions []AristaLatencyOption
	var broadcomOptions []BroadcomSwitchTelemetryOption
	var broadcomLatencyOptions []BroadcomLatencyHistOption
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			return nil, nil, nil, nil, nil, nil, nil, nil, nil, errors.New("insufficient data for option header")
		}

		option := Option{}

		// Option Class (16 bits)
		option.Class = binary.BigEndian.Uint16(data[offset:offset+2])
		offset += 2

		// Option Type (8 bits)
		option.Type = data[offset]
		offset++

		// Reserved (3 bits) + Length (5 bits)
		reservedLength := data[offset]
		option.Reserved = (reservedLength >> 5) & 0x7
		option.Length = reservedLength & 0x1F
		offset++

		// Option data
		dataLength := int(option.Length) * 4 // Convert from 4-byte units
		if dataLength > 0 {
			if offset+dataLength > len(data) {
				return nil, nil, nil, nil, nil, nil, nil, nil, nil, errors.New("insufficient data for option data")
			}
			option.Data = make([]byte, dataLength)
			copy(option.Data, data[offset:offset+dataLength])
			offset += dataLength
		}

		// Check if this is an INT option and parse accordingly
		classType := (uint32(option.Class) << 8) | uint32(option.Type)
		if classType == OptionClassINTMetadata {
			intOption, err := p.parseINTMetadataOption(option)
			if err == nil {
				intOptions = append(intOptions, intOption)
			}
		}

		// Parse enterprise-specific options if enabled
		if p.ParseEnterpriseExtensions {
			if p.isEnterpriseOption(option.Class) {
				enterpriseOpt, vmwareOpt, ciscoOpt, aristaOpt, aristaLatOpt, broadcomOpt, broadcomLatOpt := p.parseEnterpriseOption(option)
				if enterpriseOpt.VendorName != "" {
					enterpriseOptions = append(enterpriseOptions, *enterpriseOpt)
				}
				if vmwareOpt != nil {
					vmwareOptions = append(vmwareOptions, *vmwareOpt)
				}
				if ciscoOpt != nil {
					ciscoOptions = append(ciscoOptions, *ciscoOpt)
				}
				if aristaOpt != nil {
					aristaOptions = append(aristaOptions, *aristaOpt)
				}
				if aristaLatOpt != nil {
					aristaLatencyOptions = append(aristaLatencyOptions, *aristaLatOpt)
				}
				if broadcomOpt != nil {
					broadcomOptions = append(broadcomOptions, *broadcomOpt)
				}
				if broadcomLatOpt != nil {
					broadcomLatencyOptions = append(broadcomLatencyOptions, *broadcomLatOpt)
				}
			}
		}

		options = append(options, option)
	}

	return options, intOptions, enterpriseOptions, vmwareOptions, ciscoOptions, aristaOptions, aristaLatencyOptions, broadcomOptions, broadcomLatencyOptions, nil
}

// parseINTMetadataOption parses INT metadata option
func (p *Parser) parseINTMetadataOption(option Option) (INTMetadataOption, error) {
	intOpt := INTMetadataOption{Option: option}

	if len(option.Data) < 16 { // Minimum INT metadata size
		return intOpt, errors.New("insufficient data for INT metadata option")
	}

	data := option.Data
	offset := 0

	// Version (4 bits) + Discard (1 bit) + ExceededMaxHops (1 bit) + MTUExceeded (1 bit) + Reserved (1 bit)
	firstByte := data[offset]
	intOpt.Version = (firstByte >> 4) & 0xF
	intOpt.Discard = (firstByte & 0x8) != 0
	intOpt.ExceededMaxHops = (firstByte & 0x4) != 0
	intOpt.MTUExceeded = (firstByte & 0x2) != 0
	offset++

	// Reserved (12 bits continued) + HopML (5 bits)
	reservedHopML := binary.BigEndian.Uint16(data[offset:offset+2])
	intOpt.Reserved = (reservedHopML >> 5) & 0xFFF
	intOpt.HopML = uint8(reservedHopML & 0x1F)
	offset += 2

	// Remaining hop count (8 bits)
	intOpt.RemainingHopCount = data[offset]
	offset++

	// Instruction bitmap (16 bits)
	intOpt.InstructionBitmap = binary.BigEndian.Uint16(data[offset:offset+2])
	offset += 2

	// Domain specific ID (16 bits)
	intOpt.DomainSpecificID = binary.BigEndian.Uint16(data[offset:offset+2])
	offset += 2

	// Domain instruction (16 bits)
	intOpt.DomainInstruction = binary.BigEndian.Uint16(data[offset:offset+2])
	offset += 2

	// Domain flags (16 bits)
	intOpt.DomainFlags = binary.BigEndian.Uint16(data[offset:offset+2])

	return intOpt, nil
}

// isEnterpriseOption checks if an option class is enterprise/vendor-specific
func (p *Parser) isEnterpriseOption(class uint16) bool {
	// Check known enterprise classes
	switch class {
	case OptionClassVMware, OptionClassCisco, OptionClassMicrosoft, 
		 OptionClassGoogle, OptionClassAmazon, OptionClassHuawei,
		 OptionClassJuniper, OptionClassArista, OptionClassMellanox, OptionClassBroadcom:
		return true
	}
	
	// Exclude standard IETF classes
	switch class {
	case 0x0000, 0x0001, 0x0002, 0x0103, 0xFFFF: // Experimental, Linux, OVS, INT, Platform
		return false
	}
	
	// Check vendor-specific ranges (First Come First Served range)
	if class >= 0x0100 && class <= 0xFEFF {
		return true
	}
	
	// Check experimental range (but exclude platform specific)
	if class >= 0xFF00 && class <= 0xFFFE {
		return true
	}
	
	return false
}

// parseEnterpriseOption parses enterprise-specific options
func (p *Parser) parseEnterpriseOption(option Option) (*EnterpriseOption, *VMwareNSXOption, *CiscoACIOption, *AristaTAPOption, *AristaLatencyOption, *BroadcomSwitchTelemetryOption, *BroadcomLatencyHistOption) {
	enterpriseOpt := &EnterpriseOption{
		Option:      option,
		VendorName:  p.getVendorName(option.Class),
		Decoded:     false,
		DecodedData: make(map[string]interface{}),
	}

	// Try custom decoder first
	if decoder, exists := p.EnterpriseDecoders[option.Class]; exists {
		decoder(option.Data)
		enterpriseOpt.Decoded = true
		enterpriseOpt.DecodedData["custom"] = "decoded with custom decoder"
		return enterpriseOpt, nil, nil, nil, nil, nil, nil
	}

	// Parse vendor-specific options
	switch option.Class {
	case OptionClassVMware:
		if vmwareOpt := p.parseVMwareOption(option); vmwareOpt != nil {
			enterpriseOpt.Decoded = true
			enterpriseOpt.DecodedData = p.vmwareOptionToMap(*vmwareOpt)
			return enterpriseOpt, vmwareOpt, nil, nil, nil, nil, nil
		}
	case OptionClassCisco:
		if ciscoOpt := p.parseCiscoOption(option); ciscoOpt != nil {
			enterpriseOpt.Decoded = true
			enterpriseOpt.DecodedData = p.ciscoOptionToMap(*ciscoOpt)
			return enterpriseOpt, nil, ciscoOpt, nil, nil, nil, nil
		}
	case OptionClassArista:
		if aristaOpt, aristaLatOpt := p.parseAristaOption(option); aristaOpt != nil || aristaLatOpt != nil {
			enterpriseOpt.Decoded = true
			if aristaOpt != nil {
				enterpriseOpt.DecodedData = p.aristaOptionToMap(*aristaOpt)
				return enterpriseOpt, nil, nil, aristaOpt, nil, nil, nil
			} else if aristaLatOpt != nil {
				enterpriseOpt.DecodedData = p.aristaLatencyOptionToMap(*aristaLatOpt)
				return enterpriseOpt, nil, nil, nil, aristaLatOpt, nil, nil
			}
		}
	case OptionClassBroadcom:
		if broadcomOpt, broadcomLatOpt := p.parseBroadcomOption(option); broadcomOpt != nil || broadcomLatOpt != nil {
			enterpriseOpt.Decoded = true
			if broadcomOpt != nil {
				enterpriseOpt.DecodedData = p.broadcomOptionToMap(*broadcomOpt)
				return enterpriseOpt, nil, nil, nil, nil, broadcomOpt, nil
			} else if broadcomLatOpt != nil {
				enterpriseOpt.DecodedData = p.broadcomLatencyOptionToMap(*broadcomLatOpt)
				return enterpriseOpt, nil, nil, nil, nil, nil, broadcomLatOpt
			}
		}
	case OptionClassMicrosoft:
		enterpriseOpt.DecodedData = p.parseMicrosoftOption(option)
		enterpriseOpt.Decoded = len(enterpriseOpt.DecodedData) > 0
	case OptionClassGoogle:
		enterpriseOpt.DecodedData = p.parseGoogleOption(option)
		enterpriseOpt.Decoded = len(enterpriseOpt.DecodedData) > 0
	case OptionClassAmazon:
		enterpriseOpt.DecodedData = p.parseAmazonOption(option)
		enterpriseOpt.Decoded = len(enterpriseOpt.DecodedData) > 0
	default:
		// Generic vendor-specific option
		enterpriseOpt.DecodedData = p.parseGenericVendorOption(option)
		enterpriseOpt.Decoded = len(enterpriseOpt.DecodedData) > 0
	}

	return enterpriseOpt, nil, nil, nil, nil, nil, nil
}

// parseVMwareOption parses VMware NSX options
func (p *Parser) parseVMwareOption(option Option) *VMwareNSXOption {
	if option.Type != VMwareTypeNSXMetadata || len(option.Data) < 16 {
		return nil
	}

	vmwareOpt := &VMwareNSXOption{Option: option}
	data := option.Data

	// Parse NSX metadata structure (example format)
	vmwareOpt.VSID = binary.BigEndian.Uint32(data[0:4])
	vmwareOpt.SourceVNI = binary.BigEndian.Uint32(data[4:8])
	vmwareOpt.Flags = binary.BigEndian.Uint16(data[8:10])
	vmwareOpt.PolicyID = binary.BigEndian.Uint16(data[10:12])
	vmwareOpt.SourceTEP = binary.BigEndian.Uint32(data[12:16])

	return vmwareOpt
}

// parseCiscoOption parses Cisco ACI options
func (p *Parser) parseCiscoOption(option Option) *CiscoACIOption {
	if option.Type != CiscoTypeACI || len(option.Data) < 16 {
		return nil
	}

	ciscoOpt := &CiscoACIOption{Option: option}
	data := option.Data

	// Parse ACI metadata structure (example format)
	ciscoOpt.EPGID = binary.BigEndian.Uint16(data[0:2])
	ciscoOpt.BridgeDomain = binary.BigEndian.Uint16(data[2:4])
	ciscoOpt.VRF = binary.BigEndian.Uint16(data[4:6])
	ciscoOpt.ContractID = binary.BigEndian.Uint16(data[6:8])
	ciscoOpt.Flags = binary.BigEndian.Uint32(data[8:12])
	ciscoOpt.TenantID = binary.BigEndian.Uint16(data[12:14])
	ciscoOpt.ApplicationID = binary.BigEndian.Uint16(data[14:16])

	return ciscoOpt
}

// parseMicrosoftOption parses Microsoft Hyper-V/Azure options
func (p *Parser) parseMicrosoftOption(option Option) map[string]interface{} {
	decoded := make(map[string]interface{})
	
	switch option.Type {
	case MicrosoftTypeHyperV:
		decoded["type"] = "Hyper-V Metadata"
		if len(option.Data) >= 8 {
			decoded["vm_id"] = binary.BigEndian.Uint64(option.Data[0:8])
		}
	case MicrosoftTypeAzure:
		decoded["type"] = "Azure Metadata"
		if len(option.Data) >= 4 {
			decoded["subscription_id"] = binary.BigEndian.Uint32(option.Data[0:4])
		}
	case MicrosoftTypeSDN:
		decoded["type"] = "SDN Metadata"
		if len(option.Data) >= 4 {
			decoded["policy_id"] = binary.BigEndian.Uint32(option.Data[0:4])
		}
	default:
		decoded["type"] = fmt.Sprintf("Microsoft Type 0x%02x", option.Type)
	}
	
	decoded["data_length"] = len(option.Data)
	return decoded
}

// parseGoogleOption parses Google GCP options
func (p *Parser) parseGoogleOption(option Option) map[string]interface{} {
	decoded := make(map[string]interface{})
	
	switch option.Type {
	case GoogleTypeGKE:
		decoded["type"] = "Google Kubernetes Engine"
		if len(option.Data) >= 4 {
			decoded["cluster_id"] = binary.BigEndian.Uint32(option.Data[0:4])
		}
	case GoogleTypeGCE:
		decoded["type"] = "Google Compute Engine"
		if len(option.Data) >= 8 {
			decoded["instance_id"] = binary.BigEndian.Uint64(option.Data[0:8])
		}
	case GoogleTypeCloudArmor:
		decoded["type"] = "Cloud Armor"
		if len(option.Data) >= 4 {
			decoded["policy_id"] = binary.BigEndian.Uint32(option.Data[0:4])
		}
	default:
		decoded["type"] = fmt.Sprintf("Google Type 0x%02x", option.Type)
	}
	
	decoded["data_length"] = len(option.Data)
	return decoded
}

// parseAmazonOption parses Amazon AWS options
func (p *Parser) parseAmazonOption(option Option) map[string]interface{} {
	decoded := make(map[string]interface{})
	
	switch option.Type {
	case AmazonTypeVPC:
		decoded["type"] = "VPC Metadata"
		if len(option.Data) >= 4 {
			decoded["vpc_id"] = binary.BigEndian.Uint32(option.Data[0:4])
		}
	case AmazonTypeECS:
		decoded["type"] = "Elastic Container Service"
		if len(option.Data) >= 8 {
			decoded["task_arn"] = binary.BigEndian.Uint64(option.Data[0:8])
		}
	case AmazonTypeEKS:
		decoded["type"] = "Elastic Kubernetes Service"
		if len(option.Data) >= 4 {
			decoded["cluster_name"] = binary.BigEndian.Uint32(option.Data[0:4])
		}
	default:
		decoded["type"] = fmt.Sprintf("Amazon Type 0x%02x", option.Type)
	}
	
	decoded["data_length"] = len(option.Data)
	return decoded
}

// parseAristaOption parses Arista-specific telemetry options
func (p *Parser) parseAristaOption(option Option) (*AristaTAPOption, *AristaLatencyOption) {
	switch option.Type {
	case AristaTypeTAP:
		if len(option.Data) >= 16 {
			tap := &AristaTAPOption{
				Option:      option,
				FlowID:      binary.BigEndian.Uint32(option.Data[0:4]),
				IngressPort: binary.BigEndian.Uint32(option.Data[4:8]),
				EgressPort:  binary.BigEndian.Uint32(option.Data[8:12]),
				Timestamp:   binary.BigEndian.Uint64(option.Data[12:20]),
			}
			if len(option.Data) >= 24 {
				tap.QueueDepth = binary.BigEndian.Uint32(option.Data[20:24])
			}
			if len(option.Data) >= 28 {
				tap.Latency = binary.BigEndian.Uint32(option.Data[24:28])
			}
			return tap, nil
		}
	case AristaTypeLatency:
		if len(option.Data) >= 20 {
			lat := &AristaLatencyOption{
				Option:        option,
				FlowHash:      binary.BigEndian.Uint32(option.Data[0:4]),
				IngressTS:     binary.BigEndian.Uint64(option.Data[4:12]),
				EgressTS:      binary.BigEndian.Uint64(option.Data[12:20]),
			}
			if len(option.Data) >= 24 {
				lat.QueueWaitTime = binary.BigEndian.Uint32(option.Data[20:24])
			}
			return nil, lat
		}
	}
	return nil, nil
}

// parseBroadcomOption parses Broadcom-specific telemetry options
func (p *Parser) parseBroadcomOption(option Option) (*BroadcomSwitchTelemetryOption, *BroadcomLatencyHistOption) {
	switch option.Type {
	case BroadcomTypeSwitchTelem:
		if len(option.Data) >= 24 {
			telem := &BroadcomSwitchTelemetryOption{
				Option:     option,
				SwitchID:   binary.BigEndian.Uint32(option.Data[0:4]),
				ChipID:     binary.BigEndian.Uint16(option.Data[4:6]),
				PipelineID: binary.BigEndian.Uint16(option.Data[6:8]),
				BufferUtil: binary.BigEndian.Uint32(option.Data[8:12]),
				PacketRate: binary.BigEndian.Uint64(option.Data[12:20]),
				ByteRate:   binary.BigEndian.Uint64(option.Data[20:28]),
			}
			if len(option.Data) >= 32 {
				telem.DropCount = binary.BigEndian.Uint32(option.Data[28:32])
			}
			if len(option.Data) >= 36 {
				telem.ErrorCount = binary.BigEndian.Uint32(option.Data[32:36])
			}
			return telem, nil
		}
	case BroadcomTypeLatencyHist:
		if len(option.Data) >= 36 {
			hist := &BroadcomLatencyHistOption{
				Option:         option,
				PortID:        binary.BigEndian.Uint32(option.Data[0:4]),
				Bucket0_1us:   binary.BigEndian.Uint32(option.Data[4:8]),
				Bucket1_10us:  binary.BigEndian.Uint32(option.Data[8:12]),
				Bucket10_100us: binary.BigEndian.Uint32(option.Data[12:16]),
				Bucket100us_1ms: binary.BigEndian.Uint32(option.Data[16:20]),
				Bucket1ms_10ms:  binary.BigEndian.Uint32(option.Data[20:24]),
				BucketOver10ms:  binary.BigEndian.Uint32(option.Data[24:28]),
				MaxLatency:      binary.BigEndian.Uint32(option.Data[28:32]),
				MinLatency:      binary.BigEndian.Uint32(option.Data[32:36]),
			}
			if len(option.Data) >= 40 {
				hist.AvgLatency = binary.BigEndian.Uint32(option.Data[36:40])
			}
			return nil, hist
		}
	}
	return nil, nil
}

// parseGenericVendorOption parses generic vendor-specific options
func (p *Parser) parseGenericVendorOption(option Option) map[string]interface{} {
	decoded := make(map[string]interface{})
	decoded["vendor"] = p.getVendorName(option.Class)
	decoded["class"] = fmt.Sprintf("0x%04x", option.Class)
	decoded["type"] = fmt.Sprintf("0x%02x", option.Type)
	decoded["data_length"] = len(option.Data)
	
	// Try to extract common patterns
	if len(option.Data) >= 4 {
		decoded["first_uint32"] = binary.BigEndian.Uint32(option.Data[0:4])
	}
	if len(option.Data) >= 8 {
		decoded["second_uint32"] = binary.BigEndian.Uint32(option.Data[4:8])
	}
	
	return decoded
}

// getVendorName returns human-readable vendor name for option class
func (p *Parser) getVendorName(class uint16) string {
	switch class {
	case OptionClassVMware:
		return "VMware Inc."
	case OptionClassCisco:
		return "Cisco Systems Inc."
	case OptionClassMicrosoft:
		return "Microsoft Corporation"
	case OptionClassGoogle:
		return "Google Inc."
	case OptionClassAmazon:
		return "Amazon.com Inc."
	case OptionClassHuawei:
		return "Huawei Technologies"
	case OptionClassJuniper:
		return "Juniper Networks"
	case OptionClassArista:
		return "Arista Networks"
	case OptionClassMellanox:
		return "NVIDIA/Mellanox"
	case OptionClassBroadcom:
		return "Broadcom Inc."
	default:
		if class >= 0x0100 && class <= 0xFEFF {
			return fmt.Sprintf("Vendor-Specific (0x%04x)", class)
		} else if class >= 0xFF00 && class <= 0xFFFF {
			return fmt.Sprintf("Experimental (0x%04x)", class)
		}
		return fmt.Sprintf("Unknown (0x%04x)", class)
	}
}

// Helper functions to convert options to maps
func (p *Parser) vmwareOptionToMap(opt VMwareNSXOption) map[string]interface{} {
	return map[string]interface{}{
		"type":       "VMware NSX Metadata",
		"vsid":       opt.VSID,
		"source_vni": opt.SourceVNI,
		"flags":      fmt.Sprintf("0x%04x", opt.Flags),
		"policy_id":  opt.PolicyID,
		"source_tep": fmt.Sprintf("0x%08x", opt.SourceTEP),
	}
}

func (p *Parser) ciscoOptionToMap(opt CiscoACIOption) map[string]interface{} {
	return map[string]interface{}{
		"type":           "Cisco ACI Metadata",
		"epg_id":         opt.EPGID,
		"bridge_domain":  opt.BridgeDomain,
		"vrf":            opt.VRF,
		"contract_id":    opt.ContractID,
		"flags":          fmt.Sprintf("0x%08x", opt.Flags),
		"tenant_id":      opt.TenantID,
		"application_id": opt.ApplicationID,
	}
}

// aristaOptionToMap converts Arista TAP option to map
func (p *Parser) aristaOptionToMap(opt AristaTAPOption) map[string]interface{} {
	return map[string]interface{}{
		"type":         "Arista Traffic Analysis Platform",
		"flow_id":      opt.FlowID,
		"ingress_port": opt.IngressPort,
		"egress_port":  opt.EgressPort,
		"timestamp":    opt.Timestamp,
		"packet_size":  opt.PacketSize,
		"flags":        fmt.Sprintf("0x%04x", opt.Flags),
		"queue_depth":  opt.QueueDepth,
		"latency":      opt.Latency,
	}
}

// aristaLatencyOptionToMap converts Arista latency option to map
func (p *Parser) aristaLatencyOptionToMap(opt AristaLatencyOption) map[string]interface{} {
	return map[string]interface{}{
		"type":            "Arista Advanced Latency Measurement",
		"flow_hash":       opt.FlowHash,
		"ingress_ts":      opt.IngressTS,
		"egress_ts":       opt.EgressTS,
		"queue_wait_time": opt.QueueWaitTime,
	}
}

// broadcomOptionToMap converts Broadcom switch telemetry option to map
func (p *Parser) broadcomOptionToMap(opt BroadcomSwitchTelemetryOption) map[string]interface{} {
	return map[string]interface{}{
		"type":        "Broadcom Switch Telemetry",
		"switch_id":   opt.SwitchID,
		"chip_id":     opt.ChipID,
		"pipeline_id": opt.PipelineID,
		"buffer_util": opt.BufferUtil,
		"packet_rate": opt.PacketRate,
		"byte_rate":   opt.ByteRate,
		"drop_count":  opt.DropCount,
		"error_count": opt.ErrorCount,
	}
}

// broadcomLatencyOptionToMap converts Broadcom latency histogram option to map
func (p *Parser) broadcomLatencyOptionToMap(opt BroadcomLatencyHistOption) map[string]interface{} {
	return map[string]interface{}{
		"type":             "Broadcom Latency Histogram",
		"port_id":          opt.PortID,
		"bucket_0_1us":     opt.Bucket0_1us,
		"bucket_1_10us":    opt.Bucket1_10us,
		"bucket_10_100us":  opt.Bucket10_100us,
		"bucket_100us_1ms": opt.Bucket100us_1ms,
		"bucket_1ms_10ms":  opt.Bucket1ms_10ms,
		"bucket_over_10ms": opt.BucketOver10ms,
		"max_latency":      opt.MaxLatency,
		"min_latency":      opt.MinLatency,
		"avg_latency":      opt.AvgLatency,
	}
}

// isGenevePayload checks if the payload might contain another GENEVE layer
func (p *Parser) isGenevePayload(payload []byte, protocolType uint16) bool {
	// For now, we assume nested GENEVE if:
	// 1. Protocol type suggests tunneling
	// 2. Payload is large enough for another GENEVE header
	// 3. The first bytes look like a valid GENEVE header
	
	if len(payload) < GeneveHeaderSize {
		return false
	}

	// Check if first bytes look like GENEVE header
	version := (payload[0] >> 6) & 0x3
	return version == GeneveVersion
}

// EnableEnterpriseExtensions enables parsing of enterprise-specific options
func (p *Parser) EnableEnterpriseExtensions() {
	p.ParseEnterpriseExtensions = true
}

// DisableEnterpriseExtensions disables parsing of enterprise-specific options
func (p *Parser) DisableEnterpriseExtensions() {
	p.ParseEnterpriseExtensions = false
}

// RegisterEnterpriseDecoder registers a custom decoder for an enterprise option class
func (p *Parser) RegisterEnterpriseDecoder(class uint16, decoder func([]byte)) {
	if p.EnterpriseDecoders == nil {
		p.EnterpriseDecoders = make(map[uint16]func([]byte))
	}
	p.EnterpriseDecoders[class] = decoder
}

// UnregisterEnterpriseDecoder removes a custom decoder for an enterprise option class
func (p *Parser) UnregisterEnterpriseDecoder(class uint16) {
	if p.EnterpriseDecoders != nil {
		delete(p.EnterpriseDecoders, class)
	}
}

// GetVNI returns the Virtual Network Identifier from the header
func (h *Header) GetVNI() uint32 {
	return h.VNI
}

// HasCriticalOptions returns true if critical options are present
func (h *Header) HasCriticalOptions() bool {
	return h.CFlag
}

// IsOAMPacket returns true if this is an OAM packet
func (h *Header) IsOAMPacket() bool {
	return h.OFlag
}

// GetProtocolName returns a human-readable protocol name
func (h *Header) GetProtocolName() string {
	switch h.ProtocolType {
	case ProtocolTypeIPv4:
		return "IPv4"
	case ProtocolTypeIPv6:
		return "IPv6"
	case ProtocolTypeEthernet:
		return "Ethernet"
	case ProtocolTypeARP:
		return "ARP"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", h.ProtocolType)
	}
}

// String returns a string representation of the header
func (h *Header) String() string {
	return fmt.Sprintf("GENEVE(Ver:%d, VNI:%d, Proto:%s, Options:%d bytes, Flags:O=%t,C=%t)",
		h.Version, h.VNI, h.GetProtocolName(), h.OptionLength*4, h.OFlag, h.CFlag)
}

// GetOptionClassName returns a human-readable name for the option class
func (o *Option) GetOptionClassName() string {
	switch o.Class {
	case 0x0000:
		return "Experimental"
	case 0x0001:
		return "Linux Generic"
	case 0x0002:
		return "Open vSwitch"
	case 0x0003:
		return "VMware"
	case 0x0004:
		return "Cisco"
	case 0x0005:
		return "Microsoft"
	case 0x0006:
		return "Google"
	case 0x0007:
		return "Amazon"
	case 0x0008:
		return "Huawei"
	case 0x0009:
		return "Juniper"
	case 0x000A:
		return "Arista"
	case 0x000B:
		return "NVIDIA/Mellanox"
	case 0x000C:
		return "Broadcom"
	case 0x0103:
		return "INT (In-band Network Telemetry)"
	case 0xFFFF:
		return "Platform Specific"
	default:
		if o.Class >= 0x0005 && o.Class <= 0x00FF {
			return "IETF Standards"
		} else if o.Class >= 0x0100 && o.Class <= 0xFEFF {
			return "Vendor Specific"
		} else if o.Class >= 0xFF00 && o.Class <= 0xFFFE {
			return "Experimental Use"
		}
		return fmt.Sprintf("Unknown(0x%04x)", o.Class)
	}
}

// GetOptionTypeName returns a human-readable name for the option type
func (o *Option) GetOptionTypeName() string {
	classType := (uint32(o.Class) << 8) | uint32(o.Type)
	
	// Check for well-known class-type combinations first
	switch classType {
	case OptionClassINTMetadata:
		return "INT Metadata"
	case OptionClassINTDestination:
		return "INT Destination"
	case OptionClassINTMX:
		return "INT Monitoring & Export"
	}

	// Check by class and type separately
	switch o.Class {
	case 0x0103: // INT class
		switch o.Type {
		case INTTypeMetadata:
			return "INT Metadata"
		case INTTypeDestination:
			return "INT Destination"
		case INTTypeMX:
			return "INT Monitoring & Export"
		case INTTypeSource:
			return "INT Source"
		case INTTypeSink:
			return "INT Sink"
		default:
			return fmt.Sprintf("INT Type 0x%02x", o.Type)
		}
	case 0x0001: // Linux Generic
		switch o.Type {
		case GenericTypeTimestamp:
			return "Timestamp"
		case GenericTypeSecurityTag:
			return "Security Tag"
		case GenericTypeQoSMarking:
			return "QoS Marking"
		case GenericTypeLoadBalance:
			return "Load Balance Hint"
		case GenericTypeDebugInfo:
			return "Debug Info"
		default:
			return fmt.Sprintf("Generic Type 0x%02x", o.Type)
		}
	case 0x0000: // Experimental
		switch o.Type {
		case OAMTypeEcho:
			return "OAM Echo"
		case OAMTypeTrace:
			return "OAM Trace"
		case OAMTypeConnectivity:
			return "OAM Connectivity"
		default:
			return fmt.Sprintf("Experimental Type 0x%02x", o.Type)
		}
	case OptionClassVMware: // VMware
		switch o.Type {
		case VMwareTypeNSXMetadata:
			return "NSX Metadata"
		case VMwareTypeVXLANCompat:
			return "VXLAN Compatibility"
		case VMwareTypeVDSMetadata:
			return "vSphere Distributed Switch"
		case VMwareTypeDVSExtension:
			return "DVS Extension"
		default:
			return fmt.Sprintf("VMware Type 0x%02x", o.Type)
		}
	case OptionClassCisco: // Cisco
		switch o.Type {
		case CiscoTypeACI:
			return "Application Centric Infrastructure"
		case CiscoTypeSDAccess:
			return "Software-Defined Access"
		case CiscoTypeVXLANGPO:
			return "VXLAN Group Policy Option"
		case CiscoTypeSGT:
			return "Security Group Tag"
		case CiscoTypePathTrace:
			return "Path Trace"
		default:
			return fmt.Sprintf("Cisco Type 0x%02x", o.Type)
		}
	case OptionClassMicrosoft: // Microsoft
		switch o.Type {
		case MicrosoftTypeHyperV:
			return "Hyper-V Metadata"
		case MicrosoftTypeAzure:
			return "Azure Metadata"
		case MicrosoftTypeSDN:
			return "Software Defined Networking"
		default:
			return fmt.Sprintf("Microsoft Type 0x%02x", o.Type)
		}
	case OptionClassAmazon: // Amazon
		switch o.Type {
		case AmazonTypeVPC:
			return "VPC Metadata"
		case AmazonTypeECS:
			return "Elastic Container Service"
		case AmazonTypeEKS:
			return "Elastic Kubernetes Service"
		default:
			return fmt.Sprintf("Amazon Type 0x%02x", o.Type)
		}
	case OptionClassGoogle: // Google
		switch o.Type {
		case GoogleTypeGKE:
			return "Google Kubernetes Engine"
		case GoogleTypeGCE:
			return "Google Compute Engine"
		case GoogleTypeCloudArmor:
			return "Cloud Armor"
		default:
			return fmt.Sprintf("Google Type 0x%02x", o.Type)
		}
	default:
		return fmt.Sprintf("Type 0x%02x", o.Type)
	}
}

// GetOptionDescription returns a detailed description of the option
func (o *Option) GetOptionDescription() string {
	return fmt.Sprintf("%s - %s", o.GetOptionClassName(), o.GetOptionTypeName())
}

// String returns a string representation of the option
func (o *Option) String() string {
	return fmt.Sprintf("Option(Class:%s, Type:%s, Length:%d bytes)", 
		o.GetOptionClassName(), o.GetOptionTypeName(), o.Length*4)
}

// IsINTOption returns true if this is an INT (In-band Network Telemetry) option
func (o *Option) IsINTOption() bool {
	return o.Class == 0x0103
}

// IsCritical returns true if this option type is typically critical
func (o *Option) IsCritical() bool {
	switch o.Class {
	case 0x0103: // INT options are typically critical
		return true
	case 0x0001: // Security tags are critical
		return o.Type == GenericTypeSecurityTag
	default:
		return false
	}
}

// GetINTInstructionNames returns human-readable names for INT instruction bitmap
func (i *INTMetadataOption) GetINTInstructionNames() []string {
	var instructions []string
	bitmap := i.InstructionBitmap

	// INT instruction bits (from INT spec v2.1)
	if bitmap&INTInstrSwitchID != 0 {
		instructions = append(instructions, "Switch ID")
	}
	if bitmap&INTInstrIngressPort != 0 {
		instructions = append(instructions, "Ingress Port")
	}
	if bitmap&INTInstrEgressPort != 0 {
		instructions = append(instructions, "Egress Port")
	}
	if bitmap&INTInstrHopLatency != 0 {
		instructions = append(instructions, "Hop Latency")
	}
	if bitmap&INTInstrQueueOccupancy != 0 {
		instructions = append(instructions, "Queue Occupancy")
	}
	if bitmap&INTInstrIngressTimestamp != 0 {
		instructions = append(instructions, "Ingress Timestamp")
	}
	if bitmap&INTInstrEgressTimestamp != 0 {
		instructions = append(instructions, "Egress Timestamp")
	}
	if bitmap&INTInstrLevel2Port != 0 {
		instructions = append(instructions, "Level 2 Port")
	}
	if bitmap&INTInstrEgressTXUtil != 0 {
		instructions = append(instructions, "Egress TX Utilization")
	}
	if bitmap&INTInstrBufferPool != 0 {
		instructions = append(instructions, "Buffer Pool")
	}
	if bitmap&INTInstrChecksumComplement != 0 {
		instructions = append(instructions, "Checksum Complement")
	}

	if len(instructions) == 0 {
		instructions = append(instructions, fmt.Sprintf("Custom(0x%04x)", bitmap))
	}

	return instructions
}

// GetVersionName returns a human-readable name for the INT version
func (i *INTMetadataOption) GetVersionName() string {
	switch i.Version {
	case INTVersion1:
		return "INT v1.0"
	case INTVersion2:
		return "INT v2.0"
	case INTVersion3:
		return "INT v2.1"
	case INTVersion4:
		return "INT v2.1+ (Current)"
	default:
		return fmt.Sprintf("INT v%d (Unknown)", i.Version)
	}
}

// GetFlagsDescription returns a description of the INT flags
func (i *INTMetadataOption) GetFlagsDescription() string {
	var flags []string
	if i.Discard {
		flags = append(flags, "DISCARD")
	}
	if i.ExceededMaxHops {
		flags = append(flags, "MAX_HOPS_EXCEEDED")
	}
	if i.MTUExceeded {
		flags = append(flags, "MTU_EXCEEDED")
	}
	if len(flags) == 0 {
		return "None"
	}
	return fmt.Sprintf("[%s]", strings.Join(flags, ", "))
}

// String returns a string representation of the INT metadata option
func (i *INTMetadataOption) String() string {
	instructions := i.GetINTInstructionNames()
	instructStr := strings.Join(instructions, ", ")
	if len(instructStr) > 50 {
		instructStr = instructStr[:47] + "..."
	}
	
	return fmt.Sprintf("INTMetadata(%s, Hops:%d, Domain:0x%04x, Flags:%s, Instructions:[%s])",
		i.GetVersionName(), i.RemainingHopCount, i.DomainSpecificID, 
		i.GetFlagsDescription(), instructStr)
}

// String returns a string representation of an enterprise option
func (e *EnterpriseOption) String() string {
	status := "raw"
	if e.Decoded {
		status = "decoded"
	}
	return fmt.Sprintf("EnterpriseOption(%s, Class:0x%04x, Type:0x%02x, Status:%s)", 
		e.VendorName, e.Class, e.Type, status)
}

// String returns a string representation of a VMware NSX option
func (v *VMwareNSXOption) String() string {
	return fmt.Sprintf("VMwareNSX(VSID:0x%08x, SourceVNI:0x%08x, PolicyID:%d, Flags:0x%04x)", 
		v.VSID, v.SourceVNI, v.PolicyID, v.Flags)
}

// String returns a string representation of a Cisco ACI option
func (c *CiscoACIOption) String() string {
	return fmt.Sprintf("CiscoACI(EPG:%d, BD:%d, VRF:%d, Contract:%d, Tenant:%d)", 
		c.EPGID, c.BridgeDomain, c.VRF, c.ContractID, c.TenantID)
}