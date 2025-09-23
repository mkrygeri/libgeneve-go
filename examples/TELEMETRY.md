# GENEVE In-Band Telemetry Enterprise Extensions

This directory contains comprehensive examples demonstrating GENEVE protocol parsing with enterprise extensions and in-band telemetry (INT) data extraction.

## Examples

### 1. `int-telemetry.go` - Comprehensive INT Enterprise Integration
**Purpose**: Demonstrates comprehensive in-band telemetry extraction with enterprise context correlation

**Features**:
- Standard INT metadata parsing with enterprise vendor context
- Multi-vendor policy correlation (VMware NSX, Cisco ACI, Microsoft Hyper-V)
- Custom enterprise INT decoder registration and usage
- Cross-vendor telemetry analysis and network insights
- Automated monitoring recommendations

**Key Capabilities**:
```go
// Extract INT telemetry with enterprise context
📊 INT Telemetry Data:
  Version: INT v2.1+ (Current)
  Domain: 0x1000 (VMware vSphere)
  Instructions: Switch ID, Ingress Port, Hop Latency
  Network Issues: MTU exceeded detected

🏢 Enterprise Context (VMware NSX):
  VSID: 0x12345678 (Virtual Segment)
  Policy ID: 0x4444 (Security Policy)
  Source TEP: 0xabcdef00 (Tunnel Endpoint)
```

### 2. `telemetry-extraction.go` - Structured Data for Monitoring Systems
**Purpose**: Extracts structured telemetry data in JSON format for integration with monitoring systems

**Features**:
- Structured JSON output for monitoring system ingestion
- Automated alert generation based on telemetry analysis
- Policy context correlation across multiple vendors
- Network issue detection and classification
- Performance metrics and recommendations

**Output Format**:
```json
{
  "timestamp": "2025-09-22T19:18:20.260989031-04:00",
  "vni": 43707,
  "protocol": "Ethernet",
  "int_data": {
    "version": "INT v2.1+ (Current)",
    "domain": "0x1000",
    "remaining_hops": 8,
    "instructions": ["Switch ID", "Hop Latency"],
    "network_issues": ["MTU exceeded"]
  },
  "enterprise_data": [
    {
      "vendor": "VMware Inc.",
      "type": "NSX Metadata",
      "decoded": true,
      "decoded_data": {
        "vsid": 286331153,
        "policy_id": 17476,
        "source_tep": "0x55555555"
      }
    }
  ]
}
```

## Key Enterprise INT Features

### 🎯 **Vendor-Specific Telemetry Correlation**
- **VMware NSX**: VSID, Source VNI, Policy IDs, Security flags, TEP addresses
- **Cisco ACI**: EPG IDs, Bridge domains, VRFs, Contract IDs, Tenant/Application context
- **Microsoft Hyper-V**: VM IDs, Hyper-V specific metadata
- **Custom Decoders**: Extensible system for proprietary telemetry formats

### 📊 **Advanced Telemetry Analysis**
- **Network Issue Detection**: Discard flags, MTU exceeded, max hops exceeded
- **Performance Insights**: Hop count analysis, latency path assessment
- **Policy Correlation**: Security group mappings, tenant isolation context
- **Cross-Domain Analytics**: Multi-vendor environment correlation

### 🔧 **Custom Enterprise INT Extensions**
```go
// Register custom enterprise INT decoder
parser.RegisterEnterpriseDecoder(0x2000, func(data []byte) {
    switchID := binary.BigEndian.Uint32(data[0:4])
    ingressPort := binary.BigEndian.Uint32(data[4:8])
    hopLatency := binary.BigEndian.Uint32(data[12:16])
    
    fmt.Printf("Custom INT: Switch=0x%08x, Port=%d, Latency=%dμs\n", 
        switchID, ingressPort, hopLatency)
})
```

### ⚠️ **Automated Monitoring Alerts**
- **NETWORK_ISSUE**: Packet discard flags, MTU issues, hop limit exceeded
- **HIGH_LATENCY**: Excessive hop counts indicating routing issues  
- **SECURITY_POLICY**: Suspicious VSID/EPG patterns, policy violations
- **MISSING_CONTEXT**: INT telemetry without enterprise policy context

## Integration Benefits

✅ **Enhanced Network Visibility**: Correlates standard INT data with vendor-specific policy context  
✅ **Multi-Vendor Support**: Unified parsing for VMware, Cisco, Microsoft, and custom extensions  
✅ **Monitoring Integration**: JSON output ready for SIEM, APM, and network monitoring tools  
✅ **Performance Insights**: Automated analysis and recommendations for network optimization  
✅ **Security Context**: Policy enforcement visibility and security group correlation  
✅ **Extensible Architecture**: Custom decoder registration for proprietary telemetry formats  

## Usage Patterns

### Real-Time Monitoring
```bash
# Extract telemetry for real-time monitoring
go run telemetry-extraction.go > /var/log/geneve-telemetry.json

# Process with monitoring tools
cat /var/log/geneve-telemetry.json | jq '.[] | select(.network_issues | length > 0)'
```

### Network Troubleshooting  
```bash
# Analyze comprehensive telemetry with enterprise context
go run int-telemetry.go

# Focus on specific vendor contexts
grep "VMware\|Cisco\|Microsoft" telemetry-output.log
```

This enterprise INT integration provides unprecedented visibility into modern multi-vendor network environments, enabling advanced troubleshooting, performance optimization, and security policy enforcement visibility.