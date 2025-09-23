# VMware NSX Telemetry

This document describes the VMware NSX telemetry support in the GENEVE parser.

## Overview

VMware NSX uses GENEVE encapsulation to carry virtual network metadata and telemetry information. The parser provides comprehensive support for NSX-specific telemetry data embedded within GENEVE options.

## Telemetry Data Structure

### VMware NSX Metadata Option

```go
type VMwareNSXOption struct {
    Option
    VSID        uint32 // Virtual Segment ID
    SourceVNI   uint32 // Source VNI for cross-segment tracking
    Flags       uint16 // NSX-specific flags
    PolicyID    uint32 // Security policy identifier
    SourceTEP   uint32 // Source Tunnel Endpoint
}
```

## Telemetry Fields

### Core Identifiers
- **VSID (Virtual Segment ID)**: Identifies the virtual network segment
- **Source VNI**: Original VNI for multi-segment flows
- **Source TEP**: Tunnel endpoint that originated the packet

### Security Context
- **Policy ID**: References applied security policies
- **Flags**: NSX operational flags including:
  - Distributed firewall state
  - Load balancer indicators
  - Quality of Service markers

## Use Cases

### Network Segmentation
- Track traffic flow between virtual segments
- Enforce micro-segmentation policies
- Monitor east-west traffic patterns

### Security Analytics
- Correlate security policy enforcement
- Track distributed firewall decisions
- Audit compliance with network policies

### Performance Monitoring
- Measure tunnel endpoint performance
- Track cross-segment latency
- Monitor virtual network utilization

## Example Usage

```go
parser := geneve.NewParser()
parser.EnableEnterpriseExtensions()

result, err := parser.ParsePacket(packet)
if err != nil {
    log.Fatal(err)
}

// Access VMware NSX telemetry
for _, nsx := range result.VMwareOptions {
    fmt.Printf("NSX Segment: %d, Policy: %d, TEP: 0x%08x\n",
        nsx.VSID, nsx.PolicyID, nsx.SourceTEP)
    
    // Security policy analysis
    if nsx.PolicyID != 0 {
        fmt.Printf("Security policy %d applied\n", nsx.PolicyID)
    }
    
    // Cross-segment tracking
    if nsx.SourceVNI != result.Header.VNI {
        fmt.Printf("Cross-segment flow: %d -> %d\n", 
            nsx.SourceVNI, result.Header.VNI)
    }
}
```

## Human-Readable Output

The parser automatically converts NSX telemetry to human-readable format:

```json
{
  "type": "VMware NSX Metadata",
  "vsid": 12345,
  "source_vni": 67890,
  "flags": "0x0001",
  "policy_id": 100,
  "source_tep": "0x0a000001"
}
```

## Integration with Network Monitoring

### SIEM Integration
```go
// Export NSX telemetry for security analysis
for _, nsx := range result.VMwareOptions {
    securityEvent := map[string]interface{}{
        "timestamp": time.Now(),
        "segment_id": nsx.VSID,
        "policy_id": nsx.PolicyID,
        "source_tep": fmt.Sprintf("0x%08x", nsx.SourceTEP),
        "flags": nsx.Flags,
    }
    // Send to SIEM system
}
```

### Performance Analytics
```go
// Track segment performance metrics
segmentMetrics := make(map[uint32]*SegmentStats)
for _, nsx := range result.VMwareOptions {
    stats := segmentMetrics[nsx.VSID]
    if stats == nil {
        stats = &SegmentStats{}
        segmentMetrics[nsx.VSID] = stats
    }
    stats.PacketCount++
    stats.ByteCount += uint64(len(result.Payload))
}
```

## Advanced Features

### Policy Correlation
- Link telemetry data with NSX policy configurations
- Track policy effectiveness and compliance
- Generate policy optimization recommendations

### Tunnel Analytics
- Monitor tunnel endpoint health and performance
- Detect tunnel failover scenarios
- Analyze cross-datacenter traffic patterns

### Virtual Network Topology
- Build dynamic network topology maps
- Track virtual machine mobility
- Monitor network service insertion

## Configuration

### Custom Decoders
```go
parser.AddEnterpriseDecoder(geneve.OptionClassVMware, func(data []byte) {
    // Custom NSX metadata processing
    fmt.Printf("Custom NSX processing: %d bytes\n", len(data))
})
```

### Telemetry Filtering
```go
// Process only specific NSX segments
if len(result.VMwareOptions) > 0 {
    for _, nsx := range result.VMwareOptions {
        if nsx.VSID >= 10000 && nsx.VSID < 20000 {
            // Process production segments only
            processProductionTelemetry(nsx)
        }
    }
}
```

## Troubleshooting

### Common Issues
1. **Missing NSX Options**: Ensure `EnableEnterpriseExtensions()` is called
2. **Invalid Policy IDs**: Check NSX manager configuration
3. **TEP Resolution**: Verify tunnel endpoint reachability

### Debug Output
```go
// Enable verbose NSX telemetry logging
for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "VMware" && enterprise.Decoded {
        fmt.Printf("NSX Debug: %+v\n", enterprise.DecodedData)
    }
}
```

## Standards and References

- [RFC 8926 - Geneve Protocol](https://tools.ietf.org/html/rfc8926)
- [VMware NSX Data Center Documentation](https://docs.vmware.com/en/VMware-NSX-Data-Center/)
- [NSX Telemetry and Monitoring Guide](https://docs.vmware.com/en/VMware-NSX-Data-Center/3.2/administration/GUID-monitoring.html)

## Related Documentation

- [Enterprise Telemetry Overview](../README.md#enterprise-telemetry-support)
- [Cisco ACI Telemetry](cisco-aci-telemetry.md)
- [Multi-Vendor Integration](multi-vendor-integration.md)