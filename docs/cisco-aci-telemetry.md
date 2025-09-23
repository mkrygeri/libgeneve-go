# Cisco ACI Telemetry

This document describes the Cisco Application Centric Infrastructure (ACI) telemetry support in the GENEVE parser.

## Overview

Cisco ACI uses GENEVE to transport application-centric network metadata and policy information. The parser provides comprehensive support for ACI-specific telemetry data that enables application-aware network monitoring and policy enforcement.

## Telemetry Data Structure

### Cisco ACI Metadata Option

```go
type CiscoACIOption struct {
    Option
    EPGID         uint32 // Endpoint Group ID
    BridgeDomain  uint32 // Bridge Domain identifier
    VRF           uint32 // Virtual Routing and Forwarding instance
    ContractID    uint32 // Security contract identifier
    Flags         uint32 // ACI-specific operational flags
    TenantID      uint32 // Tenant identifier
    ApplicationID uint32 // Application profile identifier
}
```

## Telemetry Fields

### Network Segmentation
- **EPG ID (Endpoint Group ID)**: Application endpoint group identifier
- **Bridge Domain**: Layer 2 forwarding domain
- **VRF**: Layer 3 routing instance
- **Tenant ID**: Multi-tenant isolation identifier

### Application Context
- **Application ID**: Application profile reference
- **Contract ID**: Inter-EPG communication contract
- **Flags**: Operational state and policy enforcement indicators

## Use Cases

### Application-Centric Monitoring
- Track traffic between application tiers
- Monitor application performance and behavior
- Correlate network metrics with application topology

### Policy Enforcement Analytics
- Audit security contract compliance
- Track micro-segmentation effectiveness
- Monitor policy violation attempts

### Multi-Tenant Operations
- Isolate telemetry per tenant
- Track resource utilization by tenant
- Monitor cross-tenant communication patterns

## Example Usage

```go
parser := geneve.NewParser()
parser.EnableEnterpriseExtensions()

result, err := parser.ParsePacket(packet)
if err != nil {
    log.Fatal(err)
}

// Access Cisco ACI telemetry
for _, aci := range result.CiscoOptions {
    fmt.Printf("ACI EPG: %d, Tenant: %d, Contract: %d\n",
        aci.EPGID, aci.TenantID, aci.ContractID)
    
    // Application tier analysis
    switch aci.EPGID {
    case 100:
        fmt.Println("Web tier traffic")
    case 200:
        fmt.Println("Application tier traffic")
    case 300:
        fmt.Println("Database tier traffic")
    }
    
    // Contract enforcement check
    if aci.ContractID != 0 {
        fmt.Printf("Security contract %d enforced\n", aci.ContractID)
    }
}
```

## Human-Readable Output

The parser automatically converts ACI telemetry to structured format:

```json
{
  "type": "Cisco ACI Metadata",
  "epg_id": 12345,
  "bridge_domain": 67890,
  "vrf": 100,
  "contract_id": 500,
  "flags": "0x00000001",
  "tenant_id": 1000,
  "application_id": 2000
}
```

## Integration Patterns

### Application Performance Monitoring
```go
// Track application tier performance
tierMetrics := make(map[uint32]*TierStats)
for _, aci := range result.CiscoOptions {
    stats := tierMetrics[aci.EPGID]
    if stats == nil {
        stats = &TierStats{
            TenantID: aci.TenantID,
            AppID:    aci.ApplicationID,
        }
        tierMetrics[aci.EPGID] = stats
    }
    stats.PacketCount++
    stats.ByteCount += uint64(len(result.Payload))
}
```

### Security Analytics
```go
// Monitor contract violations
for _, aci := range result.CiscoOptions {
    if aci.ContractID == 0 {
        // Traffic without contract - potential violation
        securityAlert := SecurityAlert{
            Timestamp:     time.Now(),
            SourceEPG:     aci.EPGID,
            TenantID:      aci.TenantID,
            ViolationType: "Missing Contract",
            Severity:      "High",
        }
        // Send to security monitoring system
    }
}
```

### Multi-Tenant Resource Tracking
```go
// Track resource utilization per tenant
tenantStats := make(map[uint32]*TenantUsage)
for _, aci := range result.CiscoOptions {
    usage := tenantStats[aci.TenantID]
    if usage == nil {
        usage = &TenantUsage{}
        tenantStats[aci.TenantID] = usage
    }
    usage.NetworkTraffic += uint64(len(result.Payload))
    usage.UniqueEPGs[aci.EPGID] = true
}
```

## Advanced Analytics

### Application Flow Mapping
```go
type FlowKey struct {
    SourceEPG uint32
    DestEPG   uint32
    TenantID  uint32
}

flows := make(map[FlowKey]*FlowStats)
for _, aci := range result.CiscoOptions {
    // Build application communication matrix
    key := FlowKey{
        SourceEPG: aci.EPGID,
        // DestEPG would come from destination metadata
        TenantID: aci.TenantID,
    }
    flows[key].PacketCount++
}
```

### Contract Effectiveness Analysis
```go
// Analyze contract usage patterns
contractStats := make(map[uint32]*ContractMetrics)
for _, aci := range result.CiscoOptions {
    if aci.ContractID > 0 {
        metrics := contractStats[aci.ContractID]
        if metrics == nil {
            metrics = &ContractMetrics{}
            contractStats[aci.ContractID] = metrics
        }
        metrics.HitCount++
        metrics.LastSeen = time.Now()
        metrics.AssociatedEPGs[aci.EPGID] = true
    }
}
```

### Tenant Isolation Verification
```go
// Verify tenant isolation
func verifyTenantIsolation(results []*geneve.ParseResult) {
    for _, result := range results {
        for _, aci := range result.CiscoOptions {
            // Check for cross-tenant communication
            if hasMultipleTenants(result.CiscoOptions) {
                logIsolationViolation(aci.TenantID)
            }
        }
    }
}
```

## Configuration and Customization

### Custom ACI Decoders
```go
// Add custom ACI metadata processing
parser.AddEnterpriseDecoder(geneve.OptionClassCisco, func(data []byte) {
    // Custom ACI processing logic
    if len(data) >= 28 {
        customField := binary.BigEndian.Uint32(data[24:28])
        fmt.Printf("Custom ACI field: %d\n", customField)
    }
})
```

### Policy-Based Filtering
```go
// Process only specific tenant traffic
targetTenant := uint32(1000)
for _, aci := range result.CiscoOptions {
    if aci.TenantID == targetTenant {
        // Process tenant-specific telemetry
        processTenantTraffic(aci)
    }
}
```

## Troubleshooting Guide

### Common Issues

1. **Missing ACI Metadata**
   - Verify ACI fabric configuration
   - Check GENEVE option class registration
   - Ensure enterprise extensions are enabled

2. **Invalid EPG Mappings**
   - Validate EPG configuration in APIC
   - Check application profile assignments
   - Verify endpoint learning status

3. **Contract Resolution Failures**
   - Check contract configuration
   - Verify EPG-to-contract bindings
   - Review policy enforcement settings

### Debug Information
```go
// Enable detailed ACI debugging
for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "Cisco" {
        fmt.Printf("ACI Debug Info: %+v\n", enterprise.DecodedData)
        
        // Check for parsing errors
        if !enterprise.Decoded {
            fmt.Printf("ACI parsing failed for class 0x%04x\n", 
                enterprise.Option.Class)
        }
    }
}
```

## Performance Considerations

### Efficient Processing
```go
// Batch process ACI telemetry for better performance
const batchSize = 1000
aciBatch := make([]CiscoACIOption, 0, batchSize)

for _, aci := range result.CiscoOptions {
    aciBatch = append(aciBatch, aci)
    if len(aciBatch) >= batchSize {
        processACIBatch(aciBatch)
        aciBatch = aciBatch[:0] // Reset slice
    }
}
```

### Memory Optimization
```go
// Use object pools for high-frequency processing
var aciPool = sync.Pool{
    New: func() interface{} {
        return make(map[string]interface{})
    },
}

func processACI(aci CiscoACIOption) {
    data := aciPool.Get().(map[string]interface{})
    defer aciPool.Put(data)
    
    // Process ACI data without allocations
    data["epg_id"] = aci.EPGID
    data["tenant_id"] = aci.TenantID
    // ... process data
    
    // Clear map for reuse
    for k := range data {
        delete(data, k)
    }
}
```

## Standards and References

- [RFC 8926 - Geneve Protocol](https://tools.ietf.org/html/rfc8926)
- [Cisco ACI Architecture Documentation](https://www.cisco.com/c/en/us/solutions/data-center-virtualization/application-centric-infrastructure/index.html)
- [ACI Policy Model Guide](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/1-x/policy-model/b_APIC_Policy_Model.html)

## Related Documentation

- [Enterprise Telemetry Overview](../README.md#enterprise-telemetry-support)
- [VMware NSX Telemetry](vmware-nsx-telemetry.md)
- [Multi-Vendor Integration](multi-vendor-integration.md)