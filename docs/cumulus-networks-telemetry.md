# Cumulus Networks GENEVE Telemetry Support

This document describes the GENEVE protocol parser's support for Cumulus Linux networking telemetry.

## Overview

Cumulus Networks (now NVIDIA Cumulus Linux) provides a comprehensive network operating system based on Debian Linux for bare metal switches. Their GENEVE telemetry offers insights into EVPN, VXLAN, MLAG operations, BGP performance, fabric health, and zero-touch provisioning.

## Option Class

- **Class**: `0x000D` (Cumulus Networks)
- **Vendor**: NVIDIA Cumulus Linux (formerly Cumulus Networks)

## Supported Telemetry Types

### 1. EVPN Telemetry (Type 0x01)

Ethernet VPN performance and status information.

```go
type EVPNTelemetry struct {
    VTEPIP    uint32 // VTEP IP address
    VNIID     uint32 // VNI identifier
    MACCount  uint32 // MAC address table size
}
```

**Use Cases:**
- EVPN fabric monitoring
- VNI utilization tracking
- MAC address table optimization
- Multi-tenancy performance analysis

### 2. VXLAN Performance (Type 0x02)

Virtual Extensible LAN performance metrics.

```go
type VXLANPerformance struct {
    TunnelID      uint32 // VXLAN tunnel identifier
    EncapLatency  uint32 // Encapsulation latency in microseconds
    DecapLatency  uint32 // Decapsulation latency in microseconds
    PacketRate    uint32 // Packets per second
}
```

**Applications:**
- Overlay network optimization
- Tunnel performance monitoring
- Latency troubleshooting
- Throughput analysis

### 3. MLAG Status (Type 0x03)

Multi-Chassis Link Aggregation status and performance.

```go
type MLAGStatus struct {
    PeerID        uint32 // MLAG peer identifier
    SyncStatus    uint32 // Synchronization status (0=synced, 1=unsynced)
    BondCount     uint32 // Number of active bonds
    FailoverTime  uint32 // Last failover time in milliseconds
}
```

**Benefits:**
- High availability monitoring
- Failover performance tracking
- Bond utilization analysis
- Peer health assessment

### 4. BGP Performance (Type 0x04)

Border Gateway Protocol performance metrics.

```go
type BGPPerformance struct {
    PeerCount       uint32 // Number of BGP peers
    RouteCount      uint32 // Total routes in RIB
    ConvergenceTime uint32 // Last convergence time in seconds
    UpdateRate      uint32 // Route updates per second
}
```

**Applications:**
- Routing performance optimization
- Convergence time monitoring
- Scaling analysis
- Network stability assessment

### 5. Fabric Health (Type 0x05)

Overall fabric health and performance indicators.

```go
type FabricHealth struct {
    SpineCount   uint32 // Active spine switches
    LeafCount    uint32 // Active leaf switches
    LinkUtilMax  uint32 // Maximum link utilization percentage
    ErrorRate    uint32 // Fabric-wide error rate
}
```

**Use Cases:**
- Data center fabric monitoring
- Capacity planning
- Performance trending
- Proactive maintenance

### 6. ZTP Status (Type 0x06)

Zero Touch Provisioning status and automation metrics.

```go
type ZTPStatus struct {
    ProvisionState  uint32 // Provisioning state (0=pending, 1=active, 2=complete)
    ConfigVersion   uint32 // Current configuration version
    LastUpdate      uint32 // Last update timestamp
    AutomationLevel uint32 // Automation percentage (0-100)
}
```

**Benefits:**
- Deployment automation monitoring
- Configuration management tracking
- Operational efficiency measurement
- Infrastructure scaling insights

## Usage Examples

### Basic Cumulus Telemetry Parsing

```go
parser := geneve.NewParser()
result, err := parser.ParsePacket(geneveData)
if err != nil {
    log.Fatal(err)
}

// Process Cumulus telemetry
for _, opt := range result.Options {
    if opt.Class == geneve.OptionClassCumulus {
        switch opt.Type {
        case geneve.CumulusTypeEVPN:
            fmt.Printf("EVPN VTEP %s VNI %d: %d MACs\n",
                intToIP(opt.DecodedData["vtep_ip"].(uint32)),
                opt.DecodedData["vni_id"],
                opt.DecodedData["mac_count"])
        case geneve.CumulusTypeVXLAN:
            fmt.Printf("VXLAN Tunnel %d: Encap %d μs, Decap %d μs\n",
                opt.DecodedData["tunnel_id"],
                opt.DecodedData["encap_latency"],
                opt.DecodedData["decap_latency"])
        case geneve.CumulusTypeMLAG:
            syncStatus := "synced"
            if opt.DecodedData["sync_status"].(uint32) != 0 {
                syncStatus = "unsynced"
            }
            fmt.Printf("MLAG Peer %d: %s, %d bonds\n",
                opt.DecodedData["peer_id"],
                syncStatus,
                opt.DecodedData["bond_count"])
        }
    }
}
```

### Advanced Fabric Monitoring

```go
func monitorCumulusFabric(result *geneve.ParseResult) {
    fabricStats := &FabricStatistics{}
    
    for _, opt := range result.EnterpriseOptions {
        if opt.Vendor == "NVIDIA Cumulus Linux" && opt.Decoded {
            switch opt.DecodedData["type"] {
            case "EVPN Telemetry":
                fabricStats.EVPNVNIs++
                if macCount, ok := opt.DecodedData["mac_count"].(uint32); ok {
                    fabricStats.TotalMACs += macCount
                }
                
            case "VXLAN Performance":
                if encapLatency, ok := opt.DecodedData["encap_latency"].(uint32); ok {
                    fabricStats.VXLANLatencies = append(fabricStats.VXLANLatencies, encapLatency)
                }
                
            case "BGP Performance":
                if routeCount, ok := opt.DecodedData["route_count"].(uint32); ok {
                    fabricStats.BGPRoutes = routeCount
                }
                if convergenceTime, ok := opt.DecodedData["convergence_time"].(uint32); ok {
                    fabricStats.LastConvergence = convergenceTime
                }
                
            case "Fabric Health":
                if spineCount, ok := opt.DecodedData["spine_count"].(uint32); ok {
                    fabricStats.ActiveSpines = spineCount
                }
                if leafCount, ok := opt.DecodedData["leaf_count"].(uint32); ok {
                    fabricStats.ActiveLeaves = leafCount
                }
                if errorRate, ok := opt.DecodedData["error_rate"].(uint32); ok {
                    if errorRate > 100 { // > 0.01% error rate
                        log.Printf("High fabric error rate: %d errors/10M packets", errorRate)
                    }
                }
            }
        }
    }
    
    // Generate fabric health report
    fabricStats.Report()
}

type FabricStatistics struct {
    EVPNVNIs        int
    TotalMACs       uint32
    VXLANLatencies  []uint32
    BGPRoutes       uint32
    LastConvergence uint32
    ActiveSpines    uint32
    ActiveLeaves    uint32
}

func (fs *FabricStatistics) Report() {
    fmt.Printf("Fabric Statistics:\n")
    fmt.Printf("  EVPN VNIs: %d\n", fs.EVPNVNIs)
    fmt.Printf("  Total MACs: %d\n", fs.TotalMACs)
    fmt.Printf("  BGP Routes: %d\n", fs.BGPRoutes)
    fmt.Printf("  Active Spines: %d\n", fs.ActiveSpines)
    fmt.Printf("  Active Leaves: %d\n", fs.ActiveLeaves)
    
    if len(fs.VXLANLatencies) > 0 {
        avgLatency := calculateAverage(fs.VXLANLatencies)
        fmt.Printf("  Avg VXLAN Latency: %d μs\n", avgLatency)
    }
    
    if fs.LastConvergence > 0 {
        fmt.Printf("  Last BGP Convergence: %d seconds\n", fs.LastConvergence)
    }
}
```

### EVPN Fabric Analysis

```go
func analyzeEVPNFabric(packets [][]byte) {
    parser := geneve.NewParser()
    vtepMap := make(map[uint32]*VTEPStats)
    vniMap := make(map[uint32]*VNIStats)
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.EnterpriseOptions {
            if opt.Vendor == "NVIDIA Cumulus Linux" && opt.Decoded {
                switch opt.DecodedData["type"] {
                case "EVPN Telemetry":
                    vtepIP := opt.DecodedData["vtep_ip"].(uint32)
                    vniID := opt.DecodedData["vni_id"].(uint32)
                    macCount := opt.DecodedData["mac_count"].(uint32)
                    
                    // Track VTEP statistics
                    if _, exists := vtepMap[vtepIP]; !exists {
                        vtepMap[vtepIP] = &VTEPStats{}
                    }
                    vtepMap[vtepIP].VNICount++
                    vtepMap[vtepIP].TotalMACs += macCount
                    
                    // Track VNI statistics
                    if _, exists := vniMap[vniID]; !exists {
                        vniMap[vniID] = &VNIStats{}
                    }
                    vniMap[vniID].VTEPCount++
                    vniMap[vniID].MACCount = macCount
                    
                case "VXLAN Performance":
                    tunnelID := opt.DecodedData["tunnel_id"].(uint32)
                    encapLatency := opt.DecodedData["encap_latency"].(uint32)
                    packetRate := opt.DecodedData["packet_rate"].(uint32)
                    
                    // Analyze tunnel performance
                    if encapLatency > 1000 { // > 1ms
                        log.Printf("High VXLAN encap latency on tunnel %d: %d μs", tunnelID, encapLatency)
                    }
                    if packetRate > 1000000 { // > 1M pps
                        log.Printf("High tunnel utilization %d: %d pps", tunnelID, packetRate)
                    }
                }
            }
        }
    }
    
    // Generate EVPN fabric report
    fmt.Printf("\nEVPN Fabric Analysis:\n")
    fmt.Printf("VTEPs: %d\n", len(vtepMap))
    fmt.Printf("VNIs: %d\n", len(vniMap))
    
    for vtepIP, stats := range vtepMap {
        fmt.Printf("VTEP %s: %d VNIs, %d total MACs\n",
            intToIP(vtepIP), stats.VNICount, stats.TotalMACs)
    }
    
    for vniID, stats := range vniMap {
        fmt.Printf("VNI %d: %d VTEPs, %d MACs\n",
            vniID, stats.VTEPCount, stats.MACCount)
    }
}

type VTEPStats struct {
    VNICount  int
    TotalMACs uint32
}

type VNIStats struct {
    VTEPCount int
    MACCount  uint32
}
```

### MLAG High Availability Monitoring

```go
func monitorMLAGHA(result *geneve.ParseResult) {
    mlagPairs := make(map[uint32]*MLAGPairStatus)
    
    for _, opt := range result.EnterpriseOptions {
        if opt.Vendor == "NVIDIA Cumulus Linux" && opt.Decoded {
            if opt.DecodedData["type"] == "MLAG Status" {
                peerID := opt.DecodedData["peer_id"].(uint32)
                syncStatus := opt.DecodedData["sync_status"].(uint32)
                bondCount := opt.DecodedData["bond_count"].(uint32)
                failoverTime := opt.DecodedData["failover_time"].(uint32)
                
                if _, exists := mlagPairs[peerID]; !exists {
                    mlagPairs[peerID] = &MLAGPairStatus{}
                }
                
                pair := mlagPairs[peerID]
                pair.PeerID = peerID
                pair.IsSynced = (syncStatus == 0)
                pair.ActiveBonds = bondCount
                pair.LastFailover = failoverTime
                
                // Alert on synchronization issues
                if !pair.IsSynced {
                    log.Printf("ALERT: MLAG peer %d out of sync", peerID)
                }
                
                // Alert on recent failovers
                currentTime := uint32(time.Now().Unix() * 1000) // Convert to milliseconds
                if currentTime-failoverTime < 300000 { // < 5 minutes
                    log.Printf("ALERT: Recent MLAG failover on peer %d: %d ms ago",
                        peerID, currentTime-failoverTime)
                }
                
                // Monitor bond health
                if bondCount == 0 {
                    log.Printf("WARNING: MLAG peer %d has no active bonds", peerID)
                } else if bondCount < 2 {
                    log.Printf("WARNING: MLAG peer %d has only %d bond(s)", peerID, bondCount)
                }
            }
        }
    }
    
    // Generate MLAG health summary
    syncedPairs := 0
    totalBonds := uint32(0)
    
    for _, pair := range mlagPairs {
        if pair.IsSynced {
            syncedPairs++
        }
        totalBonds += pair.ActiveBonds
    }
    
    fmt.Printf("MLAG Health Summary:\n")
    fmt.Printf("  Total MLAG pairs: %d\n", len(mlagPairs))
    fmt.Printf("  Synced pairs: %d\n", syncedPairs)
    fmt.Printf("  Total active bonds: %d\n", totalBonds)
    
    if syncedPairs < len(mlagPairs) {
        fmt.Printf("  WARNING: %d MLAG pair(s) out of sync\n", len(mlagPairs)-syncedPairs)
    }
}

type MLAGPairStatus struct {
    PeerID       uint32
    IsSynced     bool
    ActiveBonds  uint32
    LastFailover uint32
}
```

## Integration Scenarios

### Zero Touch Provisioning Automation

```go
func monitorZTPAutomation(result *geneve.ParseResult) {
    ztpDevices := make(map[string]*ZTPDeviceStatus)
    
    for _, opt := range result.EnterpriseOptions {
        if opt.Vendor == "NVIDIA Cumulus Linux" && opt.Decoded {
            if opt.DecodedData["type"] == "ZTP Status" {
                deviceID := fmt.Sprintf("device_%d", opt.DecodedData["provision_state"])
                
                if _, exists := ztpDevices[deviceID]; !exists {
                    ztpDevices[deviceID] = &ZTPDeviceStatus{}
                }
                
                device := ztpDevices[deviceID]
                device.ProvisionState = opt.DecodedData["provision_state"].(uint32)
                device.ConfigVersion = opt.DecodedData["config_version"].(uint32)
                device.LastUpdate = opt.DecodedData["last_update"].(uint32)
                device.AutomationLevel = opt.DecodedData["automation_level"].(uint32)
                
                // Monitor provisioning progress
                switch device.ProvisionState {
                case 0: // Pending
                    log.Printf("Device %s: ZTP pending", deviceID)
                case 1: // Active
                    log.Printf("Device %s: ZTP in progress (%d%% automated)", 
                        deviceID, device.AutomationLevel)
                case 2: // Complete
                    log.Printf("Device %s: ZTP complete (config v%d)", 
                        deviceID, device.ConfigVersion)
                }
                
                // Alert on automation level
                if device.AutomationLevel < 80 && device.ProvisionState == 1 {
                    log.Printf("WARNING: Device %s has low automation level: %d%%",
                        deviceID, device.AutomationLevel)
                }
            }
        }
    }
    
    // Generate ZTP summary
    pending := 0
    active := 0
    complete := 0
    
    for _, device := range ztpDevices {
        switch device.ProvisionState {
        case 0:
            pending++
        case 1:
            active++
        case 2:
            complete++
        }
    }
    
    fmt.Printf("ZTP Automation Summary:\n")
    fmt.Printf("  Pending: %d devices\n", pending)
    fmt.Printf("  Active: %d devices\n", active)
    fmt.Printf("  Complete: %d devices\n", complete)
}

type ZTPDeviceStatus struct {
    ProvisionState  uint32
    ConfigVersion   uint32
    LastUpdate      uint32
    AutomationLevel uint32
}
```

## Enterprise Integration

### Data Center Operations Dashboard

```go
func exportCumulusMetrics(result *geneve.ParseResult) {
    metrics := map[string]interface{}{
        "timestamp": time.Now(),
        "evpn_fabric": map[string]interface{}{},
        "vxlan_overlay": map[string]interface{}{},
        "mlag_ha": map[string]interface{}{},
        "bgp_routing": map[string]interface{}{},
        "fabric_health": map[string]interface{}{},
        "automation": map[string]interface{}{},
    }
    
    for _, opt := range result.EnterpriseOptions {
        if opt.Vendor == "NVIDIA Cumulus Linux" && opt.Decoded {
            switch opt.DecodedData["type"] {
            case "EVPN Telemetry":
                evpn := metrics["evpn_fabric"].(map[string]interface{})
                evpn["vni_count"] = opt.DecodedData["vni_id"]
                evpn["mac_table_size"] = opt.DecodedData["mac_count"]
                
            case "VXLAN Performance":
                vxlan := metrics["vxlan_overlay"].(map[string]interface{})
                vxlan["encap_latency"] = opt.DecodedData["encap_latency"]
                vxlan["packet_rate"] = opt.DecodedData["packet_rate"]
                
            case "MLAG Status":
                mlag := metrics["mlag_ha"].(map[string]interface{})
                mlag["sync_status"] = opt.DecodedData["sync_status"]
                mlag["bond_count"] = opt.DecodedData["bond_count"]
                
            case "BGP Performance":
                bgp := metrics["bgp_routing"].(map[string]interface{})
                bgp["route_count"] = opt.DecodedData["route_count"]
                bgp["convergence_time"] = opt.DecodedData["convergence_time"]
                
            case "Fabric Health":
                health := metrics["fabric_health"].(map[string]interface{})
                health["spine_count"] = opt.DecodedData["spine_count"]
                health["leaf_count"] = opt.DecodedData["leaf_count"]
                health["error_rate"] = opt.DecodedData["error_rate"]
                
            case "ZTP Status":
                automation := metrics["automation"].(map[string]interface{})
                automation["provision_state"] = opt.DecodedData["provision_state"]
                automation["automation_level"] = opt.DecodedData["automation_level"]
            }
        }
    }
    
    // Export to monitoring systems (Prometheus, InfluxDB, etc.)
    exportMetrics(metrics)
}
```

## Performance Considerations

### Optimization Guidelines

1. **EVPN Scale Monitoring**: Use VNI and MAC count metrics for capacity planning
2. **VXLAN Performance Tuning**: Monitor encapsulation latency for optimization opportunities
3. **MLAG High Availability**: Track synchronization status and failover times
4. **BGP Convergence**: Monitor route table size and convergence performance
5. **Automation Efficiency**: Track ZTP success rates and automation levels

### Best Practices

1. **Selective Telemetry**: Focus on relevant telemetry types for your deployment
2. **Threshold-based Alerting**: Set appropriate thresholds for proactive monitoring
3. **Trend Analysis**: Track metrics over time for capacity planning
4. **Integration**: Combine with infrastructure monitoring for complete visibility

## Related Documentation

- [Multi-vendor Integration Guide](multi-vendor-integration.md)
- [NVIDIA/Mellanox Telemetry](nvidia-mellanox-telemetry.md)
- [Data Center Fabric Monitoring](fabric-monitoring.md)

## Technical Support

For Cumulus Linux-specific questions:
- NVIDIA Cumulus Documentation: https://docs.nvidia.com/networking-ethernet-software/
- Cumulus Community: https://community.nvidia.com/t5/Ethernet-Switches/bd-p/ethernet-switches
- Enterprise Support: Contact your NVIDIA networking representative

## Utility Functions

```go
func intToIP(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        (ip>>24)&0xFF,
        (ip>>16)&0xFF,
        (ip>>8)&0xFF,
        ip&0xFF)
}

func calculateAverage(values []uint32) uint32 {
    if len(values) == 0 {
        return 0
    }
    var sum uint64
    for _, v := range values {
        sum += uint64(v)
    }
    return uint32(sum / uint64(len(values)))
}

func exportMetrics(metrics map[string]interface{}) {
    // Implementation depends on your monitoring system
    // Examples: Prometheus client, InfluxDB client, custom API
    log.Printf("Exporting metrics: %+v", metrics)
}
```

---
*Last updated: September 23, 2025*