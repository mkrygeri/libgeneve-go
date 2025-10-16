# Open Virtual Networking (OVN) GENEVE Telemetry Support

This document describes the GENEVE protocol parser's support for Open Virtual Networking (OVN) telemetry.

## Overview

Open Virtual Networking (OVN) is an open-source network virtualization solution that provides native virtual networking capabilities for Open vSwitch (OVS). OVN enables multi-tenant network virtualization with distributed logical switching, routing, security groups, and load balancing. The OVN GENEVE telemetry provides deep insights into virtual network operations, logical flow processing, and distributed firewall enforcement.

## Option Class

- **Class**: `0x0102` (Open Virtual Networking)
- **Vendor**: Open Virtual Networking (OVN)
- **IANA Assignment**: Official IANA NVO3 registry assignment

## Supported Telemetry Types

### 1. OVN Metadata (Type 0x01)

Provides core OVN logical network metadata embedded in GENEVE packets.

```go
type OVNMetadata struct {
    DatapathID    uint64 // Logical datapath identifier
    LogicalFlowID uint32 // Logical flow table entry
    PortBinding   uint32 // Logical port binding ID
}
```

**Use Cases:**
- Multi-tenant network isolation tracking
- Logical topology mapping
- Virtual network troubleshooting
- Flow correlation across physical infrastructure

**Example:**
```go
// Parse OVN metadata from GENEVE options
for _, opt := range result.Options {
    if opt.Class == geneve.OptionClassOVN && opt.Type == 0x01 {
        datapathID := binary.BigEndian.Uint64(opt.Data[0:8])
        logicalFlow := binary.BigEndian.Uint32(opt.Data[8:12])
        portBinding := binary.BigEndian.Uint32(opt.Data[12:16])
        
        fmt.Printf("OVN Datapath: %d, Flow: %d, Port: %d\n",
            datapathID, logicalFlow, portBinding)
    }
}
```

### 2. Tunnel Key (Type 0x02)

Encapsulates tunnel endpoint and VNI mapping information.

```go
type OVNTunnelKey struct {
    TunnelID      uint32 // GENEVE VNI / Tunnel ID
    RemoteIP      uint32 // Tunnel endpoint IP address
    EncapType     uint8  // Encapsulation type (GENEVE=0x01)
    Reserved      [3]byte
}
```

**Applications:**
- Tunnel endpoint discovery
- Virtual network to physical mapping
- Overlay network topology visualization
- Encapsulation efficiency monitoring

**Example:**
```go
// Extract tunnel key information
if opt.Class == geneve.OptionClassOVN && opt.Type == 0x02 {
    tunnelID := binary.BigEndian.Uint32(opt.Data[0:4])
    remoteIP := binary.BigEndian.Uint32(opt.Data[4:8])
    
    fmt.Printf("Tunnel VNI: %d, Remote: %s\n",
        tunnelID, intToIP(remoteIP))
}
```

### 3. Logical Port (Type 0x03)

Contains logical port metadata for MAC learning and port security.

```go
type OVNLogicalPort struct {
    PortUUID      [16]byte // Logical port UUID
    MACAddress    [6]byte  // Port MAC address
    PortSecurity  uint8    // Security flags
    Reserved      uint8
}
```

**Benefits:**
- Port security enforcement tracking
- MAC address learning visibility
- Virtual machine network identity
- Anti-spoofing validation

**Example:**
```go
// Process logical port information
if opt.Class == geneve.OptionClassOVN && opt.Type == 0x03 {
    portUUID := opt.Data[0:16]
    macAddr := opt.Data[16:22]
    security := opt.Data[22]
    
    fmt.Printf("Port UUID: %x, MAC: %x, Security: 0x%02x\n",
        portUUID, macAddr, security)
}
```

### 4. Connection Tracking (Type 0x80)

Provides stateful connection tracking information for NAT and firewalling.

```go
type OVNConnTrack struct {
    ConnID        uint64 // Connection tracking ID
    State         uint8  // Connection state (NEW, ESTABLISHED, etc.)
    NATFlags      uint8  // NAT operation flags
    TCPFlags      uint16 // TCP flags if applicable
    OrigSrcIP     uint32 // Original source IP
    OrigDstIP     uint32 // Original destination IP
}
```

**Applications:**
- Stateful firewall tracking
- NAT operation monitoring
- Connection state debugging
- Security policy enforcement validation

**Example:**
```go
// Analyze connection tracking data
if opt.Class == geneve.OptionClassOVN && opt.Type == 0x80 {
    connID := binary.BigEndian.Uint64(opt.Data[0:8])
    state := opt.Data[8]
    natFlags := opt.Data[9]
    tcpFlags := binary.BigEndian.Uint16(opt.Data[10:12])
    
    stateStr := []string{"NEW", "ESTABLISHED", "RELATED", "INVALID"}[state]
    fmt.Printf("Connection %d: %s, NAT: 0x%02x, TCP: 0x%04x\n",
        connID, stateStr, natFlags, tcpFlags)
}
```

### 5. Load Balancer (Type 0x81)

Load balancer metadata for distributed L4 load balancing.

```go
type OVNLoadBalancer struct {
    LBID          uint32 // Load balancer ID
    VIP           uint32 // Virtual IP address
    BackendIP     uint32 // Selected backend IP
    BackendPort   uint16 // Backend port
    Protocol      uint8  // L4 protocol (TCP=6, UDP=17)
    HealthStatus  uint8  // Backend health (0=down, 1=up)
}
```

**Use Cases:**
- Load balancing decision tracking
- Backend health monitoring
- Session persistence validation
- Traffic distribution analysis

**Example:**
```go
// Track load balancer operations
if opt.Class == geneve.OptionClassOVN && opt.Type == 0x81 {
    lbID := binary.BigEndian.Uint32(opt.Data[0:4])
    vip := binary.BigEndian.Uint32(opt.Data[4:8])
    backend := binary.BigEndian.Uint32(opt.Data[8:12])
    port := binary.BigEndian.Uint16(opt.Data[12:14])
    health := opt.Data[15]
    
    fmt.Printf("LB %d: VIP %s -> Backend %s:%d (health: %d)\n",
        lbID, intToIP(vip), intToIP(backend), port, health)
}
```

### 6. ACL Metadata (Type 0x82)

Access control list enforcement metadata.

```go
type OVNACLMetadata struct {
    ACLID         uint32 // ACL rule identifier
    Priority      uint16 // Rule priority
    Action        uint8  // Action (ALLOW=1, DENY=2, REJECT=3)
    Direction     uint8  // Direction (INGRESS=1, EGRESS=2)
    MatchCount    uint64 // Number of matches
}
```

**Benefits:**
- Security policy enforcement tracking
- ACL rule hit counting
- Firewall troubleshooting
- Compliance auditing

**Example:**
```go
// Monitor ACL enforcement
if opt.Class == geneve.OptionClassOVN && opt.Type == 0x82 {
    aclID := binary.BigEndian.Uint32(opt.Data[0:4])
    priority := binary.BigEndian.Uint16(opt.Data[4:6])
    action := opt.Data[6]
    direction := opt.Data[7]
    
    actionStr := []string{"", "ALLOW", "DENY", "REJECT"}[action]
    dirStr := []string{"", "INGRESS", "EGRESS"}[direction]
    fmt.Printf("ACL %d: %s %s (priority %d)\n",
        aclID, actionStr, dirStr, priority)
}
```

## Usage Examples

### Basic OVN Telemetry Parsing

```go
package main

import (
    "fmt"
    "log"
    "encoding/binary"
    "github.com/yourusername/libgeneve-go/geneve"
)

func main() {
    parser := geneve.NewParser()
    result, err := parser.ParsePacket(geneveData)
    if err != nil {
        log.Fatal(err)
    }

    // Process OVN telemetry
    for _, opt := range result.Options {
        if opt.Class == geneve.OptionClassOVN {
            switch opt.Type {
            case 0x01:
                fmt.Println("OVN Metadata:", parseOVNMetadata(opt.Data))
            case 0x02:
                fmt.Println("Tunnel Key:", parseOVNTunnelKey(opt.Data))
            case 0x03:
                fmt.Println("Logical Port:", parseOVNLogicalPort(opt.Data))
            case 0x80:
                fmt.Println("Connection Tracking:", parseOVNConnTrack(opt.Data))
            case 0x81:
                fmt.Println("Load Balancer:", parseOVNLoadBalancer(opt.Data))
            case 0x82:
                fmt.Println("ACL Metadata:", parseOVNACL(opt.Data))
            }
        }
    }
}
```

### Multi-Tenant Network Monitoring

```go
func monitorTenantTraffic(packets [][]byte) {
    parser := geneve.NewParser()
    tenantStats := make(map[uint64]*TenantStats)
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x01 {
                datapathID := binary.BigEndian.Uint64(opt.Data[0:8])
                
                if _, exists := tenantStats[datapathID]; !exists {
                    tenantStats[datapathID] = &TenantStats{}
                }
                
                tenantStats[datapathID].PacketCount++
                tenantStats[datapathID].ByteCount += uint64(len(packet))
            }
        }
    }
    
    // Report per-tenant statistics
    for datapathID, stats := range tenantStats {
        fmt.Printf("Tenant %d: %d packets, %d bytes\n",
            datapathID, stats.PacketCount, stats.ByteCount)
    }
}

type TenantStats struct {
    PacketCount uint64
    ByteCount   uint64
}
```

### Distributed Firewall Analysis

```go
func analyzeFirewallEnforcement(packets [][]byte) {
    parser := geneve.NewParser()
    aclStats := make(map[uint32]*ACLStats)
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x82 {
                aclID := binary.BigEndian.Uint32(opt.Data[0:4])
                action := opt.Data[6]
                
                if _, exists := aclStats[aclID]; !exists {
                    aclStats[aclID] = &ACLStats{}
                }
                
                aclStats[aclID].HitCount++
                if action == 2 { // DENY
                    aclStats[aclID].DenyCount++
                }
            }
        }
    }
    
    // Report ACL effectiveness
    for aclID, stats := range aclStats {
        denyRate := float64(stats.DenyCount) / float64(stats.HitCount) * 100
        fmt.Printf("ACL %d: %d hits, %.2f%% deny rate\n",
            aclID, stats.HitCount, denyRate)
    }
}

type ACLStats struct {
    HitCount   uint64
    DenyCount  uint64
}
```

## Integration Scenarios

### OpenStack Neutron Integration

```go
func integrateWithNeutron(ovnPackets [][]byte) {
    parser := geneve.NewParser()
    
    // Map OVN logical networks to Neutron networks
    networkMapping := make(map[uint64]string) // datapathID -> neutron_network_id
    
    for _, packet := range ovnPackets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x01 {
                datapathID := binary.BigEndian.Uint64(opt.Data[0:8])
                
                // Query Neutron API for network details
                if neutronNetID, exists := networkMapping[datapathID]; exists {
                    fmt.Printf("Traffic on Neutron network: %s\n", neutronNetID)
                }
            }
        }
    }
}
```

### Kubernetes OVN-Kubernetes CNI

```go
func monitorKubernetesPods(packets [][]byte) {
    parser := geneve.NewParser()
    podTraffic := make(map[[16]byte]*PodTraffic) // portUUID -> pod stats
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x03 {
                var portUUID [16]byte
                copy(portUUID[:], opt.Data[0:16])
                
                if _, exists := podTraffic[portUUID]; !exists {
                    podTraffic[portUUID] = &PodTraffic{}
                }
                
                podTraffic[portUUID].PacketCount++
                podTraffic[portUUID].ByteCount += uint64(len(packet))
            }
        }
    }
    
    // Correlate with Kubernetes pods via OVN annotations
    for portUUID, traffic := range podTraffic {
        fmt.Printf("Pod port %x: %d packets, %d bytes\n",
            portUUID, traffic.PacketCount, traffic.ByteCount)
    }
}

type PodTraffic struct {
    PacketCount uint64
    ByteCount   uint64
}
```

## Advanced Analytics

### Flow Correlation

```go
func correlateOVNFlows(packets [][]byte) {
    parser := geneve.NewParser()
    flowMap := make(map[uint32][]FlowEntry)
    
    for i, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x01 {
                flowID := binary.BigEndian.Uint32(opt.Data[8:12])
                
                flowMap[flowID] = append(flowMap[flowID], FlowEntry{
                    PacketIndex: i,
                    Timestamp:   result.Timestamp,
                    VNI:         result.VNI,
                })
            }
        }
    }
    
    // Analyze flow patterns
    for flowID, entries := range flowMap {
        if len(entries) > 1 {
            duration := entries[len(entries)-1].Timestamp.Sub(entries[0].Timestamp)
            fmt.Printf("Flow %d: %d packets over %v\n",
                flowID, len(entries), duration)
        }
    }
}

type FlowEntry struct {
    PacketIndex int
    Timestamp   time.Time
    VNI         uint32
}
```

### Performance Optimization

```go
func optimizeOVNPerformance(packets [][]byte) {
    parser := geneve.NewParser()
    var connTrackLatency []time.Duration
    
    connTrackStart := make(map[uint64]time.Time)
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x80 {
                connID := binary.BigEndian.Uint64(opt.Data[0:8])
                state := opt.Data[8]
                
                if state == 0 { // NEW
                    connTrackStart[connID] = result.Timestamp
                } else if state == 1 { // ESTABLISHED
                    if startTime, exists := connTrackStart[connID]; exists {
                        latency := result.Timestamp.Sub(startTime)
                        connTrackLatency = append(connTrackLatency, latency)
                    }
                }
            }
        }
    }
    
    // Calculate connection tracking performance metrics
    if len(connTrackLatency) > 0 {
        var total time.Duration
        for _, lat := range connTrackLatency {
            total += lat
        }
        avgLatency := total / time.Duration(len(connTrackLatency))
        fmt.Printf("Avg ConnTrack Latency: %v\n", avgLatency)
    }
}
```

## Troubleshooting

### Common Issues

1. **Missing OVN Metadata**
   - **Symptom**: No OVN telemetry in GENEVE packets
   - **Cause**: OVN not configured to embed metadata
   - **Solution**: Enable OVN external IDs and metadata options

2. **Incorrect Datapath Mapping**
   - **Symptom**: Cannot correlate datapath IDs to logical networks
   - **Cause**: OVN database not synchronized
   - **Solution**: Query OVN northbound/southbound databases for mappings

3. **Connection Tracking State Mismatches**
   - **Symptom**: Connection state doesn't match expected flow
   - **Cause**: Distributed connection tracking desynchronization
   - **Solution**: Check OVN conntrack zones and flow table consistency

### Debugging Tips

```go
// Enable verbose OVN telemetry logging
func debugOVNTelemetry(packet []byte) {
    parser := geneve.NewParser()
    parser.SetDebugMode(true)
    
    result, err := parser.ParsePacket(packet)
    if err != nil {
        log.Printf("Parse error: %v", err)
        return
    }
    
    for _, opt := range result.Options {
        if opt.Class == geneve.OptionClassOVN {
            log.Printf("OVN Option - Type: 0x%02x, Length: %d, Data: %x",
                opt.Type, len(opt.Data), opt.Data)
        }
    }
}
```

## References

- [OVN Architecture](https://www.ovn.org/support/dist-docs/ovn-architecture.7.html)
- [OpenStack Neutron OVN Driver](https://docs.openstack.org/neutron/latest/admin/ovn/index.html)
- [OVN-Kubernetes CNI](https://github.com/ovn-org/ovn-kubernetes)
- [IANA NVO3 Option Classes](https://www.iana.org/assignments/nvo3/nvo3.xhtml)

---

*Last updated: October 16, 2025*
