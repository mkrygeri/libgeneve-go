# Open Virtual Networking (OVN) GENEVE Telemetry Support

This document describes the GENEVE protocol parser's support for Open Virtual Networking (OVN) tunnel encapsulation metadata.

## Overview

Open Virtual Networking (OVN) is an open-source network virtualization solution that provides native virtual networking capabilities for Open vSwitch (OVS). OVN complements OVS to add native support for logical network abstractions such as logical L2 and L3 overlays, security groups, DHCP, and other network services. OVN uses GENEVE tunneling to connect hypervisors and transport logical network packets with embedded metadata.

OVN is the official software-defined networking solution for OpenStack, Kubernetes, and other cloud management systems.

## GENEVE Encapsulation in OVN

- **IANA Class**: `0x0102` (Open Virtual Networking)
- **TLV Type**: `0x80` (Port Metadata)
- **Encoding**: 32-bit value containing logical port identifiers
- **VNI Usage**: 24-bit logical datapath identifier (or 12-bit in VXLAN mode)

## OVN GENEVE Metadata Format

## OVN GENEVE Metadata Format

OVN transmits logical network metadata in GENEVE packets using a standardized format:

### VNI Field (GENEVE Header)

The GENEVE VNI (Virtual Network Identifier) field carries the **logical datapath identifier**:
- **24-bit value** in standard Geneve mode
- **12-bit value** in VXLAN compatibility mode (when VXLAN is enabled in the cluster)

The logical datapath identifier comes from the `tunnel_key` column in the OVN Southbound `Datapath_Binding` table and uniquely identifies a logical switch or logical router.

### TLV Option (Class 0x0102, Type 0x80)

OVN transmits logical port metadata using a GENEVE TLV option:
- **Class**: `0x0102` (IANA-assigned OVN class)
- **Type**: `0x80` (Port metadata)
- **Length**: 4 bytes (32-bit value)

The 32-bit value is encoded as follows (MSB to LSB):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|    Logical Ingress Port     |      Logical Egress Port      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Field Definitions:**
- **Bit 31 (R)**: Reserved, must be 0
- **Bits 30-16 (15 bits)**: Logical Ingress Port identifier
  - ID 0: Reserved for internal OVN use
  - IDs 1-32767: Assigned to logical ports
- **Bits 15-0 (16 bits)**: Logical Egress Port identifier
  - IDs 0-32767: Unicast logical ports
  - IDs 32768-65535: Logical multicast groups

### Port Identifiers

**Logical Ingress Port**: The logical port from which the packet entered the logical datapath. This comes from the `tunnel_key` column in the `Port_Binding` table.

**Logical Egress Port**: The logical port to which the packet is destined. For unicast traffic, this is a specific port's tunnel key. For multicast/broadcast, this is a multicast group tunnel key from the `Multicast_Group` table.

### VXLAN Compatibility Mode

When VXLAN is enabled in an OVN cluster, metadata encoding is reduced:
- **12-bit logical datapath** identifier (instead of 24-bit)
- **12-bit logical egress port** identifier (instead of 16-bit)
- **No logical ingress port** field
- IDs 0-2047: Unicast ports
- IDs 2048-4095: Multicast groups

**Limitations in VXLAN mode:**
- Maximum 4096 logical networks
- Maximum 2048 ports per network
- ACLs cannot match on logical ingress ports
- OVN Interconnection feature unavailable

## OVN Logical Network Concepts

## OVN Logical Network Concepts

Understanding OVN metadata requires familiarity with OVN's logical network abstractions:

### Logical Datapaths

A **logical datapath** is OVN's internal implementation detail representing a logical switch or logical router. Each logical network element (switch or router) defined in the OVN Northbound database gets translated by `ovn-northd` into a logical datapath in the Southbound database's `Datapath_Binding` table.

The datapath's `tunnel_key` becomes the GENEVE VNI that identifies packets belonging to that logical network.

### Logical Ports

**Logical switch ports** (LSPs) and **logical router ports** (LRPs) are connection points in the logical network:

**Common LSP Types:**
- **VIF ports**: Connection points for VMs and containers (empty string type)
- **router ports**: Connect logical switches to logical routers
- **localnet ports**: Bridge logical switches to physical VLANs
- **localport ports**: Special ports present on every chassis (e.g., metadata service)
- **patch ports**: Internal ports connecting logical routers to switches

The `tunnel_key` from the `Port_Binding` table becomes the ingress/egress port identifier in GENEVE metadata.

### Logical Flows

OVN translates high-level network policies into **logical flows** stored in the `Logical_Flow` table. These flows are processed by ovn-controller on each chassis and converted to OpenFlow rules. The logical flow processing happens based on the logical datapath and port identifiers carried in GENEVE metadata.

## Parsing OVN GENEVE Metadata

### Basic Metadata Extraction

```go
package main

import (
    "encoding/binary"
    "fmt"
    "log"
    "github.com/yourusername/libgeneve-go/geneve"
)

func main() {
    parser := geneve.NewParser()
    result, err := parser.ParsePacket(geneveData)
    if err != nil {
        log.Fatal(err)
    }

    // Extract logical datapath from VNI
    datapathID := result.VNI
    fmt.Printf("Logical Datapath ID: %d (0x%06x)\n", datapathID, datapathID)

    // Process OVN port metadata
    for _, opt := range result.Options {
        if opt.Class == geneve.OptionClassOVN && opt.Type == 0x80 {
            // Parse 32-bit port metadata
            portData := binary.BigEndian.Uint32(opt.Data[0:4])
            
            // Extract ingress port (bits 30-16)
            ingressPort := uint16((portData >> 16) & 0x7FFF)
            
            // Extract egress port (bits 15-0)
            egressPort := uint16(portData & 0xFFFF)
            
            fmt.Printf("Logical Ingress Port: %d\n", ingressPort)
            fmt.Printf("Logical Egress Port: %d\n", egressPort)
            
            // Check if egress is multicast
            if egressPort >= 32768 {
                fmt.Printf("Egress is multicast group: %d\n", egressPort)
            }
        }
    }
}
```

### Mapping to OVN Database

To fully understand the logical network topology, correlate GENEVE metadata with OVN Southbound database:

```go
// Example: Query OVN Southbound DB to map tunnel keys to logical ports
func mapTunnelKeyToPort(ingressKey uint16) (string, error) {
    // Connect to OVN Southbound database via OVSDB protocol
    // Query: SELECT logical_port FROM Port_Binding WHERE tunnel_key = ingressKey
    
    // This would return the logical port name like "vm1-eth0" or "router-port1"
    // Implementation requires ovsdb client library
    return "vm1-eth0", nil
}

func mapDatapathToNetwork(datapathKey uint32) (string, error) {
    // Query: SELECT * FROM Datapath_Binding WHERE tunnel_key = datapathKey
    // Returns whether it's a logical switch or router
    return "logical-switch-1", nil
}
```

### Packet Flow Tracing

```go
func traceOVNPacket(packet []byte) {
    parser := geneve.NewParser()
    result, err := parser.ParsePacket(packet)
    if err != nil {
        log.Printf("Parse error: %v", err)
        return
    }

    // Extract OVN metadata
    var ingressPort, egressPort uint16
    for _, opt := range result.Options {
        if opt.Class == geneve.OptionClassOVN && opt.Type == 0x80 {
            portData := binary.BigEndian.Uint32(opt.Data)
            ingressPort = uint16((portData >> 16) & 0x7FFF)
            egressPort = uint16(portData & 0xFFFF)
        }
    }

    fmt.Printf("=== OVN Packet Trace ===\n")
    fmt.Printf("Logical Datapath: %d\n", result.VNI)
    fmt.Printf("Ingress Port: %d (where packet entered)\n", ingressPort)
    fmt.Printf("Egress Port: %d (where packet exits)\n", egressPort)
    fmt.Printf("Inner Protocol: 0x%04x\n", result.ProtocolType)
    
    // Trace shows packet journey through logical network
    // Example: VM1 (port 5) -> Logical Switch 100 -> Logical Router -> 
    //          Logical Switch 200 -> VM2 (port 10)
}
```

### Multi-Tenant Network Monitoring

```go
func monitorTenantTraffic(packets [][]byte) {
    parser := geneve.NewParser()
    datapathStats := make(map[uint32]*DatapathStats)
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        // Each logical datapath represents a tenant's network
        datapathID := result.VNI
        
        if _, exists := datapathStats[datapathID]; !exists {
            datapathStats[datapathID] = &DatapathStats{}
        }
        
        datapathStats[datapathID].PacketCount++
        datapathStats[datapathID].ByteCount += uint64(len(packet))
    }
    
    // Report per-datapath (tenant) statistics
    for datapathID, stats := range datapathStats {
        fmt.Printf("Datapath %d: %d packets, %d bytes\n",
            datapathID, stats.PacketCount, stats.ByteCount)
    }
}

type DatapathStats struct {
    PacketCount uint64
    ByteCount   uint64
}
```

### Port-Level Traffic Analysis

```go
func analyzePortTraffic(packets [][]byte) {
    parser := geneve.NewParser()
    portStats := make(map[uint16]*PortStats)
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x80 {
                portData := binary.BigEndian.Uint32(opt.Data)
                ingressPort := uint16((portData >> 16) & 0x7FFF)
                egressPort := uint16(portData & 0xFFFF)
                
                // Track ingress port statistics
                if _, exists := portStats[ingressPort]; !exists {
                    portStats[ingressPort] = &PortStats{}
                }
                portStats[ingressPort].TxPackets++
                portStats[ingressPort].TxBytes += uint64(len(packet))
                
                // Track egress port statistics
                if egressPort < 32768 { // Unicast only
                    if _, exists := portStats[egressPort]; !exists {
                        portStats[egressPort] = &PortStats{}
                    }
                    portStats[egressPort].RxPackets++
                    portStats[egressPort].RxBytes += uint64(len(packet))
                }
            }
        }
    }
    
    // Report per-port statistics
    for portID, stats := range portStats {
        fmt.Printf("Port %d: TX=%d pkts/%d bytes, RX=%d pkts/%d bytes\n",
            portID, stats.TxPackets, stats.TxBytes, stats.RxPackets, stats.RxBytes)
    }
}

type PortStats struct {
    TxPackets uint64
    TxBytes   uint64
    RxPackets uint64
    RxBytes   uint64
}
```

## Integration Scenarios

### OpenStack Neutron Integration

OVN is the official SDN backend for OpenStack Neutron. When Neutron creates networks, subnets, ports, routers, and security groups, they are translated into OVN logical network objects.

```go
func correlateWithNeutron(ovnPackets [][]byte, neutronClient *NeutronClient) {
    parser := geneve.NewParser()
    
    for _, packet := range ovnPackets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        // Map OVN datapath to Neutron network
        datapathID := result.VNI
        neutronNetwork := neutronClient.GetNetworkByDatapath(datapathID)
        
        // Extract port information
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x80 {
                portData := binary.BigEndian.Uint32(opt.Data)
                ingressPort := uint16((portData >> 16) & 0x7FFF)
                
                // Map to Neutron port (VM interface)
                neutronPort := neutronClient.GetPortByTunnelKey(ingressPort)
                
                fmt.Printf("Traffic from Neutron network: %s\n", neutronNetwork.Name)
                fmt.Printf("Source port: %s (instance: %s)\n", 
                    neutronPort.Name, neutronPort.DeviceID)
            }
        }
    }
}
```

### Kubernetes with OVN-Kubernetes CNI

OVN-Kubernetes is the Container Network Interface (CNI) plugin that provides pod networking using OVN.

```go
func monitorKubernetesPods(packets [][]byte) {
    parser := geneve.NewParser()
    podTraffic := make(map[uint16]*PodTraffic) // port ID -> pod stats
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x80 {
                portData := binary.BigEndian.Uint32(opt.Data)
                ingressPort := uint16((portData >> 16) & 0x7FFF)
                
                if _, exists := podTraffic[ingressPort]; !exists {
                    podTraffic[ingressPort] = &PodTraffic{}
                }
                
                podTraffic[ingressPort].PacketCount++
                podTraffic[ingressPort].ByteCount += uint64(len(packet))
            }
        }
    }
    
    // Map port IDs to Kubernetes pods via OVN port bindings
    // Port names in OVN follow pattern: namespace_podname
    for portID, traffic := range podTraffic {
        fmt.Printf("Port %d: %d packets, %d bytes\n",
            portID, traffic.PacketCount, traffic.ByteCount)
    }
}

type PodTraffic struct {
    PacketCount uint64
    ByteCount   uint64
}
```

## Advanced Analytics

### Packet Path Reconstruction

Trace packet flow through logical network topology:

```go
func reconstructPacketPath(packets [][]byte) {
    parser := geneve.NewParser()
    
    type PathSegment struct {
        DatapathID  uint32
        IngressPort uint16
        EgressPort  uint16
        Timestamp   time.Time
    }
    
    packetPaths := make(map[string][]PathSegment) // flow ID -> path
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        // Extract 5-tuple from inner packet to identify flow
        flowID := extractFlowID(result.Payload)
        
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x80 {
                portData := binary.BigEndian.Uint32(opt.Data)
                
                segment := PathSegment{
                    DatapathID:  result.VNI,
                    IngressPort: uint16((portData >> 16) & 0x7FFF),
                    EgressPort:  uint16(portData & 0xFFFF),
                    Timestamp:   time.Now(),
                }
                
                packetPaths[flowID] = append(packetPaths[flowID], segment)
            }
        }
    }
    
    // Analyze paths
    for flowID, path := range packetPaths {
        fmt.Printf("Flow %s path:\n", flowID)
        for i, segment := range path {
            fmt.Printf("  [%d] Datapath=%d, In=%d, Out=%d\n",
                i, segment.DatapathID, segment.IngressPort, segment.EgressPort)
        }
    }
}
```

### Multicast Group Analysis

```go
func analyzeMulticastTraffic(packets [][]byte) {
    parser := geneve.NewParser()
    mcastStats := make(map[uint16]*MulticastStats) // group ID -> stats
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.Options {
            if opt.Class == geneve.OptionClassOVN && opt.Type == 0x80 {
                portData := binary.BigEndian.Uint32(opt.Data)
                egressPort := uint16(portData & 0xFFFF)
                
                // Check if egress is multicast (ID >= 32768)
                if egressPort >= 32768 {
                    if _, exists := mcastStats[egressPort]; !exists {
                        mcastStats[egressPort] = &MulticastStats{}
                    }
                    
                    mcastStats[egressPort].PacketCount++
                    mcastStats[egressPort].ByteCount += uint64(len(packet))
                }
            }
        }
    }
    
    // Report multicast statistics
    for groupID, stats := range mcastStats {
        fmt.Printf("Multicast Group %d: %d packets, %d bytes\n",
            groupID, stats.PacketCount, stats.ByteCount)
    }
}

type MulticastStats struct {
    PacketCount uint64
    ByteCount   uint64
}
```

## Troubleshooting

### Common Issues

1. **Missing OVN Metadata in GENEVE Packets**
   - **Symptom**: GENEVE packets don't contain class 0x0102, type 0x80 option
   - **Cause**: OVN may not always include the port metadata TLV (it's optional)
   - **Solution**: The VNI field always contains the datapath ID. Port information may be implicit based on tunnel source/destination.

2. **Incorrect Datapath or Port Mapping**
   - **Symptom**: Cannot correlate tunnel keys to logical networks
   - **Cause**: Tunnel keys in GENEVE don't match OVN Southbound database
   - **Solution**: Query `Datapath_Binding` and `Port_Binding` tables:
     ```bash
     # Get datapath bindings
     ovn-sbctl list Datapath_Binding
     
     # Get port bindings
     ovn-sbctl list Port_Binding
     ```

3. **VXLAN Mode Limitations**
   - **Symptom**: Missing ingress port information, reduced tunnel key space
   - **Cause**: Cluster has VXLAN enabled (check `ovn-nb get NB_Global . options:vxlan_mode`)
   - **Solution**: Use Geneve-only mode for full metadata, or accept VXLAN limitations

4. **Tunnel Key Conflicts**
   - **Symptom**: Same tunnel key appears for different logical objects
   - **Cause**: Database inconsistency or interconnection setup issues
   - **Solution**: Check for duplicate tunnel_key values in Southbound DB

### Debugging Tips

```go
// Enable verbose OVN metadata logging
func debugOVNMetadata(packet []byte) {
    parser := geneve.NewParser()
    result, err := parser.ParsePacket(packet)
    if err != nil {
        log.Printf("Parse error: %v", err)
        return
    }
    
    log.Printf("=== OVN GENEVE Debug ===")
    log.Printf("VNI (Datapath): %d (0x%06x)", result.VNI, result.VNI)
    log.Printf("Protocol: 0x%04x", result.ProtocolType)
    log.Printf("Options count: %d", len(result.Options))
    
    for i, opt := range result.Options {
        log.Printf("Option[%d]: Class=0x%04x, Type=0x%02x, Length=%d bytes",
            i, opt.Class, opt.Type, len(opt.Data))
        
        if opt.Class == geneve.OptionClassOVN && opt.Type == 0x80 {
            if len(opt.Data) >= 4 {
                portData := binary.BigEndian.Uint32(opt.Data)
                ingressPort := uint16((portData >> 16) & 0x7FFF)
                egressPort := uint16(portData & 0xFFFF)
                
                log.Printf("  OVN Port Metadata:")
                log.Printf("    Ingress Port: %d (0x%04x)", ingressPort, ingressPort)
                log.Printf("    Egress Port: %d (0x%04x)", egressPort, egressPort)
                log.Printf("    Raw Value: 0x%08x", portData)
            }
        }
    }
}
```

### Correlating with OVN Commands

```bash
# Find logical datapath for a network
ovn-nbctl show

# Get datapath tunnel key
ovn-sbctl find Datapath_Binding external_ids:name="logical-switch-1"

# Get port tunnel keys
ovn-sbctl find Port_Binding logical_port="vm1-port"

# Watch tunnel traffic in real-time
ovn-trace --detailed <datapath-name> 'inport=="vm1-port" && eth.src==00:00:00:00:00:01'

# Monitor southbound database changes
ovn-sbctl --timestamp monitor Datapath_Binding Port_Binding
```

### Packet Capture and Analysis

```bash
# Capture GENEVE traffic on integration bridge
tcpdump -i genev_sys_6081 -nn -vv -X

# Capture on physical interface
tcpdump -i eth0 'udp port 6081' -nn -vv -X

# Use ovs-tcpdump for easier capture
ovs-tcpdump -i br-int --mirror-to=mirror0

# Decode with tshark
tshark -i eth0 -f 'udp port 6081' -V -O geneve
```

## References

### Official OVN Documentation
- [OVN Architecture (ovn-architecture.7)](https://www.ovn.org/support/dist-docs/ovn-architecture.7.html) - Comprehensive OVN design and implementation details
- [OVN Northbound Database Schema (ovn-nb.5)](https://www.ovn.org/support/dist-docs/ovn-nb.5.html) - Logical network configuration
- [OVN Southbound Database Schema (ovn-sb.5)](https://www.ovn.org/support/dist-docs/ovn-sb.5.html) - Runtime state and tunnel keys
- [ovn-controller(8)](https://www.ovn.org/support/dist-docs/ovn-controller.8.html) - Local controller on each chassis
- [ovn-northd(8)](https://www.ovn.org/support/dist-docs/ovn-northd.8.html) - Central control plane daemon

### Integration Guides
- [OpenStack Neutron with OVN](https://docs.openstack.org/neutron/latest/admin/ovn/index.html) - OVN as Neutron ML2 mechanism driver
- [OVN-Kubernetes](https://github.com/ovn-org/ovn-kubernetes) - Kubernetes CNI plugin using OVN
- [OVS Integration Guide](https://docs.openvswitch.org/en/latest/topics/integration/) - Hypervisor integration with Open vSwitch

### Standards and Specifications
- [RFC 8926: Geneve Protocol](https://www.rfc-editor.org/rfc/rfc8926.html) - Official GENEVE specification
- [IANA NVO3 Encapsulation Option Classes](https://www.iana.org/assignments/nvo3/nvo3.xhtml) - Official registry including OVN class 0x0102
- [OVSDB RFC 7047](https://www.rfc-editor.org/rfc/rfc7047.html) - OVSDB Management Protocol

### Tunnel Encapsulation Details
As specified in `ovn-architecture(7)`, section "Tunnel Encapsulations":
- GENEVE VNI carries the 24-bit logical datapath identifier (tunnel_key from Datapath_Binding)
- TLV with class 0x0102, type 0x80 carries 32-bit port metadata (1-bit reserved + 15-bit ingress + 16-bit egress)
- Port IDs 1-32767 are assigned to logical switch/router ports
- Port IDs 32768-65535 are assigned to multicast groups

---

*Last updated: October 16, 2025*
*Based on OVN Architecture specification from ovn-architecture.7.xml*
