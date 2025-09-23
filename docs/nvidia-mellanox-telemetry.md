# NVIDIA/Mellanox GENEVE Telemetry Support

This document describes the GENEVE protocol parser's support for NVIDIA/Mellanox networking hardware telemetry.

## Overview

NVIDIA/Mellanox produces high-performance networking equipment including Spectrum ASIC switches, ConnectX SmartNICs, and GPU-accelerated computing platforms. Their GENEVE telemetry provides deep insights into hardware performance, RDMA operations, and GPU-direct networking.

## Option Class

- **Class**: `0x000B` (NVIDIA/Mellanox)
- **Vendor**: NVIDIA Corporation / Mellanox Technologies

## Supported Telemetry Types

### 1. Spectrum ASIC Telemetry (Type 0x01)

Provides detailed performance metrics from Spectrum ASIC switches.

```go
type SpectrumTelemetry struct {
    ASICID          uint32 // Spectrum ASIC identifier
    PipelineLatency uint32 // Processing latency in nanoseconds
}
```

**Use Cases:**
- Real-time latency monitoring
- ASIC performance optimization
- Network fabric health assessment

### 2. ConnectX NIC Telemetry (Type 0x02)

Captures performance data from ConnectX network interface cards.

```go
type ConnectXTelemetry struct {
    PCIDeviceID uint32 // PCI device identifier
    TxRateMbps  uint32 // Transmit rate in Mbps
    RxRateMbps  uint32 // Receive rate in Mbps
}
```

**Applications:**
- NIC performance monitoring
- Bandwidth utilization tracking
- Host-level network optimization

### 3. In-band Telemetry (Type 0x03)

Advanced switch telemetry embedded in packet flows.

```go
type InBandTelemetry struct {
    SwitchID    uint64 // Switch identifier
    HopLatency  uint32 // Per-hop latency in microseconds
    QueueDepth  uint32 // Current queue depth
}
```

**Benefits:**
- Per-packet path visibility
- Congestion detection
- Quality of service optimization

### 4. RDMA Performance (Type 0x04)

Remote Direct Memory Access performance metrics.

```go
type RDMAPerformance struct {
    QPID              uint32 // Queue Pair identifier
    CompletionLatency uint32 // RDMA completion latency
}
```

**Applications:**
- High-performance computing optimization
- Low-latency application tuning
- RDMA fabric monitoring

### 5. NVLink Telemetry (Type 0x05)

GPU interconnect performance data.

```go
type NVLinkTelemetry struct {
    LinkID               uint32 // NVLink connection ID
    BandwidthUtilization uint32 // Link utilization percentage
    ErrorCount           uint32 // Communication errors
}
```

**Use Cases:**
- GPU cluster optimization
- AI/ML workload monitoring
- High-bandwidth computing

### 6. GPUDirect Metrics (Type 0x06)

Direct GPU-to-network performance telemetry.

```go
type GPUDirectMetrics struct {
    GPUID        uint32 // GPU device identifier
    TransferRate uint32 // Direct transfer rate in GB/s
}
```

**Benefits:**
- GPU networking optimization
- Zero-copy performance monitoring
- Accelerated computing insights

## Usage Examples

### Basic Mellanox Telemetry Parsing

```go
parser := geneve.NewParser()
result, err := parser.ParsePacket(geneveData)
if err != nil {
    log.Fatal(err)
}

// Process NVIDIA/Mellanox telemetry
for _, opt := range result.Options {
    if opt.Class == geneve.OptionClassMellanox {
        switch opt.Type {
        case geneve.MellanoxTypeSpectrum:
            fmt.Printf("Spectrum ASIC %d latency: %d ns\n", 
                opt.DecodedData["asic_id"], 
                opt.DecodedData["pipeline_latency"])
        case geneve.MellanoxTypeConnectX:
            fmt.Printf("ConnectX NIC TX: %d Mbps, RX: %d Mbps\n",
                opt.DecodedData["tx_rate_mbps"],
                opt.DecodedData["rx_rate_mbps"])
        case geneve.MellanoxTypeRDMA:
            fmt.Printf("RDMA QP %d completion: %d μs\n",
                opt.DecodedData["qp_id"],
                opt.DecodedData["completion_latency"])
        }
    }
}
```

### Advanced Performance Monitoring

```go
func monitorMellanoxPerformance(result *geneve.ParseResult) {
    var totalLatency uint64
    var linkCount int
    
    for _, opt := range result.EnterpriseOptions {
        if opt.Vendor == "NVIDIA/Mellanox" && opt.Decoded {
            switch opt.DecodedData["type"] {
            case "Spectrum ASIC Telemetry":
                if latency, ok := opt.DecodedData["pipeline_latency"].(uint32); ok {
                    totalLatency += uint64(latency)
                    linkCount++
                }
            case "NVLink Telemetry":
                if utilization, ok := opt.DecodedData["bandwidth_utilization"].(uint32); ok {
                    if utilization > 90 {
                        log.Printf("High NVLink utilization: %d%%", utilization)
                    }
                }
            case "RDMA Performance":
                if latency, ok := opt.DecodedData["completion_latency"].(uint32); ok {
                    if latency > 1000 { // > 1ms
                        log.Printf("High RDMA latency detected: %d μs", latency)
                    }
                }
            }
        }
    }
    
    if linkCount > 0 {
        avgLatency := totalLatency / uint64(linkCount)
        fmt.Printf("Average fabric latency: %d ns\n", avgLatency)
    }
}
```

### GPU Cluster Monitoring

```go
func analyzeGPUCluster(packets [][]byte) {
    parser := geneve.NewParser()
    gpuMetrics := make(map[uint32]*GPUClusterStats)
    
    for _, packet := range packets {
        result, err := parser.ParsePacket(packet)
        if err != nil {
            continue
        }
        
        for _, opt := range result.EnterpriseOptions {
            if opt.Vendor == "NVIDIA/Mellanox" && opt.Decoded {
                switch opt.DecodedData["type"] {
                case "GPUDirect Metrics":
                    if gpuID, ok := opt.DecodedData["gpu_id"].(uint32); ok {
                        if _, exists := gpuMetrics[gpuID]; !exists {
                            gpuMetrics[gpuID] = &GPUClusterStats{}
                        }
                        
                        if rate, ok := opt.DecodedData["transfer_rate"].(uint32); ok {
                            gpuMetrics[gpuID].TotalTransferRate += uint64(rate)
                            gpuMetrics[gpuID].SampleCount++
                        }
                    }
                case "NVLink Telemetry":
                    // Process NVLink interconnect data
                    if linkID, ok := opt.DecodedData["link_id"].(uint32); ok {
                        if util, ok := opt.DecodedData["bandwidth_utilization"].(uint32); ok {
                            // Track link utilization patterns
                        }
                    }
                }
            }
        }
    }
    
    // Generate cluster performance report
    for gpuID, stats := range gpuMetrics {
        avgRate := stats.TotalTransferRate / uint64(stats.SampleCount)
        fmt.Printf("GPU %d average transfer rate: %d GB/s\n", gpuID, avgRate)
    }
}

type GPUClusterStats struct {
    TotalTransferRate uint64
    SampleCount       uint64
}
```

## Integration Scenarios

### High-Performance Computing (HPC)

```go
func optimizeHPCWorkload(result *geneve.ParseResult) {
    rdmaLatencies := []uint32{}
    nvlinkUtilizations := []uint32{}
    
    for _, opt := range result.EnterpriseOptions {
        if opt.Vendor == "NVIDIA/Mellanox" {
            switch opt.DecodedData["type"] {
            case "RDMA Performance":
                if latency, ok := opt.DecodedData["completion_latency"].(uint32); ok {
                    rdmaLatencies = append(rdmaLatencies, latency)
                }
            case "NVLink Telemetry":
                if util, ok := opt.DecodedData["bandwidth_utilization"].(uint32); ok {
                    nvlinkUtilizations = append(nvlinkUtilizations, util)
                }
            }
        }
    }
    
    // Analyze performance patterns
    if len(rdmaLatencies) > 0 {
        avgRDMALatency := calculateAverage(rdmaLatencies)
        if avgRDMALatency > 500 { // > 500μs
            log.Printf("Consider RDMA optimization: avg latency %d μs", avgRDMALatency)
        }
    }
    
    if len(nvlinkUtilizations) > 0 {
        avgUtilization := calculateAverage(nvlinkUtilizations)
        if avgUtilization < 30 { // < 30% utilization
            log.Printf("NVLink underutilized: %d%% - consider workload rebalancing", avgUtilization)
        }
    }
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
```

## Enterprise Integration

### Data Center Fabric Monitoring

The NVIDIA/Mellanox telemetry can be integrated with enterprise monitoring systems:

```go
func exportToMonitoringSystem(result *geneve.ParseResult) {
    metrics := map[string]interface{}{
        "timestamp": time.Now(),
        "fabric_health": map[string]interface{}{},
        "gpu_performance": map[string]interface{}{},
        "rdma_metrics": map[string]interface{}{},
    }
    
    for _, opt := range result.EnterpriseOptions {
        if opt.Vendor == "NVIDIA/Mellanox" && opt.Decoded {
            switch opt.DecodedData["type"] {
            case "Spectrum ASIC Telemetry":
                fabricHealth := metrics["fabric_health"].(map[string]interface{})
                fabricHealth["asic_latency"] = opt.DecodedData["pipeline_latency"]
                
            case "GPUDirect Metrics":
                gpuPerf := metrics["gpu_performance"].(map[string]interface{})
                gpuPerf["transfer_rate"] = opt.DecodedData["transfer_rate"]
                
            case "RDMA Performance":
                rdmaMetrics := metrics["rdma_metrics"].(map[string]interface{})
                rdmaMetrics["completion_latency"] = opt.DecodedData["completion_latency"]
            }
        }
    }
    
    // Export to Prometheus, InfluxDB, or other monitoring systems
    exportMetrics(metrics)
}
```

## Performance Considerations

### Optimization Guidelines

1. **Latency Monitoring**: Use Spectrum ASIC telemetry for sub-microsecond latency tracking
2. **RDMA Optimization**: Monitor completion latencies to optimize high-performance applications
3. **GPU Workload Balancing**: Use NVLink telemetry to balance GPU cluster workloads
4. **Network Fabric Health**: Combine multiple telemetry types for comprehensive fabric monitoring

### Best Practices

1. **Selective Parsing**: Parse only required telemetry types for performance
2. **Batch Processing**: Process multiple packets together for efficiency
3. **Metric Aggregation**: Aggregate telemetry over time windows for trending
4. **Alert Thresholds**: Set appropriate thresholds based on workload requirements

## Related Documentation

- [Multi-vendor Integration Guide](multi-vendor-integration.md)
- [Arista EOS Telemetry](arista-eos-telemetry.md)
- [Broadcom Telemetry](broadcom-telemetry.md)
- [VMware NSX Telemetry](vmware-nsx-telemetry.md)

## Technical Support

For NVIDIA/Mellanox-specific telemetry questions:
- NVIDIA Developer Documentation: https://developer.nvidia.com/networking
- Mellanox Community: https://community.mellanox.com/
- Enterprise Support: Contact your NVIDIA representative

---
*Last updated: September 23, 2025*