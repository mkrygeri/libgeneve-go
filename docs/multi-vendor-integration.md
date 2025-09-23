# Multi-Vendor Telemetry Integration

This document provides guidance on integrating telemetry from multiple enterprise vendors using the GENEVE parser.

## Overview

Modern networks often include infrastructure from multiple vendors. The GENEVE parser's enterprise extensions enable unified telemetry collection and analysis across heterogeneous network environments.

## Unified Telemetry Processing

### Comprehensive Telemetry Collection
```go
func processMultiVendorTelemetry(packets [][]byte) *NetworkTelemetryReport {
    parser := geneve.NewParser()
    parser.EnableEnterpriseExtensions()
    
    report := &NetworkTelemetryReport{
        Timestamp:     time.Now(),
        VendorMetrics: make(map[string]*VendorMetrics),
    }
    
    for _, packetData := range packets {
        result, err := parser.ParsePacket(packetData)
        if err != nil {
            continue
        }
        
        // Process each vendor's telemetry
        processVMwareTelemetry(result.VMwareOptions, report)
        processCiscoTelemetry(result.CiscoOptions, report)
        processMicrosoftTelemetry(result.EnterpriseOptions, report)
        processGoogleTelemetry(result.EnterpriseOptions, report)
        processAmazonTelemetry(result.EnterpriseOptions, report)
        processAristaTelemetry(result.AristaOptions, result.AristaLatencyOptions, report)
        processBroadcomTelemetry(result.BroadcomOptions, result.BroadcomLatencyOptions, report)
        processNVIDIAMellanoxTelemetry(result.EnterpriseOptions, report)
        processCumulusTelemetry(result.EnterpriseOptions, report)
        
        // Correlate with INT metadata
        correlateINTTelemetry(result.INTOptions, report)
    }
    
    return report
}
```

### Vendor-Agnostic Data Model
```go
type NetworkTelemetryReport struct {
    Timestamp           time.Time
    TotalPackets        int
    VendorMetrics       map[string]*VendorMetrics
    SecurityEvents      []SecurityEvent
    PerformanceAlerts   []PerformanceAlert
    CrossVendorFlows    []CrossVendorFlow
}

type VendorMetrics struct {
    VendorName          string
    PacketCount         int
    AverageLatency      float64
    TotalThroughput     uint64
    SecurityViolations  int
    UniqueFlows         int
    ActivePolicies      int
}

type SecurityEvent struct {
    Timestamp     time.Time
    VendorName    string
    EventType     string
    Severity      string
    SourceID      string
    TargetID      string
    PolicyID      string
    Description   string
}

type PerformanceAlert struct {
    Timestamp     time.Time
    VendorName    string
    AlertType     string
    Threshold     float64
    ActualValue   float64
    ResourceID    string
    Severity      string
}
```

## Cross-Vendor Flow Correlation

### Flow Tracking Across Vendors
```go
type NetworkFlow struct {
    FlowID          string
    SourceVendor    string
    DestVendor      string
    Path            []string
    StartTime       time.Time
    EndTime         time.Time
    TotalLatency    uint32
    HopCount        int
    PolicyViolations int
}

func trackCrossVendorFlows(results []*geneve.ParseResult) []NetworkFlow {
    flowMap := make(map[string]*NetworkFlow)
    
    for _, result := range results {
        // Track VMware flows
        for _, vmware := range result.VMwareOptions {
            flowKey := fmt.Sprintf("vmware-%d", vmware.VSID)
            if flow := flowMap[flowKey]; flow == nil {
                flowMap[flowKey] = &NetworkFlow{
                    FlowID:       flowKey,
                    SourceVendor: "VMware",
                    StartTime:    time.Now(),
                }
            }
        }
        
        // Track Cisco flows
        for _, cisco := range result.CiscoOptions {
            flowKey := fmt.Sprintf("cisco-%d", cisco.EPGID)
            if flow := flowMap[flowKey]; flow == nil {
                flowMap[flowKey] = &NetworkFlow{
                    FlowID:       flowKey,
                    SourceVendor: "Cisco",
                    StartTime:    time.Now(),
                }
            }
        }
        
        // Track Arista flows
        for _, arista := range result.AristaOptions {
            flowKey := fmt.Sprintf("arista-%d", arista.FlowID)
            if flow := flowMap[flowKey]; flow == nil {
                flowMap[flowKey] = &NetworkFlow{
                    FlowID:       flowKey,
                    SourceVendor: "Arista",
                    StartTime:    time.Now(),
                }
            } else {
                // Update flow with Arista telemetry
                flow.Path = append(flow.Path, fmt.Sprintf("Arista:%d->%d", 
                    arista.IngressPort, arista.EgressPort))
                flow.HopCount++
            }
        }
        
        // Add Broadcom switch telemetry
        for _, broadcom := range result.BroadcomOptions {
            for flowKey, flow := range flowMap {
                if flow.SourceVendor != "Broadcom" {
                    flow.Path = append(flow.Path, fmt.Sprintf("Broadcom:Switch-%d", 
                        broadcom.SwitchID))
                }
            }
        }
        
        // Add NVIDIA/Mellanox telemetry
        for _, opt := range result.EnterpriseOptions {
            if opt.Vendor == "NVIDIA/Mellanox" && opt.Decoded {
                for flowKey, flow := range flowMap {
                    switch opt.DecodedData["type"] {
                    case "Spectrum ASIC Telemetry":
                        if asicID, ok := opt.DecodedData["asic_id"].(uint32); ok {
                            flow.Path = append(flow.Path, fmt.Sprintf("NVIDIA/Mellanox:ASIC-%d", asicID))
                        }
                    case "ConnectX NIC Telemetry":
                        if deviceID, ok := opt.DecodedData["pci_device_id"].(uint32); ok {
                            flow.Path = append(flow.Path, fmt.Sprintf("NVIDIA/Mellanox:NIC-%d", deviceID))
                        }
                    }
                }
            }
        }
        
        // Add Cumulus Networks telemetry
        for _, opt := range result.EnterpriseOptions {
            if opt.Vendor == "NVIDIA Cumulus Linux" && opt.Decoded {
                for flowKey, flow := range flowMap {
                    switch opt.DecodedData["type"] {
                    case "EVPN Telemetry":
                        if vtepIP, ok := opt.DecodedData["vtep_ip"].(uint32); ok {
                            flow.Path = append(flow.Path, fmt.Sprintf("Cumulus:VTEP-%s", intToIP(vtepIP)))
                        }
                    case "MLAG Status":
                        if peerID, ok := opt.DecodedData["peer_id"].(uint32); ok {
                            flow.Path = append(flow.Path, fmt.Sprintf("Cumulus:MLAG-%d", peerID))
                        }
                    }
                }
            }
        }
    }
    
    // Convert map to slice
    var flows []NetworkFlow
    for _, flow := range flowMap {
        flow.EndTime = time.Now()
        flows = append(flows, *flow)
    }
    
    return flows
}
```

## Unified Security Analysis

### Cross-Vendor Security Monitoring
```go
func analyzeSecurityAcrossVendors(results []*geneve.ParseResult) SecurityAnalysisReport {
    report := SecurityAnalysisReport{
        Timestamp:        time.Now(),
        VendorFindings:   make(map[string][]SecurityFinding),
        CorrelatedThreats: make([]CorrelatedThreat, 0),
    }
    
    // Analyze VMware NSX security
    for _, result := range results {
        for _, vmware := range result.VMwareOptions {
            if vmware.PolicyID != 0 {
                finding := SecurityFinding{
                    VendorName:   "VMware",
                    PolicyID:     fmt.Sprintf("%d", vmware.PolicyID),
                    ResourceID:   fmt.Sprintf("VSID-%d", vmware.VSID),
                    FindingType:  "Policy Enforcement",
                    Timestamp:    time.Now(),
                }
                report.VendorFindings["VMware"] = append(report.VendorFindings["VMware"], finding)
            }
        }
        
        // Analyze Cisco ACI security
        for _, cisco := range result.CiscoOptions {
            if cisco.ContractID != 0 {
                finding := SecurityFinding{
                    VendorName:   "Cisco",
                    PolicyID:     fmt.Sprintf("%d", cisco.ContractID),
                    ResourceID:   fmt.Sprintf("EPG-%d", cisco.EPGID),
                    FindingType:  "Contract Enforcement",
                    Timestamp:    time.Now(),
                }
                report.VendorFindings["Cisco"] = append(report.VendorFindings["Cisco"], finding)
            }
        }
        
        // Analyze cloud vendor security
        for _, enterprise := range result.EnterpriseOptions {
            if enterprise.Decoded {
                data := enterprise.DecodedData
                
                // Check for security actions
                if action, exists := data["security_action"]; exists {
                    if action == "DENY" || action == "BLOCK" {
                        finding := SecurityFinding{
                            VendorName:   enterprise.VendorName,
                            ResourceID:   fmt.Sprintf("%v", data["resource_id"]),
                            FindingType:  "Traffic Blocked",
                            Timestamp:    time.Now(),
                            RawData:      data,
                        }
                        report.VendorFindings[enterprise.VendorName] = 
                            append(report.VendorFindings[enterprise.VendorName], finding)
                    }
                }
            }
        }
    }
    
    // Correlate security events across vendors
    report.CorrelatedThreats = correlateThreatAcrossVendors(report.VendorFindings)
    
    return report
}

type SecurityFinding struct {
    VendorName    string
    PolicyID      string
    ResourceID    string
    FindingType   string
    Timestamp     time.Time
    Severity      string
    RawData       map[string]interface{}
}

type CorrelatedThreat struct {
    ThreatID      string
    VendorsInvolved []string
    ThreatType    string
    FirstSeen     time.Time
    LastSeen      time.Time
    EventCount    int
    RiskScore     int
}
```

## Performance Analytics Across Vendors

### Unified Performance Dashboard
```go
func generatePerformanceDashboard(results []*geneve.ParseResult) PerformanceDashboard {
    dashboard := PerformanceDashboard{
        Timestamp:     time.Now(),
        VendorMetrics: make(map[string]*PerformanceMetrics),
    }
    
    for _, result := range results {
        // VMware performance metrics
        for _, vmware := range result.VMwareOptions {
            updateVendorMetrics("VMware", vmware.VSID, dashboard.VendorMetrics)
        }
        
        // Cisco performance metrics
        for _, cisco := range result.CiscoOptions {
            updateVendorMetrics("Cisco", cisco.EPGID, dashboard.VendorMetrics)
        }
        
        // Arista latency metrics
        for _, aristaLatency := range result.AristaLatencyOptions {
            latencyNs := aristaLatency.EgressTS - aristaLatency.IngressTS
            if dashboard.VendorMetrics["Arista"] == nil {
                dashboard.VendorMetrics["Arista"] = &PerformanceMetrics{}
            }
            metrics := dashboard.VendorMetrics["Arista"]
            metrics.AverageLatencyNs = (metrics.AverageLatencyNs + latencyNs) / 2
            metrics.SampleCount++
        }
        
        // Broadcom switch metrics
        for _, broadcom := range result.BroadcomOptions {
            if dashboard.VendorMetrics["Broadcom"] == nil {
                dashboard.VendorMetrics["Broadcom"] = &PerformanceMetrics{}
            }
            metrics := dashboard.VendorMetrics["Broadcom"]
            metrics.TotalThroughput += broadcom.PacketRate * 64 * 8 // Estimate bytes
            metrics.BufferUtilization = float64(broadcom.BufferUtil) / 100.0
            metrics.SampleCount++
        }
        
        // NVIDIA/Mellanox hardware metrics
        for _, opt := range result.EnterpriseOptions {
            if opt.Vendor == "NVIDIA/Mellanox" && opt.Decoded {
                if dashboard.VendorMetrics["NVIDIA/Mellanox"] == nil {
                    dashboard.VendorMetrics["NVIDIA/Mellanox"] = &PerformanceMetrics{}
                }
                metrics := dashboard.VendorMetrics["NVIDIA/Mellanox"]
                
                switch opt.DecodedData["type"] {
                case "Spectrum ASIC Telemetry":
                    if latency, ok := opt.DecodedData["pipeline_latency"].(uint32); ok {
                        metrics.AvgLatency += float64(latency)
                    }
                case "ConnectX NIC Telemetry":
                    if txRate, ok := opt.DecodedData["tx_rate_mbps"].(uint32); ok {
                        metrics.TotalThroughput += uint64(txRate) * 1000000 // Convert to bps
                    }
                case "RDMA Performance":
                    if completionLatency, ok := opt.DecodedData["completion_latency"].(uint32); ok {
                        metrics.AvgLatency += float64(completionLatency)
                    }
                }
                metrics.SampleCount++
            }
        }
        
        // Cumulus Networks fabric metrics
        for _, opt := range result.EnterpriseOptions {
            if opt.Vendor == "NVIDIA Cumulus Linux" && opt.Decoded {
                if dashboard.VendorMetrics["Cumulus Networks"] == nil {
                    dashboard.VendorMetrics["Cumulus Networks"] = &PerformanceMetrics{}
                }
                metrics := dashboard.VendorMetrics["Cumulus Networks"]
                
                switch opt.DecodedData["type"] {
                case "VXLAN Performance":
                    if encapLatency, ok := opt.DecodedData["encap_latency"].(uint32); ok {
                        metrics.AvgLatency += float64(encapLatency)
                    }
                    if packetRate, ok := opt.DecodedData["packet_rate"].(uint32); ok {
                        metrics.TotalThroughput += uint64(packetRate) * 64 * 8 // Estimate bytes
                    }
                case "BGP Performance":
                    if routeCount, ok := opt.DecodedData["route_count"].(uint32); ok {
                        metrics.RouteTableSize = uint64(routeCount)
                    }
                case "Fabric Health":
                    if errorRate, ok := opt.DecodedData["error_rate"].(uint32); ok {
                        metrics.ErrorRate = float64(errorRate) / 10000000.0 // Convert to percentage
                    }
                }
                metrics.SampleCount++
            }
        }
        
        // Cloud vendor metrics from enterprise options
        for _, enterprise := range result.EnterpriseOptions {
            if enterprise.Decoded {
                extractCloudMetrics(enterprise, dashboard.VendorMetrics)
            }
        }
    }
    
    return dashboard
}

type PerformanceDashboard struct {
    Timestamp       time.Time
    VendorMetrics   map[string]*PerformanceMetrics
    TopPerformers   []string
    BottleneckAreas []string
    Recommendations []string
}

type PerformanceMetrics struct {
    AverageLatencyNs    uint64
    TotalThroughput     uint64
    BufferUtilization   float64
    PacketLossRate      float64
    SampleCount         int
}
```

## Data Export and Integration

### JSON Export for Monitoring Systems
```go
func exportTelemetryToJSON(report *NetworkTelemetryReport) ([]byte, error) {
    // Create exportable structure
    export := struct {
        Timestamp       string                    `json:"timestamp"`
        TotalPackets    int                      `json:"total_packets"`
        VendorSummary   map[string]interface{}   `json:"vendor_summary"`
        SecurityEvents  []SecurityEvent          `json:"security_events"`
        PerformanceData map[string]interface{}   `json:"performance_data"`
    }{
        Timestamp:       report.Timestamp.Format(time.RFC3339),
        TotalPackets:    report.TotalPackets,
        VendorSummary:   make(map[string]interface{}),
        SecurityEvents:  report.SecurityEvents,
        PerformanceData: make(map[string]interface{}),
    }
    
    // Populate vendor summary
    for vendor, metrics := range report.VendorMetrics {
        export.VendorSummary[vendor] = map[string]interface{}{
            "packet_count":         metrics.PacketCount,
            "average_latency_ms":   metrics.AverageLatency,
            "total_throughput_bps": metrics.TotalThroughput,
            "security_violations":  metrics.SecurityViolations,
            "unique_flows":         metrics.UniqueFlows,
            "active_policies":      metrics.ActivePolicies,
        }
    }
    
    return json.MarshalIndent(export, "", "  ")
}
```

### Real-Time Streaming Integration
```go
func streamTelemetryToKafka(report *NetworkTelemetryReport, kafkaProducer *kafka.Producer) {
    // Create Kafka message
    telemetryJSON, err := exportTelemetryToJSON(report)
    if err != nil {
        log.Printf("Failed to serialize telemetry: %v", err)
        return
    }
    
    message := &kafka.Message{
        TopicPartition: kafka.TopicPartition{
            Topic:     &[]string{"network-telemetry"}[0],
            Partition: kafka.PartitionAny,
        },
        Key:   []byte(report.Timestamp.Format("2006-01-02-15")),
        Value: telemetryJSON,
        Headers: []kafka.Header{
            {Key: "source", Value: []byte("geneve-parser")},
            {Key: "version", Value: []byte("1.0")},
            {Key: "vendor_count", Value: []byte(fmt.Sprintf("%d", len(report.VendorMetrics)))},
        },
    }
    
    // Send to Kafka
    err = kafkaProducer.Produce(message, nil)
    if err != nil {
        log.Printf("Failed to produce message: %v", err)
    }
}
```

## Best Practices

### Performance Optimization
```go
// Use object pools to reduce allocations
var reportPool = sync.Pool{
    New: func() interface{} {
        return &NetworkTelemetryReport{
            VendorMetrics: make(map[string]*VendorMetrics),
            SecurityEvents: make([]SecurityEvent, 0, 100),
            PerformanceAlerts: make([]PerformanceAlert, 0, 50),
        }
    },
}

func processPacketsBatch(packets [][]byte) {
    report := reportPool.Get().(*NetworkTelemetryReport)
    defer func() {
        // Reset report for reuse
        report.TotalPackets = 0
        for k := range report.VendorMetrics {
            delete(report.VendorMetrics, k)
        }
        report.SecurityEvents = report.SecurityEvents[:0]
        report.PerformanceAlerts = report.PerformanceAlerts[:0]
        reportPool.Put(report)
    }()
    
    // Process packets...
}
```

### Error Handling and Resilience
```go
func robustTelemetryProcessing(packetData []byte) error {
    parser := geneve.NewParser()
    parser.EnableEnterpriseExtensions()
    
    // Parse with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()
    
    done := make(chan error, 1)
    go func() {
        result, err := parser.ParsePacket(packetData)
        if err != nil {
            done <- err
            return
        }
        
        // Process result with error recovery
        if err := processWithRecovery(result); err != nil {
            done <- err
            return
        }
        
        done <- nil
    }()
    
    select {
    case err := <-done:
        return err
    case <-ctx.Done():
        return fmt.Errorf("telemetry processing timeout")
    }
}

func processWithRecovery(result *geneve.ParseResult) (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic in telemetry processing: %v", r)
        }
    }()
    
    // Safe processing with nil checks
    if result != nil {
        processVendorTelemetrySafely(result)
    }
    
    return nil
}

## Vendor-Specific Processing Functions

### NVIDIA/Mellanox Telemetry Processing
```go
func processNVIDIAMellanoxTelemetry(options []geneve.EnterpriseOption, report *NetworkTelemetryReport) {
    vendor := "NVIDIA/Mellanox"
    if report.VendorMetrics[vendor] == nil {
        report.VendorMetrics[vendor] = &VendorMetrics{}
    }
    
    for _, opt := range options {
        if opt.Vendor == vendor && opt.Decoded {
            switch opt.DecodedData["type"] {
            case "Spectrum ASIC Telemetry":
                if asicID, ok := opt.DecodedData["asic_id"].(uint32); ok {
                    if latency, ok := opt.DecodedData["pipeline_latency"].(uint32); ok {
                        report.VendorMetrics[vendor].ASICMetrics = append(
                            report.VendorMetrics[vendor].ASICMetrics,
                            ASICMetric{
                                ID:      asicID,
                                Latency: latency,
                                Type:    "Spectrum",
                            })
                    }
                }
                
            case "ConnectX NIC Telemetry":
                if deviceID, ok := opt.DecodedData["pci_device_id"].(uint32); ok {
                    if txRate, ok := opt.DecodedData["tx_rate_mbps"].(uint32); ok {
                        if rxRate, ok := opt.DecodedData["rx_rate_mbps"].(uint32); ok {
                            report.VendorMetrics[vendor].NICMetrics = append(
                                report.VendorMetrics[vendor].NICMetrics,
                                NICMetric{
                                    DeviceID: deviceID,
                                    TxRate:   txRate,
                                    RxRate:   rxRate,
                                    Type:     "ConnectX",
                                })
                        }
                    }
                }
                
            case "RDMA Performance":
                if qpID, ok := opt.DecodedData["qp_id"].(uint32); ok {
                    if completionLatency, ok := opt.DecodedData["completion_latency"].(uint32); ok {
                        report.VendorMetrics[vendor].RDMAMetrics = append(
                            report.VendorMetrics[vendor].RDMAMetrics,
                            RDMAMetric{
                                QPID:              qpID,
                                CompletionLatency: completionLatency,
                            })
                    }
                }
                
            case "NVLink Telemetry":
                if linkID, ok := opt.DecodedData["link_id"].(uint32); ok {
                    if utilization, ok := opt.DecodedData["bandwidth_utilization"].(uint32); ok {
                        report.VendorMetrics[vendor].NVLinkMetrics = append(
                            report.VendorMetrics[vendor].NVLinkMetrics,
                            NVLinkMetric{
                                LinkID:      linkID,
                                Utilization: utilization,
                            })
                    }
                }
                
            case "GPUDirect Metrics":
                if gpuID, ok := opt.DecodedData["gpu_id"].(uint32); ok {
                    if transferRate, ok := opt.DecodedData["transfer_rate"].(uint32); ok {
                        report.VendorMetrics[vendor].GPUDirectMetrics = append(
                            report.VendorMetrics[vendor].GPUDirectMetrics,
                            GPUDirectMetric{
                                GPUID:        gpuID,
                                TransferRate: transferRate,
                            })
                    }
                }
            }
        }
    }
}
```

### Cumulus Networks Telemetry Processing
```go
func processCumulusTelemetry(options []geneve.EnterpriseOption, report *NetworkTelemetryReport) {
    vendor := "NVIDIA Cumulus Linux"
    if report.VendorMetrics[vendor] == nil {
        report.VendorMetrics[vendor] = &VendorMetrics{}
    }
    
    for _, opt := range options {
        if opt.Vendor == vendor && opt.Decoded {
            switch opt.DecodedData["type"] {
            case "EVPN Telemetry":
                if vtepIP, ok := opt.DecodedData["vtep_ip"].(uint32); ok {
                    if vniID, ok := opt.DecodedData["vni_id"].(uint32); ok {
                        if macCount, ok := opt.DecodedData["mac_count"].(uint32); ok {
                            report.VendorMetrics[vendor].EVPNMetrics = append(
                                report.VendorMetrics[vendor].EVPNMetrics,
                                EVPNMetric{
                                    VTEPIP:   vtepIP,
                                    VNIID:    vniID,
                                    MACCount: macCount,
                                })
                        }
                    }
                }
                
            case "VXLAN Performance":
                if tunnelID, ok := opt.DecodedData["tunnel_id"].(uint32); ok {
                    if encapLatency, ok := opt.DecodedData["encap_latency"].(uint32); ok {
                        if packetRate, ok := opt.DecodedData["packet_rate"].(uint32); ok {
                            report.VendorMetrics[vendor].VXLANMetrics = append(
                                report.VendorMetrics[vendor].VXLANMetrics,
                                VXLANMetric{
                                    TunnelID:     tunnelID,
                                    EncapLatency: encapLatency,
                                    PacketRate:   packetRate,
                                })
                        }
                    }
                }
                
            case "MLAG Status":
                if peerID, ok := opt.DecodedData["peer_id"].(uint32); ok {
                    if syncStatus, ok := opt.DecodedData["sync_status"].(uint32); ok {
                        if bondCount, ok := opt.DecodedData["bond_count"].(uint32); ok {
                            report.VendorMetrics[vendor].MLAGMetrics = append(
                                report.VendorMetrics[vendor].MLAGMetrics,
                                MLAGMetric{
                                    PeerID:     peerID,
                                    SyncStatus: syncStatus,
                                    BondCount:  bondCount,
                                    IsSynced:   syncStatus == 0,
                                })
                        }
                    }
                }
                
            case "BGP Performance":
                if routeCount, ok := opt.DecodedData["route_count"].(uint32); ok {
                    if convergenceTime, ok := opt.DecodedData["convergence_time"].(uint32); ok {
                        report.VendorMetrics[vendor].BGPMetrics = append(
                            report.VendorMetrics[vendor].BGPMetrics,
                            BGPMetric{
                                RouteCount:      routeCount,
                                ConvergenceTime: convergenceTime,
                            })
                    }
                }
                
            case "Fabric Health":
                if spineCount, ok := opt.DecodedData["spine_count"].(uint32); ok {
                    if leafCount, ok := opt.DecodedData["leaf_count"].(uint32); ok {
                        if errorRate, ok := opt.DecodedData["error_rate"].(uint32); ok {
                            report.VendorMetrics[vendor].FabricHealthMetrics = append(
                                report.VendorMetrics[vendor].FabricHealthMetrics,
                                FabricHealthMetric{
                                    SpineCount: spineCount,
                                    LeafCount:  leafCount,
                                    ErrorRate:  errorRate,
                                })
                        }
                    }
                }
                
            case "ZTP Status":
                if provisionState, ok := opt.DecodedData["provision_state"].(uint32); ok {
                    if automationLevel, ok := opt.DecodedData["automation_level"].(uint32); ok {
                        report.VendorMetrics[vendor].ZTPMetrics = append(
                            report.VendorMetrics[vendor].ZTPMetrics,
                            ZTPMetric{
                                ProvisionState:  provisionState,
                                AutomationLevel: automationLevel,
                            })
                    }
                }
            }
        }
    }
}
```
```

## Configuration Management

### Vendor-Specific Configuration
```yaml
# telemetry-config.yaml
vendors:
  vmware:
    enabled: true
    policy_tracking: true
    segment_analysis: true
  
  cisco:
    enabled: true
    contract_monitoring: true
    tenant_isolation: true
  
  microsoft:
    enabled: true
    services: ["VPC", "AKS", "Application Gateway"]
    regions: ["eastus", "westus2"]
  
  google:
    enabled: true
    projects: ["prod-project", "staging-project"]
    monitoring_integration: true
  
  amazon:
    enabled: true
    accounts: ["123456789012", "234567890123"]
    cloudwatch_export: true
  
  arista:
    enabled: true
    tap_analysis: true
    latency_tracking: true
  
  broadcom:
    enabled: true
    switch_telemetry: true
    histogram_analysis: true
  
  nvidia_mellanox:
    enabled: true
    spectrum_asic: true
    connectx_nic: true
    rdma_monitoring: true
    nvlink_tracking: true
    gpudirect_analysis: true
  
  cumulus:
    enabled: true
    evpn_monitoring: true
    vxlan_analysis: true
    mlag_tracking: true
    bgp_performance: true
    fabric_health: true
    ztp_automation: true

processing:
  batch_size: 1000
  parallel_workers: 4
  timeout_ms: 100
  
export:
  format: "json"
  destinations: ["kafka", "elasticsearch", "cloudwatch"]
  sampling_rate: 0.1
```

## Utility Functions

```go
// Utility function for IP address conversion
func intToIP(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        (ip>>24)&0xFF,
        (ip>>16)&0xFF,
        (ip>>8)&0xFF,
        ip&0xFF)
}
```

## Related Documentation

- [VMware NSX Telemetry](vmware-nsx-telemetry.md)
- [Cisco ACI Telemetry](cisco-aci-telemetry.md)
- [Microsoft Azure Telemetry](microsoft-azure-telemetry.md)
- [Google Cloud Telemetry](google-cloud-telemetry.md)
- [Amazon AWS Telemetry](amazon-aws-telemetry.md)
- [Arista EOS Telemetry](arista-eos-telemetry.md)
- [Broadcom Telemetry](broadcom-telemetry.md)
- [NVIDIA/Mellanox Telemetry](nvidia-mellanox-telemetry.md)
- [Cumulus Networks Telemetry](cumulus-networks-telemetry.md)