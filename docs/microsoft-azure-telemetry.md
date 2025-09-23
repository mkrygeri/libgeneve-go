# Microsoft Azure Telemetry

This document describes the Microsoft Azure network telemetry support in the GENEVE parser.

## Overview

Microsoft Azure uses GENEVE encapsulation to transport network telemetry and virtual network metadata across its cloud infrastructure. The parser provides comprehensive support for Azure-specific telemetry data that enables cloud network monitoring, troubleshooting, and optimization.

## Telemetry Data Structure

Azure telemetry is parsed into generic key-value maps due to the variety of Azure networking services:

```go
// Azure telemetry is returned as map[string]interface{}
azureTelemetry := map[string]interface{}{
    "service_type":     "Virtual Network",
    "subscription_id":  "12345678-1234-5678-9abc-123456789012",
    "resource_group":   "production-rg",
    "virtual_network":  "prod-vnet",
    "subnet_id":        "subnet-web-tier",
    // Additional fields based on specific Azure service
}
```

## Supported Azure Services

### Virtual Network (VNet)
- **VNet Identification**: Virtual network and subnet metadata
- **Network Security Groups**: Security rule enforcement tracking
- **Route Tables**: Custom routing decisions and next-hop information
- **Service Endpoints**: Private service connectivity metrics

### Azure Kubernetes Service (AKS)
- **Pod Networking**: Container network interface telemetry
- **Service Mesh**: Istio/Linkerd integration metrics
- **Network Policies**: Kubernetes network policy enforcement
- **Load Balancer**: Azure Load Balancer traffic distribution

### Application Gateway
- **Web Application Firewall**: Security filtering and blocking
- **SSL Termination**: Certificate and encryption metrics
- **Backend Health**: Application server health monitoring
- **Request Routing**: Path-based and host-based routing decisions

### ExpressRoute
- **Private Connectivity**: Dedicated connection telemetry
- **BGP Routing**: Route advertisement and preference metrics
- **Circuit Utilization**: Bandwidth and performance monitoring
- **Redundancy Status**: High availability and failover tracking

## Telemetry Field Types

### Network Identification
```go
type AzureNetworkID struct {
    SubscriptionID   string
    ResourceGroup    string
    VirtualNetwork   string
    SubnetID         string
    NetworkInterface string
}
```

### Security Context
```go
type AzureSecurityContext struct {
    NSGRuleID        string
    SecurityAction   string // Allow/Deny
    Priority         int
    Direction        string // Inbound/Outbound
    Protocol         string
}
```

### Performance Metrics
```go
type AzurePerformanceMetrics struct {
    Bandwidth        uint64
    Latency          uint32
    PacketLoss       float64
    Jitter           uint32
    ConnectionState  string
}
```

## Example Usage

```go
parser := geneve.NewParser()
parser.EnableEnterpriseExtensions()

result, err := parser.ParsePacket(packet)
if err != nil {
    log.Fatal(err)
}

// Access Azure telemetry through enterprise options
for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "Microsoft" && enterprise.Decoded {
        azureData := enterprise.DecodedData
        
        // Virtual Network analysis
        if serviceType, exists := azureData["service_type"]; exists {
            fmt.Printf("Azure Service: %v\n", serviceType)
        }
        
        // Security monitoring
        if action, exists := azureData["security_action"]; exists {
            if action == "Deny" {
                fmt.Printf("Security block detected: %v\n", azureData)
            }
        }
        
        // Performance tracking
        if bandwidth, exists := azureData["bandwidth"]; exists {
            fmt.Printf("Bandwidth utilization: %v bps\n", bandwidth)
        }
    }
}
```

## Integration Patterns

### Azure Monitor Integration
```go
// Export telemetry to Azure Monitor
func exportToAzureMonitor(azureData map[string]interface{}) {
    metrics := []MetricData{}
    
    if bandwidth, ok := azureData["bandwidth"].(uint64); ok {
        metrics = append(metrics, MetricData{
            Name:  "NetworkBandwidth",
            Value: float64(bandwidth),
            Unit:  "BitsPerSecond",
        })
    }
    
    if latency, ok := azureData["latency"].(uint32); ok {
        metrics = append(metrics, MetricData{
            Name:  "NetworkLatency",
            Value: float64(latency),
            Unit:  "Milliseconds",
        })
    }
    
    // Send to Azure Monitor
    azureMonitorClient.SendMetrics(metrics)
}
```

### Security Information and Event Management (SIEM)
```go
// Process Azure security events
func processAzureSecurityEvents(results []*geneve.ParseResult) {
    for _, result := range results {
        for _, enterprise := range result.EnterpriseOptions {
            if enterprise.VendorName == "Microsoft" && enterprise.Decoded {
                data := enterprise.DecodedData
                
                // Check for security events
                if action, exists := data["security_action"]; exists {
                    securityEvent := SecurityEvent{
                        Timestamp:    time.Now(),
                        Source:       "Azure Network",
                        Action:       action.(string),
                        ResourceID:   data["resource_id"].(string),
                        Severity:     determineSeverity(data),
                    }
                    
                    // Send to SIEM
                    siemClient.SendEvent(securityEvent)
                }
            }
        }
    }
}
```

### Cost Optimization Analytics
```go
// Track resource utilization for cost optimization
type AzureResourceUsage struct {
    ResourceID       string
    ResourceType     string
    BandwidthUsage   uint64
    ConnectionHours  float64
    DataTransfer     uint64
}

func trackAzureResourceUsage(azureData map[string]interface{}) {
    usage := AzureResourceUsage{
        ResourceID:   azureData["resource_id"].(string),
        ResourceType: azureData["service_type"].(string),
    }
    
    // Calculate usage metrics
    if bandwidth, ok := azureData["bandwidth"].(uint64); ok {
        usage.BandwidthUsage = bandwidth
    }
    
    // Store for cost analysis
    costAnalyzer.RecordUsage(usage)
}
```

## Service-Specific Implementations

### Virtual Network Telemetry
```go
func parseVNetTelemetry(data map[string]interface{}) *VNetMetrics {
    return &VNetMetrics{
        VNetName:         data["virtual_network"].(string),
        SubnetID:         data["subnet_id"].(string),
        ConnectedDevices: data["connected_devices"].(int),
        TrafficVolume:    data["traffic_volume"].(uint64),
        SecurityEvents:   data["security_events"].(int),
    }
}
```

### AKS Network Telemetry
```go
func parseAKSTelemetry(data map[string]interface{}) *AKSNetworkMetrics {
    return &AKSNetworkMetrics{
        ClusterName:      data["cluster_name"].(string),
        Namespace:        data["namespace"].(string),
        PodName:          data["pod_name"].(string),
        ServiceName:      data["service_name"].(string),
        NetworkPlugin:    data["network_plugin"].(string),
        PodCIDR:          data["pod_cidr"].(string),
        ServiceCIDR:      data["service_cidr"].(string),
    }
}
```

### Application Gateway Telemetry
```go
func parseAppGatewayTelemetry(data map[string]interface{}) *AppGatewayMetrics {
    return &AppGatewayMetrics{
        GatewayName:      data["gateway_name"].(string),
        ListenerPort:     data["listener_port"].(int),
        BackendPool:      data["backend_pool"].(string),
        HealthyBackends:  data["healthy_backends"].(int),
        RequestCount:     data["request_count"].(uint64),
        ResponseTime:     data["response_time"].(uint32),
        WAFBlocks:        data["waf_blocks"].(int),
    }
}
```

## Advanced Analytics

### Cross-Service Correlation
```go
// Correlate telemetry across Azure services
type AzureServiceMap struct {
    Services    map[string]*ServiceMetrics
    Connections map[string][]string
}

func buildAzureServiceTopology(results []*geneve.ParseResult) *AzureServiceMap {
    serviceMap := &AzureServiceMap{
        Services:    make(map[string]*ServiceMetrics),
        Connections: make(map[string][]string),
    }
    
    for _, result := range results {
        for _, enterprise := range result.EnterpriseOptions {
            if enterprise.VendorName == "Microsoft" {
                data := enterprise.DecodedData
                resourceID := data["resource_id"].(string)
                
                // Build service relationships
                if sourceID, exists := data["source_resource"]; exists {
                    serviceMap.Connections[sourceID.(string)] = 
                        append(serviceMap.Connections[sourceID.(string)], resourceID)
                }
            }
        }
    }
    
    return serviceMap
}
```

### Performance Baseline Analysis
```go
// Establish performance baselines for Azure resources
type PerformanceBaseline struct {
    ResourceID      string
    AvgLatency      float64
    AvgBandwidth    float64
    AvgPacketLoss   float64
    SampleCount     int
    LastUpdated     time.Time
}

func updatePerformanceBaseline(azureData map[string]interface{}) {
    resourceID := azureData["resource_id"].(string)
    baseline := getBaseline(resourceID)
    
    // Update running averages
    if latency, ok := azureData["latency"].(uint32); ok {
        baseline.AvgLatency = updateAverage(baseline.AvgLatency, 
            float64(latency), baseline.SampleCount)
    }
    
    if bandwidth, ok := azureData["bandwidth"].(uint64); ok {
        baseline.AvgBandwidth = updateAverage(baseline.AvgBandwidth, 
            float64(bandwidth), baseline.SampleCount)
    }
    
    baseline.SampleCount++
    baseline.LastUpdated = time.Now()
    storeBaseline(baseline)
}
```

### Anomaly Detection
```go
// Detect performance anomalies in Azure networks
func detectAzureAnomalies(azureData map[string]interface{}) []Anomaly {
    var anomalies []Anomaly
    resourceID := azureData["resource_id"].(string)
    baseline := getBaseline(resourceID)
    
    // Check latency anomalies
    if latency, ok := azureData["latency"].(uint32); ok {
        if float64(latency) > baseline.AvgLatency*2 {
            anomalies = append(anomalies, Anomaly{
                Type:        "HighLatency",
                ResourceID:  resourceID,
                Value:       float64(latency),
                Baseline:    baseline.AvgLatency,
                Severity:    "High",
                Timestamp:   time.Now(),
            })
        }
    }
    
    // Check bandwidth anomalies
    if bandwidth, ok := azureData["bandwidth"].(uint64); ok {
        if float64(bandwidth) < baseline.AvgBandwidth*0.5 {
            anomalies = append(anomalies, Anomaly{
                Type:        "LowBandwidth",
                ResourceID:  resourceID,
                Value:       float64(bandwidth),
                Baseline:    baseline.AvgBandwidth,
                Severity:    "Medium",
                Timestamp:   time.Now(),
            })
        }
    }
    
    return anomalies
}
```

## Configuration and Customization

### Custom Azure Decoders
```go
// Add custom Azure service decoder
parser.AddEnterpriseDecoder(geneve.OptionClassMicrosoft, func(data []byte) {
    // Custom Azure telemetry processing
    if len(data) >= 16 {
        serviceTypeID := binary.BigEndian.Uint32(data[0:4])
        resourceHash := binary.BigEndian.Uint32(data[4:8])
        
        fmt.Printf("Azure Service Type: %d, Resource: 0x%08x\n", 
            serviceTypeID, resourceHash)
    }
})
```

### Service-Specific Filtering
```go
// Process only specific Azure services
targetServices := map[string]bool{
    "Virtual Network": true,
    "AKS":            true,
    "Application Gateway": true,
}

for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "Microsoft" {
        serviceType := enterprise.DecodedData["service_type"].(string)
        if targetServices[serviceType] {
            processAzureService(enterprise.DecodedData)
        }
    }
}
```

## Troubleshooting

### Common Issues

1. **Missing Azure Telemetry**
   - Verify Azure network monitoring is enabled
   - Check GENEVE option configuration
   - Ensure proper Azure service integration

2. **Incomplete Telemetry Data**
   - Validate Azure service configuration
   - Check network monitoring settings
   - Verify telemetry data retention policies

3. **Performance Impact**
   - Monitor telemetry processing overhead
   - Implement sampling for high-volume scenarios
   - Use asynchronous processing where appropriate

### Debug Information
```go
// Debug Azure telemetry parsing
for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "Microsoft" {
        if !enterprise.Decoded {
            fmt.Printf("Azure telemetry parsing failed: raw data length %d\n", 
                len(enterprise.Option.Data))
        } else {
            fmt.Printf("Azure telemetry: %+v\n", enterprise.DecodedData)
        }
    }
}
```

## Standards and References

- [RFC 8926 - Geneve Protocol](https://tools.ietf.org/html/rfc8926)
- [Azure Virtual Network Documentation](https://docs.microsoft.com/en-us/azure/virtual-network/)
- [Azure Network Monitoring](https://docs.microsoft.com/en-us/azure/network-watcher/)
- [Azure Monitor Documentation](https://docs.microsoft.com/en-us/azure/azure-monitor/)

## Related Documentation

- [Enterprise Telemetry Overview](../README.md#enterprise-telemetry-support)
- [Multi-Vendor Integration](multi-vendor-integration.md)
- [Google Cloud Telemetry](google-cloud-telemetry.md)