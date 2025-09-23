# Google Cloud Platform Telemetry

This document describes the Google Cloud Platform (GCP) network telemetry support in the GENEVE parser.

## Overview

Google Cloud Platform uses GENEVE encapsulation to transport network telemetry across its global infrastructure. The parser provides comprehensive support for GCP-specific telemetry data that enables cloud network monitoring, performance optimization, and security analytics.

## Telemetry Data Structure

GCP telemetry is parsed into structured key-value maps representing various Google Cloud services:

```go
// GCP telemetry is returned as map[string]interface{}
gcpTelemetry := map[string]interface{}{
    "service_type":     "VPC Network",
    "project_id":       "my-gcp-project-123456",
    "region":           "us-central1",
    "zone":             "us-central1-a",
    "network_name":     "production-vpc",
    "subnet_name":      "web-tier-subnet",
    // Additional fields based on specific GCP service
}
```

## Supported Google Cloud Services

### Virtual Private Cloud (VPC)
- **Network Topology**: VPC and subnet relationship mapping
- **Firewall Rules**: Security rule enforcement and traffic filtering
- **Route Tables**: Custom and system-generated routing decisions
- **Private Google Access**: Google service connectivity without external IPs

### Google Kubernetes Engine (GKE)
- **Cluster Networking**: Node and pod network configuration
- **Service Discovery**: Kubernetes service mesh telemetry
- **Network Policies**: Kubernetes network policy enforcement
- **Ingress Controllers**: HTTP(S) load balancing and routing

### Cloud Load Balancing
- **Global Load Balancer**: Cross-regional traffic distribution
- **Regional Load Balancer**: Zonal traffic management
- **Health Checks**: Backend instance health monitoring
- **SSL Policies**: Certificate management and security

### Cloud CDN
- **Cache Performance**: Hit/miss ratios and response times
- **Global Distribution**: Edge location serving statistics
- **Origin Shielding**: Origin server protection metrics
- **Bandwidth Optimization**: Compression and optimization stats

### Cloud Interconnect
- **Dedicated Connections**: Private connectivity to Google Cloud
- **Partner Interconnect**: Service provider connection telemetry
- **Cross-Cloud Connectivity**: Multi-cloud network performance
- **BGP Session Monitoring**: Route advertisement and stability

## Telemetry Field Categories

### Infrastructure Identification
```go
type GCPInfrastructureID struct {
    ProjectID     string
    Region        string
    Zone          string
    NetworkName   string
    SubnetName    string
    InstanceID    string
}
```

### Performance Metrics
```go
type GCPPerformanceMetrics struct {
    Throughput       uint64  // Bits per second
    Latency          uint32  // Milliseconds
    PacketLoss       float32 // Percentage
    Jitter           uint32  // Milliseconds
    RTT              uint32  // Round-trip time
    CacheHitRatio    float32 // For CDN services
}
```

### Security Context
```go
type GCPSecurityContext struct {
    FirewallAction   string  // ALLOW/DENY
    RuleName         string
    Priority         int32
    Direction        string  // INGRESS/EGRESS
    TargetTags       []string
    SourceRanges     []string
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

// Access GCP telemetry through enterprise options
for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "Google" && enterprise.Decoded {
        gcpData := enterprise.DecodedData
        
        // VPC network analysis
        if projectID, exists := gcpData["project_id"]; exists {
            fmt.Printf("GCP Project: %v\n", projectID)
        }
        
        // Performance monitoring
        if latency, exists := gcpData["latency"]; exists {
            if latency.(uint32) > 100 {
                fmt.Printf("High latency detected: %v ms\n", latency)
            }
        }
        
        // Security analysis
        if action, exists := gcpData["firewall_action"]; exists {
            if action == "DENY" {
                fmt.Printf("Traffic blocked by firewall: %v\n", gcpData)
            }
        }
    }
}
```

## Integration Patterns

### Cloud Monitoring Integration
```go
// Export telemetry to Google Cloud Monitoring
func exportToCloudMonitoring(gcpData map[string]interface{}) {
    ctx := context.Background()
    client, err := monitoring.NewMetricClient(ctx)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    projectID := gcpData["project_id"].(string)
    
    // Create metric descriptor
    metricType := "custom.googleapis.com/network/latency"
    if latency, ok := gcpData["latency"].(uint32); ok {
        // Create time series data
        ts := &monitoringpb.TimeSeries{
            Metric: &metricpb.Metric{
                Type: metricType,
                Labels: map[string]string{
                    "region":  gcpData["region"].(string),
                    "network": gcpData["network_name"].(string),
                },
            },
            Points: []*monitoringpb.Point{
                {
                    Interval: &monitoringpb.TimeInterval{
                        EndTime: timestamppb.Now(),
                    },
                    Value: &monitoringpb.TypedValue{
                        Value: &monitoringpb.TypedValue_DoubleValue{
                            DoubleValue: float64(latency),
                        },
                    },
                },
            },
        }
        
        // Send to Cloud Monitoring
        req := &monitoringpb.CreateTimeSeriesRequest{
            Name:       "projects/" + projectID,
            TimeSeries: []*monitoringpb.TimeSeries{ts},
        }
        client.CreateTimeSeries(ctx, req)
    }
}
```

### BigQuery Analytics Integration
```go
// Stream telemetry data to BigQuery for analysis
func streamToBigQuery(gcpData map[string]interface{}) {
    ctx := context.Background()
    client, err := bigquery.NewClient(ctx, gcpData["project_id"].(string))
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    dataset := client.Dataset("network_telemetry")
    table := dataset.Table("gcp_network_metrics")
    
    // Prepare data for insertion
    row := map[string]bigquery.Value{
        "timestamp":    time.Now(),
        "project_id":   gcpData["project_id"],
        "region":       gcpData["region"],
        "network_name": gcpData["network_name"],
        "latency":      gcpData["latency"],
        "throughput":   gcpData["throughput"],
        "packet_loss":  gcpData["packet_loss"],
    }
    
    // Insert row
    inserter := table.Inserter()
    if err := inserter.Put(ctx, row); err != nil {
        log.Printf("Failed to insert row: %v", err)
    }
}
```

### Cloud Security Command Center Integration
```go
// Report security findings to Cloud Security Command Center
func reportSecurityFinding(gcpData map[string]interface{}) {
    if action, ok := gcpData["firewall_action"].(string); ok && action == "DENY" {
        ctx := context.Background()
        client, err := securitycenter.NewClient(ctx)
        if err != nil {
            log.Fatal(err)
        }
        defer client.Close()
        
        finding := &securitycenterpb.Finding{
            Name:     "projects/PROJECT_ID/sources/SOURCE_ID/findings/FINDING_ID",
            State:    securitycenterpb.Finding_ACTIVE,
            Category: "NETWORK_SECURITY_VIOLATION",
            Severity: securitycenterpb.Finding_HIGH,
            SourceProperties: map[string]*structpb.Value{
                "firewall_rule": structpb.NewStringValue(gcpData["rule_name"].(string)),
                "source_ip":     structpb.NewStringValue(gcpData["source_ip"].(string)),
                "target_tags":   structpb.NewStringValue(strings.Join(gcpData["target_tags"].([]string), ",")),
            },
        }
        
        req := &securitycenterpb.CreateFindingRequest{
            Parent:    "projects/PROJECT_ID/sources/SOURCE_ID",
            FindingId: generateFindingID(),
            Finding:   finding,
        }
        
        client.CreateFinding(ctx, req)
    }
}
```

## Service-Specific Implementations

### VPC Network Telemetry
```go
func parseVPCTelemetry(data map[string]interface{}) *VPCMetrics {
    return &VPCMetrics{
        ProjectID:        data["project_id"].(string),
        NetworkName:      data["network_name"].(string),
        SubnetName:       data["subnet_name"].(string),
        Region:           data["region"].(string),
        FirewallHits:     data["firewall_hits"].(int),
        RouteChanges:     data["route_changes"].(int),
        ConnectedInstances: data["connected_instances"].(int),
        TrafficVolume:    data["traffic_volume"].(uint64),
    }
}
```

### GKE Cluster Telemetry
```go
func parseGKETelemetry(data map[string]interface{}) *GKEMetrics {
    return &GKEMetrics{
        ClusterName:      data["cluster_name"].(string),
        ClusterLocation:  data["cluster_location"].(string),
        NodeCount:        data["node_count"].(int),
        PodCount:         data["pod_count"].(int),
        ServiceCount:     data["service_count"].(int),
        NetworkPlugin:    data["network_plugin"].(string),
        PodCIDR:          data["pod_cidr"].(string),
        ServiceCIDR:      data["service_cidr"].(string),
        MasterVersion:    data["master_version"].(string),
    }
}
```

### Cloud Load Balancer Telemetry
```go
func parseLoadBalancerTelemetry(data map[string]interface{}) *LoadBalancerMetrics {
    return &LoadBalancerMetrics{
        LoadBalancerName: data["lb_name"].(string),
        LoadBalancerType: data["lb_type"].(string),
        Region:           data["region"].(string),
        BackendServices:  data["backend_services"].([]string),
        HealthyBackends:  data["healthy_backends"].(int),
        TotalBackends:    data["total_backends"].(int),
        RequestCount:     data["request_count"].(uint64),
        ErrorCount:       data["error_count"].(uint64),
        AverageLatency:   data["average_latency"].(float64),
    }
}
```

## Advanced Analytics

### Multi-Region Performance Analysis
```go
// Analyze performance across GCP regions
type RegionalPerformance struct {
    Region           string
    AverageLatency   float64
    ThroughputMbps   float64
    PacketLossRate   float64
    SampleCount      int
}

func analyzeRegionalPerformance(results []*geneve.ParseResult) map[string]*RegionalPerformance {
    regionMetrics := make(map[string]*RegionalPerformance)
    
    for _, result := range results {
        for _, enterprise := range result.EnterpriseOptions {
            if enterprise.VendorName == "Google" && enterprise.Decoded {
                data := enterprise.DecodedData
                region := data["region"].(string)
                
                if regionMetrics[region] == nil {
                    regionMetrics[region] = &RegionalPerformance{Region: region}
                }
                
                metrics := regionMetrics[region]
                metrics.SampleCount++
                
                // Update running averages
                if latency, ok := data["latency"].(uint32); ok {
                    metrics.AverageLatency = updateRunningAverage(
                        metrics.AverageLatency, float64(latency), metrics.SampleCount)
                }
                
                if throughput, ok := data["throughput"].(uint64); ok {
                    metrics.ThroughputMbps = updateRunningAverage(
                        metrics.ThroughputMbps, float64(throughput)/1e6, metrics.SampleCount)
                }
            }
        }
    }
    
    return regionMetrics
}
```

### Cost Optimization Analysis
```go
// Analyze GCP resource utilization for cost optimization
type GCPResourceUsage struct {
    ProjectID        string
    ResourceType     string
    Region           string
    BandwidthGB      float64
    ComputeHours     float64
    StorageGB        float64
    EstimatedCost    float64
}

func analyzeGCPCosts(gcpData map[string]interface{}) *GCPResourceUsage {
    usage := &GCPResourceUsage{
        ProjectID:    gcpData["project_id"].(string),
        ResourceType: gcpData["service_type"].(string),
        Region:       gcpData["region"].(string),
    }
    
    // Calculate bandwidth usage
    if throughput, ok := gcpData["throughput"].(uint64); ok {
        usage.BandwidthGB = float64(throughput) * 3600 / 8e9 // Convert to GB/hour
    }
    
    // Estimate costs based on GCP pricing
    usage.EstimatedCost = calculateGCPCost(usage)
    
    return usage
}
```

### Network Security Analysis
```go
// Analyze GCP network security patterns
type SecurityEvent struct {
    Timestamp       time.Time
    ProjectID       string
    FirewallRule    string
    Action          string
    SourceIP        string
    DestinationPort int
    Protocol        string
    Region          string
}

func analyzeGCPSecurity(results []*geneve.ParseResult) []SecurityEvent {
    var events []SecurityEvent
    
    for _, result := range results {
        for _, enterprise := range result.EnterpriseOptions {
            if enterprise.VendorName == "Google" && enterprise.Decoded {
                data := enterprise.DecodedData
                
                if action, exists := data["firewall_action"]; exists {
                    event := SecurityEvent{
                        Timestamp:    time.Now(),
                        ProjectID:    data["project_id"].(string),
                        Action:       action.(string),
                        Region:       data["region"].(string),
                    }
                    
                    if ruleName, ok := data["rule_name"]; ok {
                        event.FirewallRule = ruleName.(string)
                    }
                    
                    if sourceIP, ok := data["source_ip"]; ok {
                        event.SourceIP = sourceIP.(string)
                    }
                    
                    events = append(events, event)
                }
            }
        }
    }
    
    return events
}
```

## Configuration and Customization

### Custom GCP Service Decoders
```go
// Add custom decoder for specific GCP services
parser.AddEnterpriseDecoder(geneve.OptionClassGoogle, func(data []byte) {
    if len(data) >= 12 {
        serviceID := binary.BigEndian.Uint32(data[0:4])
        regionCode := binary.BigEndian.Uint32(data[4:8])
        projectHash := binary.BigEndian.Uint32(data[8:12])
        
        fmt.Printf("GCP Service: %d, Region: %d, Project: 0x%08x\n",
            serviceID, regionCode, projectHash)
    }
})
```

### Project-Specific Filtering
```go
// Process telemetry for specific GCP projects
targetProjects := map[string]bool{
    "production-project-123":  true,
    "staging-project-456":     true,
    "development-project-789": true,
}

for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "Google" && enterprise.Decoded {
        projectID := enterprise.DecodedData["project_id"].(string)
        if targetProjects[projectID] {
            processGCPTelemetry(enterprise.DecodedData)
        }
    }
}
```

## Troubleshooting

### Common Issues

1. **Missing GCP Telemetry**
   - Verify VPC Flow Logs are enabled
   - Check Cloud Monitoring configuration
   - Ensure proper IAM permissions

2. **Incomplete Service Data**
   - Validate service configuration
   - Check regional availability
   - Review API quotas and limits

3. **Performance Degradation**
   - Monitor telemetry processing overhead
   - Implement data sampling strategies
   - Use batch processing for high volume

### Debug Information
```go
// Debug GCP telemetry parsing
for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "Google" {
        if enterprise.Decoded {
            fmt.Printf("GCP telemetry decoded: %+v\n", enterprise.DecodedData)
        } else {
            fmt.Printf("GCP telemetry parsing failed: %d bytes\n", 
                len(enterprise.Option.Data))
        }
    }
}
```

## Standards and References

- [RFC 8926 - Geneve Protocol](https://tools.ietf.org/html/rfc8926)
- [Google Cloud VPC Documentation](https://cloud.google.com/vpc/docs)
- [Cloud Monitoring Documentation](https://cloud.google.com/monitoring/docs)
- [GKE Network Monitoring](https://cloud.google.com/kubernetes-engine/docs/how-to/network-observability)
- [Cloud Load Balancing Documentation](https://cloud.google.com/load-balancing/docs)

## Related Documentation

- [Enterprise Telemetry Overview](../README.md#enterprise-telemetry-support)
- [Multi-Vendor Integration](multi-vendor-integration.md)
- [Amazon AWS Telemetry](amazon-aws-telemetry.md)