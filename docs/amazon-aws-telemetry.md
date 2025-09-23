# Amazon AWS Telemetry

This document describes the Amazon Web Services (AWS) network telemetry support in the GENEVE parser.

## Overview

Amazon AWS uses GENEVE encapsulation to transport network telemetry and metadata across its cloud infrastructure services. The parser provides comprehensive support for AWS-specific telemetry data that enables cloud network monitoring, security analysis, and performance optimization.

## Telemetry Data Structure

AWS telemetry is parsed into structured key-value maps representing various AWS networking services:

```go
// AWS telemetry is returned as map[string]interface{}
awsTelemetry := map[string]interface{}{
    "service_type":     "VPC",
    "account_id":       "123456789012",
    "region":           "us-east-1",
    "availability_zone": "us-east-1a",
    "vpc_id":           "vpc-12345678",
    "subnet_id":        "subnet-87654321",
    // Additional fields based on specific AWS service
}
```

## Supported AWS Services

### Virtual Private Cloud (VPC)
- **Network Topology**: VPC, subnet, and routing table configuration
- **Security Groups**: Instance-level firewall rule enforcement
- **Network ACLs**: Subnet-level access control monitoring
- **VPC Endpoints**: Private service connectivity metrics
- **NAT Gateway**: Network address translation performance

### Elastic Container Service (ECS) / Elastic Kubernetes Service (EKS)
- **Container Networking**: Task and pod network interface metrics
- **Service Discovery**: Container service mesh telemetry
- **Load Balancer Integration**: Application and Network Load Balancer metrics
- **Fargate Networking**: Serverless container network performance

### Application Load Balancer (ALB) / Network Load Balancer (NLB)
- **Target Group Health**: Backend instance health monitoring
- **Request Routing**: Path and host-based routing decisions
- **SSL/TLS Termination**: Certificate and encryption metrics
- **Cross-Zone Load Balancing**: Multi-AZ traffic distribution

### CloudFront CDN
- **Edge Location Performance**: Global content delivery metrics
- **Cache Hit Ratios**: Content caching effectiveness
- **Origin Shield**: Origin server protection statistics
- **Real-Time Logs**: Request-level performance data

### AWS Transit Gateway
- **Cross-VPC Connectivity**: Inter-VPC routing metrics
- **On-Premises Integration**: VPN and Direct Connect performance
- **Route Propagation**: Dynamic routing advertisements
- **Bandwidth Utilization**: Cross-region traffic analysis

### AWS Direct Connect
- **Dedicated Connections**: Private connectivity to AWS
- **Virtual Interfaces**: VLAN-based service access
- **BGP Routing**: Route advertisement and path selection
- **Connection Health**: Physical link monitoring

## Telemetry Field Categories

### Infrastructure Identification
```go
type AWSInfrastructureID struct {
    AccountID         string
    Region            string
    AvailabilityZone  string
    VPCID             string
    SubnetID          string
    InstanceID        string
    SecurityGroups    []string
}
```

### Performance Metrics
```go
type AWSPerformanceMetrics struct {
    Throughput        uint64  // Bits per second
    Latency           uint32  // Milliseconds
    PacketLoss        float32 // Percentage
    Jitter            uint32  // Milliseconds
    ConnectionCount   uint32  // Active connections
    RequestRate       uint32  // Requests per second
}
```

### Security Context
```go
type AWSSecurityContext struct {
    SecurityGroupID   string
    RuleAction        string  // ALLOW/DENY
    Protocol          string
    PortRange         string
    SourceCIDR        string
    NACLRuleNumber    int32
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

// Access AWS telemetry through enterprise options
for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "Amazon" && enterprise.Decoded {
        awsData := enterprise.DecodedData
        
        // VPC network analysis
        if vpcID, exists := awsData["vpc_id"]; exists {
            fmt.Printf("AWS VPC: %v\n", vpcID)
        }
        
        // Performance monitoring
        if latency, exists := awsData["latency"]; exists {
            if latency.(uint32) > 200 {
                fmt.Printf("High latency detected: %v ms\n", latency)
            }
        }
        
        // Security analysis
        if action, exists := awsData["rule_action"]; exists {
            if action == "DENY" {
                fmt.Printf("Traffic blocked: %v\n", awsData)
            }
        }
    }
}
```

## Integration Patterns

### CloudWatch Integration
```go
// Export telemetry to Amazon CloudWatch
func exportToCloudWatch(awsData map[string]interface{}) {
    sess := session.Must(session.NewSession())
    svc := cloudwatch.New(sess)
    
    namespace := "AWS/NetworkTelemetry"
    region := awsData["region"].(string)
    
    // Create metric data
    var metricData []*cloudwatch.MetricDatum
    
    if latency, ok := awsData["latency"].(uint32); ok {
        metricData = append(metricData, &cloudwatch.MetricDatum{
            MetricName: aws.String("NetworkLatency"),
            Value:      aws.Float64(float64(latency)),
            Unit:       aws.String("Milliseconds"),
            Dimensions: []*cloudwatch.Dimension{
                {
                    Name:  aws.String("Region"),
                    Value: aws.String(region),
                },
                {
                    Name:  aws.String("VPC"),
                    Value: aws.String(awsData["vpc_id"].(string)),
                },
            },
        })
    }
    
    // Put metric data
    _, err := svc.PutMetricData(&cloudwatch.PutMetricDataInput{
        Namespace:  aws.String(namespace),
        MetricData: metricData,
    })
    if err != nil {
        log.Printf("Failed to put metric data: %v", err)
    }
}
```

### AWS Security Hub Integration
```go
// Report security findings to AWS Security Hub
func reportToSecurityHub(awsData map[string]interface{}) {
    if action, ok := awsData["rule_action"].(string); ok && action == "DENY" {
        sess := session.Must(session.NewSession())
        svc := securityhub.New(sess)
        
        accountID := awsData["account_id"].(string)
        region := awsData["region"].(string)
        
        finding := &securityhub.AwsSecurityFinding{
            AwsAccountId: aws.String(accountID),
            CreatedAt:    aws.String(time.Now().Format(time.RFC3339)),
            Description:  aws.String("Network traffic blocked by security group"),
            GeneratorId:  aws.String("geneve-parser"),
            Id:           aws.String(fmt.Sprintf("network-block-%d", time.Now().Unix())),
            ProductArn:   aws.String(fmt.Sprintf("arn:aws:securityhub:%s:%s:product/%s/geneve-parser", region, accountID, accountID)),
            SchemaVersion: aws.String("2018-10-08"),
            Severity: &securityhub.Severity{
                Label: aws.String("MEDIUM"),
            },
            Title: aws.String("Network Traffic Blocked"),
            Types: []*string{
                aws.String("Sensitive Data Identifications/PII"),
            },
            Resources: []*securityhub.Resource{
                {
                    Id:   aws.String(awsData["vpc_id"].(string)),
                    Type: aws.String("AwsEc2Vpc"),
                    Region: aws.String(region),
                },
            },
        }
        
        _, err := svc.BatchImportFindings(&securityhub.BatchImportFindingsInput{
            Findings: []*securityhub.AwsSecurityFinding{finding},
        })
        if err != nil {
            log.Printf("Failed to import finding: %v", err)
        }
    }
}
```

### Amazon Kinesis Data Streams
```go
// Stream telemetry data to Kinesis for real-time processing
func streamToKinesis(awsData map[string]interface{}) {
    sess := session.Must(session.NewSession())
    svc := kinesis.New(sess)
    
    // Prepare telemetry record
    record := map[string]interface{}{
        "timestamp": time.Now().Unix(),
        "source":    "geneve-parser",
        "data":      awsData,
    }
    
    recordJSON, err := json.Marshal(record)
    if err != nil {
        log.Printf("Failed to marshal record: %v", err)
        return
    }
    
    // Put record to stream
    _, err = svc.PutRecord(&kinesis.PutRecordInput{
        StreamName:   aws.String("aws-network-telemetry"),
        Data:         recordJSON,
        PartitionKey: aws.String(awsData["vpc_id"].(string)),
    })
    if err != nil {
        log.Printf("Failed to put record: %v", err)
    }
}
```

## Service-Specific Implementations

### VPC Flow Logs Telemetry
```go
func parseVPCFlowLogs(data map[string]interface{}) *VPCFlowLogMetrics {
    return &VPCFlowLogMetrics{
        AccountID:        data["account_id"].(string),
        VPCID:            data["vpc_id"].(string),
        SubnetID:         data["subnet_id"].(string),
        InstanceID:       data["instance_id"].(string),
        InterfaceID:      data["interface_id"].(string),
        Protocol:         data["protocol"].(string),
        SourcePort:       data["source_port"].(int),
        DestinationPort:  data["destination_port"].(int),
        Action:           data["action"].(string),
        Packets:          data["packets"].(uint64),
        Bytes:            data["bytes"].(uint64),
    }
}
```

### EKS Cluster Telemetry
```go
func parseEKSTelemetry(data map[string]interface{}) *EKSMetrics {
    return &EKSMetrics{
        ClusterName:      data["cluster_name"].(string),
        ClusterVersion:   data["cluster_version"].(string),
        NodeGroupName:    data["node_group"].(string),
        Namespace:        data["namespace"].(string),
        PodName:          data["pod_name"].(string),
        ServiceName:      data["service_name"].(string),
        NetworkMode:      data["network_mode"].(string),
        CNIPlugin:        data["cni_plugin"].(string),
    }
}
```

### Application Load Balancer Telemetry
```go
func parseALBTelemetry(data map[string]interface{}) *ALBMetrics {
    return &ALBMetrics{
        LoadBalancerName: data["lb_name"].(string),
        LoadBalancerArn:  data["lb_arn"].(string),
        TargetGroupArn:   data["target_group_arn"].(string),
        AvailabilityZone: data["availability_zone"].(string),
        HealthyTargets:   data["healthy_targets"].(int),
        UnhealthyTargets: data["unhealthy_targets"].(int),
        RequestCount:     data["request_count"].(uint64),
        ResponseTime:     data["response_time"].(float64),
        HTTPCode:         data["http_code"].(string),
    }
}
```

## Advanced Analytics

### Cross-Region Performance Analysis
```go
// Analyze performance across AWS regions
type RegionalAWSMetrics struct {
    Region            string
    AverageLatency    float64
    TotalThroughput   uint64
    ErrorRate         float64
    InstanceCount     int
}

func analyzeAWSRegionalPerformance(results []*geneve.ParseResult) map[string]*RegionalAWSMetrics {
    regionMetrics := make(map[string]*RegionalAWSMetrics)
    
    for _, result := range results {
        for _, enterprise := range result.EnterpriseOptions {
            if enterprise.VendorName == "Amazon" && enterprise.Decoded {
                data := enterprise.DecodedData
                region := data["region"].(string)
                
                if regionMetrics[region] == nil {
                    regionMetrics[region] = &RegionalAWSMetrics{Region: region}
                }
                
                metrics := regionMetrics[region]
                
                // Update metrics
                if latency, ok := data["latency"].(uint32); ok {
                    metrics.AverageLatency = (metrics.AverageLatency + float64(latency)) / 2
                }
                
                if throughput, ok := data["throughput"].(uint64); ok {
                    metrics.TotalThroughput += throughput
                }
                
                metrics.InstanceCount++
            }
        }
    }
    
    return regionMetrics
}
```

### Cost Optimization Analysis
```go
// Analyze AWS resource costs based on telemetry
type AWSCostAnalysis struct {
    AccountID         string
    Region            string
    ServiceType       string
    DataTransferGB    float64
    ComputeHours      float64
    EstimatedCost     float64
    Recommendations   []string
}

func analyzeAWSCosts(awsData map[string]interface{}) *AWSCostAnalysis {
    analysis := &AWSCostAnalysis{
        AccountID:   awsData["account_id"].(string),
        Region:      awsData["region"].(string),
        ServiceType: awsData["service_type"].(string),
    }
    
    // Calculate data transfer
    if bytes, ok := awsData["bytes"].(uint64); ok {
        analysis.DataTransferGB = float64(bytes) / 1e9
    }
    
    // Estimate costs
    analysis.EstimatedCost = calculateAWSCosts(analysis)
    
    // Generate recommendations
    if analysis.DataTransferGB > 1000 {
        analysis.Recommendations = append(analysis.Recommendations, 
            "Consider using CloudFront CDN to reduce data transfer costs")
    }
    
    return analysis
}
```

### Security Threat Analysis
```go
// Analyze AWS security threats from telemetry
type SecurityThreat struct {
    ThreatType        string
    Severity          string
    SourceIP          string
    TargetResource    string
    AttackVector      string
    FirstSeen         time.Time
    LastSeen          time.Time
    EventCount        int
}

func analyzeAWSSecurity(results []*geneve.ParseResult) []SecurityThreat {
    threatMap := make(map[string]*SecurityThreat)
    
    for _, result := range results {
        for _, enterprise := range result.EnterpriseOptions {
            if enterprise.VendorName == "Amazon" && enterprise.Decoded {
                data := enterprise.DecodedData
                
                // Detect suspicious patterns
                if action, ok := data["rule_action"].(string); ok && action == "DENY" {
                    sourceIP := data["source_ip"].(string)
                    threatKey := fmt.Sprintf("%s-%s", sourceIP, data["destination_port"])
                    
                    if threat := threatMap[threatKey]; threat == nil {
                        threatMap[threatKey] = &SecurityThreat{
                            ThreatType:     "Port Scanning",
                            Severity:       "Medium",
                            SourceIP:       sourceIP,
                            TargetResource: data["vpc_id"].(string),
                            AttackVector:   "Network",
                            FirstSeen:      time.Now(),
                            EventCount:     1,
                        }
                    } else {
                        threat.EventCount++
                        threat.LastSeen = time.Now()
                        
                        // Escalate severity based on frequency
                        if threat.EventCount > 100 {
                            threat.Severity = "High"
                        }
                    }
                }
            }
        }
    }
    
    // Convert map to slice
    var threats []SecurityThreat
    for _, threat := range threatMap {
        threats = append(threats, *threat)
    }
    
    return threats
}
```

## Configuration and Customization

### Custom AWS Service Decoders
```go
// Add custom decoder for specific AWS services
parser.AddEnterpriseDecoder(geneve.OptionClassAmazon, func(data []byte) {
    if len(data) >= 16 {
        serviceCode := binary.BigEndian.Uint32(data[0:4])
        regionCode := binary.BigEndian.Uint32(data[4:8])
        accountHash := binary.BigEndian.Uint64(data[8:16])
        
        fmt.Printf("AWS Service: %d, Region: %d, Account: 0x%016x\n",
            serviceCode, regionCode, accountHash)
    }
})
```

### Account-Specific Processing
```go
// Process telemetry for specific AWS accounts
targetAccounts := map[string]bool{
    "123456789012": true,  // Production account
    "234567890123": true,  // Staging account
    "345678901234": true,  // Development account
}

for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "Amazon" && enterprise.Decoded {
        accountID := enterprise.DecodedData["account_id"].(string)
        if targetAccounts[accountID] {
            processAWSTelemetry(enterprise.DecodedData)
        }
    }
}
```

## Troubleshooting

### Common Issues

1. **Missing AWS Telemetry**
   - Verify VPC Flow Logs are enabled
   - Check CloudTrail configuration
   - Ensure proper IAM permissions

2. **Incomplete Service Data**
   - Validate service configuration
   - Check regional service availability
   - Review AWS service quotas

3. **High Processing Latency**
   - Monitor telemetry volume
   - Implement data sampling
   - Use parallel processing

### Debug Information
```go
// Debug AWS telemetry parsing
for _, enterprise := range result.EnterpriseOptions {
    if enterprise.VendorName == "Amazon" {
        if enterprise.Decoded {
            fmt.Printf("AWS telemetry: %+v\n", enterprise.DecodedData)
        } else {
            fmt.Printf("AWS parsing failed: %d bytes raw data\n", 
                len(enterprise.Option.Data))
        }
    }
}
```

## Standards and References

- [RFC 8926 - Geneve Protocol](https://tools.ietf.org/html/rfc8926)
- [AWS VPC Documentation](https://docs.aws.amazon.com/vpc/)
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [AWS CloudWatch Documentation](https://docs.aws.amazon.com/cloudwatch/)
- [AWS Security Hub Documentation](https://docs.aws.amazon.com/securityhub/)

## Related Documentation

- [Enterprise Telemetry Overview](../README.md#enterprise-telemetry-support)
- [Multi-Vendor Integration](multi-vendor-integration.md)
- [Arista and Broadcom Telemetry](ARISTA-BROADCOM-TELEMETRY.md)