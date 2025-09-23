# GENEVE Protocol Parser for Go

[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Build Status](https://img.shields.io/badge/Build-Passing-green.svg)](#testing-and-development)
[![Security](https://img.shields.io/badge/Security-Policy-blue.svg)](SECURITY.md)

> **⚠️ IMPORTANT**: This is proprietary software with restrictive licensing. Commercial use is prohibited without explicit permission. Please review the [LICENSE](LICENSE) file before using.

A high-performance, pure Go implementation of a GENEVE (Generic Network Virtualization Encapsulation) protocol packet parser with comprehensive enterprise telemetry support. This library can extract metadata from GENEVE headers and parse vendor-specific TLV options efficiently.

## Features

- Pure Go implementation with zero dependencies (except for testing)
- RFC 8926 compliant GENEVE header parsing
- TLV (Type-Length-Value) options parsing with human-friendly names
- Support for multiple VNI layers
- Advanced INT (In-band Network Telemetry) support
- High-performance parsing with minimal allocations
- Comprehensive validation and statistics
- Human-readable option class and type descriptions
- Comprehensive test coverage

## GENEVE Protocol Overview

GENEVE is a tunneling protocol defined in RFC 8926 that provides:
- 24-bit Virtual Network Identifier (VNI)
- Variable-length TLV options
- Protocol type indication for inner payload
- Critical and optional flags for options processing
- Support for vendor-specific and experimental options

## Installation

```bash
go get github.com/mkrygeri/libgeneve-go
```

## Command-Line Analyzer Tool

For immediate GENEVE packet analysis, use the included command-line tool:

```bash
# Build the analyzer
make analyzer

# Capture live GENEVE traffic from an interface
./build/geneve-analyzer -interface eth0

# Analyze a PCAP file with detailed telemetry output
./build/geneve-analyzer -pcap-file capture.pcap -enterprise

# Filter specific traffic and output as JSON
./build/geneve-analyzer -i eth0 -filter "port 6081" -output json -count 100

# Install system-wide (requires sudo)
make install
geneve-analyzer -help
```

### Analyzer Features

- **Live Capture**: Monitor GENEVE traffic on any network interface
- **PCAP Analysis**: Process existing packet capture files
- **Multiple Output Formats**: Detailed, summary, or JSON output
- **Enterprise Telemetry**: Full support for all vendor-specific telemetry
- **BPF Filtering**: Apply Berkeley Packet Filters for targeted analysis
- **Statistics**: Real-time packet processing statistics
- **Signal Handling**: Graceful shutdown with Ctrl+C

### Output Examples

**Detailed Output:**
```
GENEVE Packet #1
================
VNI: 12345
Protocol: IPv4 (0x0800)
Options: 3 present

VMware NSX Telemetry:
  Segment ID: 4096
  Service Tag: production
  Policy ID: 100

Cisco ACI Telemetry:
  EPG ID: 200
  Tenant ID: corp-tenant
  Contract: web-to-db

Statistics:
  Processing Rate: 1,234 packets/sec
  Total Processed: 5,678
```

**JSON Output:**
```json
{
  "packet_number": 1,
  "timestamp": "2024-01-15T10:30:45Z",
  "vni": 12345,
  "protocol": "IPv4",
  "telemetry": {
    "vmware": { "segment_id": 4096 },
    "cisco": { "epg_id": 200 }
  }
}
```

## Library Usage

### Basic Parsing
```go
parser := geneve.NewParser()
result, err := parser.ParsePacket(packetBytes)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("VNI: %d, Protocol: %s\n", 
    result.Header.VNI, result.Header.GetProtocolName())

// Human-friendly option analysis
for i, opt := range result.Options {
    fmt.Printf("Option %d: %s\n", i+1, opt.GetOptionDescription())
    fmt.Printf("  Class: %s\n", opt.GetOptionClassName())
    fmt.Printf("  Type: %s\n", opt.GetOptionTypeName())
    fmt.Printf("  Critical: %t\n", opt.IsCritical())
}
```

### Enterprise Telemetry Support

The parser includes comprehensive support for enterprise vendor-specific telemetry options:

```go
parser := geneve.NewParser()
parser.EnableEnterpriseExtensions()

result, err := parser.ParsePacket(packetBytes)
if err != nil {
    log.Fatal(err)
}

// Access vendor-specific telemetry
for _, vmware := range result.VMwareOptions {
    fmt.Printf("VMware NSX - Segment: %d, Policy: %d\n", 
        vmware.VSID, vmware.PolicyID)
}

for _, cisco := range result.CiscoOptions {
    fmt.Printf("Cisco ACI - EPG: %d, Tenant: %d, Contract: %d\n",
        cisco.EPGID, cisco.TenantID, cisco.ContractID)
}

for _, arista := range result.AristaOptions {
    fmt.Printf("Arista TAP - Flow: %d, Ports: %d->%d\n",
        arista.FlowID, arista.IngressPort, arista.EgressPort)
}

for _, broadcom := range result.BroadcomOptions {
    fmt.Printf("Broadcom Switch - ID: %d, Buffer: %.2f%%\n",
        broadcom.SwitchID, float64(broadcom.BufferUtil)/100.0)
}
```

#### Supported Enterprise Vendors

| Vendor | Telemetry Types | Documentation |
|--------|----------------|---------------|
| **VMware NSX** | Virtual segments, security policies, tunnel endpoints | [VMware NSX Telemetry](docs/vmware-nsx-telemetry.md) |
| **Cisco ACI** | Application endpoint groups, contracts, tenants | [Cisco ACI Telemetry](docs/cisco-aci-telemetry.md) |
| **Microsoft Azure** | Virtual networks, security groups, load balancers | [Microsoft Azure Telemetry](docs/microsoft-azure-telemetry.md) |
| **Google Cloud** | VPC networks, GKE clusters, Cloud CDN | [Google Cloud Telemetry](docs/google-cloud-telemetry.md) |
| **Amazon AWS** | VPC flow logs, EKS clusters, load balancers | [Amazon AWS Telemetry](docs/amazon-aws-telemetry.md) |
| **Arista Networks** | Traffic analysis platform, latency measurement | [Arista & Broadcom Telemetry](docs/ARISTA-BROADCOM-TELEMETRY.md) |
| **Broadcom** | Switch telemetry, latency histograms | [Arista & Broadcom Telemetry](docs/ARISTA-BROADCOM-TELEMETRY.md) |

### INT Metadata Analysis
```go
for _, intOpt := range result.INTOptions {
    fmt.Printf("INT Version: %s\n", intOpt.GetVersionName())
    fmt.Printf("Status: %s\n", intOpt.GetFlagsDescription())
    
    instructions := intOpt.GetINTInstructionNames()
    fmt.Printf("Telemetry Instructions: %v\n", instructions)
}
```

## Examples

The repository includes comprehensive examples demonstrating different use cases:

- **[Basic Usage](examples/basic-usage.go)** - Simple GENEVE packet parsing
- **[Advanced Analytics](examples/advanced-analytics.go)** - Comprehensive telemetry analysis
- **[Enterprise Integration](examples/enterprise-integration.go)** - Multi-vendor telemetry processing
- **[INT Telemetry](examples/int-telemetry.go)** - In-band Network Telemetry analysis
- **[Telemetry Extraction](examples/telemetry-extraction.go)** - JSON export for monitoring systems
- **[Arista & Broadcom Demo](examples/arista-broadcom-telemetry.go)** - Hardware vendor telemetry

## Testing and Development

### Running Tests
```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run benchmarks
make bench

# Run race condition tests
make test-race

# Run all checks (format, vet, lint, test)
make check
```

### Building
```bash
# Build everything
make all

# Build just the library
make build

# Build the analyzer tool
make analyzer

# Install analyzer system-wide
sudo make install
```

### Makefile Targets

| Target | Description |
|--------|-------------|
| `all` | Build the project and analyzer |
| `build` | Build the project libraries |
| `analyzer` | Build the command-line analyzer tool |
| `install` | Install analyzer to `/usr/local/bin` |
| `uninstall` | Uninstall analyzer from system |
| `test` | Run tests |
| `test-coverage` | Run tests with coverage report |
| `bench` | Run benchmarks |
| `test-race` | Run race condition tests |
| `deps` | Install dependencies |
| `deps-update` | Update dependencies |
| `fmt` | Format code |
| `vet` | Vet code |
| `lint` | Lint code (requires golangci-lint) |
| `check` | Run all checks (fmt, vet, lint, test) |
| `clean` | Clean build artifacts |

## Performance

The parser is optimized for high-throughput packet processing:

- **Zero-allocation parsing** for standard GENEVE headers
- **Efficient TLV parsing** with minimal memory overhead
- **Vectorized processing** for option validation
- **Benchmark results** (on modern hardware):
  - ~2M packets/sec for basic parsing
  - ~500K packets/sec with full telemetry extraction
  - <100ns per packet for header parsing only

## Supported Platforms

- Linux (amd64, arm64)
- macOS (amd64, arm64) 
- Windows (amd64)
- FreeBSD (amd64)

## License

No.talk to me brah
