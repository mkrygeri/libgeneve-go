# Linux Cooked Capture Support Enhancement

## Overview

The GENEVE analyzer has been enhanced to support Linux cooked capture format (DLT_LINUX_SLL), commonly produced by `tcpdump -i any` and similar tools. This enhancement improves compatibility with PCAP files captured in containerized environments and complex network topologies.

## Changes Made

### 1. Automatic Link Type Detection

The analyzer now automatically detects the PCAP file's link layer type and adjusts packet parsing accordingly:

```go
// Determine link type from the pcap file
linkType := pcapReader.LinkType()
var layerType gopacket.LayerType

switch linkType {
case layers.LinkTypeEthernet:
    layerType = layers.LayerTypeEthernet
    fmt.Printf("Link type: Ethernet\n")
case layers.LinkTypeLinuxSLL:
    layerType = layers.LayerTypeLinuxSLL
    fmt.Printf("Link type: Linux cooked capture (SLL)\n")
default:
    // Fallback to Ethernet with warning
    layerType = layers.LayerTypeEthernet
    fmt.Printf("Link type: %v (defaulting to Ethernet - may not work correctly)\n", linkType)
    fmt.Printf("Warning: Unsupported link type. Supported types are Ethernet and Linux SLL\n")
}
```

### 2. Enhanced Debugging

Added verbose output to show packet layer structure for troubleshooting:

```go
if config.Verbose && stats.TotalPackets <= 5 {
    // Debug first few packets to show layer structure
    fmt.Printf("DEBUG: Packet %d layers: ", stats.TotalPackets)
    for _, layer := range packet.Layers() {
        fmt.Printf("%v ", layer.LayerType())
    }
    fmt.Printf("\n")
}
```

### 3. Updated Documentation

- Enhanced help message to show supported formats
- Updated README with Linux cooked capture examples
- Added demonstration scripts

## Supported Formats

| Format | Link Type | Description | Common Use Cases |
|--------|-----------|-------------|------------------|
| **Ethernet** | DLT_EN10MB | Standard Ethernet frames | Interface-specific captures |
| **Linux SLL** | DLT_LINUX_SLL | Linux cooked capture | `tcpdump -i any`, container networking |

## Usage Examples

### Capturing Linux Cooked Format

```bash
# Capture GENEVE traffic from any interface
sudo tcpdump -i any -w cooked-geneve.pcap 'udp port 6081'
```

### Analyzing Linux Cooked Captures

```bash
# Basic analysis
./build/geneve-analyzer -pcap-file cooked-geneve.pcap

# Verbose analysis (shows link type detection)
./build/geneve-analyzer -pcap-file cooked-geneve.pcap -verbose

# Enterprise telemetry with JSON output
./build/geneve-analyzer -pcap-file cooked-geneve.pcap -enterprise -output json
```

### Sample Output

```
Processing PCAP file: cooked-geneve.pcap
Link type: Linux cooked capture (SLL)
DEBUG: Packet 1 layers: LinuxSLL IPv4 UDP 
DEBUG: Found GENEVE packet - UDP payload size: 64 bytes

=== GENEVE Packet @ 2025-09-23 10:30:15.123456 ===
VNI: 12345 (0x003039)
Protocol: IPv4 (0x0800)
Options: 2, Payload: 42 bytes
...
```

## Benefits

1. **Container Environments**: Works with captures from container network interfaces
2. **Multi-Interface Monitoring**: Supports captures from multiple interfaces simultaneously  
3. **Complex Topologies**: Handles traffic from various network namespace configurations
4. **Standard Compatibility**: Works with common tcpdump capture formats
5. **Automatic Detection**: No user configuration required - format detected automatically

## Technical Details

### Packet Processing Flow

1. **PCAP Reading**: Use `pcapgo.NewReader()` to read file metadata
2. **Link Type Detection**: Check `pcapReader.LinkType()` for format identification
3. **Layer Type Selection**: Map link type to appropriate gopacket layer type
4. **Packet Parsing**: Create packets with correct layer type for parsing
5. **UDP Extraction**: Extract UDP layer (works for both Ethernet and SLL)
6. **GENEVE Analysis**: Parse GENEVE payload regardless of link layer format

### Error Handling

- Unsupported link types fall back to Ethernet with warnings
- Verbose mode shows layer structure for debugging
- Clear error messages for unsupported formats

## Testing

Use the provided demonstration scripts:

```bash
# Test format support
./scripts/test-pcap-formats.sh

# Linux cooked capture demo
./examples/linux-cooked-capture-demo.sh
```

## Backward Compatibility

- Existing Ethernet PCAP files continue to work without changes
- No breaking changes to command-line interface
- Automatic format detection requires no user intervention

---

This enhancement significantly improves the analyzer's utility in modern containerized and cloud-native environments where Linux cooked capture format is commonly used.