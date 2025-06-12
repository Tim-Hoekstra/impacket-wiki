# getArch.py

## Overview
`getArch.py` is a remote architecture detection tool in the Impacket suite. This tool is categorized under System Information and provides functionality for determining the OS architecture (32-bit or 64-bit) of remote Windows systems without requiring authentication.

## Detailed Description
`getArch.py` exploits a documented Microsoft RPC behavior to determine the target system's OS architecture remotely. The tool connects to the RPC endpoint mapper service (port 135) and attempts to bind using NDR64 syntax. If the target supports NDR64, it's a 64-bit system; if the binding fails with "syntaxes_not_supported", it's a 32-bit system.

This technique is based on Microsoft's own documentation (MS-RPC specification) and leverages the fact that NDR64 syntax is only supported on 64-bit Windows systems. The method is completely passive and doesn't require any authentication, making it ideal for initial reconnaissance.

### Key Features:
- **Unauthenticated Detection**: No credentials required for architecture detection
- **Bulk Scanning**: Support for scanning multiple targets from a file
- **Fast Detection**: Uses RPC endpoint mapper for quick determination
- **Timeout Control**: Configurable connection timeout for network optimization
- **Clean Output**: Simple output format showing target and architecture

### Technical Details:
- Uses DCE/RPC over TCP (ncacn_ip_tcp) transport
- Leverages RPC endpoint mapper service on port 135
- Attempts NDR64 syntax binding (GUID: 71710533-BEBA-4937-8319-B5DBEF9CCC36)
- Based on Microsoft MS-RPC specification behavior
- Compatible with Windows systems (not Samba servers)

## Command Line Options

```
usage: getArch.py [-h] [-target TARGET] [-targets TARGETS] [-timeout TIMEOUT] [-debug] [-ts]

Optional Arguments:
  -h, --help            Show help message and exit
  -target TARGET        Target hostname or IP address
  -targets TARGETS      Input file with target systems (one per line)
  -timeout TIMEOUT      Socket timeout when connecting (default: 2 seconds)
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output
```

## Usage Examples

### Basic Usage
```bash
# Check single target architecture
python3 getArch.py -target 192.168.1.100

# Check domain controller architecture
python3 getArch.py -target dc01.domain.com

# Scan multiple targets from file
python3 getArch.py -targets targets.txt

# With custom timeout (useful for slow networks)
python3 getArch.py -target 192.168.1.100 -timeout 5

# With debug output
python3 getArch.py -target 192.168.1.100 -debug
```

### Bulk Scanning
```bash
# Create targets file
echo "192.168.1.100" > targets.txt
echo "192.168.1.101" >> targets.txt
echo "dc01.domain.com" >> targets.txt

# Scan all targets
python3 getArch.py -targets targets.txt

# Example output:
# 192.168.1.100 is 64-bit
# 192.168.1.101 is 32-bit
# dc01.domain.com is 64-bit
```

### Network Reconnaissance
```bash
# Quick architecture survey of domain controllers
python3 getArch.py -target dc01.domain.com -timeout 1
python3 getArch.py -target dc02.domain.com -timeout 1

# Combine with nmap for comprehensive scanning
nmap -p 135 --open 192.168.1.0/24 | grep -oP '\d+\.\d+\.\d+\.\d+' > rpc_hosts.txt
python3 getArch.py -targets rpc_hosts.txt
```

## Attack Integration

### Reconnaissance Phase
```bash
# Architecture detection for payload selection
python3 getArch.py -target target.domain.com

# Based on results, select appropriate payloads:
# 64-bit: Use x64 shellcode, 64-bit exploits
# 32-bit: Use x86 shellcode, 32-bit exploits
```

### Payload Preparation
```bash
# After determining architecture, prepare matching tools
if [[ $(python3 getArch.py -target 192.168.1.100) == *"64-bit"* ]]; then
    echo "Target is 64-bit - use x64 payloads"
    # Select 64-bit versions of tools like:
    # - psexec.py with 64-bit payloads
    # - wmiexec.py with 64-bit commands
else
    echo "Target is 32-bit - use x86 payloads"
    # Select 32-bit versions
fi
```

## Security Implications

### Defensive Considerations
- **RPC Filtering**: Block unnecessary RPC traffic at network borders
- **Endpoint Mapper**: Consider disabling RPC endpoint mapper if not needed
- **Network Segmentation**: Limit RPC access between network segments
- **Monitoring**: Log RPC endpoint mapper connections for suspicious activity

### Detection Methods
```bash
# Monitor for RPC endpoint mapper connections
# Windows Event ID 5156 (Network filtering)
# Look for connections to port 135 from external sources

# Network monitoring
tcpdump -i any port 135 and host [suspicious_ip]

# Firewall logs for RPC endpoint mapper access
```

## Troubleshooting

### Common Issues
1. **Connection Timeouts**:
   - Increase timeout value: `-timeout 10`
   - Check network connectivity to port 135
   - Verify RPC service is running

2. **No Response**:
   - Target may be running Samba (not Windows)
   - RPC endpoint mapper may be filtered
   - System may be offline

3. **Inconsistent Results**:
   - Network latency affecting detection
   - RPC service instability
   - Firewall interference

### Debugging
```bash
# Enable debug output
python3 getArch.py -target 192.168.1.100 -debug

# Test RPC connectivity manually
telnet 192.168.1.100 135

# Check if RPC endpoint mapper is accessible
rpcinfo -p 192.168.1.100  # Linux systems
```

## Related Tools
- **rpcdump.py**: Enumerate RPC endpoints and interfaces
- **rpcmap.py**: Map RPC services and endpoints
- **psexec.py**: Remote execution (architecture-dependent payloads)
- **wmiexec.py**: WMI-based execution (architecture considerations)
- **secretsdump.py**: Credential extraction (architecture-specific locations)

## Technical References
- [MS-RPC: Remote Procedure Call Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpc/)
- [Microsoft NDR64 Transfer Syntax](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpc/b6090c2b-f44a-47a1-a13b-b82ade0137b2)
- [RPC Endpoint Mapper Service](https://docs.microsoft.com/en-us/windows/win32/rpc/the-rpc-endpoint-mapper)

# Using hash authentication
python3 getArch.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Test with specific timeout
python3 getArch.py 192.168.1.100 445 -timeout 10

# Use with domain credentials
python3 getArch.py -hashes :ntlmhash domain.com/user@192.168.1.100

# Batch testing multiple hosts
for host in $(cat targets.txt); do
    echo "Testing $host..."
    python3 getArch.py "$host" 445
done
```

## Attack Chain Integration

### Pre-exploitation Architecture Discovery
```bash
# Step 1: Discover SMB hosts
nmap -p 445 --open 192.168.1.0/24 -oG smb_discovery.txt

# Step 2: Check architecture for each target
grep "445/open" smb_discovery.txt | awk '{print $2}' | while read target; do
    echo "Architecture for $target:"
    python3 getArch.py "$target" 445
done

# Step 3: Use architecture-specific tools
python3 psexec.py domain/user:pass@target  # Use x64 or x86 payloads accordingly
```

### Post-compromise Architecture Verification
```bash
# Step 1: Initial access via existing credentials
python3 wmiexec.py domain/user:pass@target

# Step 2: Verify architecture for lateral movement
python3 getArch.py target 445

# Step 3: Use appropriate tools based on architecture
python3 psexec.py domain/user:pass@target  # Select x64/x86 payload accordingly
```

## Prerequisites
- Network access to target system on port 135 (RPC endpoint mapper)
- No authentication required (works anonymously)
- Python 3.x with Impacket installed
- Target system must be running Windows (not compatible with Samba)

## Detection Considerations
- **Event IDs**: 
  - Event ID 5156 (Windows Filtering Platform connection)
  - Event ID 4624 (Anonymous logon attempts if logging enabled)
- **Network Indicators**: 
  - Connections to port 135 (RPC endpoint mapper)
  - RPC traffic with NDR64 transfer syntax negotiation
- **Process Indicators**: 
  - No process indicators on target (passive technique)
- **File Indicators**: 
  - No file modifications on target system
- **Registry Indicators**: 
  - No registry modifications

## Defensive Measures
- Monitor and log RPC endpoint mapper connections on port 135
- Implement network segmentation to limit RPC exposure
- Use Windows Firewall to restrict port 135 access
- Deploy network intrusion detection systems to monitor RPC traffic
- Regular security updates and patches
- Consider disabling RPC endpoint mapper if not required

## Common Issues and Troubleshooting

### Connection Timeout Issues
```bash
# Problem: Target system not responding or connection times out
# Solution: Verify target accessibility and adjust timeout
python3 getArch.py -timeout 10 -target 192.168.1.100
```

### Firewall Blocking Access
```bash
# Problem: Unable to connect to port 135 due to firewall
# Solution: Verify firewall rules and network connectivity
nmap -p 135 192.168.1.100  # Test port accessibility first
```

## Related Tools
- [psexec.py](psexec.md) - Execute commands after architecture detection
- [wmiexec.py](wmiexec.md) - Alternative execution method based on architecture
- [smbexec.py](smbexec.md) - SMB-based execution requiring architecture info
- [rpcmap.py](rpcmap.md) - RPC endpoint enumeration and mapping

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
