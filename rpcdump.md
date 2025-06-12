# rpcdump.py

## Overview
`rpcdump.py` is a network enumeration tool in the Impacket suite. DCE/RPC endpoint mapper dumper.

## Detailed Description
DCE/RPC endpoint mapper dumper.

### Key Features:
- **RPC endpoint enumeration**: Core functionality
- **Interface discovery**: Core functionality
- **Protocol and port identification**: Core functionality
- **Service version detection**: Core functionality
- **Authentication method discovery**: Core functionality
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication
- **Cross-Platform Compatibility**: Works with various Windows versions

### Technical Details:
- Uses [specific protocol/technique]
- Leverages [specific Windows API/service]
- Implements [specific attack technique]
- Compatible with [specific versions/systems]

## Command Line Options

```
rpcdump.py [-h] [-debug] [-ts] [-target-ip ip address]
```

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

usage: rpcdump.py [-h] [-debug] [-ts] [-target-ip ip address]
                  [-port [destination port]] [-hashes LMHASH:NTHASH]
                  target

Dumps the remote RPC enpoints information via epmapper.

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

connection:
  -target-ip ip address
                        IP Address of the target machine. If ommited it will
                        use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve
                        it
  -port [destination port]
                        Destination port to connect to RPC Endpoint Mapper

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH


## Usage Examples

### Basic Usage
```bash
# Basic command execution
python3 rpcdump.py [basic_parameters]

# With authentication
python3 rpcdump.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 rpcdump.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 rpcdump.py [advanced_parameters]

# Advanced example 2
python3 rpcdump.py [advanced_parameters_2]

# Debug mode
python3 rpcdump.py target -debug
```

## Attack Chain Integration

### [Specific Attack Scenario]
```bash
# Step 1: [First step description]
python3 rpcdump.py [step1_parameters]

# Step 2: [Second step description]
python3 [related_tool] [step2_parameters]

# Step 3: [Third step description]
python3 [another_tool] [step3_parameters]
```

### RPC Service Enumeration
```bash
# Step 1: Enumerate RPC endpoints for reconnaissance
python3 rpcdump.py target-ip

# Step 2: Use rpcdump.py with authentication for detailed enumeration
python3 rpcdump.py DOMAIN/user:password@target -port 445

# Step 3: Use discovered RPC services for further attacks
python3 dcomexec.py DOMAIN/user:password@target
```

## Prerequisites
- Network access to target system (RPC ports 135, 139, 445, or 593)
- Valid domain credentials for authenticated enumeration (optional)
- Basic understanding of Windows RPC/DCE services
- Knowledge of common RPC interfaces and their purposes

## Detection Considerations
- **Event IDs**: 5156 (Windows Filtering Platform allowed connection), network connection events
- **Network Indicators**: Connections to RPC endpoint mapper (port 135), SMB (445), or HTTP-RPC (593)
- **Process Indicators**: RPC endpoint enumeration activities
- **File Indicators**: No direct file system modifications
- **Registry Indicators**: No registry modifications

## Defensive Measures
- Restrict access to RPC endpoint mapper and limit anonymous connections
- Use Windows Firewall to block unnecessary RPC ports
- Implement network monitoring to detect RPC enumeration activities
- Enable RPC logging and monitor for unusual endpoint requests
- Use endpoint detection and response (EDR) tools to identify reconnaissance

## Common Issues and Troubleshooting

### Connection Refused Errors
```bash
# Problem: Cannot connect to RPC endpoint mapper
# Solution: Try different ports or verify service availability
python3 rpcdump.py target -port 445
```

### Authentication Failures with RPC Proxy
```bash
# Problem: RPC Proxy authentication issues
# Solution: Use proper credentials and verify proxy configuration
python3 rpcdump.py DOMAIN/user:password@target -port 443
```

## Related Tools

## Related Tools
- [rpcdump.py](link.md) - Related functionality
- [secretsdump.py](secretsdump.md) - Often used together
- [psexec.py](psexec.md) - Lateral movement tool
- [GetUserSPNs.py](GetUserSPNs.md) - Credential attacks

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
