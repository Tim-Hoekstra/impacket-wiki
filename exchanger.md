# exchanger.py

## Overview
`exchanger.py` is a exchange server operations tool in the Impacket suite. This tool is categorized under Email Services and provides functionality for [specific use case].

## Detailed Description
[Detailed description of what this tool does, its purpose, and technical background]

### Key Features:
- **Feature 1**: Description of primary feature
- **Feature 2**: Description of secondary feature
- **Feature 3**: Description of additional feature
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication
- **Cross-Platform Compatibility**: Works with various Windows versions

### Technical Details:
- Uses [specific protocol/technique]
- Leverages [specific Windows API/service]
- Implements [specific attack technique]
- Compatible with [specific versions/systems]

## Command Line Options

```
usage: exchanger.py [-h] [options] target

Required Arguments:
  target                [Description of target parameter]

Optional Arguments:
  -h, --help            Show help message
  [Add specific options based on tool functionality]

Authentication:
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password
  -k                    Use Kerberos authentication
  -aesKey               AES key for Kerberos authentication
  -dc-ip                Domain controller IP address
```

## Usage Examples

### Basic Usage
```bash
# Basic command execution
python3 exchanger.py [basic_parameters]

# With authentication
python3 exchanger.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 exchanger.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 exchanger.py [advanced_parameters]

# Advanced example 2
python3 exchanger.py [advanced_parameters_2]

# Debug mode
python3 exchanger.py -h -debug
```

## Attack Chain Integration

### [Specific Attack Scenario]
```bash
# Step 1: [First step description]
python3 exchanger.py [step1_parameters]

# Step 2: [Second step description]
python3 [related_tool] [step2_parameters]

# Step 3: [Third step description]
python3 [another_tool] [step3_parameters]
```

### Exchange Server Reconnaissance
```bash
# Step 1: Discover Exchange server and autodiscover service
nslookup autodiscover.target.com

# Step 2: Use exchanger.py to enumerate Exchange via RPC over HTTP
python3 exchanger.py -t RPC_LOOKUP target.com/user:password@mail.target.com

# Step 3: Extract Global Address List information
python3 exchanger.py -t DUMP_GALS target.com/user:password@mail.target.com
```

## Prerequisites
- Valid Exchange mailbox credentials
- Network access to Exchange server (HTTPS port 443)
- Exchange server with RPC over HTTP enabled
- Understanding of Exchange Web Services and MAPI protocols
- Network access to target system
- Appropriate credentials or permissions
- [Specific service/protocol requirements]

## Detection Considerations
- **Event IDs**: Exchange server logs, IIS access logs, authentication events
- **Network Indicators**: HTTPS connections to Exchange /mapi/ endpoint, RPC over HTTP traffic
- **Process Indicators**: Automated Exchange enumeration patterns
- **File Indicators**: No direct file system modifications
- **Registry Indicators**: No registry modifications

## Defensive Measures
- Monitor Exchange server access logs for unusual RPC over HTTP patterns
- Implement multi-factor authentication for Exchange access
- Use Exchange advanced threat protection to detect reconnaissance
- Enable detailed Exchange auditing and monitoring
- Implement rate limiting on Exchange web services

## Common Issues and Troubleshooting

### RPC Hostname Resolution Errors
```bash
# Problem: Cannot resolve RPC server hostname automatically
# Solution: Manually specify RPC hostname from autodiscover service
python3 exchanger.py -t RPC_LOOKUP -rpc-hostname exchange.target.com target.com/user:password@mail.target.com
```

### Authentication Failures
```bash
# Problem: HTTP 401 errors during RPC over HTTP connection
# Solution: Verify credentials and Exchange permissions
python3 exchanger.py -t TEST target.com/user:password@mail.target.com -debug
```

## Related Tools
- [exchanger.py](link.md) - Related functionality
- [secretsdump.py](secretsdump.md) - Often used together
- [psexec.py](psexec.md) - Lateral movement tool
- [GetUserSPNs.py](GetUserSPNs.md) - Credential attacks

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
