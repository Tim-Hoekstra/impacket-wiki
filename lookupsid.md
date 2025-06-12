# lookupsid.py

## Overview
`lookupsid.py` performs SID lookups and enumeration to discover user accounts, groups, and computer accounts in Active Directory.

## Detailed Description
This tool enumerates Security Identifiers (SIDs) to discover domain objects including users, groups, and computers. It is valuable for reconnaissance as it can reveal the domain structure and identify potential targets.

### Key Features:
- **SID-to-name resolution**: Core functionality
- **User and group enumeration**: Core functionality
- **Computer account discovery**: Core functionality
- **Domain structure reconnaissance**: Core functionality
- **RID cycling attacks**: Core functionality
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication
- **Cross-Platform Compatibility**: Works with various Windows versions

### Technical Details:
- Uses [specific protocol/technique]
- Leverages [specific Windows API/service]
- Implements [specific attack technique]
- Compatible with [specific versions/systems]

## Command Line Options

```
usage: lookupsid.py [-h] [options] target

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
python3 lookupsid.py [basic_parameters]

# With authentication
python3 lookupsid.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 lookupsid.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 lookupsid.py [advanced_parameters]

# Advanced example 2
python3 lookupsid.py [advanced_parameters_2]

# Debug mode
python3 lookupsid.py DOMAIN/user:password@target -debug
```

## Attack Chain Integration

### [Specific Attack Scenario]
```bash
# Step 1: [First step description]
python3 lookupsid.py [step1_parameters]

# Step 2: [Second step description]
python3 [related_tool] [step2_parameters]

# Step 3: [Third step description]
python3 [another_tool] [step3_parameters]
```

### Domain SID Enumeration and User Discovery
```bash
# Step 1: Perform initial domain reconnaissance
python3 GetADUsers.py DOMAIN/user:password@dc-ip

# Step 2: Use lookupsid.py to enumerate domain SIDs and users
python3 lookupsid.py DOMAIN/user:password@target

# Step 3: Use discovered information for further attacks
python3 GetUserSPNs.py DOMAIN/user:password -dc-ip dc-ip -request
```

## Prerequisites
- Valid domain credentials or authenticated SMB access
- Network access to target system (SMB port 445)
- Understanding of Windows SID structure and enumeration
- Basic knowledge of domain user and group relationships
- Network access to target system
- Appropriate credentials or permissions
- [Specific service/protocol requirements]

## Detection Considerations
- **Event IDs**: Relevant Windows Event IDs
- **Network Indicators**: Unusual network traffic patterns
- **Process Indicators**: Suspicious process activity
- **File Indicators**: Temporary files or modifications
- **Registry Indicators**: Registry modifications

## Defensive Measures
- Restrict anonymous access to SID enumeration
- Monitor for bulk SID lookup activities in security logs
- Implement network monitoring to detect reconnaissance patterns
- Use endpoint detection and response (EDR) tools
- Enable detailed auditing for account enumeration events

## Common Issues and Troubleshooting

### Access Denied Errors
```bash
# Problem: Insufficient privileges to enumerate SIDs
# Solution: Ensure valid credentials with appropriate permissions
python3 lookupsid.py DOMAIN/user:password@target -debug
```

### Connection Failures
```bash
# Problem: Cannot connect to target RPC services
# Solution: Verify network connectivity and SMB service availability
python3 lookupsid.py DOMAIN/user:password@target -port 139
```

## Related Tools
- [lookupsid.py](link.md) - Related functionality
- [secretsdump.py](secretsdump.md) - Often used together
- [psexec.py](psexec.md) - Lateral movement tool
- [GetUserSPNs.py](GetUserSPNs.md) - Credential attacks

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
