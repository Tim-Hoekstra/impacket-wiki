# GetADComputers.py

## Overview
`GetADComputers.py` is a active directory enumeration tool in the Impacket suite. This script  is inspired from Alberto Solino's -> imacket-GetAdUsers.

## Detailed Description
This script  is inspired from Alberto Solino's -> imacket-GetAdUsers.

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
GetADComputers.py [options] target
```

Traceback (most recent call last):
  File "/home/tim/impacket/examples/GetADComputers.py", line 41, in <module>
    from impacket.examples.utils import parse_identity, ldap_login
ImportError: cannot import name 'parse_identity' from 'impacket.examples.utils' (/home/tim/.local/lib/python3.12/site-packages/impacket/examples/utils.py)


## Usage Examples

### Basic Usage
```bash
# Basic command execution
python3 GetADComputers.py [basic_parameters]

# With authentication
python3 GetADComputers.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 GetADComputers.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 GetADComputers.py [advanced_parameters]

# Advanced example 2
python3 GetADComputers.py [advanced_parameters_2]

# Debug mode
python3 GetADComputers.py DOMAIN/user:password@dc-ip -debug
```

## Attack Chain Integration

### [Specific Attack Scenario]
```bash
# Step 1: [First step description]
python3 GetADComputers.py [step1_parameters]

# Step 2: [Second step description]
python3 [related_tool] [step2_parameters]

# Step 3: [Third step description]
python3 [another_tool] [step3_parameters]
```

### [Another Attack Scenario]
```bash
# Step 1: Enumerate domain computers for reconnaissance
python3 GetADComputers.py DOMAIN/user:password@dc-ip

# Step 2: Get computers with IP resolution for network mapping
python3 GetADComputers.py DOMAIN/user:password@dc-ip -resolve

# Step 3: Target specific computers for lateral movement
python3 smbclient.py DOMAIN/user:password@target-computer
```

## Prerequisites
- Valid domain credentials (username/password or hash)
- Network access to domain controller (LDAP port 389/636)
- DNS resolution access if using -resolve option
- Basic understanding of Active Directory computer objects

## Detection Considerations
- **Event IDs**: 4624 (Logon), 4625 (Failed logon), 4648 (Explicit credentials)
- **Network Indicators**: LDAP queries to domain controllers, DNS resolution requests
- **Process Indicators**: Bulk computer enumeration patterns
- **File Indicators**: Output files containing computer lists and IP addresses
- **Registry Indicators**: No specific registry modifications

## Defensive Measures
- Monitor LDAP queries for computer object enumeration patterns
- Implement rate limiting on LDAP queries to domain controllers
- Use network monitoring to detect reconnaissance activities
- Enable detailed LDAP auditing on domain controllers
- Monitor DNS query patterns for bulk resolution activities

## Common Issues and Troubleshooting

### DNS Resolution Failures
```bash
# Problem: Cannot resolve computer IP addresses
# Solution: Ensure DNS access or use without -resolve option
python3 GetADComputers.py DOMAIN/user:password@dc-ip
```

### LDAP Authentication Issues
```bash
# Problem: Authentication failures to domain controller
# Solution: Verify credentials and use hash authentication if needed
python3 GetADComputers.py DOMAIN/user -hashes :NTHASH@dc-ip
```

## Related Tools
- [GetADComputers.py](link.md) - Related functionality
- [secretsdump.py](secretsdump.md) - Often used together
- [psexec.py](psexec.md) - Lateral movement tool
- [GetUserSPNs.py](GetUserSPNs.md) - Credential attacks

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
