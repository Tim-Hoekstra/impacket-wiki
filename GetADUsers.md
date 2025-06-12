# GetADUsers.py

## Overview
`GetADUsers.py` gathers comprehensive data about Active Directory domain users and their corresponding email addresses. It provides detailed information about user accounts including logon history, password attributes, and account status.

## Detailed Description
This script performs LDAP queries against Active Directory to enumerate domain users and extract valuable information such as email addresses, last logon times, and password set dates. It's particularly useful for reconnaissance during penetration testing to identify valid user accounts and gather intelligence about the domain environment. The tool can display customizable attributes and filter results based on various criteria.Users.py

## Overview
`GetADUsers.py` is a active directory enumeration tool in the Impacket suite. This script will gather data about the domain's users and their corresponding email addresses. It will also

## Detailed Description
This script will gather data about the domain's users and their corresponding email addresses. It will also

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
GetADUsers.py [options] target
```

Traceback (most recent call last):
  File "/home/tim/impacket/examples/GetADUsers.py", line 38, in <module>
    from impacket.examples.utils import parse_identity, ldap_login
ImportError: cannot import name 'parse_identity' from 'impacket.examples.utils' (/home/tim/.local/lib/python3.12/site-packages/impacket/examples/utils.py)


## Usage Examples

### Basic Usage
```bash
# Basic command execution
python3 GetADUsers.py [basic_parameters]

# With authentication
python3 GetADUsers.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 GetADUsers.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 GetADUsers.py [advanced_parameters]

# Advanced example 2
python3 GetADUsers.py [advanced_parameters_2]

# Debug mode
python3 GetADUsers.py DOMAIN/user:password@dc-ip -debug
```

## Attack Chain Integration

### [Specific Attack Scenario]
```bash
# Step 1: [First step description]
python3 GetADUsers.py [step1_parameters]

# Step 2: [Second step description]
python3 [related_tool] [step2_parameters]

# Step 3: [Third step description]
python3 [another_tool] [step3_parameters]
```

### User Enumeration for Targeted Attacks
```bash
# Step 1: Perform initial domain reconnaissance
python3 GetADUsers.py DOMAIN/user:password@dc-ip

# Step 2: Get detailed user information including disabled accounts
python3 GetADUsers.py DOMAIN/user:password@dc-ip -all

# Step 3: Target specific users for further attacks
python3 GetUserSPNs.py DOMAIN/user:password -dc-ip dc-ip -request
```

## Prerequisites
- Valid domain credentials (username/password or hash)
- Network access to domain controller (typically port 389/636 for LDAP)
- Domain controller IP address or FQDN
- Basic understanding of Active Directory structure

## Detection Considerations
- **Event IDs**: 4624 (Logon), 4625 (Failed logon), 4648 (Explicit credentials), 4776 (NTLM authentication)
- **Network Indicators**: LDAP queries to domain controllers (ports 389/636)
- **Process Indicators**: Unusual LDAP search patterns or high-frequency queries
- **File Indicators**: Large result files containing user enumeration data
- **Registry Indicators**: No specific registry modifications

## Defensive Measures
- Monitor LDAP query patterns for unusual enumeration activity
- Implement query rate limiting on domain controllers
- Use advanced threat protection solutions to detect reconnaissance activities
- Enable detailed LDAP auditing on domain controllers
- Monitor for bulk user enumeration from single source IPs

## Common Issues and Troubleshooting

### LDAP Connection Failures
```bash
# Problem: Cannot connect to domain controller
# Solution: Verify DC IP and ensure LDAP ports are accessible
python3 GetADUsers.py DOMAIN/user:password -dc-ip DC_IP -debug
```

### Authentication Errors
```bash
# Problem: Invalid credentials or Kerberos issues
# Solution: Use hash authentication or verify domain name format
python3 GetADUsers.py DOMAIN/user -hashes :NTHASH -dc-ip DC_IP
```

## Related Tools
- [GetADUsers.py](link.md) - Related functionality
- [secretsdump.py](secretsdump.md) - Often used together
- [psexec.py](psexec.md) - Lateral movement tool
- [GetUserSPNs.py](GetUserSPNs.md) - Credential attacks

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
