# samrdump.py

## Overview
`samrdump.py` dumps user information from the Security Account Manager (SAM) database via RPC calls.

## Detailed Description
This tool extracts user account information from the SAM database using RPC calls to the SAMR interface. It provides details about local user accounts, groups, and their properties without requiring direct database access.

### Key Features:
- **SAM database enumeration**: Core functionality
- **User account information**: Core functionality
- **Group membership details**: Core functionality
- **Account status and properties**: Core functionality
- **Password policy information**: Core functionality
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication
- **Cross-Platform Compatibility**: Works with various Windows versions

### Technical Details:
- Uses [specific protocol/technique]
- Leverages [specific Windows API/service]
- Implements [specific attack technique]
- Compatible with [specific versions/systems]

## Command Line Options

```
usage: samrdump.py [-h] [options] target

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
python3 samrdump.py [basic_parameters]

# With authentication
python3 samrdump.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 samrdump.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 samrdump.py [advanced_parameters]

# Advanced example 2
python3 samrdump.py [advanced_parameters_2]

# Debug mode
python3 samrdump.py DOMAIN/user:password@target -debug
```

## Attack Chain Integration

### [Specific Attack Scenario]
```bash
# Step 1: [First step description]
python3 samrdump.py [step1_parameters]

# Step 2: [Second step description]
python3 [related_tool] [step2_parameters]

# Step 3: [Third step description]
python3 [another_tool] [step3_parameters]
```

### [Another Attack Scenario]
```bash
# Step 1: Enumerate users via SMB for reconnaissance
python3 samrdump.py DOMAIN/user:password@target

# Step 2: Use samrdump.py to extract user information
python3 samrdump.py DOMAIN/user:password@target -csv

# Step 3: Use collected information for further attacks
python3 GetUserSPNs.py DOMAIN/user:password -dc-ip target -request
```

## Prerequisites
- Valid domain credentials or authenticated SMB access
- Network access to target system (SMB port 445)
- SAMR (Security Account Manager Remote) protocol access
- Basic understanding of Windows user account structure

## Detection Considerations
- **Event IDs**: 4624 (Logon), 4625 (Failed logon), 4634 (Logoff), 4648 (Explicit credentials)
- **Network Indicators**: SMB connections (port 445), DCE/RPC SAMR calls
- **Process Indicators**: Enumeration of user accounts via SAMR protocol
- **File Indicators**: CSV output files containing user information
- **Registry Indicators**: No direct registry modifications

## Defensive Measures
- Monitor SAMR protocol usage and user enumeration activities
- Implement SMB signing and encryption to secure communications
- Use endpoint detection and response (EDR) tools to detect reconnaissance
- Restrict anonymous access to SAM database
- Enable advanced auditing for account enumeration events

## Common Issues and Troubleshooting

### Access Denied Errors
```bash
# Problem: Insufficient privileges to access SAMR
# Solution: Ensure valid credentials with appropriate permissions
python3 samrdump.py DOMAIN/user:password@target -debug
```

### Connection Failures
```bash
# Problem: Cannot connect to target SMB service
# Solution: Verify network connectivity and SMB service availability
python3 samrdump.py DOMAIN/user:password@target -port 139
```

## Related Tools
- [samrdump.py](link.md) - Related functionality
- [secretsdump.py](secretsdump.md) - Often used together
- [psexec.py](psexec.md) - Lateral movement tool
- [GetUserSPNs.py](GetUserSPNs.md) - Credential attacks

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
