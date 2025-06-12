# getST.py

## Overview
`getST.py` is a kerberos authentication tool in the Impacket suite. Given a password, hash, aesKey or TGT in ccache, it will request a Service Ticket and save it as ccache

## Detailed Description
Given a password, hash, aesKey or TGT in ccache, it will request a Service Ticket and save it as ccache

### Key Features:
- **Service ticket (TGS) requests for any SPN**: Core functionality
- **S4U2Self and S4U2Proxy delegation support**: Core functionality
- **Impersonation capabilities**: Core functionality
- **Multiple authentication methods**: Core functionality
- **ccache file output for ticket reuse**: Core functionality
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication
- **Cross-Platform Compatibility**: Works with various Windows versions

### Technical Details:
- Uses [specific protocol/technique]
- Leverages [specific Windows API/service]
- Implements [specific attack technique]
- Compatible with [specific versions/systems]

## Command Line Options

```
getST.py [options] target
```

Traceback (most recent call last):
  File "/home/tim/impacket/examples/getST.py", line 63, in <module>
    from impacket.examples.utils import parse_identity
ImportError: cannot import name 'parse_identity' from 'impacket.examples.utils' (/home/tim/.local/lib/python3.12/site-packages/impacket/examples/utils.py)


## Usage Examples

### Basic Usage
```bash
# Basic command execution
python3 getST.py [basic_parameters]

# With authentication
python3 getST.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 getST.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 getST.py [advanced_parameters]

# Advanced example 2
python3 getST.py [advanced_parameters_2]

# Debug mode
python3 getST.py DOMAIN/user:password -spn service/target -debug
```

## Attack Chain Integration

### [Specific Attack Scenario]
```bash
# Step 1: [First step description]
python3 getST.py [step1_parameters]

# Step 2: [Second step description]
python3 [related_tool] [step2_parameters]

# Step 3: [Third step description]
python3 [another_tool] [step3_parameters]
```

### Kerberos Service Ticket Attacks
```bash
# Step 1: Get TGT for user with delegation privileges
python3 getTGT.py DOMAIN/user:password -dc-ip dc-ip

# Step 2: Use getST.py to request service ticket with impersonation
python3 getST.py DOMAIN/user:password -spn cifs/target.domain.com -impersonate Administrator

# Step 3: Use the obtained service ticket for access
export KRB5CCNAME=Administrator.ccache
python3 smbclient.py target.domain.com -k -no-pass
```

## Prerequisites
- Valid domain credentials for user with constrained delegation privileges
- Network access to domain controller (Kerberos ports 88/464)
- Target Service Principal Name (SPN) configured for delegation
- Understanding of Kerberos S4U2Self and S4U2Proxy attacks

## Detection Considerations
- **Event IDs**: 4769 (Kerberos service ticket requested), 4768 (Kerberos TGT requested), 4624/4625 (Logon events)
- **Network Indicators**: Kerberos traffic to domain controllers (port 88), unusual S4U requests
- **Process Indicators**: Service ticket requests with impersonation flags
- **File Indicators**: .ccache files containing Kerberos tickets
- **Registry Indicators**: No direct registry modifications

## Defensive Measures
- Monitor for S4U2Self and S4U2Proxy requests in Kerberos logs
- Audit constrained delegation configurations and limit delegation privileges
- Implement advanced threat protection to detect abnormal Kerberos patterns
- Use Kerberos Armoring (FAST) to protect against ticket manipulation
- Regular review of service accounts with delegation privileges

## Common Issues and Troubleshooting

### Delegation Permission Errors
```bash
# Problem: KDC_ERR_S_PRINCIPAL_UNKNOWN or KDC_ERR_BADOPTION
# Solution: Verify user has constrained delegation permissions
python3 getST.py DOMAIN/user:password -spn service/target -impersonate user -debug
```

### SPN Not Found Errors
```bash
# Problem: Service Principal Name not found in Active Directory
# Solution: Verify SPN exists and is properly configured
setspn -Q service/target.domain.com
```

## Related Tools

## Related Tools
- [getST.py](link.md) - Related functionality
- [secretsdump.py](secretsdump.md) - Often used together
- [psexec.py](psexec.md) - Lateral movement tool
- [GetUserSPNs.py](GetUserSPNs.md) - Credential attacks

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
