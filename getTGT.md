# getTGT.py

## Overview
`getTGT.py` is a kerberos authentication tool in the Impacket suite. Given a password, hash or aesKey, it will request a TGT and save it as ccache

## Detailed Description
Given a password, hash or aesKey, it will request a TGT and save it as ccache

### Key Features:
- **TGT requests from KDC**: Core functionality
- **Password and hash authentication**: Core functionality
- **AES key support**: Core functionality
- **ccache output format**: Core functionality
- **PKINIT support for certificate authentication**: Core functionality
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication
- **Cross-Platform Compatibility**: Works with various Windows versions

### Technical Details:
- Uses [specific protocol/technique]
- Leverages [specific Windows API/service]
- Implements [specific attack technique]
- Compatible with [specific versions/systems]

## Command Line Options

```
getTGT.py [options] target
```

Traceback (most recent call last):
  File "/home/tim/impacket/examples/getTGT.py", line 31, in <module>
    from impacket.examples.utils import parse_identity
ImportError: cannot import name 'parse_identity' from 'impacket.examples.utils' (/home/tim/.local/lib/python3.12/site-packages/impacket/examples/utils.py)


## Usage Examples

### Basic Usage
```bash
# Basic command execution
python3 getTGT.py [basic_parameters]

# With authentication
python3 getTGT.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 getTGT.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 getTGT.py [advanced_parameters]

# Advanced example 2
python3 getTGT.py [advanced_parameters_2]

# Debug mode
python3 getTGT.py DOMAIN/user:password -dc-ip dc-ip -debug
```

## Attack Chain Integration

### [Specific Attack Scenario]
```bash
# Step 1: [First step description]
python3 getTGT.py [step1_parameters]

# Step 2: [Second step description]
python3 [related_tool] [step2_parameters]

# Step 3: [Third step description]
python3 [another_tool] [step3_parameters]
```

### Kerberos Ticket Granting Ticket Acquisition
```bash
# Step 1: Obtain TGT using credentials
python3 getTGT.py DOMAIN/user:password -dc-ip dc-ip

# Step 2: Use getTGT.py with hash for pass-the-hash attack
python3 getTGT.py DOMAIN/user -hashes :NTHASH -dc-ip dc-ip

# Step 3: Use the TGT for further Kerberos attacks
export KRB5CCNAME=user.ccache
python3 getST.py DOMAIN/user -spn service/target -k -no-pass
```

## Prerequisites
- Valid domain credentials (password, hash, or AES key)
- Network access to domain controller (Kerberos port 88)
- Domain controller IP address or FQDN
- Basic understanding of Kerberos authentication protocol

## Detection Considerations
- **Event IDs**: 4768 (Kerberos TGT requested), 4771 (Kerberos pre-authentication failed), 4625 (Failed logon)
- **Network Indicators**: Kerberos authentication traffic to domain controllers (port 88)
- **Process Indicators**: TGT requests from unusual sources or with suspicious timing
- **File Indicators**: .ccache files containing Kerberos tickets
- **Registry Indicators**: No direct registry modifications

## Defensive Measures
- Monitor for unusual TGT request patterns and failed authentication attempts
- Implement Kerberos Armoring (FAST) to protect against offline attacks
- Use advanced threat protection to detect pass-the-hash attacks
- Enable detailed Kerberos logging on domain controllers
- Implement time-based access controls and monitor for off-hours authentication

## Common Issues and Troubleshooting

### Clock Skew Errors
```bash
# Problem: Kerberos time synchronization issues
# Solution: Ensure client and server clocks are synchronized
ntpdate -s dc-ip && python3 getTGT.py DOMAIN/user:password -dc-ip dc-ip
```

### Pre-authentication Failures
```bash
# Problem: Invalid credentials or account lockout
# Solution: Verify credentials and account status
python3 getTGT.py DOMAIN/user:password -dc-ip dc-ip -debug
```

## Related Tools

## Related Tools
- [getTGT.py](link.md) - Related functionality
- [secretsdump.py](secretsdump.md) - Often used together
- [psexec.py](psexec.md) - Lateral movement tool
- [GetUserSPNs.py](GetUserSPNs.md) - Credential attacks

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
