# DumpNTLMInfo.py

## Overview
`DumpNTLMInfo.py` is an NTLM authentication information extraction tool in the Impacket suite. This tool is categorized under Information Gathering and provides functionality for dumping remote host information through NTLM authentication challenges without requiring valid credentials.

## Detailed Description
`DumpNTLMInfo.py` performs unauthenticated enumeration of Windows systems by initiating NTLM authentication flows and analyzing the server's responses. The tool extracts valuable system information from NTLM Type 2 (Challenge) messages, including OS version, build number, domain information, server time, and various security settings.

The tool supports multiple protocols (SMB and RPC) and can gather information from negotiate responses that reveal dialect versions, signing requirements, maximum transmission sizes, and boot time information when available. This makes it extremely useful for reconnaissance and system profiling without requiring valid credentials.

### Key Features:
- **Unauthenticated Enumeration**: Extract system information without valid credentials
- **Multi-Protocol Support**: Works with both SMB (1/2/3) and RPC protocols
- **OS Version Detection**: Identify Windows version, build, and service pack information
- **Domain Information**: Extract domain/workgroup names and DNS information
- **Time Synchronization**: Retrieve server time for reconnaissance and attack timing
- **Security Configuration**: Identify signing requirements and security settings
- **Boot Time Detection**: Extract system boot time when available in responses

### Technical Details:
- Initiates NTLM Type 1 (Negotiate) messages to trigger server responses
- Parses NTLM Type 2 (Challenge) messages for embedded system information
- Supports SMB 1.0, 2.0, 2.1, 3.0, 3.02, and 3.11 protocols
- Implements custom SMB negotiation to access low-level response details
- Compatible with RPC endpoint mapper for alternative information gathering

## Command Line Options

```
usage: DumpNTLMInfo.py [-h] [-debug] [-ts] [-target-ip ip address] [-port PORT] 
                       [-protocol {SMB,RPC}] target

Required Arguments:
  target                Target hostname or IP address

Connection Options:
  -target-ip ip address IP address of target machine (if target is NetBIOS name)
  -port PORT            Destination port for SMB/RPC server (default: 445)
  -protocol {SMB,RPC}   Protocol to use (SMB or RPC, auto-detected based on port)

Debug Options:
  -debug                Turn DEBUG output ON
  -ts                   Add timestamp to every logging output
```

## Usage Examples

### Basic SMB Enumeration
```bash
# Enumerate target via SMB (default port 445)
python3 DumpNTLMInfo.py 192.168.1.100

# Enumerate domain controller
python3 DumpNTLMInfo.py dc01.domain.com

# Enumerate with NetBIOS name resolution
python3 DumpNTLMInfo.py SERVER01 -target-ip 192.168.1.100
```

### Alternative Ports and Protocols
```bash
# Enumerate via SMB on alternate port
python3 DumpNTLMInfo.py 192.168.1.100 -port 139

# Enumerate via RPC endpoint mapper
python3 DumpNTLMInfo.py 192.168.1.100 -port 135 -protocol RPC

# Force SMB protocol on RPC port (unusual but possible)
python3 DumpNTLMInfo.py 192.168.1.100 -port 135 -protocol SMB
```

### Network Reconnaissance
```bash
# Survey multiple targets
for ip in 192.168.1.{1..254}; do
    echo "=== $ip ==="
    python3 DumpNTLMInfo.py $ip 2>/dev/null
done

# Domain controller enumeration
python3 DumpNTLMInfo.py dc01.domain.com
python3 DumpNTLMInfo.py dc02.domain.com
python3 DumpNTLMInfo.py dc03.domain.com
```

### Debug and Troubleshooting
```bash
# Enable debug output for detailed analysis
python3 DumpNTLMInfo.py 192.168.1.100 -debug

# Include timestamps for timing analysis
python3 DumpNTLMInfo.py 192.168.1.100 -debug -ts
```

## Example Output Analysis

### Typical SMB Output
```
[+] Domain              : DOMAIN
[+] NetBIOS Domain      : DOMAIN
[+] NetBIOS Computer    : SERVER01
[+] DNS Domain          : domain.local
[+] DNS Computer        : server01.domain.local
[+] DNS Tree            : domain.local
[+] OS                  : Windows NT 10.0 Build 17763
[+] Server Time         : 2023-12-15 14:30:25.123456+00:00
[+] Boot Time           : 2023-12-10 08:15:30.789012+00:00
[+] SMB Version         : 3.1.1
[+] Signing Required    : True
[+] Max Read Size       : 8388608
[+] Max Write Size      : 8388608
[+] Null Session        : False
```

### RPC Output
```
[+] Domain              : DOMAIN
[+] NetBIOS Computer    : SERVER01
[+] OS                  : Windows NT 10.0 Build 17763
[+] Server Time         : 2023-12-15 14:30:25.123456+00:00
[+] Max Transmission    : 5840
```

## Attack Integration

### Reconnaissance Phase
```bash
# Initial target profiling
python3 DumpNTLMInfo.py 192.168.1.100 > target_info.txt

# Extract specific information for targeting
DOMAIN=$(python3 DumpNTLMInfo.py 192.168.1.100 | grep "Domain" | head -1 | cut -d: -f2 | xargs)
OS_BUILD=$(python3 DumpNTLMInfo.py 192.168.1.100 | grep "OS" | cut -d: -f2 | xargs)

echo "Target domain: $DOMAIN"
echo "Target OS: $OS_BUILD"
```

### Time Synchronization Attacks
```bash
# Extract server time for Kerberos attacks
SERVER_TIME=$(python3 DumpNTLMInfo.py dc01.domain.com | grep "Server Time" | cut -d: -f2- | xargs)
echo "DC Time: $SERVER_TIME"

# Use for ticket manipulation timing
# python3 ticketer.py -nthash <hash> -domain domain.com -user admin -spn <spn> -extra-sid <sid>
```

### Domain Enumeration
```bash
# Map domain infrastructure
for dc in dc01 dc02 dc03; do
    echo "=== $dc.domain.com ==="
    python3 DumpNTLMInfo.py $dc.domain.com | grep -E "(Domain|DNS|NetBIOS|OS|Time)"
done

# Identify domain functional level from OS versions
python3 DumpNTLMInfo.py dc01.domain.com | grep "OS"
```

### SMB Version Detection for Exploit Selection
```bash
# Identify SMB version for vulnerability assessment
SMB_VERSION=$(python3 DumpNTLMInfo.py 192.168.1.100 | grep "SMB Version" | cut -d: -f2 | xargs)

case $SMB_VERSION in
    "1.0")
        echo "SMB1 detected - vulnerable to EternalBlue (MS17-010)"
        ;;
    "2.0"|"2.1")
        echo "SMB2 detected - check for SMB2 vulnerabilities"
        ;;
    "3.0"|"3.02"|"3.1.1")
        echo "SMB3 detected - modern protocol, limited exploit options"
        ;;
esac
```

### Null Session Testing
```bash
# Check if null sessions are allowed
NULL_SESSION=$(python3 DumpNTLMInfo.py 192.168.1.100 | grep "Null Session" | cut -d: -f2 | xargs)

if [ "$NULL_SESSION" = "True" ]; then
    echo "Null sessions allowed - attempting enumeration"
    python3 samrdump.py 192.168.1.100
    python3 lookupsid.py 192.168.1.100
fi
```

## Security Implications

### Information Disclosure
- **OS Fingerprinting**: Precise Windows version and build identification
- **Domain Structure**: Full domain naming and hierarchy information
- **Time Information**: Server and boot times for attack timing
- **SMB Capabilities**: Protocol versions and security configurations
- **Network Architecture**: Domain controller and server roles

### Attack Preparation
1. **Exploit Selection**: Choose exploits based on OS version and SMB protocol
2. **Credential Attacks**: Use domain information for targeted attacks
3. **Time-based Attacks**: Synchronize Kerberos and time-sensitive exploits
4. **Protocol Downgrade**: Identify older SMB versions for exploitation

### Defensive Considerations
```bash
# Disable SMB1 to prevent information disclosure
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Configure SMB signing requirements
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# Disable NetBIOS over TCP/IP to reduce exposure
netsh interface ipv4 set global taskoffload=disabled
```

## Troubleshooting

### Common Issues
1. **Connection Refused**: Target port not accessible or service not running
2. **Timeout Errors**: Network connectivity issues or firewall blocking
3. **Protocol Errors**: Incompatible SMB/RPC versions or configurations
4. **Empty Responses**: Modern systems with restricted information disclosure

### Network Connectivity Testing
```bash
# Test SMB connectivity
telnet 192.168.1.100 445
nmap -p 445 192.168.1.100

# Test RPC connectivity
telnet 192.168.1.100 135
nmap -p 135 192.168.1.100

# Test with different protocols
python3 DumpNTLMInfo.py 192.168.1.100 -protocol SMB -debug
python3 DumpNTLMInfo.py 192.168.1.100 -protocol RPC -debug
```

### Firewall and Security Bypass
```bash
# Try different ports if standard ports are blocked
python3 DumpNTLMInfo.py 192.168.1.100 -port 139  # NetBIOS SMB
python3 DumpNTLMInfo.py 192.168.1.100 -port 135  # RPC Endpoint Mapper

# Test through proxy or tunnel if direct access blocked
ssh -L 445:192.168.1.100:445 user@jumphost
python3 DumpNTLMInfo.py localhost
```

## Related Tools
- **enum4linux**: Linux SMB enumeration tool
- **smbclient.py**: SMB client for file access and enumeration
- **rpcdump.py**: RPC endpoint enumeration
- **samrdump.py**: SAM database enumeration
- **lookupsid.py**: SID enumeration and user discovery
- **nbtscan**: NetBIOS name scanning

## Technical References
- [MS-SMB: Server Message Block Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/)
- [MS-SMB2: Server Message Block Protocol v2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [MS-NLMP: NT LAN Manager Authentication Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [NTLM Authentication Process](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)

# Using hash authentication
python3 DumpNTLMInfo.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Extract NTLM info from multiple targets
for target in $(cat dc_list.txt); do
    echo "=== $target ==="
    python3 DumpNTLMInfo.py "$target"
done

# Use with specific authentication
python3 DumpNTLMInfo.py -hashes :ntlmhash domain.com/user@192.168.1.100

# Extract and save to file for analysis
python3 DumpNTLMInfo.py 192.168.1.100 > ntlm_info_analysis.txt
```

## Attack Chain Integration

### Domain Reconnaissance Phase
```bash
# Step 1: Identify domain controllers
nmap -p 445 --script smb-os-discovery 192.168.1.0/24

# Step 2: Extract NTLM configuration from each DC
python3 DumpNTLMInfo.py 192.168.1.10

# Step 3: Analyze authentication policies for attack vectors
python3 GetUserSPNs.py domain.com/user:pass -dc-ip 192.168.1.10
```

### Pre-attack Environment Analysis
```bash
# Step 1: Gather NTLM authentication information
python3 DumpNTLMInfo.py target.domain.com

# Step 2: Use information to configure relay attacks
python3 ntlmrelayx.py -t smb://192.168.1.100 -smb2support
```

## Prerequisites
- Network access to target system on SMB ports (445, 139) or RPC port (135)
- No authentication required (anonymous enumeration)
- Python 3.x with Impacket library installed
- Target must support NTLM authentication

## Detection Considerations
- **Event IDs**: 
  - Event ID 4624 (Anonymous logon)
  - Event ID 5156 (Windows Filtering Platform connection)
  - Event ID 4648 (Authentication attempts)
- **Network Indicators**: 
  - Connections to ports 135, 139, 445
  - SMB negotiate requests without authentication
  - RPC endpoint mapper queries
- **Process Indicators**: 
  - SMB server processes handling negotiate requests
  - RPC endpoint mapper service activity
- **File Indicators**: 
  - No file modifications (passive information gathering)
- **Registry Indicators**: 
  - No registry modifications

## Defensive Measures
- Monitor anonymous SMB and RPC connections
- Implement network access controls to restrict SMB/RPC access
- Enable SMB signing requirements to prevent downgrade attacks
- Use network intrusion detection systems to monitor reconnaissance
- Regular security assessments to identify information disclosure
- Disable unnecessary SMB/RPC services where possible

## Common Issues and Troubleshooting

### Connection Timeout or Refused
```bash
# Problem: Cannot connect to target SMB/RPC services
# Solution: Verify services are running and accessible
nmap -p 135,139,445 target_ip
python3 DumpNTLMInfo.py target_ip
```

### Incomplete Information Returned
```bash
# Problem: Some NTLM information is missing from response
# Solution: Try different protocols (SMB1, SMB2, RPC)
# Some servers may not provide all information in negotiate response
```

## Related Tools
- [ntlmrelayx.py](ntlmrelayx.md) - NTLM relay attacks using gathered info
- [smbclient.py](smbclient.md) - SMB client for further enumeration
- [rpcdump.py](rpcdump.md) - RPC endpoint enumeration
- [enum4linux.py](enum4linux.md) - Comprehensive SMB enumeration

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
