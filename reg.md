# reg.py

## Overview
`reg.py` provides remote Windows registry access and manipulation capabilities for configuration changes and information gathering.

## Detailed Description
This tool allows remote registry operations on Windows systems, enabling reading, writing, and modification of registry keys and values. It is essential for persistence, privilege escalation, and system configuration manipulation.

### Key Features:
- **Remote registry access**: Core functionality
- **Key and value enumeration**: Core functionality
- **Registry modification capabilities**: Core functionality
- **Backup and restore functions**: Core functionality
- **Security descriptor access**: Core functionality
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication
- **Cross-Platform Compatibility**: Works with various Windows versions

### Technical Details:
- Uses [specific protocol/technique]
- Leverages [specific Windows API/service]
- Implements [specific attack technique]
- Compatible with [specific versions/systems]

## Command Line Options

```
usage: reg.py [-h] [options] target

Required Arguments:
  target                [Description of target parameter]

Optional Arguments:
  -h, --help            Show help message
  [Add specific options based on tool functionality]

Authentication:
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password
  -k                    Use Kerberos authentication
  -aesKey               AES key for Kerberos authentication
  -dc-ip                Domain controller IP address
```

## Usage Examples

### Basic Usage
```bash
# Basic command execution
python3 reg.py [basic_parameters]

# With authentication
python3 reg.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 reg.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 reg.py [advanced_parameters]

# Advanced example 2
python3 reg.py [advanced_parameters_2]

# Debug mode
python3 reg.py DOMAIN/user:password@target query -keyName "HKLM\\SOFTWARE" -debug
```

## Attack Chain Integration

### [Specific Attack Scenario]
```bash
# Step 1: [First step description]
python3 reg.py [step1_parameters]

# Step 2: [Second step description]
python3 [related_tool] [step2_parameters]

# Step 3: [Third step description]
python3 [another_tool] [step3_parameters]
```

### Remote Registry Operations
```bash
# Step 1: Enumerate registry keys for reconnaissance
python3 reg.py DOMAIN/user:password@target query -keyName "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"

# Step 2: Use reg.py to query specific registry values
python3 reg.py DOMAIN/user:password@target query -keyName "HKLM\\SYSTEM\\CurrentControlSet\\Services"

# Step 3: Modify registry for persistence
python3 reg.py DOMAIN/user:password@target add -keyName "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -v "Updater" -vt REG_SZ -vd "C:\\temp\\malware.exe"
```

## Prerequisites
- Valid domain credentials with administrative privileges
- Network access to target system (RPC port 135)
- Remote Registry service enabled on target
- Understanding of Windows registry structure
- Network access to target system
- Appropriate credentials or permissions
- [Specific service/protocol requirements]

## Detection Considerations
- **Event IDs**: Relevant Windows Event IDs
- **Network Indicators**: Unusual network traffic patterns
- **Process Indicators**: Suspicious process activity
- **File Indicators**: Temporary files or modifications
- **Registry Indicators**: Registry modifications

## Defensive Measures
- Disable Remote Registry service if not required
- Monitor registry access and modifications in audit logs
- Implement endpoint detection and response (EDR) tools
- Use registry monitoring tools to detect unauthorized changes
- Restrict administrative privileges and monitor privileged access

## Common Issues and Troubleshooting

### Remote Registry Service Disabled
```bash
# Problem: Cannot connect to remote registry service
# Solution: Verify Remote Registry service is running on target
sc \\target query RemoteRegistry
python3 reg.py DOMAIN/user:password@target query -keyName "HKLM" -debug
```

### Access Denied Errors
```bash
# Problem: Insufficient privileges for registry operations
# Solution: Ensure account has administrative rights
python3 reg.py DOMAIN/administrator:password@target query -keyName "HKLM\\SAM"
```

## Related Tools
- [reg.py](link.md) - Related functionality
- [secretsdump.py](secretsdump.md) - Often used together
- [psexec.py](psexec.md) - Lateral movement tool
- [GetUserSPNs.py](GetUserSPNs.md) - Credential attacks

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
