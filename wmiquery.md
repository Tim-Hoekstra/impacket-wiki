# wmiquery.py

## Overview
`wmiquery.py` is a wmi query execution tool in the Impacket suite. This tool is categorized under System Information and provides functionality for [specific use case].

## Detailed Description
# wmiquery.py

## Overview
`wmiquery.py` is a WMI query execution tool in the Impacket suite. This tool is categorized under Information Gathering and provides functionality for executing WQL (WMI Query Language) queries against remote Windows systems through WMI.

## Detailed Description
`wmiquery.py` enables remote execution of WMI queries using DCOM connections to gather system information, enumerate processes, services, users, and other Windows management data. The tool supports authenticated WMI access and can execute complex WQL queries for comprehensive system reconnaissance.

### Key Features:
- **Feature 1**: Description of primary feature
- **Feature 2**: Description of secondary feature
- **Feature 3**: Description of additional feature
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication
- **Cross-Platform Compatibility**: Works with various Windows versions

### Technical Details:
- Uses [specific protocol/technique]
- Leverages [specific Windows API/service]
- Implements [specific attack technique]
- Compatible with [specific versions/systems]

## Command Line Options

```
usage: wmiquery.py [-h] [options] target

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
python3 wmiquery.py [basic_parameters]

# With authentication
python3 wmiquery.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 wmiquery.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Execute specific WQL queries for system information
python3 wmiquery.py -query "SELECT * FROM Win32_Process WHERE Name='svchost.exe'" domain.com/user:pass@target

# Query installed software for vulnerability assessment
python3 wmiquery.py -query "SELECT * FROM Win32_Product" domain.com/user:pass@target

# Monitor system events and logs
python3 wmiquery.py -query "SELECT * FROM Win32_NTLogEvent WHERE Logfile='System'" domain.com/user:pass@target
```

## Attack Chain Integration

### System Reconnaissance via WMI
```bash
# Step 1: Gather system information
python3 wmiquery.py -query "SELECT * FROM Win32_OperatingSystem" domain/user:pass@target

# Step 2: Enumerate running processes
python3 wmiquery.py -query "SELECT * FROM Win32_Process" domain/user:pass@target

# Step 3: Identify security software
python3 wmiquery.py -query "SELECT * FROM Win32_Product WHERE Name LIKE '%antivirus%'" domain/user:pass@target
```

### Post-compromise Information Gathering
```bash
# Step 1: Establish WMI access
python3 wmiexec.py domain/user:pass@target

# Step 2: Query for sensitive information
python3 wmiquery.py -query "SELECT * FROM Win32_UserAccount" domain/user:pass@target

## Prerequisites
- Administrative credentials on target system
- Network access to target on WMI ports (135, random high ports)
- Python 3.x with Impacket installed
- Windows target system with WMI service enabled

## Detection Considerations
- **Event IDs**: 
  - Event ID 4624/4625 (Authentication events)
  - Event ID 5857-5861 (WMI Activity)
  - Event ID 4688 (Process creation for WMI queries)
- **Network Indicators**: 
  - Connections to port 135 (RPC endpoint mapper)
  - WMI DCOM traffic on random high ports
  - Multiple WQL query requests
- **Process Indicators**: 
  - WMI provider processes (wmiprvse.exe)
  - Python processes making WMI calls
  - Unusual WMI service activity
- **File Indicators**: 
  - WMI repository access
  - Query result files if output is saved
- **Registry Indicators**: 
  - WMI service registry access

## Defensive Measures
- Enable WMI Activity logging (Event IDs 5857-5861)
- Monitor and restrict WMI access permissions
- Implement application whitelisting for WMI consumers
- Network segmentation to limit WMI access
- Regular auditing of WMI namespace permissions
- Use Windows Firewall to restrict WMI ports

## Common Issues and Troubleshooting

### WMI Access Denied
```bash
# Problem: Insufficient privileges for WMI operations
# Solution: Verify account has administrative privileges
# Check WMI namespace permissions
python3 wmiexec.py domain/admin:pass@target "whoami /groups"
```

### Invalid WQL Syntax
```bash
# Problem: WQL query syntax errors
# Solution: Verify WQL syntax and available classes
# Test query syntax before running
wbemtest.exe  # Use on Windows to test queries locally
```

## Related Tools
- [wmiexec.py](wmiexec.md) - WMI command execution
- [wmipersist.py](wmipersist.md) - WMI persistence mechanisms
- [psexec.py](psexec.md) - Alternative remote execution
- [services.py](services.md) - Windows service queries

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
