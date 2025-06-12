#!/usr/bin/env python3
"""
Impacket Wiki Generator
Generates documentation for remaining Impacket examples
"""

import os
import sys

# Define the remaining tools to document
REMAINING_TOOLS = [
    # Authentication & Credential Attacks
    ("changepasswd.py", "Change user passwords", "Password Management"),
    ("getST.py", "Service ticket requests", "Kerberos Authentication"),
    ("getTGT.py", "Ticket granting ticket requests", "Kerberos Authentication"),
    ("goldenPac.py", "Golden PAC attack", "Privilege Escalation"),
    ("keylistattack.py", "KeyList attack", "Credential Extraction"),
    ("ticketer.py", "Golden/Silver ticket creation", "Kerberos Attacks"),
    ("ticketConverter.py", "Convert ticket formats", "Kerberos Utilities"),
    
    # Credential Dumping & Extraction
    ("DumpNTLMInfo.py", "Dump NTLM authentication info", "Information Gathering"),
    ("mimikatz.py", "Mimikatz-like functionality", "Credential Extraction"),
    ("dpapi.py", "DPAPI blob decryption", "Credential Extraction"),
    ("regsecrets.py", "Extract secrets from registry", "Registry Operations"),
    
    # Remote Command Execution
    ("smbexec.py", "SMB-based remote execution", "Lateral Movement"),
    ("dcomexec.py", "DCOM-based remote execution", "Lateral Movement"),
    ("atexec.py", "Scheduled task execution", "Remote Execution"),
    
    # Active Directory Enumeration
    ("GetADUsers.py", "Enumerate AD users", "Active Directory"),
    ("GetADComputers.py", "Enumerate AD computers", "Active Directory"),
    ("findDelegation.py", "Find delegation relationships", "Active Directory"),
    ("GetLAPSPassword.py", "Extract LAPS passwords", "Active Directory"),
    ("Get-GPPPassword.py", "Extract Group Policy passwords", "Active Directory"),
    
    # Privilege Escalation & Persistence
    ("dacledit.py", "Edit DACL permissions", "Privilege Escalation"),
    ("owneredit.py", "Edit object ownership", "Privilege Escalation"),
    ("rbcd.py", "Resource-based constrained delegation", "Privilege Escalation"),
    ("raiseChild.py", "Child to parent domain privilege escalation", "Privilege Escalation"),
    ("wmipersist.py", "WMI-based persistence", "Persistence"),
    
    # Network Services & Protocols
    ("smbserver.py", "SMB server implementation", "Network Services"),
    ("mssqlclient.py", "MSSQL client", "Database Access"),
    ("mssqlinstance.py", "MSSQL instance enumeration", "Database Access"),
    ("rpcdump.py", "RPC endpoint enumeration", "Network Enumeration"),
    ("rpcmap.py", "RPC endpoint mapping", "Network Enumeration"),
    ("sambaPipe.py", "Samba pipe operations", "Network Services"),
    
    # Registry & System Operations
    ("reg.py", "Remote registry operations", "Registry Operations"),
    ("registry-read.py", "Read registry remotely", "Registry Operations"),
    ("services.py", "Windows service management", "System Administration"),
    ("ntfs-read.py", "NTFS file system operations", "File System"),
    
    # Information Gathering
    ("lookupsid.py", "SID lookup and enumeration", "Information Gathering"),
    ("samrdump.py", "SAM database enumeration", "Information Gathering"),
    ("netview.py", "Network view enumeration", "Network Discovery"),
    ("net.py", "Network operations", "Network Utilities"),
    ("machine_role.py", "Determine machine role", "Information Gathering"),
    
    # Network Analysis & Monitoring
    ("sniff.py", "Network packet sniffing", "Network Analysis"),
    ("sniffer.py", "Advanced packet sniffing", "Network Analysis"),
    ("kintercept.py", "Kerberos interception", "Network Analysis"),
    ("karmaSMB.py", "SMB honeypot", "Honeypot"),
    
    # Utilities & Miscellaneous
    ("ping.py", "ICMP ping utility", "Network Utilities"),
    ("ping6.py", "IPv6 ping utility", "Network Utilities"),
    ("split.py", "File splitting utility", "File Utilities"),
    ("exchanger.py", "Exchange server operations", "Email Services"),
    ("esentutl.py", "ESE database utilities", "Database Utilities"),
    ("getArch.py", "Architecture detection", "System Information"),
    ("getPac.py", "PAC information extraction", "Kerberos Utilities"),
    ("describeTicket.py", "Kerberos ticket analysis", "Kerberos Utilities"),
    ("tstool.py", "Terminal services operations", "Remote Access"),
    ("mqtt_check.py", "MQTT protocol testing", "Protocol Testing"),
    ("rdp_check.py", "RDP service checking", "Protocol Testing"),
    ("wmiquery.py", "WMI query execution", "System Information"),
]

def generate_tool_documentation(tool_name, description, category):
    """Generate documentation for a single tool"""
    
    template = f"""# {tool_name}

## Overview
`{tool_name}` is a {description.lower()} tool in the Impacket suite. This tool is categorized under {category} and provides functionality for [specific use case].

## Detailed Description
[Detailed description of what this tool does, its purpose, and technical background]

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
usage: {tool_name} [-h] [options] target

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
python3 {tool_name} [basic_parameters]

# With authentication
python3 {tool_name} domain.com/user:password@target.domain.com

# Using hash authentication
python3 {tool_name} -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 {tool_name} [advanced_parameters]

# Advanced example 2
python3 {tool_name} [advanced_parameters_2]

# Debug mode
python3 {tool_name} [parameters] -debug
```

## Attack Chain Integration

### [Specific Attack Scenario]
```bash
# Step 1: [First step description]
python3 {tool_name} [step1_parameters]

# Step 2: [Second step description]
python3 [related_tool] [step2_parameters]

# Step 3: [Third step description]
python3 [another_tool] [step3_parameters]
```

### [Another Attack Scenario]
```bash
# Step 1: [Description]
python3 [prerequisite_tool] [parameters]

# Step 2: Use {tool_name}
python3 {tool_name} [parameters]

# Step 3: [Follow-up action]
python3 [followup_tool] [parameters]
```

## Prerequisites
- [List of requirements]
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
- [Specific defensive recommendations]
- Enable appropriate logging and monitoring
- Implement network segmentation
- Use principle of least privilege
- Regular security updates and patches

## Common Issues and Troubleshooting

### [Common Issue 1]
```bash
# Problem description
# Solution or workaround
```

### [Common Issue 2]
```bash
# Problem description  
# Solution or workaround
```

## Related Tools
- [{tool_name}](link.md) - Related functionality
- [secretsdump.py](secretsdump.md) - Often used together
- [psexec.py](psexec.md) - Lateral movement tool
- [GetUserSPNs.py](GetUserSPNs.md) - Credential attacks

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
"""
    
    return template

def main():
    """Generate documentation for all remaining tools"""
    
    wiki_dir = "/home/tim/impacket/impacket-wiki"
    
    if not os.path.exists(wiki_dir):
        print(f"Wiki directory {wiki_dir} does not exist!")
        return
    
    print(f"Generating documentation for {len(REMAINING_TOOLS)} tools...")
    
    for tool_name, description, category in REMAINING_TOOLS:
        file_path = os.path.join(wiki_dir, tool_name.replace('.py', '.md'))
        
        # Skip if file already exists
        if os.path.exists(file_path):
            print(f"Skipping {tool_name} - documentation already exists")
            continue
        
        # Generate documentation
        content = generate_tool_documentation(tool_name, description, category)
        
        try:
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"Generated documentation for {tool_name}")
        except Exception as e:
            print(f"Error generating documentation for {tool_name}: {e}")
    
    print("Documentation generation complete!")
    print("Please review and customize each file with specific tool information.")

if __name__ == "__main__":
    main()
