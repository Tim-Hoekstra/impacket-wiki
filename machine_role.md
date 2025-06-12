# machine_role.py

## Overview
`machine_role.py` is a determine machine role tool in the Impacket suite. This tool is categorized under Information Gathering and provides functionality for [specific use case].

## Detailed Description
# machine_role.py

## Overview
`machine_role.py` is a Windows machine role detection tool in the Impacket suite. This tool is categorized under Information Gathering and provides functionality for determining the role and configuration of Windows systems in Active Directory environments.

## Detailed Description
`machine_role.py` queries remote Windows systems to determine their role within an Active Directory domain, such as domain controller, member server, standalone server, or workstation. The tool helps identify the function and trust relationships of systems during network reconnaissance.

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
usage: machine_role.py [-h] [options] target

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
python3 machine_role.py [basic_parameters]

# With authentication
python3 machine_role.py domain.com/user:password@target.domain.com

# Using hash authentication
python3 machine_role.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Check role of multiple machines in batch
for host in $(cat domain_machines.txt); do
    echo "Checking role of $host..."
    python3 machine_role.py domain.com/user:password@"$host"
done

# Query with specific domain controller
python3 machine_role.py -dc-ip 192.168.1.10 domain.com/user:password@target.domain.com

# Use hash authentication for stealth
python3 machine_role.py -hashes :ntlmhash domain.com/user@target.domain.com
```

## Attack Chain Integration

### Domain Environment Mapping
```bash
# Step 1: Enumerate domain computers
python3 GetADComputers.py domain.com/user:password -dc-ip 192.168.1.10

# Step 2: Identify roles of discovered machines
python3 machine_role.py domain.com/user:password@discovered_machine

# Step 3: Target high-value systems based on roles
python3 psexec.py domain.com/user:password@domain_controller
```

### Lateral Movement Planning
```bash
# Step 1: Identify machine role after initial compromise
python3 machine_role.py domain.com/user:password@current_host

# Step 2: Plan next targets based on role information
# If domain controller: extract NTDS
# Step 2: Plan next targets based on role information
# If domain controller: extract NTDS
# If member server: look for credentials
```

## Prerequisites
- Valid domain credentials (any authenticated user)
- Network access to target system on SMB/RPC ports (445, 135)
- Python 3.x with Impacket installed
- Target must be part of Windows domain

## Detection Considerations
- **Event IDs**: 
  - Event ID 4624/4625 (Authentication success/failure)
  - Event ID 5140/5145 (SMB share access)
  - Event ID 4672 (Special logon if admin privileges used)
- **Network Indicators**: 
  - SMB/RPC connections to domain systems
  - LDAP queries to domain controllers
  - NetBIOS name resolution activity
- **Process Indicators**: 
  - Python processes accessing domain services
  - Network authentication processes
- **File Indicators**: 
  - No file modifications on target
- **Registry Indicators**: 
  - No registry modifications

## Defensive Measures
- Monitor domain authentication and enumeration activities
- Enable SMB and LDAP access logging
- Implement network segmentation between domain tiers
- Use honeypot accounts to detect reconnaissance
- Deploy domain controller monitoring solutions
- Regular security auditing of domain structure

## Common Issues and Troubleshooting

### Authentication Failures
```bash
# Problem: Cannot authenticate to query machine role
# Solution: Verify domain credentials and connectivity
python3 machine_role.py -dc-ip dc_ip domain.com/user:password@target
net use \\target\IPC$ /user:domain\user password  # Test connectivity
```

### Domain Controller Unreachable
```bash
# Problem: Cannot contact domain controller for role lookup
# Solution: Specify domain controller explicitly
python3 machine_role.py -dc-ip 192.168.1.10 domain.com/user:password@target
nslookup domain.com  # Verify DNS resolution
```

## Related Tools
- [GetADComputers.py](GetADComputers.md) - Enumerate domain computers
- [secretsdump.py](secretsdump.md) - Extract credentials based on role
- [psexec.py](psexec.md) - Execute commands on identified systems
- [GetUserSPNs.py](GetUserSPNs.md) - Target services based on role

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
