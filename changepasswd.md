# changepasswd.py

## Overview
`changepasswd.py` is a comprehensive password management tool that can change or reset user passwords through multiple protocols. This tool supports various authentication methods and password modification techniques, making it valuable for both legitimate administration and security testing scenarios.

## Detailed Description
This script provides functionality to change or reset passwords via different protocols, each with their own advantages and limitations. It supports both password changes (where the current password is known) and password resets (which require administrative privileges). The tool can work with plaintext passwords or NTLM hashes depending on the protocol used.

### Supported Protocols:
- **MS-SAMR over SMB**: Like smbpasswd, supports password expiration handling and NTLM hashes
- **MS-SAMR over RPC**: Direct RPC communication, plaintext passwords only
- **Kerberos Change Password**: Standard kpasswd protocol, requires valid TGT
- **Kerberos Set Password**: Administrative password reset via Kerberos
- **LDAP Password Change/Set**: Secure LDAP-based password operations

### Key Features:
- **Multiple Protocol Support**: Choose the most appropriate protocol for your environment
- **Password Change vs Reset**: Change with current credentials or reset with admin privileges
- **Hash Support**: Use NTLM hashes directly with SMB-SAMR protocol
- **Kerberos Integration**: Full support for Kerberos authentication and ticketing
- **Flexible Authentication**: Support for alternative user credentials and various auth methods

### Technical Details:
- Implements MS-SAMR NetUserChangePassword and NetUserSetInfo protocols
- Supports Kerberos change-password and reset-password protocols  
- Uses secure LDAP connections for password operations
- Handles password policy enforcement based on protocol used
- Compatible with both domain and local accounts

## Command Line Options

```
usage: changepasswd.py [-h] [-ts] [-debug] [-newpass NEWPASS | -newhashes LMHASH:NTHASH] 
                       [-hashes LMHASH:NTHASH] [-no-pass] [-altuser ALTUSER] 
                       [-altpass ALTPASS | -althash ALTHASH] [-protocol {smb-samr,rpc-samr,kpasswd,ldap}] 
                       [-reset] [-k] [-aesKey hex key] [-dc-ip ip address]
                       target

Change or reset passwords over different protocols.

Required Arguments:
  target                [[domain/]username[:password]@]<hostname or address>

General Options:
  -h, --help            Show help message and exit
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

New Credentials for Target:
  -newpass NEWPASS      New password (plaintext)
  -newhashes LMHASH:NTHASH
                        New NTLM hashes, format is NTHASH or LMHASH:NTHASH

Authentication (target user):
  -hashes LMHASH:NTHASH NTLM hashes for target user, format is NTHASH or LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for Kerberos, -k)

Authentication (privileged user):
  -altuser ALTUSER      Alternative username (for password reset operations)
  -altpass ALTPASS      Alternative password
  -althash ALTHASH      Alternative NT hash, format is NTHASH or LMHASH:NTHASH

Method of Operations:
  -protocol {smb-samr,rpc-samr,kpasswd,ldap}
                        Protocol to use for password change/reset (default: smb-samr)
  -reset, -admin        Try to reset password with privileges (may bypass password policies)

Kerberos Authentication:
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller for Kerberos
```
## Usage Examples

### SMB-SAMR Protocol (Default)
```bash
# Basic password change (prompts for old and new passwords)
python3 changepasswd.py j.doe@192.168.1.11

# Change password with NTLM hash authentication
python3 changepasswd.py contoso.local/j.doe@DC1 -hashes :fc525c9683e8fe067095ba2ddc971889

# Change password with explicit new password
python3 changepasswd.py contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'

# Change password using new NT hash (password will be marked as expired)
python3 changepasswd.py contoso.local/j.doe:'Passw0rd!'@DC1 -newhashes :126502da14a98b58f2c319b81b3a49cb

# Change password using Kerberos ticket
python3 changepasswd.py contoso.local/j.doe@DC1 -newhashes :126502da14a98b58f2c319b81b3a49cb -k -no-pass
```

### Password Reset Operations
```bash
# Reset password with admin credentials
python3 changepasswd.py -reset contoso.local/j.doe@DC1 -newpass 'N3wPassw0rd!' \
    -altuser administrator -altpass 'Adm1nPassw0rd!'

# Reset password using admin NT hash
python3 changepasswd.py -reset contoso.local/j.doe@DC1 -newhashes :126502da14a98b58f2c319b81b3a49cb \
    -altuser CONTOSO/administrator -althash 6fe945ead39a7a6a2091001d98a913ab

# Reset password using Kerberos admin ticket
python3 changepasswd.py -reset contoso.local/j.doe@DC1 -newhashes :126502da14a98b58f2c319b81b3a49cb \
    -altuser CONTOSO/DomAdm -k -no-pass
```

### Alternative Protocols
```bash
# Using RPC-SAMR protocol
python3 changepasswd.py -protocol rpc-samr contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'

# Using Kerberos change password protocol
python3 changepasswd.py -protocol kpasswd contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'

# Using Kerberos reset password protocol
python3 changepasswd.py -reset -protocol kpasswd contoso.local/j.doe@DC1 -newpass 'N3wPassw0rd!' \
    -altuser CONTOSO/SrvAdm

# Using LDAP password change
python3 changepasswd.py -protocol ldap contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'

# Using LDAP with Kerberos authentication
python3 changepasswd.py -protocol ldap -k contoso.local/j.doe@DC1 -newpass 'N3wPassw0rd!'
```

### Local Account Operations
```bash
# Change local account password
python3 changepasswd.py SRV01/administrator:'Passw0rd!'@10.10.13.37 -newpass 'N3wPassw0rd!'

# Reset local account password with domain admin
python3 changepasswd.py -reset SRV01/administrator@10.10.13.37 -newhashes :126502da14a98b58f2c319b81b3a49cb \
    -altuser CONTOSO/DomAdm -althash 6fe945ead39a7a6a2091001d98a913ab
```

## Protocol Comparison

| Protocol | Auth Methods | Hash Support | Password Policy | Expired Password | Network Requirement |
|----------|-------------|--------------|-----------------|------------------|-------------------|
| SMB-SAMR | Password, Hash, Kerberos | Yes (NT/LM) | Enforced (plaintext) | Supported | SMB (445/tcp) |
| RPC-SAMR | Password, Kerberos | No | Enforced | No | RPC (135/tcp + high ports) |
| Kerberos | Password, Kerberos, Key | No | Enforced | No | Kerberos (88/tcp) |
| LDAP | Password, Kerberos | No | Enforced | No | LDAPS (636/tcp) |

### Protocol Selection Guidelines:
- **SMB-SAMR**: Best for hash-based operations and expired password handling
- **RPC-SAMR**: Good for environments where SMB is blocked
- **Kerberos**: Ideal for domain environments with proper Kerberos infrastructure  
- **LDAP**: Suitable when secure LDAP is available and configured

## Attack Chain Integration

### Password Spraying Follow-up
```bash
# Step 1: Identify valid accounts with password spraying
python3 GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -outputfile asrep.out

# Step 2: Change passwords for compromised accounts
python3 changepasswd.py domain.local/validuser@dc.domain.local -newpass 'CompromisedPass123!'
```

### Credential Harvesting to Password Change
```bash
# Step 1: Extract credentials from compromised system
python3 secretsdump.py domain.local/admin:password@target.domain.local

# Step 2: Change passwords using extracted hashes
python3 changepasswd.py domain.local/user@dc.domain.local -hashes :extractedhash -newpass 'NewPass123!'
```

### Kerberos Ticket to Password Change
```bash
# Step 1: Obtain service ticket
python3 getST.py domain.local/user:password -spn cifs/dc.domain.local

# Step 2: Use ticket for password change
export KRB5CCNAME=user.ccache
python3 changepasswd.py -protocol kpasswd -k domain.local/user@dc.domain.local -newpass 'NewPass123!'
```

### Administrative Password Reset
```bash
# Step 1: Compromise administrative account
python3 psexec.py domain.local/admin:password@dc.domain.local

# Step 2: Reset user passwords with admin privileges
python3 changepasswd.py -reset domain.local/targetuser@dc.domain.local -newpass 'AdminSetPass!' \
    -altuser domain.local/admin -altpass 'AdminPassword123!'
```

## Prerequisites
- Python 3.x with Impacket installed
- Network access to target system on required ports
- Valid credentials for the target user (for password change) or administrative user (for password reset)
- Appropriate protocol-specific requirements:
  - SMB: SMB access (port 445)
  - RPC: RPC access (port 135 + high ports)
  - Kerberos: Kerberos access (port 88)
  - LDAP: Secure LDAP access (port 636)

## Detection Considerations
- **Event IDs**:
  - 4723: An attempt was made to change an account's password
  - 4724: An attempt was made to reset an account's password
  - 4625: An account failed to log on (failed attempts)
  - 4648: A logon was attempted using explicit credentials
- **Network Indicators**: 
  - Unusual password change frequency
  - Password changes from non-administrative sources
  - Multiple protocol attempts for same user
- **Security Indicators**:
  - Password changes outside business hours
  - Bulk password changes across multiple accounts
  - Password changes immediately after compromise indicators

## Defensive Measures
- **Password Policies**: Implement and enforce strong password complexity requirements
- **Account Monitoring**: Monitor for unusual password change patterns
- **Protocol Restrictions**: Limit which protocols can be used for password changes
- **Privileged Access Management**: Restrict who can perform password resets
- **Audit Logging**: Enable comprehensive password change auditing
- **Network Segmentation**: Limit access to password change protocols
- **Multi-Factor Authentication**: Require additional verification for password changes

## Common Issues and Troubleshooting

### Protocol-Specific Issues

#### SMB-SAMR Protocol
```bash
# Issue: SMB connection refused
# Solution: Check if SMB service is running and accessible
python3 changepasswd.py -debug domain.local/user@target -newpass 'password'

# Issue: Access denied with valid credentials
# Solution: User may not have permission to change their own password
python3 changepasswd.py -reset domain.local/user@target -newpass 'password' -altuser admin -altpass 'adminpass'
```

#### Kerberos Protocol
```bash
# Issue: "KDC_ERR_PREAUTH_FAILED"
# Solution: Verify user credentials and ensure account is not locked
python3 changepasswd.py -protocol kpasswd domain.local/user:correctpassword@dc -newpass 'newpass'

# Issue: Clock skew errors
# Solution: Synchronize time with domain controller
ntpdate dc.domain.local
```

#### LDAP Protocol
```bash
# Issue: "Server not configured for SSL"
# Solution: Ensure LDAPS is properly configured on the domain controller
# Check if certificate is valid and LDAPS is enabled

# Issue: "Insufficient access rights"
# Solution: User needs permission to change their password or admin needs reset rights
python3 changepasswd.py -reset -protocol ldap domain.local/user@dc -newpass 'newpass' -altuser admin -altpass 'adminpass'
```

### Authentication Issues
```bash
# Issue: "The specified network password is not correct"
# Solution: Verify credentials and account status
# Check if account is locked, disabled, or password has expired

# Issue: Hash authentication not working
# Solution: Ensure you're using SMB-SAMR protocol (default) for hash support
python3 changepasswd.py -protocol smb-samr domain.local/user@target -hashes :nthash -newpass 'newpass'
```

### General Troubleshooting Tips
- Use `-debug` flag for detailed error information
- Verify network connectivity to required ports
- Check if target account has necessary permissions
- Ensure domain controller is accessible for domain accounts
- Verify time synchronization for Kerberos authentication

## Password Policy Considerations

### Policy Enforcement by Protocol:
- **SMB-SAMR**: 
  - Plaintext passwords: Policy enforced
  - Hash passwords: Policy bypassed (password marked expired)
- **RPC-SAMR**: Always enforces password policy
- **Kerberos**: Always enforces password policy  
- **LDAP**: Always enforces password policy

### Reset vs Change Operations:
- **Change**: Requires current password, subject to policy
- **Reset**: Requires admin privileges, may bypass some policies

## Related Tools
- [psexec.py](psexec.md) - Execute commands with new credentials
- [secretsdump.py](secretsdump.md) - Extract password hashes
- [GetNPUsers.py](GetNPUsers.md) - AS-REP roasting attacks
- [getST.py](getST.md) - Obtain service tickets
- [getTGT.py](getTGT.md) - Obtain ticket granting tickets
- [smbclient.py](smbclient.md) - SMB operations with new passwords

---

*This documentation is based on the actual source code and functionality of changepasswd.py from Impacket.*
