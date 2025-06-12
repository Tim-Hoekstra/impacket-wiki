# rpcmap.py

## Overview
`rpcmap.py` is an RPC endpoint discovery and enumeration tool in the Impacket suite. This tool is categorized under Network Enumeration and provides functionality for scanning and mapping listening MSRPC interfaces on remote systems.

## Detailed Description
`rpcmap.py` scans for listening MSRPC interfaces by connecting to the MGMT interface and retrieving a list of interface UUIDs. When the MGMT interface is unavailable, it performs brute-force scanning against a database of known UUIDs. The tool can also brute-force operation numbers (opnums) and interface versions to provide comprehensive RPC service mapping.

The tool supports multiple RPC transports including TCP, named pipes, and HTTP/RPC over HTTP. This makes it valuable for discovering RPC services in various network configurations and identifying potential attack vectors through exposed RPC interfaces.

### Key Features:
- **Interface Discovery**: Enumerate available MSRPC interfaces via MGMT interface
- **UUID Brute-forcing**: Test against known RPC interface UUIDs when MGMT unavailable
- **Operation Enumeration**: Brute-force RPC operation numbers (opnums) for discovered interfaces
- **Version Detection**: Test different major versions of RPC interfaces
- **Multiple Transports**: Support for TCP, named pipes, and HTTP/RPC proxy
- **Authentication Support**: Separate credentials for RPC and transport layers
- **Comprehensive Mapping**: Detailed information about discovered RPC services

### Technical Details:
- Uses DCE/RPC over multiple transport protocols
- Leverages MGMT interface (AFA8BD80-7D8A-11C9-BEF4-08002B102989) for enumeration
- Implements brute-force against known UUID database
- Supports RPC over HTTP for Exchange and other Microsoft services
- Compatible with various authentication levels (1-6)

## Command Line Options

```
usage: rpcmap.py [-h] [-brute-uuids] [-brute-opnums] [-brute-versions] [-opnum-max N] 
                 [-version-max N] [-auth-level N] [-uuid UUID] [-debug] [-ts]
                 [-target-ip IP] [-port {139,445}] [-auth-rpc CREDS] [-auth-transport CREDS]
                 [-hashes-rpc HASHES] [-hashes-transport HASHES] [-no-pass]
                 stringbinding

Required Arguments:
  stringbinding         RPC string binding (e.g., ncacn_ip_tcp:192.168.1.100[135])

Enumeration Options:
  -brute-uuids          Bruteforce UUIDs even if MGMT interface is available
  -brute-opnums         Bruteforce opnums for found UUIDs
  -brute-versions       Bruteforce major versions of found UUIDs
  -opnum-max N          Bruteforce opnums from 0 to N (default: 64)
  -version-max N        Bruteforce versions from 0 to N (default: 64)
  -auth-level N         MS-RPCE auth level, 1-6 (default: 6)
  -uuid UUID            Test only this specific UUID

Connection Options:
  -target-ip IP         IP address of target machine
  -port {139,445}       SMB destination port (default: 445)

Authentication:
  -auth-rpc CREDS       [domain/]username[:password] for RPC
  -auth-transport CREDS [domain/]username[:password] for transport
  -hashes-rpc HASHES    NTLM hashes for RPC (LMHASH:NTHASH)
  -hashes-transport HASHES NTLM hashes for transport (LMHASH:NTHASH)
  -no-pass              Don't ask for passwords

Debug Options:
  -debug                Turn DEBUG output ON
  -ts                   Add timestamp to logging output
```

## Usage Examples

### Basic RPC Enumeration
```bash
# Enumerate RPC interfaces via TCP endpoint mapper
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135]

# Enumerate via named pipes over SMB
python3 rpcmap.py ncacn_np:192.168.1.100[\\pipe\\epmapper]

# Scan domain controller
python3 rpcmap.py ncacn_ip_tcp:dc01.domain.com[135]
```

### Authenticated Enumeration
```bash
# With credentials for both RPC and transport
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] \
  -auth-rpc domain.com/user:password \
  -auth-transport domain.com/user:password

# Using NTLM hashes
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] \
  -hashes-rpc aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 \
  -hashes-transport aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76

# Different credentials for RPC vs transport
python3 rpcmap.py ncacn_np:192.168.1.100[\\pipe\\epmapper] \
  -auth-rpc domain.com/rpcuser:pass1 \
  -auth-transport domain.com/smbuser:pass2
```

### Advanced Enumeration
```bash
# Force UUID brute-forcing even if MGMT available
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] -brute-uuids

# Brute-force operation numbers for discovered interfaces
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] -brute-opnums

# Test interface versions
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] -brute-versions

# Test specific UUID only
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] \
  -uuid 12345678-1234-ABCD-EF00-01234567CFFB

# Custom brute-force ranges
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] \
  -brute-opnums -opnum-max 128 -brute-versions -version-max 32
```

### Exchange Server Enumeration
```bash
# RPC over HTTP for Exchange
python3 rpcmap.py ncacn_http:exchange.contoso.com[593] \
  -auth-transport domain.com/user:password

# Exchange with RPC proxy authentication
python3 rpcmap.py "ncacn_http:[6001,RpcProxy=exchange.contoso.com:443]" \
  -auth-transport domain.com/user:password

# RDS/Terminal Services RPC proxy
python3 rpcmap.py "ncacn_http:localhost[3388,RpcProxy=rds.contoso:443]" \
  -auth-transport domain.com/user:password
```

### Multiple Transport Testing
```bash
# Test both TCP and named pipe transports
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135]
python3 rpcmap.py ncacn_np:192.168.1.100[\\pipe\\epmapper] -port 445
python3 rpcmap.py ncacn_np:192.168.1.100[\\pipe\\epmapper] -port 139

# HTTP RPC scanning
python3 rpcmap.py ncacn_http:192.168.1.100[593]
```

## Attack Integration

### Service Discovery
```bash
# Comprehensive RPC service mapping
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] -brute-uuids -brute-opnums

# Identify vulnerable RPC services
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] | grep -E "(MS-RPRN|MS-PAR|MS-SCMR)"

# Map print spooler services
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] | grep -i "print\|spooler"
```

### Privilege Escalation Research
```bash
# Look for privileged RPC interfaces
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] -brute-uuids | \
  grep -E "(ATSVC|SVCCTL|SAMR|LSARPC)"

# Service Control Manager enumeration
python3 rpcmap.py ncacn_np:192.168.1.100[\\pipe\\svcctl] \
  -auth-transport domain.com/user:password -brute-opnums

# Task Scheduler interface testing
python3 rpcmap.py ncacn_np:192.168.1.100[\\pipe\\atsvc] \
  -auth-transport domain.com/user:password
```

### Domain Controller Analysis
```bash
# Map domain controller RPC services
python3 rpcmap.py ncacn_ip_tcp:dc01.domain.com[135] \
  -auth-rpc domain.com/user:password -brute-uuids

# LDAP over RPC enumeration
python3 rpcmap.py ncacn_ip_tcp:dc01.domain.com[389] \
  -auth-transport domain.com/user:password

# Active Directory replication interfaces
python3 rpcmap.py ncacn_ip_tcp:dc01.domain.com[135] | \
  grep -E "(DRSR|FRS|DFSR)"
```

### Post-Exploitation Enumeration
```bash
# Enumerate all available RPC interfaces after gaining access
python3 rpcmap.py ncacn_ip_tcp:192.168.1.100[135] \
  -auth-rpc domain.com/compromised_user:password \
  -brute-uuids -brute-opnums

# Test high-privilege RPC interfaces
python3 rpcmap.py ncacn_np:192.168.1.100[\\pipe\\netlogon] \
  -auth-transport domain.com/admin:password -brute-opnums
```

## Security Implications

### Defensive Considerations
- **RPC Filtering**: Block unnecessary RPC ports at network perimeter
- **Endpoint Mapper**: Disable RPC endpoint mapper if not required
- **Authentication**: Require authentication for sensitive RPC interfaces
- **Service Hardening**: Disable unused RPC services and interfaces
- **Network Segmentation**: Isolate RPC services to necessary network segments

### Attack Vectors Discovered
1. **Unauthenticated RPC Services**: Interfaces accessible without credentials
2. **Print Spooler Exploits**: MS-RPRN interface vulnerabilities
3. **Service Control**: SVCCTL interface for service manipulation
4. **Task Scheduling**: ATSVC interface for scheduled task creation
5. **Registry Access**: WINREG interface for registry manipulation

### Detection Methods
```bash
# Monitor for RPC enumeration attempts
# Windows Event ID 5156 (Network filtering)
# Look for multiple connections to port 135

# Network monitoring for RPC scanning
tcpdump -i any port 135 and host [suspicious_ip]

# Monitor authentication failures on RPC interfaces
grep "rpc_s_access_denied" /var/log/syslog
```

## Troubleshooting

### Common Issues
1. **Access Denied Errors**:
   - Verify credentials have RPC access permissions
   - Try different authentication levels (1-6)
   - Check if account is locked out

2. **Connection Failures**:
   - Ensure target port 135 is accessible
   - Test named pipe transport as alternative
   - Verify RPC service is running

3. **Exchange RPC Proxy Issues**:
   - Verify RPC proxy configuration
   - Check authentication requirements
   - Test different RPC proxy ports (593, 6001, 6002)

### String Binding Examples
```bash
# TCP transport
ncacn_ip_tcp:192.168.1.100[135]
ncacn_ip_tcp:server.domain.com[1024]

# Named pipe transport
ncacn_np:192.168.1.100[\\pipe\\epmapper]
ncacn_np:server.domain.com[\\pipe\\spoolss]

# HTTP transport (Exchange/OWA)
ncacn_http:exchange.contoso.com[593]
ncacn_http:[6001,RpcProxy=exchange.contoso.com:443]

# Local system
ncalrpc:[LRPC-address]
```

### Authentication Levels
- **Level 1**: RPC_C_AUTHN_LEVEL_NONE
- **Level 2**: RPC_C_AUTHN_LEVEL_CONNECT  
- **Level 3**: RPC_C_AUTHN_LEVEL_CALL
- **Level 4**: RPC_C_AUTHN_LEVEL_PKT
- **Level 5**: RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
- **Level 6**: RPC_C_AUTHN_LEVEL_PKT_PRIVACY (default)

## Related Tools
- **rpcdump.py**: Enumerate RPC endpoints via endpoint mapper
- **dcomexec.py**: DCOM-based remote execution
- **smbclient.py**: SMB enumeration and file access
- **services.py**: Service control via RPC
- **atexec.py**: Task scheduling via RPC
- **reg.py**: Registry access via RPC

## Technical References
- [MS-RPC: Remote Procedure Call Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpc/)
- [RPC over HTTP Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpch/)
- [RPC Endpoint Mapper Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpc/c681d488-d850-11d0-8c52-00c04fd90f7e)
- [DCE/RPC Security Considerations](https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm)

# Using hash authentication
python3 rpcmap.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Query specific RPC endpoint with authentication
python3 rpcmap.py -p 135 domain.com/user:password@192.168.1.100

# Enumerate with specific authentication method
python3 rpcmap.py -hashes :ntlmhash domain.com/user@192.168.1.100

# Comprehensive RPC enumeration across multiple ports
for port in 135 1024 1025 1026; do
    echo "Checking port $port..."
    python3 rpcmap.py -p "$port" target.domain.com
done
```

## Attack Chain Integration

### Initial Domain Reconnaissance
```bash
# Step 1: Discover RPC endpoints on domain controllers
nmap -p 135,445 --script rpc-grind domain.com

# Step 2: Map available RPC services
python3 rpcmap.py domain.com

# Step 3: Use discovered services for further enumeration
python3 rpcdump.py domain.com/user:pass@192.168.1.100
```

### Post-compromise Service Discovery
```bash
# Step 1: Gain initial access
python3 psexec.py domain/user:pass@target

# Step 2: Map RPC services on compromised host
python3 rpcmap.py -hashes :ntlmhash domain/user@target
```

## Prerequisites
- Network access to target system on RPC ports (135, 445, or custom)
- Valid credentials may be required for authenticated enumeration
- Python 3.x with Impacket library installed
- Understanding of RPC string binding formats

## Detection Considerations
- **Event IDs**: 
  - Event ID 4624/4625 (Authentication success/failure)
  - Event ID 5156 (Windows Filtering Platform connection)
  - Event ID 4688 (Process creation if RPC services are started)
- **Network Indicators**: 
  - Multiple connections to port 135 (RPC endpoint mapper)
  - Connections to various high ports (RPC services)
  - Unusual RPC traffic patterns and bind attempts
- **Process Indicators**: 
  - RPC service processes being accessed
  - Unusual MGMT interface queries
- **File Indicators**: 
  - No direct file modifications
- **Registry Indicators**: 
  - No direct registry modifications

## Defensive Measures
- Monitor and log RPC endpoint mapper connections (port 135)
- Implement network segmentation to restrict RPC access
- Use Windows Firewall to limit RPC port exposure
- Enable RPC authentication and encryption where possible
- Deploy intrusion detection systems to monitor RPC enumeration
- Regular security updates for RPC services

## Common Issues and Troubleshooting

### Connection Refused or Timeout
```bash
# Problem: Cannot connect to RPC endpoint
# Solution: Verify target accessibility and port availability
nmap -p 135,445 target_ip
python3 rpcmap.py ncacn_ip_tcp:target_ip[135]
```

### Authentication Required Errors
```bash
# Problem: MGMT interface requires authentication
# Solution: Provide valid credentials for authenticated enumeration
python3 rpcmap.py ncacn_ip_tcp:target[135] -auth-rpc domain/user:password
```

## Related Tools
- [rpcdump.py](rpcdump.md) - Dump RPC interface information
- [psexec.py](psexec.md) - Execute commands via RPC services
- [wmiexec.py](wmiexec.md) - WMI-based execution using RPC
- [services.py](services.md) - Service management via RPC

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
