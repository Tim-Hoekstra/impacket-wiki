# sniff.py

## Overview
`sniff.py` is a network packet sniffing tool in the Impacket suite. This tool is categorized under Network Analysis and provides functionality for capturing and analyzing network traffic using the pcap library with support for BPF filtering.

## Detailed Description
`sniff.py` is a simple packet sniffer that uses the pcap library to listen for packets in transit over a specified network interface. The tool automatically detects available network interfaces and allows users to select one for monitoring. It supports BPF (Berkeley Packet Filter) syntax for filtering captured packets, making it useful for focused network analysis and troubleshooting.

The tool leverages Impacket's ImpactDecoder to parse captured packets into human-readable format, supporting both Ethernet (DLT_EN10MB) and Linux SLL (DLT_LINUX_SLL) data link types. This makes it suitable for analyzing network traffic on various platforms and network configurations.

### Key Features:
- **Interface Detection**: Automatically discovers available network interfaces
- **BPF Filtering**: Support for Berkeley Packet Filter syntax for selective capture
- **Multiple Data Link Types**: Support for Ethernet and Linux SLL interfaces
- **Real-time Analysis**: Live packet capture and display
- **Human-readable Output**: Automatic packet parsing and formatting
- **Cross-platform Compatibility**: Works on various operating systems with pcap support

### Technical Details:
- Uses pcapy library for packet capture functionality
- Implements ImpactDecoder for packet parsing and display
- Supports BPF filter syntax (compatible with tcpdump)
- Runs capture in separate thread for non-blocking operation
- Compatible with DLT_EN10MB and DLT_LINUX_SLL data link types

## Command Line Options

```
usage: sniff.py [BPF_FILTER]

Arguments:
  BPF_FILTER            Berkeley Packet Filter expression (optional, defaults to capture all)
                       Examples: "tcp port 80", "host 192.168.1.1", "icmp"
```

Note: The tool takes all command-line arguments as a BPF filter expression. No separate options or authentication parameters are required.

## Usage Examples

### Basic Usage
```bash
# Capture all traffic (no filter)
python3 sniff.py

# Capture only HTTP traffic
python3 sniff.py "tcp port 80"

# Capture traffic from specific host
python3 sniff.py "host 192.168.1.100"

# Capture ICMP traffic
python3 sniff.py "icmp"

# Capture DNS queries
python3 sniff.py "udp port 53"
```

### Advanced Filtering
```bash
# Capture TCP traffic on multiple ports
python3 sniff.py "tcp port 80 or tcp port 443"

# Capture traffic between specific hosts
python3 sniff.py "host 192.168.1.100 and host 192.168.1.200"

# Capture SMB traffic
python3 sniff.py "tcp port 445 or tcp port 139"

# Capture Kerberos authentication
python3 sniff.py "tcp port 88 or udp port 88"

# Capture LDAP traffic
python3 sniff.py "tcp port 389 or tcp port 636"
```

### Network Analysis Scenarios
```bash
# Monitor domain controller traffic
python3 sniff.py "host dc01.domain.com"

# Capture authentication traffic
python3 sniff.py "tcp port 88 or tcp port 389 or tcp port 445"

# Monitor NTLM authentication
python3 sniff.py "tcp port 445 and tcp[tcpflags] & tcp-syn != 0"

# Capture credential-related protocols
python3 sniff.py "tcp port 139 or tcp port 445 or tcp port 389"
```

## Attack Integration

### Credential Interception
```bash
# Monitor for NTLM challenges/responses
python3 sniff.py "tcp port 445"

# Capture Kerberos tickets
python3 sniff.py "tcp port 88 or udp port 88"

# Monitor LDAP bind operations
python3 sniff.py "tcp port 389"
```

### Network Reconnaissance
```bash
# Identify active services
python3 sniff.py "tcp[tcpflags] & tcp-syn != 0"

# Monitor DNS queries for domain mapping
python3 sniff.py "udp port 53"

# Capture broadcast traffic for network discovery  
python3 sniff.py "broadcast"
```

### Post-exploitation Monitoring
```bash
# Monitor lateral movement attempts
python3 sniff.py "tcp port 445 or tcp port 135 or tcp port 3389"

# Capture C2 communication patterns
python3 sniff.py "tcp port 80 or tcp port 443 or tcp port 8080"

# Monitor data exfiltration
python3 sniff.py "tcp and greater 1000"
```

## Security Implications

### Defensive Considerations
- **Network Segmentation**: Limit broadcast domains to reduce sniffing scope
- **Encryption**: Use encrypted protocols to protect sensitive data
- **Switch Security**: Enable port security and dynamic ARP inspection
- **Network Monitoring**: Deploy IDS/IPS to detect sniffing activities

### Detection Methods
```bash
# Monitor for promiscuous mode interfaces
ip link show | grep PROMISC

# Check for suspicious processes with network access
lsof -i

# Monitor system logs for pcap library usage
grep -i pcap /var/log/syslog
```

## Troubleshooting

### Common Issues
1. **Permission Errors**:
   - Requires root/administrator privileges for packet capture
   - Use `sudo` on Linux/macOS systems
   - Run as administrator on Windows

2. **No Interfaces Available**:
   - Check if user has sufficient permissions
   - Verify pcap library installation
   - Ensure network interfaces are active

3. **Filter Syntax Errors**:
   - Verify BPF filter syntax (see tcpdump manual)
   - Test filters with tcpdump first
   - Use quotes around complex expressions

### Prerequisites
```bash
# Install pcapy library
pip install pcapy-ng

# Or using system package manager
sudo apt-get install python3-pcapy  # Debian/Ubuntu
sudo yum install python3-pcapy      # RHEL/CentOS
```

### Interface Selection
```bash
# List available interfaces manually
python3 -c "import pcapy; print(pcapy.findalldevs())"

# Check interface status
ip link show
ifconfig -a
```

## Related Tools
- **sniffer.py**: Similar packet capture functionality with different implementation
- **tcpdump**: Command-line packet analyzer
- **wireshark**: GUI-based network protocol analyzer
- **tshark**: Command-line version of Wireshark
- **ntlmrelayx.py**: NTLM relay attacks (can benefit from traffic analysis)

## Technical References
- [BPF Filter Syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html)
- [pcapy Documentation](https://github.com/CoreSecurity/pcapy)
- [tcpdump Manual](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Network Traffic Analysis Techniques](https://www.sans.org/white-papers/1653/)

# Using hash authentication
python3 sniff.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Capture with specific filter and output
python3 sniff.py eth0 -filter "tcp port 445" -pcap smb_traffic.pcap

# Long-duration capture with rotation
python3 sniff.py eth0 -pcap capture_%Y%m%d_%H%M%S.pcap -filter "host 192.168.1.100"

# Monitor multiple protocols
python3 sniff.py eth0 -filter "port 139 or port 445 or port 88" -pcap ad_traffic.pcap
```

## Attack Chain Integration

### Network Reconnaissance and Credential Harvesting
```bash
# Step 1: Start packet capture for credential harvesting
python3 sniff.py eth0 -filter "tcp port 445 or tcp port 139" -pcap smb_creds.pcap

# Step 2: Force authentication attempts (separate terminal)
python3 ntlmrelayx.py -t smb://target -smb2support

# Step 3: Analyze captured traffic for credentials
python3 secretsdump.py -pcap smb_creds.pcap
```

### Man-in-the-Middle Attack Support
```bash
# Step 1: Set up network interception
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.0-255//

# Step 2: Capture authentication traffic
python3 sniff.py eth0 -filter "tcp port 445" -pcap mitm_capture.pcap
```

## Prerequisites
- Root/Administrator privileges for packet capture
- Python 3.x with Impacket and pcapy libraries installed
- Network interface access (promiscuous mode capability)
- Sufficient storage space for captured packets

## Detection Considerations
- **Event IDs**: 
  - Event ID 5154 (Windows Filtering Platform packet drop)
  - Event ID 5156 (Connection allowed)
- **Network Indicators**: 
  - Network interface in promiscuous mode
  - Unusual packet capture processes
  - Large amounts of network data being processed
- **Process Indicators**: 
  - Python processes with elevated privileges
  - High CPU usage during packet processing
- **File Indicators**: 
  - Large capture files (.pcap) being created
  - Temporary packet storage files
- **Registry Indicators**: 
  - No direct registry modifications

## Defensive Measures
- Monitor for network interfaces entering promiscuous mode
- Implement network segmentation to limit packet visibility
- Use encrypted protocols (TLS/SSL) to protect data in transit
- Deploy network access control (NAC) solutions
- Regular monitoring of privileged user activities
- Network intrusion detection systems (NIDS)

## Common Issues and Troubleshooting

### Permission Denied Errors
```bash
# Problem: Insufficient privileges to capture packets
# Solution: Run with elevated privileges
sudo python3 sniff.py "tcp port 443"
```

### Interface Selection Issues
```bash
# Problem: Cannot find appropriate network interface
# Solution: List available interfaces and select manually
# The tool will prompt for interface selection automatically
```

## Related Tools
- [sniffer.py](sniffer.md) - Alternative network sniffer
- [split.py](split.md) - Split large capture files
- [ntlmrelayx.py](ntlmrelayx.md) - NTLM relay attacks using captured traffic
- [secretsdump.py](secretsdump.md) - Extract credentials from captured packets

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
