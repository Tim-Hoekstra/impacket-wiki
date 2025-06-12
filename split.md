# split.py

## Overview
`split.py` is a pcap file splitting utility in the Impacket suite. This tool is categorized under File Utilities and provides functionality for splitting large pcap capture files into smaller ones, with each output file containing packets from a single TCP connection.

## Detailed Description
`split.py` is a pcap dump splitter that processes capture files and separates them into individual files based on TCP connections. For each unique TCP connection found in the original capture, the tool creates a separate pcap file containing only the packets belonging to that specific connection. This is extremely useful for analyzing large network captures by isolating individual communication sessions.

The tool automatically detects connection pairs based on source and destination IP addresses and ports, treating bidirectional connections as a single session. Each output file is named using the format `source_ip.source_port-destination_ip.destination_port.pcap`, making it easy to identify which connection each file contains.

### Key Features:
- **Connection-based Splitting**: Separates packets by individual TCP connections
- **Automatic Detection**: Identifies unique connections by IP/port pairs
- **Bidirectional Support**: Treats both directions of a connection as one session
- **Descriptive Naming**: Output files named with connection details
- **Multiple Data Link Types**: Support for Ethernet and Linux SLL captures
- **Efficient Processing**: Streams through large files without loading entirely into memory

### Technical Details:
- Uses pcapy library for pcap file processing
- Implements ImpactDecoder for packet parsing
- Applies TCP filter automatically (ip proto \tcp)
- Supports DLT_EN10MB and DLT_LINUX_SLL data link types
- Creates separate pcapdumper for each unique connection

## Command Line Options

```
usage: split.py <filename>

Required Arguments:
  filename              Path to the pcap file to split
```

Note: The tool automatically applies a TCP filter (`ip proto \tcp`) and processes only TCP connections.

## Usage Examples

### Basic Usage
```bash
# Split a pcap file into individual connections
python3 split.py capture.pcap

# Example output files created:
# 192.168.1.100.12345-192.168.1.200.80.pcap
# 192.168.1.100.12346-192.168.1.200.443.pcap
# 192.168.1.100.12347-192.168.1.150.22.pcap
```

### Network Analysis Workflow
```bash
# Capture network traffic first
tcpdump -i eth0 -w network_traffic.pcap

# Split the capture by connections
python3 split.py network_traffic.pcap

# Analyze individual connections
wireshark 192.168.1.100.12345-192.168.1.200.80.pcap
```

### Forensic Analysis
```bash
# Split a large forensic capture
python3 split.py incident_capture.pcap

# List all generated connection files
ls -la *.pcap | grep -v incident_capture.pcap

# Count unique connections
ls -1 *.pcap | grep -v incident_capture.pcap | wc -l

# Analyze suspicious connections
for file in 192.168.1.100.*-*.*.*.443.pcap; do
    echo "Analyzing HTTPS connection: $file"
    tshark -r "$file" -T fields -e tcp.stream
done
```

### Attack Analysis
```bash
# Split capture containing attack traffic
python3 split.py attack_capture.pcap

# Identify connections to common attack ports
ls *443.pcap *80.pcap *22.pcap *445.pcap

# Analyze lateral movement patterns
for file in *445.pcap; do
    echo "SMB connection analysis: $file"
    tshark -r "$file" -Y "smb2" | head -10
done

# Extract C2 communications
ls *8080.pcap *8443.pcap *4444.pcap
```

## Analysis Integration

### Post-Split Analysis
```bash
# Analyze individual connections with tshark
tshark -r connection.pcap -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport

# Extract application data
tshark -r connection.pcap -T fields -e tcp.payload

# Timeline analysis
tshark -r connection.pcap -T fields -e frame.time -e tcp.flags
```

### Connection Pattern Analysis
```bash
# Count connections per host
ls *.pcap | cut -d'.' -f1-4 | sort | uniq -c | sort -nr

# Identify port scanning patterns
ls *.pcap | grep -o '\.[0-9]\+\.pcap' | cut -d'.' -f2 | sort -n | uniq -c

# Find short-lived connections (potential scans)
for file in *.pcap; do
    packets=$(tshark -r "$file" | wc -l)
    if [ $packets -lt 10 ]; then
        echo "Short connection: $file ($packets packets)"
    fi
done
```

### Automated Processing
```bash
# Batch process multiple captures
for capture in *.pcap; do
    if [ "$capture" != "*.pcap" ]; then
        echo "Processing $capture"
        mkdir "${capture%.pcap}_split"
        cd "${capture%.pcap}_split"
        python3 ../split.py "../$capture"
        cd ..
    fi
done

# Generate connection summary
for file in *.pcap; do
    if [[ $file =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.pcap$ ]]; then
        packets=$(tshark -r "$file" 2>/dev/null | wc -l)
        size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
        echo "$file: $packets packets, $size bytes"
    fi
done
```

## Security Analysis Applications

### Incident Response
```bash
# Split incident capture for detailed analysis
python3 split.py incident.pcap

# Identify data exfiltration connections
for file in *.pcap; do
    size=$(stat -c%s "$file")
    if [ $size -gt 1000000 ]; then  # Files > 1MB
        echo "Large data transfer: $file ($size bytes)"
    fi
done

# Extract credentials from authentication flows
for file in *389.pcap *636.pcap *88.pcap; do
    echo "Authentication analysis: $file"
    tshark -r "$file" -Y "ldap or kerberos"
done
```

### Malware Analysis
```bash
# Split malware traffic capture
python3 split.py malware_traffic.pcap

# Identify C2 channels
ls *443.pcap *80.pcap *8080.pcap *53.pcap

# Analyze beaconing patterns
for file in *.pcap; do
    intervals=$(tshark -r "$file" -T fields -e frame.time_relative | 
                tail -n +2 | awk '{print $1-prev; prev=$1}' | 
                sort -n | uniq -c | sort -nr | head -5)
    if [[ ! -z "$intervals" ]]; then
        echo "Connection $file timing patterns:"
        echo "$intervals"
    fi
done
```

### Network Forensics
```bash
# Extract file transfers
for file in *21.pcap *22.pcap *80.pcap *443.pcap; do
    echo "File transfer analysis: $file"
    tshark -r "$file" --export-objects http,extracted_http/
    tshark -r "$file" --export-objects smb,extracted_smb/
done

# Identify encrypted vs unencrypted communications
for file in *.pcap; do
    encrypted=$(tshark -r "$file" -Y "tls or ssl" | wc -l)
    total=$(tshark -r "$file" | wc -l)
    if [ $total -gt 0 ]; then
        ratio=$((encrypted * 100 / total))
        echo "$file: $ratio% encrypted ($encrypted/$total packets)"
    fi
done
```

## Troubleshooting

### Common Issues
1. **Large Memory Usage**:
   - Tool streams data, but many connections can use significant memory
   - Process smaller captures or increase available RAM
   - Monitor disk space for output files

2. **File Permission Errors**:
   - Ensure write permissions in output directory
   - Check disk space availability
   - Verify input file is readable

3. **Missing Connections**:
   - Tool only processes TCP connections
   - UDP traffic is ignored (filtered out)
   - Malformed packets may be skipped

### Prerequisites
```bash
# Install required dependencies
pip install pcapy-ng

# System packages
sudo apt-get install python3-pcapy libpcap-dev  # Debian/Ubuntu
sudo yum install python3-pcapy libpcap-devel    # RHEL/CentOS
```

### Performance Optimization
```bash
# Process large files efficiently
# Monitor progress
python3 split.py large_capture.pcap &
PID=$!
while kill -0 $PID 2>/dev/null; do
    echo "Files created: $(ls *.pcap | wc -l)"
    sleep 10
done

# Clean up small/empty files
find . -name "*.pcap" -size -1k -delete
```

## Related Tools
- **sniff.py**: Live packet capture
- **sniffer.py**: Alternative packet capture implementation
- **tcpdump**: Command-line packet analyzer
- **wireshark**: GUI network analyzer
- **tshark**: Command-line wireshark
- **editcap**: Wireshark's pcap editing tool

## Technical References
- [pcapy Documentation](https://github.com/CoreSecurity/pcapy)
- [Wireshark Network Analysis](https://www.wireshark.org/docs/)
- [tcpdump and pcap Programming](https://www.tcpdump.org/)
- [Network Forensics Best Practices](https://www.sans.org/white-papers/1653/)

# Using hash authentication
python3 split.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Split large capture file by size (100MB chunks)
python3 split.py large_capture.pcap -size 100MB

# Split by time intervals (1 hour chunks)
python3 split.py network_trace.pcap -time 3600

# Split with custom naming pattern
python3 split.py evidence.pcap -prefix forensic_chunk_ -size 50MB
```

## Attack Chain Integration

### Forensic Analysis Workflow
```bash
# Step 1: Capture network traffic during attack
python3 sniff.py eth0 -pcap attack_evidence.pcap -filter "host 192.168.1.100"

# Step 2: Split large capture for analysis
python3 split.py attack_evidence.pcap -time 300 -prefix analysis_chunk_

# Step 3: Analyze individual chunks for specific indicators
for chunk in analysis_chunk_*.pcap; do
    echo "Analyzing $chunk..."
    python3 analyze_traffic.py "$chunk"
done
```

### Evidence Management for Large Investigations
```bash
# Step 1: Organize captured evidence
mkdir investigation_chunks

# Step 2: Split large evidence files by size
python3 split.py full_network_capture.pcap -size 500MB -output investigation_chunks/
```

## Prerequisites
- Python 3.x with Impacket and pcapy libraries installed
- Read access to the source PCAP file
- Write permissions in the output directory
- Sufficient disk space for split output files

## Detection Considerations
- **Event IDs**: 
  - No Windows Event IDs (forensic tool, runs on analyst system)
- **Network Indicators**: 
  - No network indicators (offline analysis tool)
- **Process Indicators**: 
  - Python processes reading large PCAP files
  - High disk I/O activity during splitting operation
- **File Indicators**: 
  - Creation of multiple smaller PCAP files
  - Temporary files during processing
  - Original PCAP file being accessed
- **Registry Indicators**: 
  - No registry modifications

## Defensive Measures
- Monitor access to sensitive PCAP files containing evidence
- Implement file integrity monitoring for forensic evidence
- Use proper chain of custody procedures for evidence handling
- Encrypt stored PCAP files to prevent unauthorized access
- Regular backup of forensic evidence
- Access logging for forensic analysis systems

## Common Issues and Troubleshooting

### File Permission Errors
```bash
# Problem: Cannot read input file or write output files
# Solution: Check file permissions and disk space
chmod 644 input.pcap
ls -la output_directory/
```

### Large File Processing Issues
```bash
# Problem: System runs out of memory with very large PCAP files
# Solution: Use system monitoring and process in smaller chunks
# Monitor system resources during processing
top -p $(pgrep -f split.py)
```

## Related Tools
- [sniff.py](sniff.md) - Capture network traffic for analysis
- [sniffer.py](sniffer.md) - Alternative packet capture tool
- [pcapfile.py](pcapfile.md) - PCAP file manipulation utilities
- Wireshark - GUI-based packet analysis tool

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
