# mqtt_check.py

## Overview
`mqtt_check.py` is an MQTT protocol testing tool in the Impacket suite. This tool is categorized under Protocol Testing and provides functionality for testing MQTT broker authentication and connection capabilities.

## Detailed Description
`mqtt_check.py` is a simple MQTT authentication checker that can be used to test login credentials against MQTT brokers. The tool implements the MQTT protocol to establish connections and verify authentication mechanisms. It supports both standard and SSL/TLS encrypted connections, making it useful for testing MQTT security configurations.

The tool is designed as a foundation for MQTT security testing and can be easily extended into a credential brute-forcer. It provides clear feedback on connection attempts and authentication results, making it valuable for both security testing and troubleshooting MQTT deployments.

### Key Features:
- **MQTT Authentication Testing**: Test username/password combinations against MQTT brokers
- **SSL/TLS Support**: Connect to encrypted MQTT brokers (MQTTS)
- **Client ID Customization**: Specify custom client identifiers for testing
- **Connection Verification**: Verify broker accessibility and authentication status
- **Protocol Compliance**: Implements standard MQTT connection procedures
- **Extensible Design**: Easy to extend for brute-force testing scenarios

### Technical Details:
- Implements MQTT v3.1.1 protocol for connection establishment
- Supports both TCP and SSL/TLS transport layers
- Uses CONNECT packet for authentication testing
- Handles CONNACK responses for authentication status
- Compatible with standard MQTT brokers (Mosquitto, HiveMQ, etc.)

## Command Line Options

```
usage: mqtt_check.py [--help] [-client-id CLIENT_ID] [-ssl] [-port PORT] [-debug] [-ts] target

Required Arguments:
  target                [[domain/]username[:password]@]<targetName>

Connection Options:
  -client-id CLIENT_ID  Client ID used when authenticating (default: random)
  -ssl                  Turn SSL on for encrypted connection
  -port PORT            Port to connect to (default: 1883)

Debug Options:
  -debug                Turn DEBUG output ON
  -ts                   Add timestamp to every logging output
  --help                Show help message and exit
```

## Usage Examples

### Basic MQTT Testing
```bash
# Test anonymous connection (no credentials)
python3 mqtt_check.py mqtt.broker.com

# Test with username and password
python3 mqtt_check.py user:password@mqtt.broker.com

# Test with domain/username format
python3 mqtt_check.py domain.com/user:password@mqtt.broker.com
```

### SSL/TLS Testing
```bash
# Test encrypted MQTT connection (MQTTS)
python3 mqtt_check.py user:password@mqtts.broker.com -ssl -port 8883

# Test SSL with custom port
python3 mqtt_check.py user:password@secure.mqtt.com -ssl -port 8884
```

### Custom Client ID Testing
```bash
# Test with specific client ID
python3 mqtt_check.py user:password@mqtt.broker.com -client-id "TestClient123"

# Test with device-like client ID
python3 mqtt_check.py user:password@iot.broker.com -client-id "Device001"
```

### Port Scanning and Testing
```bash
# Test common MQTT ports
python3 mqtt_check.py user:password@mqtt.broker.com -port 1883  # Standard
python3 mqtt_check.py user:password@mqtt.broker.com -port 8883 -ssl  # SSL
python3 mqtt_check.py user:password@mqtt.broker.com -port 8884 -ssl  # Alt SSL
python3 mqtt_check.py user:password@mqtt.broker.com -port 8885  # WebSocket
```

### IoT Device Testing
```bash
# Test IoT device credentials
python3 mqtt_check.py device001:defaultpass@iot.company.com

# Test with MAC address as client ID
python3 mqtt_check.py device:password@iot.broker.com -client-id "AA:BB:CC:DD:EE:FF"

# Test with serial number as client ID
python3 mqtt_check.py admin:admin@mqtt.device.local -client-id "SN123456789"
```

### Debugging and Troubleshooting
```bash
# Enable debug output for connection analysis
python3 mqtt_check.py user:password@mqtt.broker.com -debug

# Test with timestamps for timing analysis
python3 mqtt_check.py user:password@mqtt.broker.com -debug -ts
```

## Attack Integration

### Credential Testing
```bash
# Test default credentials
python3 mqtt_check.py admin:admin@192.168.1.100
python3 mqtt_check.py admin:password@192.168.1.100
python3 mqtt_check.py mqtt:mqtt@192.168.1.100
python3 mqtt_check.py test:test@192.168.1.100

# Test empty password
python3 mqtt_check.py admin:@192.168.1.100
python3 mqtt_check.py guest:@192.168.1.100
```

### IoT Device Enumeration
```bash
# Test common IoT device patterns
python3 mqtt_check.py device001:12345@192.168.1.100
python3 mqtt_check.py sensor:sensor@192.168.1.100
python3 mqtt_check.py camera:camera@192.168.1.100
python3 mqtt_check.py thermostat:1234@192.168.1.100
```

### Brute Force Framework
```bash
# Create simple brute force script
#!/bin/bash
for user in admin guest mqtt test device; do
    for pass in admin password 123456 mqtt guest; do
        echo "Testing $user:$pass"
        python3 mqtt_check.py $user:$pass@$1
    done
done
```

### Network Discovery
```bash
# Test multiple hosts for MQTT services
for host in 192.168.1.{1..254}; do
    echo "Testing $host"
    timeout 5 python3 mqtt_check.py admin:admin@$host 2>/dev/null && echo "$host: MQTT accessible"
done
```

## Security Implications

### Common Vulnerabilities
1. **Default Credentials**: Many IoT devices ship with default MQTT credentials
2. **Weak Passwords**: Simple passwords often used for device authentication
3. **No Authentication**: Some brokers configured without authentication
4. **Unencrypted Connections**: MQTT traffic transmitted in plaintext
5. **Client ID Enumeration**: Predictable client IDs can be enumerated

### Attack Vectors
- **Credential Brute Force**: Automated testing of common credentials
- **IoT Device Compromise**: Gaining access to connected devices
- **Message Interception**: Subscribing to sensitive topics
- **Command Injection**: Publishing malicious commands to devices
- **Denial of Service**: Overwhelming broker with connections

### Detection Methods
```bash
# Monitor MQTT connection attempts
tcpdump -i any port 1883 or port 8883

# Check for failed authentication attempts in broker logs
grep "authentication failed" /var/log/mosquitto/mosquitto.log

# Monitor for unusual client IDs or connection patterns
grep "Client.*connected" /var/log/mosquitto/mosquitto.log
```

## Troubleshooting

### Common Issues
1. **Connection Refused**: MQTT broker not running or port blocked
2. **Authentication Failed**: Invalid credentials or broker config
3. **SSL Errors**: Certificate issues or incorrect SSL configuration
4. **Timeout**: Network connectivity issues or broker overload

### Debugging Steps
```bash
# Test network connectivity
telnet mqtt.broker.com 1883
openssl s_client -connect mqtts.broker.com:8883  # For SSL

# Verify MQTT service
nmap -p 1883,8883 mqtt.broker.com

# Test with mosquitto client tools
mosquitto_pub -h mqtt.broker.com -t test -m "hello"
mosquitto_sub -h mqtt.broker.com -t test
```

### Common MQTT Ports
- **1883**: Standard MQTT (unencrypted)
- **8883**: MQTT over SSL/TLS (MQTTS)
- **8884**: Alternative SSL port
- **8885**: MQTT over WebSocket
- **8886**: MQTT over WebSocket Secure

## Related Tools
- **mqtt_publisher**: Publishing messages to MQTT topics
- **mqtt_subscriber**: Subscribing to MQTT topics
- **nmap**: Network scanning and service detection
- **mosquitto_pub/sub**: Standard MQTT client tools
- **Metasploit MQTT modules**: Advanced MQTT exploitation

## Technical References
- [MQTT Protocol Specification](http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html)
- [MQTT Security Best Practices](https://www.hivemq.com/blog/mqtt-security-fundamentals/)
- [IoT Security Testing Guide](https://www.owasp.org/index.php/IoT_Security_Testing_Guide)
- [MQTT Broker Security](https://mosquitto.org/documentation/authentication-methods/)

# Using hash authentication
python3 mqtt_check.py -hashes :ntlmhash domain.com/user@target.domain.com
```

### Advanced Usage
```bash
# Test MQTT broker with custom client ID and credentials
python3 mqtt_check.py -host 192.168.1.100 -port 1883 -client-id "security_test" -username admin -password secret

# Check for anonymous access across multiple brokers
for broker in $(cat mqtt_brokers.txt); do
    echo "Testing $broker..."
    python3 mqtt_check.py -host "$broker" -port 1883
done

# Test with SSL/TLS enabled brokers
python3 mqtt_check.py -host secure-mqtt.example.com -port 8883 -ssl
```

## Attack Chain Integration

### IoT Network Reconnaissance
```bash
# Step 1: Discover MQTT brokers on the network
nmap -p 1883,8883 --script mqtt-subscribe 192.168.1.0/24

# Step 2: Test each discovered broker for security issues
python3 mqtt_check.py -host 192.168.1.50 -port 1883

# Step 3: Exploit identified vulnerabilities
mosquitto_pub -h 192.168.1.50 -t "device/control" -m "malicious_command"
```

### Industrial Control System Testing
```bash
# Step 1: Identify MQTT infrastructure in SCADA networks
python3 mqtt_check.py -host scada-broker.local -port 1883

# Step 2: Monitor critical control topics
mosquitto_sub -h scada-broker.local -t "control/+/status" -v

# Step 3: Document findings for further analysis
echo "MQTT broker findings" > mqtt_report.txt
```

## Prerequisites
- Network access to target MQTT brokers on ports 1883 (unencrypted) or 8883 (SSL/TLS)
- Python 3.x with Impacket installed
- Optional: Valid MQTT credentials for authenticated brokers
- Optional: mosquitto-clients for additional testing

## Detection Considerations
- **Event IDs**: 
  - No Windows Event IDs (MQTT is typically on IoT/Linux systems)
  - Custom application logs on MQTT broker systems
- **Network Indicators**: 
  - Connections to MQTT ports (1883, 8883)
  - MQTT protocol traffic with CONNECT packets
  - Multiple authentication attempts from single source
- **Process Indicators**: 
  - MQTT broker processes handling new connections
  - Python processes attempting MQTT connections
- **File Indicators**: 
  - MQTT broker log files showing connection attempts
  - Client connection logs
- **Registry Indicators**: 
  - No registry modifications (Linux/IoT systems typically)

## Defensive Measures
- Enable MQTT broker authentication and authorization
- Implement SSL/TLS encryption for MQTT traffic
- Monitor and log all MQTT connection attempts
- Use strong, unique credentials for MQTT clients
- Network segmentation to isolate MQTT infrastructure
- Regular security updates for MQTT broker software

## Common Issues and Troubleshooting

### Connection Refused Errors
```bash
# Problem: Cannot connect to MQTT broker
# Solution: Verify broker is running and accessible
nmap -p 1883,8883 target_mqtt_broker
telnet target_mqtt_broker 1883
```

### Authentication Failures
```bash
# Problem: Invalid credentials or authentication required
# Solution: Verify credentials or test anonymous access
python3 mqtt_check.py target_broker  # Test anonymous
python3 mqtt_check.py user:pass@target_broker  # Test with credentials
```

## Related Tools
- [sniff.py](sniff.md) - Capture MQTT traffic for analysis
- mosquitto_pub/mosquitto_sub - MQTT client tools for testing
- [sniffer.py](sniffer.md) - Network traffic analysis
- nmap - Network discovery and port scanning

---

*Note: This documentation is a template. Please refer to the actual tool's help output and source code for complete and accurate information.*
