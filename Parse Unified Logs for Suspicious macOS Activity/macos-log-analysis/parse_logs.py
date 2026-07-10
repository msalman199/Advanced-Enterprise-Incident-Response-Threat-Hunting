#!/usr/bin/env python3
import re
import json
from datetime import datetime

def parse_unified_log(log_file):
    """Parse macOS unified log format"""
    parsed_entries = []
    
    with open(log_file, 'r') as f:
        for line in f:
            # Parse unified log format
            pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[-+]\d{4}) (0x[0-9a-f]+) (\w+) (0x[0-9a-f]+) (\d+) (\d+) ([^:]+): (.+)'
            match = re.match(pattern, line.strip())
            
            if match:
                entry = {
                    'timestamp': match.group(1),
                    'thread_id': match.group(2),
                    'log_level': match.group(3),
                    'activity_id': match.group(4),
                    'pid': int(match.group(5)),
                    'ttl': int(match.group(6)),
                    'process': match.group(7),
                    'message': match.group(8)
                }
                parsed_entries.append(entry)
    
    return parsed_entries

def analyze_suspicious_patterns(entries):
    """Identify suspicious patterns in log entries"""
    suspicious_indicators = []
    
    for entry in entries:
        message = entry['message'].lower()
        process = entry['process'].lower()
        
        # Check for authentication failures
        if 'failed password' in message or 'authentication failed' in message:
            suspicious_indicators.append({
                'type': 'Authentication Failure',
                'severity': 'Medium',
                'entry': entry,
                'reason': 'Failed authentication attempt detected'
            })
        
        # Check for privilege escalation
        if 'sudo' in process and 'root' in message:
            suspicious_indicators.append({
                'type': 'Privilege Escalation',
                'severity': 'High',
                'entry': entry,
                'reason': 'Sudo command executed with root privileges'
            })
        
        # Check for sandbox violations
        if 'sandbox' in process and 'deny' in message:
            suspicious_indicators.append({
                'type': 'Sandbox Violation',
                'severity': 'High',
                'entry': entry,
                'reason': 'Process attempted unauthorized system access'
            })
        
        # Check for code signature failures
        if 'code signature' in message or 'not notarized' in message:
            suspicious_indicators.append({
                'type': 'Code Signature Issue',
                'severity': 'Medium',
                'entry': entry,
                'reason': 'Unsigned or unnotarized binary detected'
            })
        
        # Check for network anomalies
        if 'network-outbound' in message and 'deny' in message:
            suspicious_indicators.append({
                'type': 'Network Anomaly',
                'severity': 'High',
                'entry': entry,
                'reason': 'Blocked outbound network connection'
            })
    
    return suspicious_indicators

# Main execution
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 parse_logs.py <log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    
    # Parse logs
    entries = parse_unified_log(log_file)
    print(f"Parsed {len(entries)} log entries")
    
    # Analyze for suspicious patterns
    suspicious = analyze_suspicious_patterns(entries)
    
    print(f"\nFound {len(suspicious)} suspicious indicators:")
    for indicator in suspicious:
        print(f"\n[{indicator['severity']}] {indicator['type']}")
        print(f"Process: {indicator['entry']['process']}")
        print(f"Time: {indicator['entry']['timestamp']}")
        print(f"Message: {indicator['entry']['message']}")
        print(f"Reason: {indicator['reason']}")
        print("-" * 60)
