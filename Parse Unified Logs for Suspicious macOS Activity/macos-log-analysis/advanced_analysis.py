#!/usr/bin/env python3
import re
import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta

class MacOSLogAnalyzer:
    def __init__(self):
        self.threat_patterns = {
            'malware_indicators': [
                r'malware|trojan|virus|backdoor',
                r'suspicious.*app|unknown.*binary',
                r'hijack.*endpoint|service.*hijack'
            ],
            'persistence_mechanisms': [
                r'launchd.*plist|launch.*agent|launch.*daemon',
                r'cron|periodic|startup.*item',
                r'login.*hook|authorization.*plugin'
            ],
            'privilege_escalation': [
                r'sudo.*root|su.*root',
                r'setuid|setgid',
                r'authorization.*bypass'
            ],
            'data_exfiltration': [
                r'network.*outbound.*deny',
                r'file.*read.*sensitive',
                r'keychain.*access.*unauthorized'
            ]
        }
    
    def parse_log_entry(self, line):
        """Parse individual log entry"""
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[-+]\d{4}) (0x[0-9a-f]+) (\w+) (0x[0-9a-f]+) (\d+) (\d+) ([^:]+): (.+)'
        match = re.match(pattern, line.strip())
        
        if match:
            return {
                'timestamp': match.group(1),
                'thread_id': match.group(2),
                'log_level': match.group(3),
                'activity_id': match.group(4),
                'pid': int(match.group(5)),
                'ttl': int(match.group(6)),
                'process': match.group(7),
                'message': match.group(8),
                'raw_line': line.strip()
            }
        return None
    
    def detect_threats(self, entries):
        """Detect various threat categories"""
        threats = defaultdict(list)
        
        for entry in entries:
            message_lower = entry['message'].lower()
            process_lower = entry['process'].lower()
            combined_text = f"{message_lower} {process_lower}"
            
            for threat_type, patterns in self.threat_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, combined_text):
                        threats[threat_type].append({
                            'entry': entry,
                            'pattern_matched': pattern,
                            'confidence': self.calculate_confidence(pattern, combined_text)
                        })
        
        return threats
    
    def calculate_confidence(self, pattern, text):
        """Calculate confidence score for threat detection"""
        base_score = 0.5
        
        # Increase confidence for specific indicators
        if 'malware' in text or 'trojan' in text:
            base_score += 0.3
        if 'deny' in text or 'failed' in text:
            base_score += 0.2
        if 'root' in text or 'sudo' in text:
            base_score += 0.1
        
        return min(base_score, 1.0)
    
    def timeline_analysis(self, entries):
        """Analyze timeline for suspicious patterns"""
        timeline = defaultdict(list)
        
        for entry in entries:
            timestamp = entry['timestamp'][:19]  # Remove timezone for grouping
            timeline[timestamp].append(entry)
        
        # Look for rapid successive events (potential automated attacks)
        suspicious_bursts = []
        for timestamp, events in timeline.items():
            if len(events) > 3:  # More than 3 events in same second
                suspicious_bursts.append({
                    'timestamp': timestamp,
                    'event_count': len(events),
                    'events': events
                })
        
        return suspicious_bursts
    
    def process_analysis(self, entries):
        """Analyze process behavior patterns"""
        process_stats = defaultdict(lambda: {
            'count': 0,
            'error_count': 0,
            'privilege_operations': 0,
            'network_operations': 0
        })
        
        for entry in entries:
            process = entry['process']
            message = entry['message'].lower()
            
            process_stats[process]['count'] += 1
            
            if entry['log_level'] == 'Error':
                process_stats[process]['error_count'] += 1
            
            if 'sudo' in message or 'root' in message:
                process_stats[process]['privilege_operations'] += 1
            
            if 'network' in message:
                process_stats[process]['network_operations'] += 1
        
        # Identify suspicious processes
        suspicious_processes = []
        for process, stats in process_stats.items():
            risk_score = 0
            
            # High error rate
            if stats['count'] > 0 and stats['error_count'] / stats['count'] > 0.5:
                risk_score += 30
            
            # High privilege operations
            if stats['privilege_operations'] > 2:
                risk_score += 40
            
            # Network operations with errors
            if stats['network_operations'] > 0 and stats['error_count'] > 0:
                risk_score += 30
            
            if risk_score > 50:
                suspicious_processes.append({
                    'process': process,
                    'risk_score': risk_score,
                    'stats': stats
                })
        
        return suspicious_processes

def main():
    analyzer = MacOSLogAnalyzer()
    
    # Analyze both log files
    all_entries = []
    
    for log_file in ['sample_unified.log', 'suspicious_activity.log']:
        print(f"\nAnalyzing {log_file}...")
        
        with open(log_file, 'r') as f:
            for line in f:
                entry = analyzer.parse_log_entry(line)
                if entry:
                    all_entries.append(entry)
    
    print(f"\nTotal entries analyzed: {len(all_entries)}")
    
    # Threat detection
    threats = analyzer.detect_threats(all_entries)
    print(f"\n=== THREAT ANALYSIS ===")
    for threat_type, detections in threats.items():
        print(f"\n{threat_type.upper().replace('_', ' ')} ({len(detections)} detections):")
        for detection in detections:
            entry = detection['entry']
            print(f"  - Process: {entry['process']}")
            print(f"    Time: {entry['timestamp']}")
            print(f"    Message: {entry['message']}")
            print(f"    Confidence: {detection['confidence']:.2f}")
            print()
    
    # Timeline analysis
    bursts = analyzer.timeline_analysis(all_entries)
    if bursts:
        print(f"\n=== SUSPICIOUS ACTIVITY BURSTS ===")
        for burst in bursts:
            print(f"Time: {burst['timestamp']} - {burst['event_count']} events")
    
    # Process analysis
    suspicious_procs = analyzer.process_analysis(all_entries)
    if suspicious_procs:
        print(f"\n=== SUSPICIOUS PROCESSES ===")
        for proc in suspicious_procs:
            print(f"Process: {proc['process']}")
            print(f"Risk Score: {proc['risk_score']}")
            print(f"Stats: {proc['stats']}")
            print()

if __name__ == "__main__":
    main()
