#!/usr/bin/env python3
import os
import json
import plistlib
from datetime import datetime
from analyze_persistence import MacOSPersistenceAnalyzer
from analyze_logs import LogAnalyzer

class PersistenceTimelineGenerator:
    def __init__(self, base_path):
        self.base_path = base_path
        self.timeline_events = []
    
    def collect_persistence_artifacts(self):
        analyzer = MacOSPersistenceAnalyzer(self.base_path)
        analyzer.scan_persistence_locations()
        
        for finding in analyzer.findings:
            if 'error' not in finding:
                event = {
                    'timestamp': self.get_file_timestamp(finding['file']),
                    'event_type': 'Persistence Mechanism',
                    'source': finding['file'],
                    'details': {
                        'label': finding['label'],
                        'program': finding['program'],
                        'suspicious_indicators': finding['suspicious_indicators']
                    },
                    'severity': 'HIGH' if finding['suspicious_indicators'] else 'MEDIUM'
                }
                self.timeline_events.append(event)
    
    def collect_log_events(self):
        log_analyzer = LogAnalyzer(os.path.join(self.base_path, "Library/Logs"))
        findings = log_analyzer.scan_logs()
        
        for finding in findings:
            event = {
                'timestamp': finding['timestamp'],
                'event_type': 'Log Entry',
                'source': finding['file'],
                'details': {
                    'content': finding['content'],
                    'pattern': finding['pattern'],
                    'line': finding['line']
                },
                'severity': 'HIGH'
            }
            self.timeline_events.append(event)
    
    def get_file_timestamp(self, file_path):
        try:
            stat = os.stat(file_path)
            return datetime.fromtimestamp(stat.st_mtime).strftime("%b %d %H:%M:%S")
        except:
            return "Unknown"
    
    def generate_timeline_report(self):
        # Sort events by timestamp (simplified for demo)
        sorted_events = sorted(self.timeline_events, 
                             key=lambda x: x['timestamp'] if x['timestamp'] != "Unknown" else "")
        
        print("=== Comprehensive Persistence Timeline ===")
        print(f"Generated: {datetime.now()}")
        print(f"Total Events: {len(sorted_events)}")
        print("=" * 50)
        
        for i, event in enumerate(sorted_events, 1):
            print(f"\nEvent #{i} [{event['severity']}]")
            print(f"Timestamp: {event['timestamp']}")
            print(f"Type: {event['event_type']}")
            print(f"Source: {event['source']}")
            print("Details:")
            
            for key, value in event['details'].items():
                if isinstance(value, list) and value:
                    print(f"  {key}:")
                    for item in value:
                        print(f"    - {item}")
                elif value:
                    print(f"  {key}: {value}")
        
        print("\n" + "=" * 50)
        self.generate_summary()
    
    def generate_summary(self):
        high_severity = len([e for e in self.timeline_events if e['severity'] == 'HIGH'])
        medium_severity = len([e for e in self.timeline_events if e['severity'] == 'MEDIUM'])
        
        print("SUMMARY:")
        print(f"High Severity Events: {high_severity}")
        print(f"Medium Severity Events: {medium_severity}")
        print(f"Total Persistence Mechanisms: {len([e for e in self.timeline_events if e['event_type'] == 'Persistence Mechanism'])}")
        print(f"Total Log Entries: {len([e for e in self.timeline_events if e['event_type'] == 'Log Entry'])}")

if __name__ == "__main__":
    timeline_gen = PersistenceTimelineGenerator("samples")
    timeline_gen.collect_persistence_artifacts()
    timeline_gen.collect_log_events()
    timeline_gen.generate_timeline_report()
