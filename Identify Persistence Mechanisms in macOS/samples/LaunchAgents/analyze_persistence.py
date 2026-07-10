#!/usr/bin/env python3
import os
import plistlib
import json
from datetime import datetime

class MacOSPersistenceAnalyzer:
    def __init__(self, base_path):
        self.base_path = base_path
        self.persistence_locations = [
            'LaunchAgents',
            'LaunchDaemons',
            'System/Library/LaunchAgents',
            'System/Library/LaunchDaemons'
        ]
        self.findings = []
    
    def analyze_plist(self, plist_path):
        try:
            with open(plist_path, 'rb') as f:
                plist_data = plistlib.load(f)
            
            finding = {
                'file': plist_path,
                'type': 'Launch Agent/Daemon',
                'label': plist_data.get('Label', 'Unknown'),
                'program': plist_data.get('ProgramArguments', []),
                'run_at_load': plist_data.get('RunAtLoad', False),
                'keep_alive': plist_data.get('KeepAlive', False),
                'start_interval': plist_data.get('StartInterval', None),
                'suspicious_indicators': []
            }
            
            # Check for suspicious indicators
            program_args = ' '.join(finding['program'])
            if any(indicator in program_args.lower() for indicator in 
                   ['curl', 'wget', 'nc', 'netcat', '/tmp/', 'bash -c', 'python -c']):
                finding['suspicious_indicators'].append('Suspicious command execution')
            
            if finding['run_at_load'] and finding['keep_alive']:
                finding['suspicious_indicators'].append('Persistent execution enabled')
            
            return finding
        except Exception as e:
            return {'file': plist_path, 'error': str(e)}
    
    def scan_persistence_locations(self):
        for location in self.persistence_locations:
            full_path = os.path.join(self.base_path, location)
            if os.path.exists(full_path):
                for file in os.listdir(full_path):
                    if file.endswith('.plist'):
                        file_path = os.path.join(full_path, file)
                        finding = self.analyze_plist(file_path)
                        self.findings.append(finding)
    
    def generate_report(self):
        print("=== macOS Persistence Analysis Report ===")
        print(f"Analysis Time: {datetime.now()}")
        print(f"Total Findings: {len(self.findings)}\n")
        
        for i, finding in enumerate(self.findings, 1):
            print(f"Finding #{i}:")
            print(f"  File: {finding['file']}")
            print(f"  Type: {finding.get('type', 'Unknown')}")
            print(f"  Label: {finding.get('label', 'N/A')}")
            print(f"  Program: {finding.get('program', 'N/A')}")
            
            if finding.get('suspicious_indicators'):
                print(f"  Suspicious Indicators:")
                for indicator in finding['suspicious_indicators']:
                    print(f"    - {indicator}")
            print()

if __name__ == "__main__":
    analyzer = MacOSPersistenceAnalyzer("samples")
    analyzer.scan_persistence_locations()
    analyzer.generate_report()
