#!/usr/bin/env python3
import re
import os
from datetime import datetime
from collections import defaultdict

class LogAnalyzer:
    def __init__(self, log_directory):
        self.log_directory = log_directory
        self.suspicious_patterns = [
            r'launchd.*spawned.*com\..*\.agent',
            r'launchd.*spawned.*com\..*\.daemon',
            r'Establishing connection.*:\d+',
            r'Downloading.*from.*',
            r'Creating launch agent',
            r'postinstall.*\.plist'
        ]
        self.timeline = []
    
    def analyze_log_file(self, log_file):
        findings = []
        try:
            with open(log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    for pattern in self.suspicious_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({
                                'file': log_file,
                                'line': line_num,
                                'content': line.strip(),
                                'pattern': pattern,
                                'timestamp': self.extract_timestamp(line)
                            })
        except Exception as e:
            print(f"Error analyzing {log_file}: {e}")
        
        return findings
    
    def extract_timestamp(self, log_line):
        # Simple timestamp extraction for demo logs
        timestamp_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        match = re.search(timestamp_pattern, log_line)
        return match.group(1) if match else "Unknown"
    
    def scan_logs(self):
        all_findings = []
        for root, dirs, files in os.walk(self.log_directory):
            for file in files:
                if file.endswith('.log'):
                    log_path = os.path.join(root, file)
                    findings = self.analyze_log_file(log_path)
                    all_findings.extend(findings)
        
        return sorted(all_findings, key=lambda x: x['timestamp'])
    
    def generate_timeline_report(self, findings):
        print("=== Log Analysis Timeline Report ===")
        print(f"Analysis Time: {datetime.now()}")
        print(f"Total Suspicious Log Entries: {len(findings)}\n")
        
        for i, finding in enumerate(findings, 1):
            print(f"Entry #{i}:")
            print(f"  Timestamp: {finding['timestamp']}")
            print(f"  File: {finding['file']}")
            print(f"  Line: {finding['line']}")
            print(f"  Content: {finding['content']}")
            print(f"  Matched Pattern: {finding['pattern']}")
            print()

if __name__ == "__main__":
    analyzer = LogAnalyzer("samples/Library/Logs")
    findings = analyzer.scan_logs()
    analyzer.generate_timeline_report(findings)
