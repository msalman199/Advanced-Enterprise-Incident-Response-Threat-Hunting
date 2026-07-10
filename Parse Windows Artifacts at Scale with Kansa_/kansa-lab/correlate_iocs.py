#!/usr/bin/env python3
import pandas as pd
import json
from datetime import datetime
import os

class IOCCorrelator:
    def __init__(self):
        self.iocs = []
        self.timeline = []
    
    def add_ioc(self, ioc_type, value, source, computer, timestamp=None, severity="Medium"):
        """Add an IOC to the correlation database"""
        ioc = {
            'type': ioc_type,
            'value': value,
            'source': source,
            'computer': computer,
            'timestamp': timestamp or datetime.now().isoformat(),
            'severity': severity
        }
        self.iocs.append(ioc)
        self.timeline.append(ioc)
    
    def analyze_all_artifacts(self):
        """Analyze all artifact types and correlate IOCs"""
        print("=== IOC Correlation Analysis ===")
        
        # Analyze Event Logs
        self.analyze_event_logs()
        
        # Analyze Registry
        self.analyze_registry()
        
        # Analyze Processes
        self.analyze_processes()
        
        # Generate correlation report
        self.generate_correlation_report()
    
    def analyze_event_logs(self):
        """Extract IOCs from Event Logs"""
        log_file = "/home/ubuntu/kansa-lab/sample-data/eventlogs/Security.evtx.csv"
        if not os.path.exists(log_file):
            return
        
        df = pd.read_csv(log_file)
        
        # Failed logons (potential brute force)
        failed_logons = df[df['Id'] == 4625]
        for _, row in failed_logons.iterrows():
            self.add_ioc(
                'failed_logon',
                row['UserId'],
                'Security Event Log',
                row['MachineName'],
                row['TimeCreated'],
                'High'
            )
        
        # Explicit credential usage (lateral movement)
        explicit_creds = df[df['Id'] == 4648]
        for _, row in explicit_creds.iterrows():
            self.add_ioc(
                'explicit_credentials',
                row['UserId'],
                'Security Event Log',
                row['MachineName'],
                row['TimeCreated'],
                'Medium'
            )
    
    def analyze_registry(self):
        """Extract IOCs from Registry"""
        reg_file = "/home/ubuntu/kansa-lab/sample-data/registry/autorun-entries.csv"
        if not os.path.exists(reg_file):
            return
        
        df = pd.read_csv(reg_file)
        
        for _, row in df.iterrows():
            value_lower = row['Value'].lower()
            
            # Suspicious autorun entries
            if any(path in value_lower for path in ['temp', 'tmp', 'malware']):
                self.add_ioc(
                    'suspicious_autorun',
                    row['Value'],
                    'Registry Autorun',
                    row['ComputerName'],
                    severity='High'
                )
    
    def analyze_processes(self):
        """Extract IOCs from Process data"""
        proc_file = "/home/ubuntu/kansa-lab/sample-data/processes/running-processes.csv"
        if not os.path.exists(proc_file):
            return
        
        df = pd.read_csv(proc_file)
        
        for _, row in df.iterrows():
            cmdline_lower = str(row['CommandLine']).lower()
            
            # Suspicious PowerShell usage
            if 'powershell' in row['ProcessName'].lower() and 'bypass' in cmdline_lower:
                self.add_ioc(
                    'suspicious_powershell',
                    row['CommandLine'],
                    'Process List',
                    row['ComputerName'],
                    row['CreationDate'],
                    'High'
                )
    
    def generate_correlation_report(self):
        """Generate comprehensive IOC correlation report"""
        print(f"\n=== IOC CORRELATION REPORT ===")
        print(f"Total IOCs Identified: {len(self.iocs)}")
        
        # Group by computer
        computers = {}
        for ioc in self.iocs:
            comp = ioc['computer']
            if comp not in computers:
                computers[comp] = []
            computers[comp].append(ioc)
        
        print(f"Affected Computers: {len(computers)}")
        
        # Severity breakdown
        severity_counts = {}
        for ioc in self.iocs:
            sev = ioc['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print("\nSeverity Breakdown:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")
        
        # Computer-by-computer analysis
        print("\n=== PER-COMPUTER ANALYSIS ===")
        for computer, iocs in computers.items():
            print(f"\n🖥️  {computer} ({len(iocs)} IOCs)")
            
            high_severity = [ioc for ioc in iocs if ioc['severity'] == 'High']
            if high_severity:
                print(f"  ⚠️  HIGH PRIORITY: {len(high_severity)} critical IOCs")
            
            for ioc in iocs:
                severity_icon = "🚨" if ioc['severity'] == 'High' else "⚠️" if ioc['severity'] == 'Medium' else "ℹ️"
                print(f"    {severity_icon} {ioc['type']}: {ioc['value'][:50]}...")
        
        # Timeline analysis
        print(f"\n=== TIMELINE ANALYSIS ===")
        sorted_timeline = sorted(self.timeline, key=lambda x: x['timestamp'])
        
        print("Chronological IOC sequence:")
        for ioc in sorted_timeline:
            print(f"  {ioc['timestamp'][:19]} | {ioc['computer']} | {ioc['type']} | {ioc['severity']}")
        
        # Save detailed report
        report_file = "/home/ubuntu/kansa-lab/results/ioc_correlation_report.json"
        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump({
                'summary': {
                    'total_iocs': len(self.iocs),
                    'affected_computers': len(computers),
                    'severity_breakdown': severity_counts
                },
                'iocs': self.iocs,
                'timeline': sorted_timeline
            }, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")

if __name__ == "__main__":
    correlator = IOCCorrelator()
    correlator.analyze_all_artifacts()
