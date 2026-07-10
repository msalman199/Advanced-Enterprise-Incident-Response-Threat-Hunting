#!/usr/bin/env python3
import json
import re
from datetime import datetime
from collections import defaultdict

class ArtifactCorrelator:
    def __init__(self):
        self.artifacts = {
            'processes': {},
            'network_connections': {},
            'file_operations': {},
            'user_activities': {}
        }
    
    def create_sample_artifacts(self):
        """Create sample system artifacts for correlation"""
        # Sample process artifacts
        self.artifacts['processes'] = {
            '1240': {
                'name': 'chrome',
                'path': '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                'parent_pid': '1',
                'user': 'admin',
                'start_time': '2024-01-15 10:25:00',
                'suspicious_flags': ['sandbox_violation']
            },
            '2003': {
                'name': 'unknown',
                'path': '/tmp/suspicious_binary',
                'parent_pid': '1',
                'user': 'root',
                'start_time': '2024-01-15 11:10:00',
                'suspicious_flags': ['unsigned', 'temp_location']
            },
            '2006': {
                'name': 'malicious_app',
                'path': '/Applications/Suspicious App.app/Contents/MacOS/main',
                'parent_pid': '1',
                'user': 'admin',
                'start_time': '2024-01-15 11:14:00',
                'suspicious_flags': ['not_notarized', 'keychain_access']
            }
        }
        
        # Sample network artifacts
        self.artifacts['network_connections'] = {
            '192.168.1.100:22': {
                'type': 'inbound',
                'protocol': 'tcp',
                'service': 'ssh',
                'first_seen': '2024-01-15 10:30:17',
                'attempts': 5,
                'status': 'failed'
            },
            '192.168.1.200:4444': {
                'type': 'outbound',
                'protocol': 'tcp',
                'service': 'unknown',
                'first_seen': '2024-01-15 11:15:31',
                'attempts': 1,
                'status': 'blocked'
            }
        }
        
        # Sample file artifacts
        self.artifacts['file_operations'] = {
            '/System/Library/LaunchDaemons/': {
                'operation': 'write_attempt',
                'process': 'chrome',
                'result': 'denied',
                'timestamp': '2024-01-15 10:30:20'
            },
            '/tmp/malicious_binary': {
                'operation': 'signature_verification',
                'process': 'SecurityServer',
                'result': 'failed',
                'timestamp': '2024-01-15 10:30:22'
            },
            '/Users/backdoor': {
                'operation': 'user_creation',
                'process': 'dscl',
                'result': 'attempted',
                'timestamp': '2024-01-15 11:15:34'
            }
        }
    
    def correlate_with_logs(self, log_entries):
        """Correlate log entries with system artifacts"""
        correlations = []
        
        for entry in log_entries:
            pid = str(entry['pid'])
            message = entry['message']
            process = entry['process']
            
            correlation = {
                'log_entry': entry,
                'correlated_artifacts': []
            }
            
            # Correlate with process artifacts
            if pid in self.artifacts['processes']:
                proc_artifact = self.artifacts['processes'][pid]
                correlation['correlated_artifacts'].append({
                    'type': 'process',
                    'artifact': proc_artifact,
                    'correlation_strength': self.calculate_correlation_strength(entry, proc_artifact)
                })
            
            # Correlate with network artifacts
            for network_key, network_artifact in self.artifacts['network_connections'].items():
                if network_key.split(':')[0] in message:
                    correlation['correlated_artifacts'].append({
                        'type': 'network',
                        'artifact': network_artifact,
                        'correlation_strength': 0.8
                    })
            
            # Correlate with file artifacts
            for file_path, file_artifact in self.artifacts['file_operations'].items():
                if file_path in message:
                    correlation['correlated_artifacts'].append({
                        'type': 'file',
                        'artifact': file_artifact,
                        'correlation_strength': 0.9
                    })
            
            if correlation['correlated_artifacts']:
                correlations.append(correlation)
        
        return correlations
    
    def calculate_correlation_strength(self, log_entry, artifact):
        """Calculate correlation strength between log entry and artifact"""
        strength = 0.5  # Base strength
        
        # Time proximity
        if 'start_time' in artifact:
            # Simplified time comparison
            strength += 0.2
        
        # Process name match
        if artifact.get('name', '').lower() in log_entry['process'].lower():
            strength += 0.3
        
        # Suspicious flags
        if 'suspicious_flags' in artifact and artifact['suspicious_flags']:
            strength += 0.2
        
        return min(strength, 1.0)
    
    def generate_threat_report(self, correlations):
        """Generate comprehensive threat report"""
        report = {
            'summary': {
                'total_correlations': len(correlations),
                'high_risk_events': 0,
                'medium_risk_events': 0,
                'low_risk_events': 0
            },
            'detailed_findings': []
        }
        
        for correlation in correlations:
            risk_level = self.assess_risk_level(correlation)
            
            if risk_level == 'high':
                report['summary']['high_risk_events'] += 1
            elif risk_level == 'medium':
                report['summary']['medium_risk_events'] += 1
            else:
                report['summary']['low_risk_events'] += 1
            
            finding = {
                'risk_level': risk_level,
                'timestamp': correlation['log_entry']['timestamp'],
                'process': correlation['log_entry']['process'],
                'message': correlation['log_entry']['message'],
                'correlated_artifacts': correlation['correlated_artifacts']
            }
            
            report['detailed_findings'].append(finding)
        
        return report
    
    def assess_risk_level(self, correlation):
        """Assess risk level based on correlation data"""
        risk_score = 0
        
        for artifact in correlation['correlated_artifacts']:
            risk_score += artifact['correlation_strength']
            
            # Additional risk factors
            if artifact['type'] == 'process':
                if 'suspicious_flags' in artifact['artifact']:
                    risk_score += len(artifact['artifact']['suspicious_flags']) * 0.2
            
            elif artifact['type'] == 'network':
                if artifact['artifact'].get('status') == 'blocked':
                    risk_score += 0.5
            
            elif artifact['type'] == 'file':
                if artifact['artifact'].get('result') in ['denied', 'failed']:
                    risk_score += 0.3
        
        if risk_score >= 2.0:
            return 'high'
        elif risk_score >= 1.0:
            return 'medium'
        else:
            return 'low'

def main():
    correlator = ArtifactCorrelator()
    correlator.create_sample_artifacts()
    
    # Parse log entries
    log_entries = []
    for log_file in ['sample_unified.log', 'suspicious_activity.log']:
        with open(log_file, 'r') as f:
            for line in f:
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
                    log_entries.append(entry)
    
    # Perform correlation
    correlations = correlator.correlate_with_logs(log_entries)
    
    # Generate threat report
    report = correlator.generate_threat_report(correlations)
    
    print("=== ARTIFACT CORRELATION REPORT ===")
    print(f"Total Correlations: {report['summary']['total_correlations']}")
    print(f"High Risk Events: {report['summary']['high_risk_events']}")
    print(f"Medium Risk Events: {report['summary']['medium_risk_events']}")
    print(f"Low Risk Events: {report['summary']['low_risk_events']}")
    
    print("\n=== DETAILED FINDINGS ===")
    for finding in report['detailed_findings']:
        print(f"\n[{finding['risk_level'].upper()}] {finding['timestamp']}")
        print(f"Process: {finding['process']}")
        print(f"Message: {finding['message']}")
        print("Correlated Artifacts:")
        for artifact in finding['correlated_artifacts']:
            print(f"  - Type: {artifact['type']}")
            print(f"    Strength: {artifact['correlation_strength']:.2f}")
            print(f"    Details: {artifact['artifact']}")
        print("-" * 60)

if __name__ == "__main__":
    main()
