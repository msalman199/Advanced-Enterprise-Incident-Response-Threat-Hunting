#!/usr/bin/env python3
import json
from datetime import datetime

def generate_investigation_summary():
    """Generate comprehensive investigation summary"""
    
    summary = {
        'investigation_metadata': {
            'analyst': 'Security Analyst',
            'investigation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'case_id': 'MACOS-LOG-2024-001',
            'evidence_sources': ['sample_unified.log', 'suspicious_activity.log']
        },
        'executive_summary': {
            'threat_level': 'HIGH',
            'confidence': 'MEDIUM',
            'key_findings': [
                'Multiple authentication failures detected from external IP',
                'Privilege escalation attempts using sudo',
                'Sandbox violations by Chrome browser',
                'Unsigned binary execution attempts',
                'Potential backdoor user creation attempt',
                'Blocked outbound network connections to suspicious IP'
            ],
            'recommended_actions': [
                'Block IP address 192.168.1.100 at firewall level',
                'Investigate Chrome browser for potential compromise',
                'Remove unsigned binaries from /tmp directory',
                'Review user account creation logs',
                'Monitor network traffic to 192.168.1.200',
                'Implement additional endpoint monitoring'
            ]
        },
        'technical_analysis': {
            'timeline': [
                {
                    'time': '10:30:16',
                    'event': 'User authentication succeeded for admin',
                    'significance': 'Normal login activity'
                },
                {
                    'time': '10:30:17',
                    'event': 'SSH authentication failure from 192.168.1.100',
                    'significance': 'Potential brute force attack'
                },
                {
                    'time': '10:30:18',
                    'event': 'Sudo command executed by admin',
                    'significance': 'Privilege escalation'
                },
                {
                    'time': '10:30:20',
                    'event': 'Chrome attempted to write to system directory',
                    'significance': 'Sandbox violation - potential compromise'
                },
                {
                    'time': '11:15:30',
                    'event': 'Service hijacking attempt detected',
                    'significance': 'Persistence mechanism attempt'
                },
                {
                    'time': '11:15:34',
                    'event': 'Backdoor user creation attempt',
                    'significance': 'Persistence mechanism'
                }
            ],
            'iocs': [
                {
                    'type': 'IP Address',
                    'value': '192.168.1.100',
                    'description': 'Source of SSH brute force attack'
                },
                {
                    'type': 'IP Address',
                    'value': '192.168.1.200',
                    'description': 'Destination of blocked outbound connection'
                },
                {
                    'type': 'File Path',
                    'value': '/tmp/malicious_binary',
                    'description': 'Unsigned binary with failed signature verification'
                },
                {
                    'type': 'User Account',
                    'value': 'backdoor',
                    'description': 'Attempted backdoor user creation'
                },
                {
                    'type': 'Service',
                    'value': 'com.malware.agent',
                    'description': 'Malicious service attempting endpoint hijacking'
                }
            ]
        },
        'risk_assessment': {
            'attack_vectors': [
                'SSH brute force attack',
                'Browser exploitation',
                'Privilege escalation',
                'Persistence mechanisms'
            ],
            'potential_impact': [
                'Unauthorized system access',
                'Data exfiltration',
                'System compromise',
                'Lateral movement'
            ],
            'mitigation_status': 'PARTIAL - Some attacks blocked by system defenses'
        }
    }
    
    return summary

def print_summary(summary):
    """Print formatted investigation summary"""
    print("=" * 80)
    print("MACOS UNIFIED LOG INVESTIGATION SUMMARY")
    print("=" * 80)
    
    # Metadata
    meta = summary['investigation_metadata']
    print(f"\nCase ID: {meta['case_id']}")
    print(f"Investigation Date: {meta['investigation_date']}")
    print(f"Evidence Sources: {', '.join(meta['evidence_sources'])}")
    
    # Executive Summary
    exec_sum = summary['executive_summary']
    print(f"\n=== EXECUTIVE SUMMARY ===")
    print(f"Threat Level: {exec_sum['threat_level']}")
    print(f"Confidence: {exec_sum['confidence']}")
    
    print(f"\nKey Findings:")
    for i, finding in enumerate(exec_sum['key_findings'], 1):
        print(f"  {i}. {finding}")
    
    print(f"\nRecommended Actions:")
    for i, action in enumerate(exec_sum['recommended_actions'], 1):
        print(f"  {i}. {action}")
    
    # Technical Analysis
    tech = summary['technical_analysis']
    print(f"\n=== TECHNICAL ANALYSIS ===")
    print(f"\nTimeline of Events:")
    for event in tech['timeline']:
        print(f"  {event['time']} - {event['event']}")
        print(f"    Significance: {event['significance']}")
    
    print(f"\nIndicators of Compromise (IOCs):")
    for ioc in tech['iocs']:
        print(f"  Type: {ioc['type']}")
        print(f"  Value: {ioc['value']}")
        print(f"  Description: {ioc['description']}")
        print()
    
    # Risk Assessment
    risk = summary['risk_assessment']
    print(f"=== RISK ASSESSMENT ===")
    print(f"Attack Vectors: {', '.join(risk['attack_vectors'])}")
    print(f"Potential Impact: {', '.join(risk['potential_impact'])}")
    print(f"Mitigation Status: {risk['mitigation_status']}")
    
    print("\n" + "=" * 80)

def main():
    summary = generate_investigation_summary()
    print_summary(summary)
    
    # Save summary to file
    with open('investigation_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\nInvestigation summary saved to: investigation_summary.json")

if __name__ == "__main__":
    main()
