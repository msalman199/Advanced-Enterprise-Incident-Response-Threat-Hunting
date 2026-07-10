#!/usr/bin/env python3
import json
import os
from datetime import datetime

def generate_executive_summary():
    """Generate executive summary report"""
    
    report_file = "/home/ubuntu/kansa-lab/results/ioc_correlation_report.json"
    if not os.path.exists(report_file):
        print("No correlation report found.")
        return
    
    with open(report_file, 'r') as f:
        report = json.load(f)
    
    summary = report['summary']
    iocs = report['iocs']
    
    # Generate executive summary
    exec_summary = f"""
WINDOWS ARTIFACT ANALYSIS - EXECUTIVE SUMMARY
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

OVERVIEW:
- Total IOCs Identified: {summary['total_iocs']}
- Affected Systems: {summary['affected_computers']}
- Analysis Timeframe: Enterprise-wide artifact collection

THREAT LANDSCAPE:
"""
    
    for severity, count in summary['severity_breakdown'].items():
        exec_summary += f"- {severity} Priority Threats: {count}\n"
    
    exec_summary += f"""
KEY FINDINGS:
"""
    
    # Identify key patterns
    high_priority = [ioc for ioc in iocs if ioc['severity'] == 'High']
    if high_priority:
        exec_summary += f"- {len(high_priority)} critical security incidents require immediate attention\n"
    
    # Count by type
    ioc_types = {}
    for ioc in iocs:
        ioc_type = ioc['type']
        ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
    
    exec_summary += "- Threat Distribution:\n"
    for ioc_type, count in ioc_types.items():
        exec_summary += f"  * {ioc_type.replace('_', ' ').title()}: {count}\n"
    
    exec_summary += f"""
RECOMMENDATIONS:
1. Immediately investigate all High priority IOCs
2. Implement additional monitoring for affected systems
3. Review and update security policies based on findings
4. Consider threat hunting activities for similar patterns

TECHNICAL DETAILS:
- Analysis performed using Kansa framework simulation
- Artifacts analyzed: Event Logs, Registry, Process Lists
- Correlation engine identified cross-system patterns
- Results exported for SIEM integration
"""
    
    # Save executive summary
    summary_file = "/home/ubuntu/kansa-lab/results/executive_summary.txt"
    with open(summary_file, 'w') as f:
        f.write(exec_summary)
    
    print("=== EXECUTIVE SUMMARY ===")
    print(exec_summary)
    print(f"\nFull report saved to: {summary_file}")

if __name__ == "__main__":
    generate_executive_summary()
