#!/usr/bin/env python3
import json
import csv
import os

def export_iocs_to_formats():
    """Export IOCs to various formats for SIEM integration"""
    
    # Load the correlation report
    report_file = "/home/ubuntu/kansa-lab/results/ioc_correlation_report.json"
    if not os.path.exists(report_file):
        print("No correlation report found. Run the analysis first.")
        return
    
    with open(report_file, 'r') as f:
        report = json.load(f)
    
    iocs = report['iocs']
    
    # Export to CSV for Splunk/ELK
    csv_file = "/home/ubuntu/kansa-lab/results/iocs_for_siem.csv"
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['timestamp', 'computer', 'type', 'value', 'severity', 'source'])
        writer.writeheader()
        writer.writerows(iocs)
    
    print(f"IOCs exported to CSV: {csv_file}")
    
    # Export high-severity IOCs only
    high_severity_iocs = [ioc for ioc in iocs if ioc['severity'] == 'High']
    high_sev_file = "/home/ubuntu/kansa-lab/results/high_priority_iocs.json"
    
    with open(high_sev_file, 'w') as f:
        json.dump(high_severity_iocs, f, indent=2)
    
    print(f"High-priority IOCs exported: {high_sev_file}")
    print(f"Total high-priority IOCs: {len(high_severity_iocs)}")
    
    # Create YARA-style rules for detected patterns
    yara_file = "/home/ubuntu/kansa-lab/results/detected_patterns.yar"
    with open(yara_file, 'w') as f:
        f.write('rule Suspicious_PowerShell_Bypass {\n')
        f.write('    meta:\n')
        f.write('        description = "Detects PowerShell execution policy bypass"\n')
        f.write('        severity = "High"\n')
        f.write('    strings:\n')
        f.write('        $bypass = "ExecutionPolicy Bypass" nocase\n')
        f.write('        $powershell = "powershell.exe" nocase\n')
        f.write('    condition:\n')
        f.write('        $bypass and $powershell\n')
        f.write('}\n\n')
        
        f.write('rule Suspicious_Temp_Autorun {\n')
        f.write('    meta:\n')
        f.write('        description = "Detects autorun entries in temp directories"\n')
        f.write('        severity = "High"\n')
        f.write('    strings:\n')
        f.write('        $temp1 = "\\\\temp\\\\" nocase\n')
        f.write('        $temp2 = "\\\\tmp\\\\" nocase\n')
        f.write('        $exe = ".exe" nocase\n')
        f.write('    condition:\n')
        f.write('        ($temp1 or $temp2) and $exe\n')
        f.write('}\n')
    
    print(f"YARA rules generated: {yara_file}")

if __name__ == "__main__":
    export_iocs_to_formats()
