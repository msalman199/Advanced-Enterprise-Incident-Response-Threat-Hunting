#!/usr/bin/env python3
import re
import subprocess
import json

def check_file_encryption_indicators():
    """Check for file encryption indicators in Sysmon logs"""
    print("=== Checking for File Encryption Indicators ===")
    
    # Get recent Sysmon logs
    result = subprocess.run(['sudo', 'journalctl', '-u', 'sysmon', '-n', '100', '--no-pager'], 
                          capture_output=True, text=True)
    
    logs = result.stdout
    
    # Look for encrypted file extensions
    encrypted_patterns = ['.encrypted', '.locked', '.crypto', '.crypt']
    ransom_notes = ['README', 'DECRYPT', 'RANSOM']
    
    findings = []
    
    for line in logs.split('\n'):
        for pattern in encrypted_patterns:
            if pattern in line and 'EventID=11' in line:
                findings.append(f"ALERT: Encrypted file detected - {line.strip()}")
        
        for note in ransom_notes:
            if note in line and 'EventID=11' in line:
                findings.append(f"ALERT: Potential ransom note - {line.strip()}")
    
    if findings:
        for finding in findings:
            print(finding)
    else:
        print("No file encryption indicators found.")
    
    return len(findings)

def check_process_indicators():
    """Check for suspicious process execution"""
    print("\n=== Checking for Suspicious Process Indicators ===")
    
    result = subprocess.run(['sudo', 'journalctl', '-u', 'sysmon', '-n', '100', '--no-pager'], 
                          capture_output=True, text=True)
    
    logs = result.stdout
    
    suspicious_commands = ['vssadmin delete', 'wbadmin delete', 'bcdedit', 'cipher /w']
    findings = []
    
    for line in logs.split('\n'):
        for cmd in suspicious_commands:
            if cmd.lower() in line.lower() and 'EventID=1' in line:
                findings.append(f"ALERT: Suspicious command detected - {line.strip()}")
    
    if findings:
        for finding in findings:
            print(finding)
    else:
        print("No suspicious process indicators found.")
    
    return len(findings)

def main():
    print("Ransomware Detection Analysis")
    print("=" * 50)
    
    file_alerts = check_file_encryption_indicators()
    process_alerts = check_process_indicators()
    
    total_alerts = file_alerts + process_alerts
    
    print(f"\n=== Summary ===")
    print(f"File encryption alerts: {file_alerts}")
    print(f"Process execution alerts: {process_alerts}")
    print(f"Total alerts: {total_alerts}")
    
    if total_alerts > 0:
        print("\n⚠️  POTENTIAL RANSOMWARE ACTIVITY DETECTED!")
        print("Recommended actions:")
        print("1. Isolate affected systems")
        print("2. Check backup integrity")
        print("3. Investigate network connections")
        print("4. Review recent user activities")
    else:
        print("\n✅ No ransomware indicators detected in current logs.")

if __name__ == "__main__":
    main()
