#!/usr/bin/env python3
import pandas as pd
import os

def analyze_autorun_entries(file_path):
    """Analyze Windows Registry Autorun entries for suspicious activity"""
    print("=== Registry Autorun Analysis ===")
    
    df = pd.read_csv(file_path)
    
    print(f"Total Autorun Entries: {len(df)}")
    print(f"Affected Computers: {df['ComputerName'].nunique()}")
    
    # Suspicious indicators
    suspicious_paths = [
        'temp', 'tmp', 'appdata', 'programdata', 
        'users\\public', 'windows\\temp'
    ]
    
    suspicious_names = [
        'update', 'security', 'system', 'windows',
        'microsoft', 'adobe', 'java'
    ]
    
    print("\n=== Suspicious Autorun Entries ===")
    for idx, row in df.iterrows():
        value_lower = row['Value'].lower()
        name_lower = row['Name'].lower()
        
        is_suspicious = False
        reasons = []
        
        # Check for suspicious paths
        for sus_path in suspicious_paths:
            if sus_path in value_lower:
                is_suspicious = True
                reasons.append(f"Suspicious path: {sus_path}")
        
        # Check for suspicious names (potential impersonation)
        for sus_name in suspicious_names:
            if sus_name in name_lower and 'malware' in value_lower:
                is_suspicious = True
                reasons.append(f"Potential impersonation: {sus_name}")
        
        # Check for .exe in temp directories
        if '.exe' in value_lower and ('temp' in value_lower or 'tmp' in value_lower):
            is_suspicious = True
            reasons.append("Executable in temp directory")
        
        if is_suspicious:
            print(f"\n🚨 SUSPICIOUS ENTRY FOUND:")
            print(f"  Computer: {row['ComputerName']}")
            print(f"  Name: {row['Name']}")
            print(f"  Value: {row['Value']}")
            print(f"  Reasons: {', '.join(reasons)}")

if __name__ == "__main__":
    reg_file = "/home/ubuntu/kansa-lab/sample-data/registry/autorun-entries.csv"
    if os.path.exists(reg_file):
        analyze_autorun_entries(reg_file)
    else:
        print(f"File not found: {reg_file}")
