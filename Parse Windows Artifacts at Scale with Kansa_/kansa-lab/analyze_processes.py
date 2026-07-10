#!/usr/bin/env python3
import pandas as pd
import os

def analyze_processes(file_path):
    """Analyze running processes for suspicious activity"""
    print("=== Process Analysis ===")
    
    df = pd.read_csv(file_path)
    
    print(f"Total Processes: {len(df)}")
    print(f"Unique Computers: {df['ComputerName'].nunique()}")
    
    # Suspicious process indicators
    suspicious_commands = [
        'executionpolicy bypass',
        'hidden',
        'encoded',
        'downloadstring',
        'invoke-expression',
        'iex',
        'malicious'
    ]
    
    print("\n=== Suspicious Process Analysis ===")
    for idx, row in df.iterrows():
        cmdline_lower = str(row['CommandLine']).lower()
        
        is_suspicious = False
        reasons = []
        
        # Check for suspicious command line arguments
        for sus_cmd in suspicious_commands:
            if sus_cmd in cmdline_lower:
                is_suspicious = True
                reasons.append(f"Suspicious command: {sus_cmd}")
        
        # Check for PowerShell with bypass
        if 'powershell' in row['ProcessName'].lower() and 'bypass' in cmdline_lower:
            is_suspicious = True
            reasons.append("PowerShell execution policy bypass")
        
        if is_suspicious:
            print(f"\n🚨 SUSPICIOUS PROCESS FOUND:")
            print(f"  Computer: {row['ComputerName']}")
            print(f"  Process: {row['ProcessName']} (PID: {row['ProcessId']})")
            print(f"  Command Line: {row['CommandLine']}")
            print(f"  Reasons: {', '.join(reasons)}")

if __name__ == "__main__":
    proc_file = "/home/ubuntu/kansa-lab/sample-data/processes/running-processes.csv"
    if os.path.exists(proc_file):
        analyze_processes(proc_file)
    else:
        print(f"File not found: {proc_file}")
