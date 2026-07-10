#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os

def analyze_security_logs(file_path):
    """Analyze Windows Security Event Logs"""
    print("=== Security Event Log Analysis ===")
    
    # Read the CSV file
    df = pd.read_csv(file_path)
    
    # Convert TimeCreated to datetime
    df['TimeCreated'] = pd.to_datetime(df['TimeCreated'])
    
    # Basic statistics
    print(f"Total Events: {len(df)}")
    print(f"Date Range: {df['TimeCreated'].min()} to {df['TimeCreated'].max()}")
    print(f"Unique Machines: {df['MachineName'].nunique()}")
    
    # Event ID analysis
    event_counts = df['Id'].value_counts()
    print("\nEvent ID Distribution:")
    for event_id, count in event_counts.items():
        event_type = {
            4624: "Successful Logon",
            4625: "Failed Logon", 
            4648: "Explicit Credential Use"
        }.get(event_id, "Unknown")
        print(f"  {event_id} ({event_type}): {count}")
    
    # Failed logon analysis (potential brute force)
    failed_logons = df[df['Id'] == 4625]
    if not failed_logons.empty:
        print(f"\n⚠️  ALERT: {len(failed_logons)} failed logon attempts detected")
    
    # Explicit credential use (potential lateral movement)
    explicit_creds = df[df['Id'] == 4648]
    if not explicit_creds.empty:
        print(f"⚠️  ALERT: {len(explicit_creds)} explicit credential usage events")
    
    return df

if __name__ == "__main__":
    log_file = "/home/ubuntu/kansa-lab/sample-data/eventlogs/Security.evtx.csv"
    if os.path.exists(log_file):
        analyze_security_logs(log_file)
    else:
        print(f"File not found: {log_file}")
