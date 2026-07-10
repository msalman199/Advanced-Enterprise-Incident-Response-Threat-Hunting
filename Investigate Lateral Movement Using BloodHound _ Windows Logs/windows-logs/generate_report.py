#!/usr/bin/env python3
import json
import pandas as pd
from datetime import datetime

def generate_investigation_report():
    print("LATERAL MOVEMENT INVESTIGATION REPORT")
    print("=" * 60)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Load and analyze data
    log_df = pd.read_csv('security_events.evtx.csv')
    
    print("EXECUTIVE SUMMARY:")
    print("-" * 20)
    print(f"Total Events Analyzed: {len(log_df)}")
    print(f"Unique Accounts: {log_df['Account'].nunique()}")
    print(f"Unique Computers: {log_df['Computer'].nunique()}")
    print()
    
    print("KEY FINDINGS:")
    print("-" * 20)
    
    # Identify accounts with multiple computer access
    account_computers = log_df.groupby('Account')['Computer'].nunique()
    suspicious_accounts = account_computers[account_computers > 1]
    
    for account, computer_count in suspicious_accounts.items():
        print(f"• {account}: Accessed {computer_count} different computers")
        computers = log_df[log_df['Account'] == account]['Computer'].unique()
        print(f"  Computers: {', '.join(computers)}")
    
    print()
    print("RECOMMENDATIONS:")
    print("-" * 20)
    print("• Monitor accounts with cross-system access")
    print("• Implement additional authentication for privileged accounts")
    print("• Review network segmentation policies")
    print("• Enable advanced logging on critical systems")

generate_investigation_report()
