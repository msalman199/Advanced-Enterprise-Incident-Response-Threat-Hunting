#!/usr/bin/env python3
import json
import pandas as pd
from datetime import datetime

def load_bloodhound_data(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def correlate_findings(ad_data_file, log_file):
    # Load BloodHound data
    ad_data = load_bloodhound_data(ad_data_file)
    
    # Load Windows logs
    log_df = pd.read_csv(log_file)
    
    # Extract computer and user lists from AD data
    ad_computers = {comp['name'].lower() for comp in ad_data['computers']}
    ad_users = {user['name'].lower() for user in ad_data['users']}
    
    print("Correlation Analysis Results:")
    print("=" * 50)
    
    # Check if logged events involve AD assets
    for _, row in log_df.iterrows():
        computer = row['Computer'].lower()
        account = row['Account'].lower()
        
        if computer in ad_computers and account in ad_users:
            print(f"MATCH FOUND:")
            print(f"  Time: {row['TimeCreated']}")
            print(f"  Event: {row['EventID']}")
            print(f"  Account: {account}")
            print(f"  Computer: {computer}")
            print(f"  Risk Level: HIGH")
            print("-" * 30)

# Run correlation
correlate_findings('sample_ad_data.json', 'security_events.evtx.csv')
