#!/usr/bin/env python3
import pandas as pd
import json
from collections import defaultdict

def analyze_lateral_movement(log_file):
    # Read the CSV file
    df = pd.read_csv(log_file)
    
    # Group by account to track movement
    movement_patterns = defaultdict(list)
    
    for _, row in df.iterrows():
        account = row['Account']
        computer = row['Computer']
        event_id = row['EventID']
        time = row['TimeCreated']
        
        movement_patterns[account].append({
            'time': time,
            'computer': computer,
            'event_id': event_id,
            'source_ip': row.get('SourceIP', 'N/A')
        })
    
    # Detect potential lateral movement
    suspicious_accounts = []
    for account, events in movement_patterns.items():
        unique_computers = set([event['computer'] for event in events])
        if len(unique_computers) > 1:
            suspicious_accounts.append({
                'account': account,
                'computers_accessed': list(unique_computers),
                'event_count': len(events)
            })
    
    return suspicious_accounts

# Analyze the logs
results = analyze_lateral_movement('security_events.evtx.csv')
print("Potential Lateral Movement Detected:")
print(json.dumps(results, indent=2))
