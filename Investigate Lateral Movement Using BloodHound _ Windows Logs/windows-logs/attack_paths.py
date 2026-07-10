#!/usr/bin/env python3
import json
import pandas as pd
from collections import defaultdict

def analyze_attack_paths(ad_data_file, log_file):
    # Load data
    with open(ad_data_file, 'r') as f:
        ad_data = json.load(f)
    
    log_df = pd.read_csv(log_file)
    
    # Build attack timeline
    attack_timeline = []
    
    for _, row in log_df.iterrows():
        attack_timeline.append({
            'timestamp': row['TimeCreated'],
            'event_id': row['EventID'],
            'account': row['Account'],
            'computer': row['Computer'],
            'source_ip': row.get('SourceIP', 'Unknown')
        })
    
    # Sort by timestamp
    attack_timeline.sort(key=lambda x: x['timestamp'])
    
    print("Potential Attack Path Analysis:")
    print("=" * 50)
    
    current_account = None
    step = 1
    
    for event in attack_timeline:
        if event['account'] != current_account:
            print(f"\nStep {step}: Account Compromise")
            print(f"  Account: {event['account']}")
            current_account = event['account']
            step += 1
        
        print(f"  {event['timestamp']}: Event {event['event_id']} on {event['computer']}")
        
        if event['event_id'] == 4648:
            print(f"    -> Explicit credential use detected")
        elif event['event_id'] == 5140:
            print(f"    -> Network share access detected")

analyze_attack_paths('sample_ad_data.json', 'security_events.evtx.csv')
