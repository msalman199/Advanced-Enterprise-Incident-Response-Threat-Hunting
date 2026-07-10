#!/usr/bin/env python3
import pandas as pd

def extract_indicators(log_file):
    df = pd.read_csv(log_file)
    
    # Key event IDs for lateral movement
    lateral_movement_events = [4624, 4648, 4672, 5140]
    
    # Filter relevant events
    filtered_df = df[df['EventID'].isin(lateral_movement_events)]
    
    print("Lateral Movement Indicators:")
    print("=" * 50)
    
    for _, row in filtered_df.iterrows():
        print(f"Time: {row['TimeCreated']}")
        print(f"Event ID: {row['EventID']}")
        print(f"Account: {row['Account']}")
        print(f"Computer: {row['Computer']}")
        print(f"Source IP: {row.get('SourceIP', 'N/A')}")
        print("-" * 30)

extract_indicators('security_events.evtx.csv')
