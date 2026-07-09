#!/usr/bin/env python3
from timesketch_api_client import client

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost:5000', 'admin', 'admin')
sketches = ts_client.list_sketches()
sketch = sketches[0]

# Create saved views for different investigation aspects
views = [
    {
        'name': 'Security Incidents',
        'query': 'event_id:4625 OR action:BLOCK OR "Failed"',
        'description': 'Focus on security-related events'
    },
    {
        'name': 'User Activity Timeline',
        'query': 'user:* AND (logon OR logoff OR login)',
        'description': 'User authentication timeline'
    },
    {
        'name': 'Network Communications',
        'query': 'source_ip:* OR dest_ip:*',
        'description': 'Network traffic analysis'
    }
]

print("Creating timeline views...")

for view_info in views:
    try:
        view = sketch.create_view(
            view_name=view_info['name'],
            query_string=view_info['query']
        )
        print(f"Created view: {view_info['name']}")
    except Exception as e:
        print(f"Error creating view {view_info['name']}: {e}")

print("\nViews created successfully!")
