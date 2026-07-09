#!/usr/bin/env python3
from timesketch_api_client import client
from datetime import datetime, timedelta

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost:5000', 'admin', 'admin')
sketches = ts_client.list_sketches()
sketch = sketches[0]

# Define correlation queries
correlation_queries = [
    {
        'name': 'Failed Login Attempts',
        'query': 'event_id:4625 OR "Failed logon" OR "401"',
        'description': 'Identify failed authentication attempts across systems'
    },
    {
        'name': 'Suspicious Network Activity',
        'query': 'action:BLOCK OR "suspicious" OR "malware"',
        'description': 'Blocked network connections and suspicious domains'
    },
    {
        'name': 'Administrative Activities',
        'query': 'user:admin OR user:administrator OR "/admin/"',
        'description': 'Administrative user activities across platforms'
    },
    {
        'name': 'File Access Events',
        'query': '"sensitive" OR "upload" OR "data.txt"',
        'description': 'Access to sensitive files and uploads'
    }
]

print("=== Event Correlation Analysis ===\n")

for query_info in correlation_queries:
    print(f"Query: {query_info['name']}")
    print(f"Description: {query_info['description']}")
    print(f"Search: {query_info['query']}")
    
    # Execute search
    try:
        events = sketch.explore(query_string=query_info['query'])
        print(f"Results: Found {len(events)} matching events")
    except Exception as e:
        print(f"Error executing query: {e}")
    
    print("-" * 50)
