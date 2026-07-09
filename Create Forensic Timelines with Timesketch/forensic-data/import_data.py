#!/usr/bin/env python3
import csv
from timesketch_api_client import client

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost:5000', 'admin', 'admin')

# Get the sketch (assuming it's the first one)
sketches = ts_client.list_sketches()
sketch = sketches[0]

print(f"Using sketch: {sketch.name}")

# Import CSV files
import_files = [
    'security_events.csv',
    'network_connections.csv'
]

for filename in import_files:
    try:
        with open(f'/home/{os.getenv("USER")}/forensic-data/{filename}', 'r') as file:
            print(f"Importing {filename}...")
            timeline = sketch.upload_from_csv(file, filename.replace('.csv', ''))
            print(f"Successfully imported {filename}")
    except Exception as e:
        print(f"Error importing {filename}: {e}")
