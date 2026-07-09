#!/usr/bin/env python3
from timesketch_api_client import client

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost:5000', 'admin', 'admin')

# Create new sketch
sketch = ts_client.create_sketch(
    name='Forensic Investigation Lab',
    description='Multi-platform forensic timeline analysis'
)

print(f"Created sketch: {sketch.name} (ID: {sketch.id})")
