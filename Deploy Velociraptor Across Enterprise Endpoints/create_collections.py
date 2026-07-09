#!/usr/bin/env python3
import requests
import json
import urllib3
urllib3.disable_warnings()

# API configuration
base_url = "https://127.0.0.1:8080"
auth = ("admin", "VelociraptorAdmin123!")

def create_hunt():
    hunt_data = {
        "description": "Enterprise Endpoint Monitoring",
        "artifacts": ["Generic.Client.Info", "Custom.Endpoint.Monitoring"],
        "condition": {"os": "linux"},
        "expires": 3600
    }
    
    response = requests.post(
        f"{base_url}/api/v1/CreateHunt",
        json=hunt_data,
        auth=auth,
        verify=False
    )
    
    if response.status_code == 200:
        print("Hunt created successfully")
        return response.json()
    else:
        print(f"Failed to create hunt: {response.status_code}")
        return None

if __name__ == "__main__":
    result = create_hunt()
    if result:
        print(f"Hunt ID: {result.get('hunt_id', 'Unknown')}")
