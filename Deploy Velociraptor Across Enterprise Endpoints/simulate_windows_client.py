#!/usr/bin/env python3
import json
import time
import random
import requests
import os

class WindowsClientSimulator:
    def __init__(self):
        self.client_id = f"C.{random.randint(1000000000000000, 9999999999999999):016x}"
        self.hostname = f"WIN-{random.randint(100000, 999999)}"
        
    def generate_process_data(self):
        processes = [
            {"name": "explorer.exe", "pid": 1234, "ppid": 567},
            {"name": "chrome.exe", "pid": 2345, "ppid": 1234},
            {"name": "notepad.exe", "pid": 3456, "ppid": 1234},
            {"name": "powershell.exe", "pid": 4567, "ppid": 1234}
        ]
        return {"processes": processes, "timestamp": int(time.time())}
    
    def simulate_activity(self):
        print(f"Simulating Windows client: {self.hostname} ({self.client_id})")
        for i in range(5):
            data = self.generate_process_data()
            print(f"Generated process data: {len(data['processes'])} processes")
            time.sleep(2)

if __name__ == "__main__":
    simulator = WindowsClientSimulator()
    simulator.simulate_activity()
