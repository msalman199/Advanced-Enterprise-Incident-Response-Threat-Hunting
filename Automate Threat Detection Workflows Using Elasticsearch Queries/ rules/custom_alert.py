#!/usr/bin/env python3
import json
import sys
import datetime
import subprocess

def send_alert(alert_data):
    """Process and send custom alerts"""
    
    # Parse alert data
    rule_name = alert_data.get('rule_name', 'Unknown Rule')
    num_matches = alert_data.get('num_matches', 0)
    
    # Create alert message
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    alert_message = f"""
    SECURITY ALERT - {timestamp}
    ================================
    Rule: {rule_name}
    Matches: {num_matches}
    
    Event Details:
    """
    
    # Add event details
    for match in alert_data.get('matches', []):
        alert_message += f"""
    - Source IP: {match.get('source_ip', 'N/A')}
    - Event Type: {match.get('event_type', 'N/A')}
    - Severity: {match.get('severity', 'N/A')}
    - Threat Score: {match.get('threat_score', 'N/A')}
    - Timestamp: {match.get('@timestamp', 'N/A')}
    """
    
    # Log alert to file
    with open('/home/' + subprocess.getoutput('whoami') + '/elastalert/alerts.log', 'a') as f:
        f.write(alert_message + "\n" + "="*50 + "\n")
    
    print(f"Alert processed: {rule_name}")
    return True

if __name__ == "__main__":
    # Read alert data from stdin
    alert_data = json.loads(sys.stdin.read())
    send_alert(alert_data)
