#!/bin/bash

REPORT_FILE="container_incident_report_$(date +%Y%m%d_%H%M%S).txt"

echo "Generating Container Security Incident Report..."

cat > $REPORT_FILE << 'REPORT_EOF'
CONTAINER SECURITY INCIDENT REPORT
==================================
Generated: $(date)
Analyst: Security Team
Environment: Lab Environment

EXECUTIVE SUMMARY
-----------------
This report documents the investigation of suspicious activities detected
in Docker containers using Falco security monitoring.

INCIDENT TIMELINE
-----------------
REPORT_EOF

echo "$(date): Investigation initiated" >> $REPORT_FILE
echo "$(date): Falco monitoring activated" >> $REPORT_FILE
echo "$(date): Suspicious activities simulated" >> $REPORT_FILE
echo "$(date): Forensic analysis completed" >> $REPORT_FILE

cat >> $REPORT_FILE << 'REPORT_EOF'

AFFECTED SYSTEMS
----------------
REPORT_EOF

echo "Containers investigated:" >> $REPORT_FILE
docker ps --format "- {{.Names}} ({{.Image}})" >> $REPORT_FILE

cat >> $REPORT_FILE << 'REPORT_EOF'

SECURITY EVENTS DETECTED
------------------------
REPORT_EOF

echo "Recent security events:" >> $REPORT_FILE
sudo tail -20 /var/log/falco_events.log >> $REPORT_FILE 2>/dev/null || echo "No events logged" >> $REPORT_FILE

cat >> $REPORT_FILE << 'REPORT_EOF'

RECOMMENDATIONS
---------------
1. Implement container runtime security policies
2. Regular security monitoring with Falco
3. Container image vulnerability scanning
4. Principle of least privilege for containers
5. Network segmentation for container workloads

CONCLUSION
----------
The investigation demonstrates the effectiveness of Falco for detecting
container security incidents. Continuous monitoring is essential for
maintaining container security posture.
REPORT_EOF

echo "Report generated: $REPORT_FILE"
cat $REPORT_FILE
