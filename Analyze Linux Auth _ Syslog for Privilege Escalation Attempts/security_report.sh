#!/bin/bash
echo "=== COMPREHENSIVE SECURITY REPORT ==="
echo "Generated: $(date)"
echo "=========================================="

echo -e "\n1. AUTHENTICATION SUMMARY:"
echo "Total login attempts: $(sudo grep -c "authentication" /var/log/auth.log)"
echo "Failed logins: $(sudo grep -c "Failed password" /var/log/auth.log)"
echo "Successful logins: $(sudo grep -c "session opened" /var/log/auth.log)"

echo -e "\n2. SUDO ACTIVITY:"
echo "Total sudo commands: $(sudo grep -c "sudo:" /var/log/auth.log)"
echo "Failed sudo attempts: $(sudo grep -c "sudo.*FAILED" /var/log/auth.log)"
echo "Unique users using sudo: $(sudo grep "sudo:" /var/log/auth.log | awk '{print $5}' | sort -u | wc -l)"

echo -e "\n3. PRIVILEGE ESCALATION INDICATORS:"
echo "User modifications: $(sudo grep -c -E "usermod|useradd" /var/log/syslog)"
echo "Group modifications: $(sudo grep -c "groupadd\|groupmod" /var/log/syslog)"

echo -e "\n4. TOP SUSPICIOUS ACTIVITIES:"
sudo grep -E "(Failed|sudo.*FAILED|usermod)" /var/log/auth.log /var/log/syslog | tail -5

echo -e "\n5. RECOMMENDATIONS:"
echo "- Monitor users with failed sudo attempts"
echo "- Review off-hours authentication activity"
echo "- Investigate rapid authentication patterns"
echo "- Verify legitimacy of user/group modifications"
