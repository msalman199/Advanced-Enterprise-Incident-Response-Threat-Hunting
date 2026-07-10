#!/bin/bash
echo "=== PRIVILEGE ESCALATION DETECTION ==="

echo "1. Sudo usage by non-privileged users:"
sudo awk '/sudo:/ && !/root/ {print $1, $2, $3, $5, $6}' /var/log/auth.log | tail -5

echo -e "\n2. User account modifications:"
sudo grep -E "usermod|useradd|groupadd" /var/log/syslog | tail -3

echo -e "\n3. Failed sudo attempts:"
sudo grep "sudo.*FAILED" /var/log/auth.log | tail -3

echo -e "\n4. Successful privilege escalation:"
sudo grep "sudo.*root" /var/log/auth.log | tail -3
