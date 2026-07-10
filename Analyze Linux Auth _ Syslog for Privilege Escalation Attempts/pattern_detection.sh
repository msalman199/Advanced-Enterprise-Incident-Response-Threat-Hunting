#!/bin/bash
echo "=== ATTACK PATTERN DETECTION ==="

# Check for rapid sudo attempts
echo "1. Rapid sudo attempts (potential brute force):"
sudo awk '/sudo:/ {print $3 " " $4 " " $5}' /var/log/auth.log | sort | uniq -c | sort -nr | head -5

# Check for privilege escalation after failed attempts
echo -e "\n2. Users with both failed and successful sudo:"
FAILED_USERS=$(sudo grep "sudo.*FAILED" /var/log/auth.log | awk '{print $5}' | sort -u)
for user in $FAILED_USERS; do
    SUCCESS=$(sudo grep "sudo.*$user" /var/log/auth.log | grep -v "FAILED" | wc -l)
    if [ $SUCCESS -gt 0 ]; then
        echo "User $user: Failed attempts followed by success"
    fi
done

# Check for unusual time patterns
echo -e "\n3. Off-hours activity (outside 9-17):"
sudo awk '/sudo:/ {
    hour = substr($3, 1, 2)
    if (hour < 9 || hour > 17) print $0
}' /var/log/auth.log | tail -3
