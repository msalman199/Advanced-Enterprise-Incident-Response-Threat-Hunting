#!/bin/bash
echo "=== AUTHENTICATION ANALYSIS ==="
echo "Recent sudo attempts:"
sudo grep "sudo:" /var/log/auth.log | tail -5

echo -e "\nFailed password attempts:"
sudo grep "Failed password" /var/log/auth.log | tail -5

echo -e "\nSuccessful logins:"
sudo grep "session opened" /var/log/auth.log | tail -5
