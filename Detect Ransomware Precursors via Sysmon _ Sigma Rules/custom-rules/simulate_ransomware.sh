#!/bin/bash
echo "Simulating ransomware-like activity..."

# Create test files
mkdir -p /tmp/test_files
for i in {1..5}; do
    echo "Important document $i" > /tmp/test_files/document$i.txt
done

# Simulate file encryption (rename files)
for file in /tmp/test_files/*.txt; do
    mv "$file" "$file.encrypted"
done

# Create ransom note
echo "Your files have been encrypted! Contact us for decryption key." > /tmp/test_files/README_DECRYPT.txt

# Simulate shadow copy deletion attempt (safe simulation)
echo "vssadmin delete shadows /all /quiet" > /tmp/fake_command.log

echo "Simulation complete. Check Sysmon logs for detection."
