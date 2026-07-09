#!/bin/bash
echo "=== VELOCIRAPTOR DEPLOYMENT VERIFICATION ==="
echo

echo "1. Server Status:"
pgrep -f "velociraptor.*frontend" > /dev/null && echo "✓ Server running" || echo "✗ Server not running"

echo "2. Client Status:"
systemctl is-active velociraptor-client > /dev/null && echo "✓ Client active" || echo "✗ Client inactive"

echo "3. Web Interface:"
curl -k -s https://127.0.0.1:8080/app/index.html > /dev/null && echo "✓ Web interface accessible" || echo "✗ Web interface not accessible"

echo "4. Configuration Files:"
[ -f server.config.yaml ] && echo "✓ Server config exists" || echo "✗ Server config missing"
[ -f client.config.yaml ] && echo "✓ Client config exists" || echo "✗ Client config missing"

echo "5. Data Collection:"
[ -f security_report.json ] && echo "✓ Security report generated" || echo "✗ Security report missing"

echo
echo "=== ACCESS INFORMATION ==="
echo "Web Interface: https://127.0.0.1:8080"
echo "Username: admin"
echo "Password: VelociraptorAdmin123!"
echo
