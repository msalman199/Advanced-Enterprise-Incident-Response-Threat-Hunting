#!/bin/bash

echo "Container Forensics Investigation"
echo "================================="

CONTAINER_NAME="vulnerable-app"

echo "1. Container Process Analysis:"
echo "-----------------------------"
docker exec $CONTAINER_NAME ps aux

echo ""
echo "2. Network Connections:"
echo "----------------------"
docker exec $CONTAINER_NAME netstat -tulpn 2>/dev/null || echo "netstat not available"

echo ""
echo "3. File System Changes:"
echo "----------------------"
docker diff $CONTAINER_NAME | head -20

echo ""
echo "4. Container Logs Analysis:"
echo "--------------------------"
docker logs $CONTAINER_NAME --tail 20

echo ""
echo "5. Environment Variables:"
echo "------------------------"
docker exec $CONTAINER_NAME env | grep -E "(PATH|USER|HOME|SHELL)"

echo ""
echo "6. Running Services:"
echo "-------------------"
docker exec $CONTAINER_NAME bash -c "
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=running
    else
        ps aux | grep -v grep | grep -E '(daemon|service)'
    fi
" 2>/dev/null || echo "Service information not available"

echo ""
echo "7. Recent File Modifications:"
echo "----------------------------"
docker exec $CONTAINER_NAME find / -type f -mtime -1 2>/dev/null | head -10 || echo "Cannot access file system"

echo ""
echo "8. Container Metadata:"
echo "---------------------"
docker inspect $CONTAINER_NAME | jq -r '.[] | {
    Name: .Name,
    Image: .Config.Image,
    Privileged: .HostConfig.Privileged,
    Mounts: [.Mounts[].Source],
    NetworkMode: .HostConfig.NetworkMode
}' 2>/dev/null || docker inspect $CONTAINER_NAME | grep -E "(Name|Image|Privileged)"
