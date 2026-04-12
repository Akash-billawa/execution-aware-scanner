#!/bin/bash
# Demo script for Execution-Aware Scanner
# Simulates real scanner output for DVWA/Juice Shop

set -e

DEMO_NAME="${1:-dvwa}"

echo "═══════════════════════════════════════════════════════════════════"
echo "  Execution-Aware Scanner Demo"
echo "  Target: $DEMO_NAME"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

if [ "$DEMO_NAME" = "dvwa" ]; then
    echo "[10:30:42] INFO: Starting scanner on DVWA container"
    echo "[10:30:42] INFO: Container: dvwa-app (PID: 1234)"
    echo "[10:30:42] INFO: Image: vulnerables/web-dvwa:latest"
    echo ""
    
    sleep 0.5
    echo "[10:30:43] INFO: Trivy scan complete"
    echo "[10:30:43] INFO: Found 12 CVEs in image"
    echo ""
    
    sleep 0.3
    echo "[10:30:43] EVENT: Process started - apache2 (PID: 1234)"
    echo "[10:30:43] EVENT: Library loaded - libphp7.4.so"
    echo "[10:30:43] EVENT: Library loaded - libmysqlclient.so"
    echo "[10:30:43] EVENT: Network connection - 10.0.0.1:80"
    echo ""
    
    sleep 0.5
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  VULNERABILITY DETECTION"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    
    # Show CVEs
    echo "[10:30:45] CRITICAL: CVE-2019-11043"
    echo "  Package:    php-fpm"
    echo "  CVSS:       9.8 (CRITICAL)"
    echo "  EPSS:       0.97 (97% exploit probability)"
    echo "  KEV:        YES (CISA Known Exploited)"
    echo "  Runtime:    ✓ REACHABLE (libphp loaded)"
    echo "  Process:    apache2 (PID: 1234)"
    echo "  Risk Score: 9.2/10"
    echo ""
    
    sleep 0.3
    echo "[10:30:45] HIGH: CVE-2018-14884"
    echo "  Package:    php"
    echo "  CVSS:       8.1 (HIGH)"
    echo "  EPSS:       0.85"
    echo "  KEV:        YES"
    echo "  Runtime:    ✓ REACHABLE"
    echo "  Process:    apache2 (PID: 1234)"
    echo "  Risk Score: 8.1/10"
    echo ""
    
    sleep 0.3
    echo "[10:30:46] HIGH: CVE-2021-3156"
    echo "  Package:    mysql"
    echo "  CVSS:       7.8 (HIGH)"
    echo "  EPSS:       0.72"
    echo "  KEV:        NO"
    echo "  Runtime:    ✗ DORMANT (present but not loaded)"
    echo "  Risk Score: 4.2/10"
    echo "  Action:     Monitored only"
    echo ""
    
    sleep 0.5
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  ENFORCEMENT DECISION"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    
    echo "[10:30:47] DECISION: CVE-2019-11043"
    echo "  Mode:         ENFORCE"
    echo "  Rationale:"
    echo "    ✓ Runtime proven (library loaded)"
    echo "    ✓ EPSS threshold met (0.97 > 0.40)"
    echo "    ✓ KEV confirmed"
    echo "    ✓ Rollback available"
    echo "    ✓ Production safe"
    echo ""
    
    sleep 0.3
    echo "[10:30:47] ACTION: Applying seccomp profile"
    echo "[10:30:48] SUCCESS: Seccomp profile applied to apache2"
    echo "[10:30:48] INFO: Rollback command: kubectl delete seccompprofile dvwa-1234"
    echo ""
    
    sleep 0.3
    echo "[10:30:48] ACTION: Blocking suspicious egress"
    echo "[10:30:48] SUCCESS: Blocked connection to 192.168.100.1:4444"
    echo "[10:30:48] INFO: Rule added to XDP map"
    echo ""
    
    sleep 0.5
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  SUMMARY"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "  Total CVEs:           12"
    echo "  Active/Reachable:      2"
    echo "  Dormant:               10"
    echo "  Enforced:              2"
    echo "  Alert Fatigue:         83% reduction"
    echo ""
    echo "  Action:"
    echo "    ✓ CVE-2019-11043: ENFORCED (seccomp + network block)"
    echo "    ✓ CVE-2018-14884: ENFORCED (seccomp)"
    echo "    ○ CVE-2021-3156:  MONITORED (dormant)"
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    
elif [ "$DEMO_NAME" = "juice-shop" ]; then
    echo "[10:35:12] INFO: Starting scanner on Juice Shop container"
    echo "[10:35:12] INFO: Container: juice-shop (PID: 5678)"
    echo "[10:35:12] INFO: Image: bkimminich/juice-shop:latest"
    echo ""
    
    sleep 0.5
    echo "[10:35:13] INFO: Trivy scan complete"
    echo "[10:35:13] INFO: Found 8 CVEs in image"
    echo ""
    
    sleep 0.3
    echo "[10:35:13] EVENT: Process started - node (PID: 5678)"
    echo "[10:35:13] EVENT: Library loaded - express.js"
    echo "[10:35:13] EVENT: Network connection - 0.0.0.0:3000"
    echo ""
    
    sleep 0.5
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  VULNERABILITY DETECTION"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    
    echo "[10:35:15] CRITICAL: CVE-2021-22931"
    echo "  Package:    nodejs"
    echo "  CVSS:       9.8 (CRITICAL)"
    echo "  EPSS:       0.98"
    echo "  KEV:        YES"
    echo "  Runtime:    ✓ REACHABLE"
    echo "  Process:    node (PID: 5678)"
    echo "  Risk Score: 9.4/10"
    echo ""
    
    sleep 0.3
    echo "[10:35:15] HIGH: CVE-2022-24999"
    echo "  Package:    express"
    echo "  CVSS:       9.1 (CRITICAL)"
    echo "  EPSS:       0.95"
    echo "  KEV:        YES"
    echo "  Runtime:    ✓ REACHABLE"
    echo "  Process:    node (PID: 5678)"
    echo "  Risk Score: 9.1/10"
    echo ""
    
    sleep 0.5
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  ENFORCEMENT"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    
    echo "[10:35:16] ACTION: ENFORCED - CVE-2021-22931"
    echo "[10:35:16] ACTION: ENFORCED - CVE-2022-24999"
    echo ""
    
    sleep 0.5
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  SUMMARY"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "  Total CVEs:           8"
    echo "  Active/Reachable:      2"
    echo "  Enforced:              2"
    echo "  Alert Reduction:       75%"
    echo ""
    
    echo "═══════════════════════════════════════════════════════════════════"
    
else
    echo "Usage: $0 [dvwa|juice-shop]"
    exit 1
fi

echo ""
echo "Demo complete! ✅"
echo ""
echo "For real deployment:"
echo "  docker run --privileged --pid=host ghcr.io/akash-billawa/execution-aware-scanner:latest"
