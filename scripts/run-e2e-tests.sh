#!/bin/bash
# End-to-end test runner
# Usage: ./run-e2e-tests.sh

set -e

echo "═══════════════════════════════════════════════════════════════"
echo "  Execution-Aware Scanner - End-to-End Tests"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Check if we're in a Linux environment
echo "[CHECK] Environment"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "  ✓ Linux detected"
    
    # Check kernel version
    KERNEL=$(uname -r | cut -d. -f1)
    if [ "$KERNEL" -ge 5 ]; then
        echo "  ✓ Kernel $KERNEL.x (supports eBPF)"
    else
        echo "  ⚠ Kernel $KERNEL.x (eBPF may have limitations)"
    fi
    
    # Check BTF
    if [ -d "/sys/kernel/btf" ]; then
        echo "  ✓ BTF enabled"
    else
        echo "  ⚠ BTF not enabled"
    fi
else
    echo "  ⚠ Not Linux - tests will run in mock mode"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Running Tests"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Run cargo tests
cd "$(dirname "$0")/.."
echo "Building scanner..."
cargo build -p scanner-agent --no-default-features --release 2>&1 | tail -5

echo ""
echo "Running E2E tests..."
cargo test -p scanner-agent --no-default-features --test e2e_test -- --nocapture 2>&1 | grep -E "(PASSED|FAILED|test)" || true

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Test Summary"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Expected Output Format:"
echo "  CVE-2023-XXXX → ACTIVE → HIGH → ENFORCED"
echo ""
echo "Pipeline Stages:"
echo "  [1/5] eBPF Event Capture       → Process + Library + Network"
echo "  [2/5] Runtime Correlation     → Map to container identity"
echo "  [3/5] Vulnerability Detection   → Trivy CVE scan"
echo "  [4/5] EXF Risk Scoring        → CVSS × EPSS × KEV × Runtime"
echo "  [5/5] Safe Enforcement        → Audit → Warn → Enforce"
echo ""
echo "═══════════════════════════════════════════════════════════════"
