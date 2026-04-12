#!/bin/bash
# eBPF Safety & Stability Audit Script
#
# Validates:
# - No kernel crashes
# - No verifier rejections
# - Maps not leaking
# - BPF programs unload cleanly
#
# Usage: ./scripts/ebpf-audit.sh [before|after]

set -e

MODE=${1:-"check"}
LOG_FILE="ebpf-audit-$(date +%Y%m%d-%H%M%S).log"

echo "========================================" | tee -a $LOG_FILE
echo "eBPF Safety & Stability Audit" | tee -a $LOG_FILE
echo "Mode: $MODE" | tee -a $LOG_FILE
echo "Timestamp: $(date)" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "⚠️  bpftool not found. Install: sudo apt-get install linux-tools-generic" | tee -a $LOG_FILE
    exit 1
fi

echo "Kernel Version: $(uname -r)" | tee -a $LOG_FILE
echo "BTF Support: $(test -f /sys/kernel/debug/btf/vmlinux && echo "✅ YES" || echo "❌ NO")" | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE

# Function to capture state
capture_state() {
    echo "Capturing eBPF state..." | tee -a $LOG_FILE
    
    echo "--- BPF Programs ---" >> $LOG_FILE
    bpftool prog list 2>/dev/null >> $LOG_FILE || echo "Failed to list programs" >> $LOG_FILE
    
    echo "" >> $LOG_FILE
    echo "--- BPF Maps ---" >> $LOG_FILE
    bpftool map list 2>/dev/null >> $LOG_FILE || echo "Failed to list maps" >> $LOG_FILE
    
    echo "" >> $LOG_FILE
    echo "--- Kernel Logs (last 50) ---" >> $LOG_FILE
    dmesg | tail -50 >> $LOG_FILE 2>/dev/null || journalctl -k -n 50 >> $LOG_FILE 2>/dev/null || echo "Cannot access kernel logs" >> $LOG_FILE
    
    echo "" >> $LOG_FILE
    echo "--- Memory Usage ---" >> $LOG_FILE
    cat /proc/meminfo | grep -E "^(MemTotal|MemFree|Buffers|Cached)" >> $LOG_FILE
    
    echo "" >> $LOG_FILE
    echo "--- Scanner Process ---" >> $LOG_FILE
    ps aux | grep -E "(scanner-agent|scanner)" | grep -v grep >> $LOG_FILE 2>/dev/null || echo "Scanner not running" >> $LOG_FILE
}

# Function to check for issues
check_issues() {
    echo "" | tee -a $LOG_FILE
    echo "Checking for issues..." | tee -a $LOG_FILE
    
    local ISSUES=0
    
    # Check for kernel oops/panics
    if dmesg 2>/dev/null | grep -qi "oops\|panic\|BUG:"; then
        echo "❌ FAIL: Kernel oops/panic detected!" | tee -a $LOG_FILE
        ISSUES=$((ISSUES + 1))
    else
        echo "✅ PASS: No kernel oops/panics" | tee -a $LOG_FILE
    fi
    
    # Check for verifier rejections
    if dmesg 2>/dev/null | grep -q "verifier"; then
        echo "⚠️  WARNING: Verifier messages found:" | tee -a $LOG_FILE
        dmesg | grep -i "verifier" | tail -5 | tee -a $LOG_FILE
    else
        echo "✅ PASS: No verifier issues" | tee -a $LOG_FILE
    fi
    
    # Check for map leaks (compare counts)
    MAP_COUNT=$(bpftool map list 2>/dev/null | wc -l)
    if [ "$MAP_COUNT" -gt 100 ]; then
        echo "⚠️  WARNING: High map count ($MAP_COUNT) - potential leak" | tee -a $LOG_FILE
        ISSUES=$((ISSUES + 1))
    else
        echo "✅ PASS: Map count normal ($MAP_COUNT)" | tee -a $LOG_FILE
    fi
    
    # Check for orphan programs
    PROG_COUNT=$(bpftool prog list 2>/dev/null | wc -l)
    if [ "$PROG_COUNT" -gt 50 ]; then
        echo "⚠️  WARNING: High program count ($PROG_COUNT) - check for orphans" | tee -a $LOG_FILE
        ISSUES=$((ISSUES + 1))
    else
        echo "✅ PASS: Program count normal ($PROG_COUNT)" | tee -a $LOG_FILE
    fi
    
    # Check scanner memory
    SCANNER_MEM=$(ps aux | grep scanner-agent | grep -v grep | awk '{print $6}' 2>/dev/null || echo "0")
    if [ "${SCANNER_MEM:-0}" -gt 524288 ]; then  # 512MB
        echo "❌ FAIL: Scanner memory too high (${SCANNER_MEM}KB)" | tee -a $LOG_FILE
        ISSUES=$((ISSUES + 1))
    else
        echo "✅ PASS: Scanner memory within limits (${SCANNER_MEM}KB)" | tee -a $LOG_FILE
    fi
    
    echo "" | tee -a $LOG_FILE
    if [ $ISSUES -eq 0 ]; then
        echo "✅ ALL CHECKS PASSED" | tee -a $LOG_FILE
        return 0
    else
        echo "❌ FOUND $ISSUES ISSUE(S)" | tee -a $LOG_FILE
        return 1
    fi
}

case $MODE in
    "before")
        echo "Capturing pre-deployment state..." | tee -a $LOG_FILE
        capture_state
        echo "" | tee -a $LOG_FILE
        echo "State captured to: $LOG_FILE" | tee -a $LOG_FILE
        echo "Run 'after' scanner deployment" | tee -a $LOG_FILE
        ;;
    
    "after")
        echo "Capturing post-deployment state..." | tee -a $LOG_FILE
        capture_state
        echo "" | tee -a $LOG_FILE
        check_issues
        echo "" | tee -a $LOG_FILE
        echo "Comparison with 'before' state:" | tee -a $LOG_FILE
        echo "  Review bpf-audit-before.log vs $LOG_FILE" | tee -a $LOG_FILE
        ;;
    
    "cleanup")
        echo "Cleaning up eBPF artifacts..." | tee -a $LOG_FILE
        
        # Try to unload scanner programs gracefully
        for pid in $(pgrep -f "scanner-agent"); do
            echo "Stopping scanner process $pid" | tee -a $LOG_FILE
            kill -TERM $pid 2>/dev/null || true
            sleep 2
            kill -KILL $pid 2>/dev/null || true
        done
        
        sleep 3
        
        # Check cleanup
        PROG_COUNT=$(bpftool prog list 2>/dev/null | wc -l)
        MAP_COUNT=$(bpftool map list 2>/dev/null | wc -l)
        
        echo "Remaining programs: $PROG_COUNT" | tee -a $LOG_FILE
        echo "Remaining maps: $MAP_COUNT" | tee -a $LOG_FILE
        
        if [ "$PROG_COUNT" -lt 10 ] && [ "$MAP_COUNT" -lt 20 ]; then
            echo "✅ Cleanup successful" | tee -a $LOG_FILE
        else
            echo "⚠️  Manual cleanup may be needed" | tee -a $LOG_FILE
        fi
        ;;
    
    "check"|*)
        echo "Running eBPF health check..." | tee -a $LOG_FILE
        capture_state
        echo "" | tee -a $LOG_FILE
        check_issues
        ;;
esac

echo "" | tee -a $LOG_FILE
echo "Log saved to: $LOG_FILE" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE
