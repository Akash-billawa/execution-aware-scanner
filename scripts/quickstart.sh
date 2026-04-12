#!/bin/bash
# Quickstart Script for Execution-Aware Scanner
# One-command setup: curl -sSL .../quickstart.sh | bash
#
# Usage: ./quickstart.sh [mode]
#   mode: stream (default), batch, demo

set -e

SCRIPT_VERSION="0.1.0"
IMAGE="ghcr.io/akash-billawa/execution-aware-scanner:latest"
MODE=${1:-"stream"}

echo "========================================"
echo "Execution-Aware Scanner Quickstart"
echo "Version: $SCRIPT_VERSION"
echo "Mode: $MODE"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}❌ Error: This scanner requires Linux with kernel 5.8+${NC}"
    echo "Current OS: $OSTYPE"
    exit 1
fi

# Check kernel version
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
if [[ "$KERNEL_MAJOR" -lt 5 ]] || ([[ "$KERNEL_MAJOR" -eq 5 ]] && [[ "$KERNEL_MINOR" -lt 8 ]]); then
    echo -e "${RED}❌ Error: Kernel $KERNEL_MAJOR.$KERNEL_MINOR detected, requires 5.8+${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Kernel version check passed${NC} (Linux $(uname -r))"

# Check for BTF support
if [[ ! -f /sys/kernel/debug/btf/vmlinux ]]; then
    echo -e "${YELLOW}⚠ Warning: BTF not detected. eBPF may fail.${NC}"
    echo "  Install: sudo apt-get install linux-headers-$(uname -r)"
fi

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker not found${NC}"
    echo "Installing Docker..."
    
    # Install Docker
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    
    echo -e "${GREEN}✓ Docker installed. Please log out and back in.${NC}"
    exit 0
fi

echo -e "${GREEN}✓ Docker detected${NC} ($(docker --version))"

# Check for bpftool (optional but recommended)
if command -v bpftool &> /dev/null; then
    echo -e "${GREEN}✓ bpftool detected${NC}"
else
    echo -e "${YELLOW}⚠ bpftool not found (optional but recommended)${NC}"
    echo "  Install: sudo apt-get install linux-tools-generic"
fi

echo ""
echo "Pulling scanner image..."
docker pull $IMAGE

echo ""
echo "Starting scanner in $MODE mode..."

# Create config directory
mkdir -p ~/.execution-aware-scanner
cd ~/.execution-aware-scanner

# Generate config based on mode
case $MODE in
    "demo")
        echo "Running demo mode with simulated events..."
        docker run --rm -it \
            --privileged \
            --pid=host \
            --network=host \
            -v /sys/kernel/debug:/sys/kernel/debug:ro \
            -v /proc:/host/proc:ro \
            -e RUST_LOG=info \
            $IMAGE \
            --mode stream \
            --stream-json \
            --stream-interval 1s
        ;;
    
    "batch")
        echo "Running batch mode (single scan)..."
        docker run --rm -it \
            --privileged \
            --pid=host \
            --network=host \
            -v /sys/kernel/debug:/sys/kernel/debug:ro \
            -v /proc:/host/proc:ro \
            -e RUST_LOG=info \
            $IMAGE \
            --once
        ;;
    
    "stream"|*)
        echo "Running stream mode (continuous monitoring)..."
        echo ""
        echo "Available endpoints:"
        echo "  Health:   http://localhost:9898/health"
        echo "  Ready:    http://localhost:9898/ready"
        echo "  Metrics:  http://localhost:9898/metrics"
        echo ""
        echo "Press Ctrl+C to stop"
        echo ""
        
        docker run --rm -it \
            --name execution-aware-scanner \
            --privileged \
            --pid=host \
            --network=host \
            -v /sys/kernel/debug:/sys/kernel/debug:ro \
            -v /proc:/host/proc:ro \
            -p 9898:9898 \
            -e RUST_LOG=info \
            $IMAGE \
            --mode stream \
            --stream-json \
            --stream-interval 1s \
            --top-k 3
        ;;
esac

echo ""
echo -e "${GREEN}✓ Scanner stopped${NC}"
echo ""
echo "For production deployment:"
echo "  kubectl apply -f https://raw.githubusercontent.com/Akash-billawa/execution-aware-scanner/main/deploy/kubernetes/daemonset-prod.yaml"
echo ""
echo "Documentation: https://github.com/Akash-billawa/execution-aware-scanner#readme"
