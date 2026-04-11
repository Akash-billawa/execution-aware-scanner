#!/bin/bash
# Generate SBOMs for container images using Trivy
# Usage: ./generate-sboms.sh [image1] [image2] ...
# Or: ./generate-sboms.sh (scans default images)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../examples/sboms"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if Trivy is installed
if ! command -v trivy &> /dev/null; then
    echo "❌ Trivy not found. Install with:"
    echo "   sudo apt install trivy    # Debian/Ubuntu"
    echo "   brew install trivy        # macOS"
    echo "   See: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    exit 1
fi

# Default images to scan if none provided
DEFAULT_IMAGES=(
    "nginx:alpine"
    "redis:alpine"
    "postgres:15-alpine"
    "busybox:latest"
)

# Use provided images or defaults
if [ $# -eq 0 ]; then
    IMAGES=("${DEFAULT_IMAGES[@]}")
    echo "ℹ️  No images provided, using defaults: ${IMAGES[*]}"
else
    IMAGES=("$@")
fi

echo "🔍 Generating SBOMs with Trivy..."
echo "📁 Output directory: $OUTPUT_DIR"
echo ""

for image in "${IMAGES[@]}"; do
    # Sanitize image name for filename (replace : and / with _)
    safe_name=$(echo "$image" | tr '/:' '__')
    output_file="$OUTPUT_DIR/${safe_name}.json"
    
    echo "⏳ Scanning: $image"
    
    # Generate SBOM in CycloneDX JSON format
    trivy image \
        --format cyclonedx \
        --output "$output_file" \
        "$image" 2>/dev/null || {
        echo "   ⚠️  Failed to scan $image (may require docker pull)"
        continue
    }
    
    # Convert to our internal format (extract packages)
    echo "   ✅ Generated: $output_file"
    
    # Show summary
    pkg_count=$(grep -c '"name"' "$output_file" 2>/dev/null || echo "0")
    echo "   📦 Packages found: $pkg_count"
done

echo ""
echo "✅ SBOM generation complete!"
echo "📂 Files in: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"
