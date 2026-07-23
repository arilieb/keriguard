#!/bin/bash
set -e

# KERIGuard Debian Package Build Script
# Builds .deb packages for ARM64 and AMD64 architectures using Docker

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Usage information
usage() {
    echo "Usage: $0 [ARCHITECTURE]"
    echo ""
    echo "Arguments:"
    echo "  ARCHITECTURE  Target architecture (arm64 or amd64, default: arm64)"
    echo ""
    echo "Examples:"
    echo "  $0           # Build for ARM64"
    echo "  $0 arm64     # Build for ARM64"
    echo "  $0 amd64     # Build for AMD64"
    exit 1
}

# Parse arguments
ARCH="${1:-arm64}"

if [[ "$ARCH" != "arm64" && "$ARCH" != "amd64" ]]; then
    echo -e "${RED}Error: Invalid architecture '$ARCH'. Must be 'arm64' or 'amd64'.${NC}"
    usage
fi

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo -e "${GREEN}KERIGuard Debian Package Builder${NC}"
echo "=================================="
echo "Architecture: $ARCH"
echo "Project root: $PROJECT_ROOT"
echo ""

# Extract version from pyproject.toml
cd "$PROJECT_ROOT"
VERSION=$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/')
if [ -z "$VERSION" ]; then
    echo -e "${RED}Error: Could not extract version from pyproject.toml${NC}"
    exit 1
fi
echo "Package version: $VERSION"

# Get git commit hash for dev version suffix
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DEB_VERSION="${VERSION}-1+dev${GIT_COMMIT}"
echo "Debian version: $DEB_VERSION"
echo ""

# Docker image name
DOCKER_IMAGE="keriguard-builder:22.04-${ARCH}"

# Check if Docker image exists
echo -e "${YELLOW}Checking for Docker builder image...${NC}"
if ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo -e "${YELLOW}Builder image not found. Building Docker image...${NC}"
    docker build --platform "linux/${ARCH}" -t "$DOCKER_IMAGE" -f Dockerfile.builder .
    echo -e "${GREEN}Docker image built successfully.${NC}"
else
    echo -e "${GREEN}Docker image found.${NC}"
fi
echo ""

# Create build directory
BUILD_DIR="$PROJECT_ROOT/build"
mkdir -p "$BUILD_DIR"

# Clean previous builds
echo -e "${YELLOW}Cleaning previous builds...${NC}"
rm -rf debian/keriguard/
rm -rf debian/.debhelper/
rm -f debian/files
rm -f debian/*.substvars
rm -f debian/*.debhelper.log
rm -f debian/debhelper-build-stamp
rm -rf .pybuild/
echo -e "${GREEN}Cleanup complete.${NC}"
echo ""

# Update changelog with git commit
echo -e "${YELLOW}Updating debian/changelog...${NC}"
cat > debian/changelog <<EOF
keriguard (${DEB_VERSION}) stable; urgency=medium

  * Development build from commit ${GIT_COMMIT}
  * Guardian service for Wireguard management
  * Sentinel service for KERI event monitoring
  * CLI utilities: kg and kg-sentinel

 -- Phil Feairheller <phil@healthKERI.com>  $(date -R)
EOF
echo -e "${GREEN}Changelog updated.${NC}"
echo ""

# Build package in Docker container
echo -e "${YELLOW}Building Debian package...${NC}"
docker run --rm \
    --platform "linux/${ARCH}" \
    -v "$PROJECT_ROOT:/build" \
    -w /build \
    -e DEBFULLNAME="Phil Feairheller" \
    -e DEBEMAIL="phil@healthKERI.com" \
    "$DOCKER_IMAGE" \
    bash -c "
        set -e
        echo 'Building package...'
        dpkg-buildpackage -us -uc -b -a${ARCH}

        echo 'Collecting artifacts...'
        mkdir -p /build/build
        mv ../*.deb /build/build/ 2>/dev/null || true
        mv ../*.buildinfo /build/build/ 2>/dev/null || true
        mv ../*.changes /build/build/ 2>/dev/null || true
        mv ../*.ddeb /build/build/ 2>/dev/null || true
        ls -lh /build/build/

        echo 'Build complete.'
    "

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Package built successfully.${NC}"
echo ""

# Fix permissions (Docker runs as root, so files are owned by root)
echo -e "${YELLOW}Fixing file permissions...${NC}"
chown -R $(id -u):$(id -g) "$BUILD_DIR" 2>/dev/null || \
    sudo chown -R $(id -u):$(id -g) "$BUILD_DIR"
echo -e "${GREEN}Permissions fixed.${NC}"
echo ""

# List built packages
echo -e "${GREEN}Build complete! Packages:${NC}"
ls -lh "$BUILD_DIR"/*.deb 2>/dev/null || echo "No .deb files found in $BUILD_DIR"
echo ""

echo -e "${GREEN}=================================="
echo "Build finished successfully!"
echo "==================================${NC}"
echo ""
echo "Package location: $BUILD_DIR"
echo ""
echo "To install the package:"
echo "  sudo dpkg -i $BUILD_DIR/keriguard_${DEB_VERSION}_${ARCH}.deb"
echo "  sudo apt-get install -f  # Fix dependencies if needed"
echo ""
