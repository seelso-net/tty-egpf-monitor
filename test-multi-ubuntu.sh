#!/bin/bash
# Test tty-egpf-monitor on multiple Ubuntu versions using Docker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configurations
UBUNTU_VERSIONS=("22.04" "24.04")
TEST_RESULTS=()

echo "🧪 Testing tty-egpf-monitor on multiple Ubuntu versions"
echo "======================================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is required but not installed.${NC}"
    exit 1
fi

# Build the package first
echo -e "\n${YELLOW}Building package on host system...${NC}"
if [ -x ./build-package.sh ]; then
    ./build-package.sh
else
    echo -e "${RED}Error: build-package.sh not found or not executable${NC}"
    exit 1
fi

# Find the latest .deb file
LATEST_DEB=$(ls -t *.deb 2>/dev/null | head -1)
if [ -z "$LATEST_DEB" ]; then
    echo -e "${RED}Error: No .deb file found${NC}"
    exit 1
fi
echo -e "${GREEN}Found package: $LATEST_DEB${NC}"

# Create test directory
TEST_DIR="test-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$TEST_DIR"

# Test on each Ubuntu version
for VERSION in "${UBUNTU_VERSIONS[@]}"; do
    echo -e "\n${YELLOW}Testing on Ubuntu $VERSION...${NC}"
    
    CONTAINER_NAME="tty-egpf-test-$VERSION"
    DOCKERFILE="$TEST_DIR/Dockerfile.$VERSION"
    
    # Create Dockerfile for this version
    cat > "$DOCKERFILE" << EOF
FROM ubuntu:$VERSION

# Install required packages
RUN apt-get update && \\
    apt-get install -y \\
        systemd \\
        systemd-sysv \\
        wget \\
        gpg \\
        lsb-release \\
        sudo \\
        libcap2-bin \\
        && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/*

# Enable systemd
ENV container docker
VOLUME ["/sys/fs/cgroup"]

# Copy the .deb file
COPY $LATEST_DEB /tmp/

# Install the package
RUN dpkg -i /tmp/$LATEST_DEB || apt-get install -f -y

# Create test script
RUN echo '#!/bin/bash' > /test.sh && \\
    echo 'set -e' >> /test.sh && \\
    echo 'echo "=== System Information ==="' >> /test.sh && \\
    echo 'lsb_release -a' >> /test.sh && \\
    echo 'uname -r' >> /test.sh && \\
    echo 'echo ""' >> /test.sh && \\
    echo 'echo "=== Package Status ==="' >> /test.sh && \\
    echo 'dpkg -l | grep tty-egpf || true' >> /test.sh && \\
    echo 'echo ""' >> /test.sh && \\
    echo 'echo "=== Binary Test ==="' >> /test.sh && \\
    echo 'which tty-egpf-monitord' >> /test.sh && \\
    echo 'which tty-egpf-monitor' >> /test.sh && \\
    echo 'echo ""' >> /test.sh && \\
    echo 'echo "=== Library Dependencies ==="' >> /test.sh && \\
    echo 'ldd /usr/bin/tty-egpf-monitord | head -20' >> /test.sh && \\
    echo 'echo ""' >> /test.sh && \\
    echo 'echo "=== Capability Check ==="' >> /test.sh && \\
    echo 'getcap /usr/bin/tty-egpf-monitord' >> /test.sh && \\
    echo 'echo ""' >> /test.sh && \\
    echo 'echo "=== Service File Check ==="' >> /test.sh && \\
    echo 'cat /lib/systemd/system/tty-egpf-monitord.service | grep -E "^(Exec|Ambient|Capability)" || true' >> /test.sh && \\
    echo 'echo ""' >> /test.sh && \\
    echo 'echo "=== Help Output ==="' >> /test.sh && \\
    echo '/usr/bin/tty-egpf-monitor --help || true' >> /test.sh && \\
    echo '/usr/bin/tty-egpf-monitord --help || true' >> /test.sh && \\
    chmod +x /test.sh

CMD ["/test.sh"]
EOF

    # Build and run the test container
    echo "Building container..."
    if docker build -f "$DOCKERFILE" -t "$CONTAINER_NAME" . > "$TEST_DIR/build-$VERSION.log" 2>&1; then
        echo "Running tests..."
        if docker run --rm --privileged "$CONTAINER_NAME" > "$TEST_DIR/test-$VERSION.log" 2>&1; then
            echo -e "${GREEN}✅ Ubuntu $VERSION: PASSED${NC}"
            TEST_RESULTS+=("$VERSION: PASSED")
            
            # Show key results
            echo "Key results:"
            grep -A1 "Binary Test" "$TEST_DIR/test-$VERSION.log" | tail -n2 || true
            grep "cap_" "$TEST_DIR/test-$VERSION.log" || true
        else
            echo -e "${RED}❌ Ubuntu $VERSION: FAILED${NC}"
            TEST_RESULTS+=("$VERSION: FAILED")
            echo "Error output:"
            tail -20 "$TEST_DIR/test-$VERSION.log"
        fi
    else
        echo -e "${RED}❌ Ubuntu $VERSION: BUILD FAILED${NC}"
        TEST_RESULTS+=("$VERSION: BUILD FAILED")
        echo "Build error:"
        tail -20 "$TEST_DIR/build-$VERSION.log"
    fi
    
    # Clean up
    docker rmi "$CONTAINER_NAME" 2>/dev/null || true
done

# Summary
echo -e "\n${YELLOW}=== Test Summary ===${NC}"
for result in "${TEST_RESULTS[@]}"; do
    if [[ $result == *"PASSED"* ]]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${RED}$result${NC}"
    fi
done

echo -e "\nTest results saved in: $TEST_DIR/"
echo "View individual test logs:"
ls -la "$TEST_DIR"/*.log
