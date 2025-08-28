#!/bin/bash
# Setup APT repository structure for GitHub Pages

set -e

# Configuration
REPO_ROOT="apt-repo"
CODENAMES=("jammy" "noble")
ARCHITECTURES=("amd64")
COMPONENT="main"
ORIGIN="TTY EGPF Monitor"
LABEL="TTY EGPF Monitor APT Repository"
DESCRIPTION="eBPF-based TTY monitoring tool"

# Check for required tools
for tool in dpkg-scanpackages apt-ftparchive gpg; do
    if ! command -v $tool &> /dev/null; then
        echo "Error: $tool is required but not installed."
        exit 1
    fi
done

# Create repository structure
echo "Creating APT repository structure..."
mkdir -p "$REPO_ROOT"/{pool/$COMPONENT,dists}

# Copy all .deb files to pool
echo "Copying packages to pool..."
find . -maxdepth 1 -name "*.deb" -exec cp {} "$REPO_ROOT/pool/$COMPONENT/" \;

# Create distributions for each codename
for CODENAME in "${CODENAMES[@]}"; do
    echo "Setting up distribution for $CODENAME..."
    DIST_DIR="$REPO_ROOT/dists/$CODENAME"
    mkdir -p "$DIST_DIR/$COMPONENT/binary-amd64"
    
    # Generate Packages file
    echo "Generating Packages file for $CODENAME..."
    cd "$REPO_ROOT"
    dpkg-scanpackages pool/$COMPONENT /dev/null > "dists/$CODENAME/$COMPONENT/binary-amd64/Packages"
    gzip -9c "dists/$CODENAME/$COMPONENT/binary-amd64/Packages" > "dists/$CODENAME/$COMPONENT/binary-amd64/Packages.gz"
    cd - > /dev/null
    
    # Create Release file for component
    cat > "$DIST_DIR/$COMPONENT/Release" << EOF
Archive: $CODENAME
Component: $COMPONENT
Origin: $ORIGIN
Label: $LABEL
Architecture: amd64
Description: $DESCRIPTION
EOF
    
    # Create main Release file
    cat > "$DIST_DIR/Release" << EOF
Origin: $ORIGIN
Label: $LABEL
Suite: $CODENAME
Codename: $CODENAME
Version: 1.0
Architectures: ${ARCHITECTURES[*]}
Components: $COMPONENT
Description: $DESCRIPTION
Date: $(date -R)
EOF
    
    # Add checksums to Release file
    cd "$DIST_DIR"
    apt-ftparchive release . >> Release
    cd - > /dev/null
done

# Sign Release files if GPG key is available
if [ -f "public-apt-key.asc" ]; then
    echo "Signing Release files..."
    # Extract key ID from public key
    KEY_ID=$(gpg --list-packets public-apt-key.asc 2>/dev/null | grep -A1 "public key packet" | grep "keyid:" | awk '{print $2}')
    
    if [ -n "$KEY_ID" ]; then
        for CODENAME in "${CODENAMES[@]}"; do
            gpg --default-key "$KEY_ID" -abs -o "$REPO_ROOT/dists/$CODENAME/Release.gpg" "$REPO_ROOT/dists/$CODENAME/Release" 2>/dev/null || \
                echo "Warning: Could not sign Release file for $CODENAME (GPG key not in keyring)"
            
            gpg --default-key "$KEY_ID" --clearsign -o "$REPO_ROOT/dists/$CODENAME/InRelease" "$REPO_ROOT/dists/$CODENAME/Release" 2>/dev/null || \
                echo "Warning: Could not create InRelease file for $CODENAME (GPG key not in keyring)"
        done
    else
        echo "Warning: Could not extract key ID from public-apt-key.asc"
    fi
else
    echo "Warning: public-apt-key.asc not found, skipping Release file signing"
fi

# Copy public key to repository root
if [ -f "public-apt-key.asc" ]; then
    cp public-apt-key.asc "$REPO_ROOT/"
fi

# Create repository index.html
if [ -f "index.html" ]; then
    cp index.html "$REPO_ROOT/"
fi

echo "APT repository structure created in $REPO_ROOT/"
echo "To publish, copy the contents of $REPO_ROOT/ to your web server or GitHub Pages"
