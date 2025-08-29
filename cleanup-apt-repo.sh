#!/bin/bash
# Script to remove specific versions from the APT repository

set -e

echo "🧹 Cleaning up APT repository..."

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Clone the gh-pages branch
echo "📥 Cloning gh-pages branch..."
git clone --depth 1 --branch gh-pages https://github.com/seelso-net/tty-egpf-monitor.git apt-repo
cd apt-repo

# Remove v1.1.0 packages from pool
echo "🗑️  Removing v1.1.0 packages..."
rm -fv pool/main/*_1.1.0-1_*.deb

# List remaining packages
echo ""
echo "📦 Remaining packages in pool:"
ls -la pool/main/*.deb | awk '{print $9}' | sort -V

# Regenerate package indices for all distributions
echo ""
echo "🔧 Regenerating package indices..."
for CODENAME in jammy noble; do
    echo "Processing $CODENAME..."
    
    # Regenerate Packages files
    mkdir -p dists/${CODENAME}/main/binary-amd64
    apt-ftparchive packages pool/main > dists/${CODENAME}/main/binary-amd64/Packages
    gzip -9c dists/${CODENAME}/main/binary-amd64/Packages > dists/${CODENAME}/main/binary-amd64/Packages.gz
    
    # Regenerate Release file
    apt-ftparchive \
        -o APT::FTPArchive::Release::Label="tty-egpf-monitor" \
        -o APT::FTPArchive::Release::Suite="${CODENAME}" \
        -o APT::FTPArchive::Release::Codename="${CODENAME}" \
        -o APT::FTPArchive::Release::Architectures="amd64" \
        -o APT::FTPArchive::Release::Components="main" \
        release dists/${CODENAME} > dists/${CODENAME}/Release
done

# Check if we have GPG key for signing
if [ -n "$GPG_PRIVATE_KEY" ]; then
    echo "🔐 Signing Release files..."
    echo "$GPG_PRIVATE_KEY" | gpg --batch --yes --import
    for CODENAME in jammy noble; do
        gpg --batch --yes --pinentry-mode loopback --passphrase "$GPG_PASSPHRASE" -abs -o dists/${CODENAME}/Release.gpg dists/${CODENAME}/Release
        gpg --batch --yes --pinentry-mode loopback --passphrase "$GPG_PASSPHRASE" --clearsign -o dists/${CODENAME}/InRelease dists/${CODENAME}/Release || true
    done
else
    echo "⚠️  No GPG key provided, skipping signing"
fi

# Show what changed
echo ""
echo "📊 Changes to be committed:"
git status --short

# Commit and push
echo ""
echo "💾 Committing changes..."
git add -A
git commit -m "Remove v1.1.0 packages from APT repository" || echo "No changes to commit"

echo ""
echo "✅ Repository cleaned!"
echo ""
echo "To push changes to GitHub Pages, run:"
echo "cd $TEMP_DIR/apt-repo && git push origin gh-pages"
