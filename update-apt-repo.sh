#!/bin/bash
# Manual script to update APT repository from existing releases

set -e

echo "📦 Updating APT repository from GitHub releases..."

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download all .deb files from recent releases
echo "📥 Downloading packages from GitHub releases..."
for VERSION in v0.3.0 v0.3.1 v0.3.2; do
    echo "Processing $VERSION..."
    URLS=$(curl -s "https://api.github.com/repos/seelso-net/tty-egpf-monitor/releases/tags/$VERSION" | \
           grep "browser_download_url.*\.deb" | cut -d '"' -f 4)
    
    for URL in $URLS; do
        if [ -n "$URL" ]; then
            echo "Downloading: $(basename $URL)"
            wget -q "$URL" || echo "Failed to download $URL"
        fi
    done
done

# Run the setup-apt-repo script
echo "🔧 Building APT repository structure..."
cp "$OLDPWD/setup-apt-repo.sh" .
cp "$OLDPWD/public-apt-key.asc" . || true
cp "$OLDPWD/index.html" . || true

./setup-apt-repo.sh

echo "✅ APT repository created in: $TEMP_DIR/apt-repo"
echo ""
echo "To publish to GitHub Pages:"
echo "1. cd $TEMP_DIR/apt-repo"
echo "2. git init && git checkout -b gh-pages"
echo "3. git add -A && git commit -m 'Update APT repository'"
echo "4. git remote add origin https://github.com/seelso-net/tty-egpf-monitor.git"
echo "5. git push -f origin gh-pages"
