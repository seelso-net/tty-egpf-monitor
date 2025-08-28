#!/bin/bash
# Build Debian package with OS-specific dependencies

set -e

# Detect Ubuntu version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "Building for $NAME $VERSION_ID"
else
    echo "Warning: Cannot detect OS version, using default control file"
    VERSION_ID="default"
fi

# Clean previous builds
rm -rf debian/tty-egpf-monitord debian/tty-egpf-monitor-cli debian/*.deb debian/files debian/*.buildinfo debian/*.changes

# Select appropriate control file
if [ "$VERSION_ID" = "22.04" ] && [ -f debian/control.jammy ]; then
    echo "Using Jammy (22.04) control file"
    cp debian/control.jammy debian/control
elif [ "$VERSION_ID" = "24.04" ] && [ -f debian/control.noble ]; then
    echo "Using Noble (24.04) control file"
    cp debian/control.noble debian/control
else
    echo "Using default control file"
    # Keep the existing control file
fi

# Build the package
echo "Building package..."
dpkg-buildpackage -b -uc -us

echo "Build complete!"
echo "Packages created:"
ls -la ../*.deb 2>/dev/null || echo "No .deb files found in parent directory"
