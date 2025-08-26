# Release Guide

This guide explains how to create new releases of TTY EGPF Monitor with Debian package support.

## Creating a New Release

### 1. Update Version Information

Before creating a release, update the version in the following files:

- `debian/changelog` - Update the version number and add release notes
- `README.md` - Update any version-specific information

### 2. Create and Push a Tag

```bash
# Create a new tag (use semantic versioning)
git tag v1.0.0

# Push the tag to trigger the release workflow
git push origin v1.0.0
```

### 3. Automatic Release Process

When you push a tag, the GitHub Actions workflows will automatically:

1. **Build the application** with all dependencies
2. **Create a Debian package** (.deb file)
3. **Create a GitHub release** with the .deb file attached
4. **Update the APT repository** on GitHub Pages
5. **Generate release notes** from commits

### 4. Release Artifacts

Each release will include:

- `tty-egpf-monitor_<version>_<arch>.deb` - Debian package for installation
- Release notes with changelog
- Source code archive

## Installation Methods

### For Users

Users can install the release using:

```bash
# APT repository installation (recommended)
curl -sSL https://raw.githubusercontent.com/seelso-net/tty-egpf-monitor/main/setup-repo.sh | bash

# Manual APT repository setup
echo "deb [trusted=yes] https://seelso-net.github.io/tty-egpf-monitor stable main" | sudo tee /etc/apt/sources.list.d/tty-egpf-monitor.list
sudo apt update
sudo apt install tty-egpf-monitor

# Manual .deb installation
wget https://github.com/seelso-net/tty-egpf-monitor/releases/download/v1.0.0/tty-egpf-monitor_1.0.0_amd64.deb
sudo dpkg -i tty-egpf-monitor_1.0.0_amd64.deb
sudo apt-get install -f -y
```

### For Package Managers

The package can be installed using standard APT package management:

```bash
# Add repository and install
echo "deb [trusted=yes] https://seelso-net.github.io/tty-egpf-monitor stable main" | sudo tee /etc/apt/sources.list.d/tty-egpf-monitor.list
sudo apt update
sudo apt install tty-egpf-monitor

# Or install .deb file directly
sudo apt install ./tty-egpf-monitor_1.0.0_amd64.deb
```

## Versioning

Use semantic versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality in a backward-compatible manner
- **PATCH**: Backward-compatible bug fixes

## Release Checklist

- [ ] Update version in `debian/changelog`
- [ ] Update any version-specific documentation
- [ ] Test the build locally: `make clean && make`
- [ ] Create and push the tag: `git tag v1.0.0 && git push origin v1.0.0`
- [ ] Verify the GitHub release was created automatically
- [ ] Test the .deb package installation
- [ ] Update the installation script if needed
