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

When you push a tag, the GitHub Actions workflow will automatically:

1. **Build the application** with all dependencies
2. **Create a Debian package** (.deb file)
3. **Create a GitHub release** with the .deb file attached
4. **Generate release notes** from commits

### 4. Release Artifacts

Each release will include:

- `tty-egpf-monitor_<version>_<arch>.deb` - Debian package for installation
- Release notes with changelog
- Source code archive

## Installation Methods

### For Users

Users can install the release using:

```bash
# Download and install the latest release
wget https://github.com/seelso-net/tty-egpf-monitor/releases/latest/download/tty-egpf-monitor_*_amd64.deb
sudo dpkg -i tty-egpf-monitor_*_amd64.deb
sudo apt-get install -f -y  # Fix any dependency issues

# Or install a specific version
wget https://github.com/seelso-net/tty-egpf-monitor/releases/download/v1.0.0/tty-egpf-monitor_1.0.0_amd64.deb
sudo dpkg -i tty-egpf-monitor_1.0.0_amd64.deb
sudo apt-get install -f -y
```

### For Package Managers

The package can be installed using standard Debian package management:

```bash
# Install .deb file directly
sudo apt install ./tty-egpf-monitor_1.0.0_amd64.deb

# Or download and install
wget https://github.com/seelso-net/tty-egpf-monitor/releases/download/v1.0.0/tty-egpf-monitor_1.0.0_amd64.deb
sudo dpkg -i tty-egpf-monitor_1.0.0_amd64.deb
sudo apt-get install -f -y
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
