# KERIGuard Debian Packaging

This directory contains Debian packaging files for the keriguard project. The packaging system creates a single unified package with two systemd services: `keriguard-guardian` and `keriguard-sentinel`.

## Package Architecture

- **Single package design**: One `keriguard` package containing both services
- **Python virtualenv**: Located at `/opt/keriguard/venv/`
- **Two systemd services**: Guardian and Sentinel running as separate system users
- **dh-virtualenv**: Handles Python dependency management

## Directory Structure

```
debian/
├── source/
│   └── format              # Debian source format (3.0 native)
├── changelog               # Package version history
├── compat                  # Debhelper compatibility version
├── control                 # Package metadata and dependencies
├── rules                   # Build rules (Makefile)
├── keriguard.postinst     # Post-installation script
├── keriguard-guardian.service  # Guardian systemd unit
└── keriguard-sentinel.service  # Sentinel systemd unit
```

## Building Packages

### Prerequisites

1. Docker installed and running
2. Git repository with current code

### Build Commands

```bash
# Build for ARM64 (default)
bash scripts/build-deb.sh arm64

# Build for AMD64
bash scripts/build-deb.sh amd64
```

The build script will:
1. Check for or build the Docker builder image
2. Clean previous build artifacts
3. Update the changelog with current git commit
4. Build the package using dpkg-buildpackage
5. Collect artifacts to `build/` directory

### Build Output

```
build/
├── keriguard_0.0.1-1+dev<commit>_arm64.deb
├── keriguard_0.0.1-1+dev<commit>_arm64.buildinfo
└── keriguard_0.0.1-1+dev<commit>_arm64.changes
```

## Installation

### Install Package

```bash
# Install the package
sudo dpkg -i build/keriguard_*.deb

# Fix dependencies if needed
sudo apt-get install -f
```

### Configure Services

#### Configure Guardian Service

Edit `/etc/default/keriguard-guardian`:

```bash
sudo nano /etc/default/keriguard-guardian
```

Required changes:
- Set `KERIGUARD_SENTINEL_AID` to the sentinel's AID
- Update `KERIGUARD_EXPORT_DIR` if different from default
- Adjust other settings as needed

#### Configure Sentinel Service

Edit `/etc/keriguard/sentinel.yaml`:

```bash
sudo nano /etc/keriguard/sentinel.yaml
```

Required changes:
- Set `export_dir` (must match guardian's `KERIGUARD_EXPORT_DIR`)
- Set `base_dir` for KERI data
- Configure other sentinel options

### Enable and Start Services

```bash
# Start sentinel first (guardian depends on its exports)
sudo systemctl enable keriguard-sentinel
sudo systemctl start keriguard-sentinel

# Then start guardian
sudo systemctl enable keriguard-guardian
sudo systemctl start keriguard-guardian
```

### Verify Services

```bash
# Check service status
sudo systemctl status keriguard-guardian
sudo systemctl status keriguard-sentinel

# View logs
tail -f /var/log/keriguard-guardian/guardian.log
tail -f /var/log/keriguard-sentinel/sentinel.log
```

## Post-Installation Directory Structure

```
/opt/keriguard/
├── venv/                          # Python virtualenv
│   ├── bin/
│   │   ├── kg                    # CLI utility
│   │   ├── kg-sentinel           # Sentinel CLI utility
│   │   └── sentinel              # Sentinel command
│   └── lib/python3.13/
├── guardian/                      # Guardian working dir
└── sentinel/                      # Sentinel working dir

/etc/
├── default/
│   ├── keriguard-guardian        # Guardian env vars
│   └── keriguard-sentinel        # Sentinel env vars
├── keriguard/
│   └── sentinel.yaml             # Sentinel config
└── logrotate.d/
    ├── keriguard-guardian
    └── keriguard-sentinel

/var/
├── log/
│   ├── keriguard-guardian/       # Guardian logs
│   └── keriguard-sentinel/       # Sentinel logs
└── lib/
    ├── keriguard-guardian/       # Guardian runtime data
    └── keriguard-sentinel/       # Sentinel runtime data
```

## CLI Utilities

After installation, CLI utilities are available at:

```bash
# KERIGuard CLI
/opt/keriguard/venv/bin/kg --help
/opt/keriguard/venv/bin/kg guardian up --config /path/to/config.yaml
/opt/keriguard/venv/bin/kg interface list

# Sentinel CLI
/opt/keriguard/venv/bin/kg-sentinel --help
/opt/keriguard/venv/bin/sentinel --help
```

## Troubleshooting

### Service Won't Start

1. Check configuration:
   ```bash
   cat /etc/default/keriguard-guardian
   cat /etc/keriguard/sentinel.yaml
   ```

2. Check logs:
   ```bash
   sudo journalctl -u keriguard-guardian -n 50
   sudo journalctl -u keriguard-sentinel -n 50
   ```

3. Verify permissions:
   ```bash
   ls -ld /var/log/keriguard-*
   ls -ld /var/lib/keriguard-*
   ```

### Build Fails

1. Clean and rebuild Docker image:
   ```bash
   docker system prune -a
   docker build --platform linux/arm64 -t keriguard-builder:22.04-arm64 -f Dockerfile.builder .
   ```

2. Clean build artifacts:
   ```bash
   rm -rf debian/keriguard/
   rm -rf debian/.debhelper/
   rm -f debian/files debian/*.substvars debian/*.log
   ```

### Permission Errors

Fix ownership:
```bash
sudo chown -R keriguard-guardian:keriguard-guardian /opt/keriguard/guardian
sudo chown -R keriguard-guardian:keriguard-guardian /var/log/keriguard-guardian
sudo chown -R keriguard-sentinel:keriguard-sentinel /opt/keriguard/sentinel
sudo chown -R keriguard-sentinel:keriguard-sentinel /var/log/keriguard-sentinel
```

## Development

### Modifying the Package

1. Update source code in `src/`
2. Update version in `pyproject.toml`
3. Rebuild package: `bash scripts/build-deb.sh arm64`
4. Test installation in clean environment

### Testing in Docker

```bash
# Start test container
docker run -it --rm -v $(pwd)/build:/build ubuntu:22.04 bash

# Inside container
apt-get update
apt-get install -y /build/keriguard_*.deb
```

## Dependencies

### Build Dependencies

- debhelper-compat (= 13)
- dh-virtualenv
- python3.13, python3.13-dev, python3.13-venv
- build-essential, git
- libsodium-dev (for KERI cryptography)
- libdbus-1-dev (for dbus-fast Python package)

### Runtime Dependencies

- python3.13
- systemd
- adduser
- wireguard-tools (provides `wg` and `wg-quick` commands)
- dbus (system message bus)

## Related Files

- `Dockerfile.builder` - Docker image for building packages
- `scripts/build-deb.sh` - Build orchestration script
- `pyproject.toml` - Python package configuration with entry points
- `.gitignore` - Updated to exclude debian build artifacts

## References

- [dh-virtualenv Documentation](https://dh-virtualenv.readthedocs.io/)
- [Debian New Maintainers' Guide](https://www.debian.org/doc/manuals/maint-guide/)
- [systemd Service Unit Documentation](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
