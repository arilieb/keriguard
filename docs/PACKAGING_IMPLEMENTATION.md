# KERIGuard Debian Packaging Implementation

## Implementation Summary

The Debian packaging system for keriguard has been successfully implemented according to the design plan. This creates a single unified package with two systemd services for Guardian and Sentinel.

## Files Created

### Debian Package Configuration

```
debian/
├── source/
│   └── format                          # Debian source format specification
├── changelog                           # Package version history
├── compat                              # Debhelper compatibility level (13)
├── control                             # Package metadata and dependencies
├── rules                               # Build rules (Makefile)
├── keriguard.postinst                 # Post-installation setup script
├── keriguard-guardian.service         # Guardian systemd unit file
├── keriguard-sentinel.service         # Sentinel systemd unit file
└── README.md                           # Packaging documentation
```

### Build Infrastructure

```
Dockerfile.builder                      # Docker image for building packages
scripts/build-deb.sh                   # Build orchestration script
```

### Configuration Updates

```
.gitignore                             # Updated to exclude debian build artifacts
pyproject.toml                         # Existing file (verified entry points)
```

## Key Features Implemented

### 1. Single Package Architecture

- **Package name**: `keriguard`
- **Python virtualenv**: `/opt/keriguard/venv/`
- **Two systemd services**:
  - `keriguard-guardian.service`
  - `keriguard-sentinel.service`
- **Two system users**:
  - `keriguard-guardian`
  - `keriguard-sentinel`

### 2. Systemd Integration

Both services are configured with:
- Automatic restart on failure (10-second backoff)
- File-based logging (not journald)
- Environment-based configuration
- Network dependency (After=network-online.target)
- User isolation (dedicated service users)

### 3. Configuration Management

**Guardian**: `/etc/default/keriguard-guardian`
- Environment variables for all service settings
- Includes: sentinel AID, export directory, poll interval, config directory, KERI base, log level

**Sentinel**: `/etc/keriguard/sentinel.yaml`
- YAML configuration file
- Includes: export directory, poll interval, base directory, service name

### 4. Logging

**Guardian logs**:
- `/var/log/keriguard-guardian/guardian.log`
- `/var/log/keriguard-guardian/guardian.error.log`

**Sentinel logs**:
- `/var/log/keriguard-sentinel/sentinel.log`
- `/var/log/keriguard-sentinel/sentinel.error.log`

**Log rotation**: Daily rotation with 14-day retention (automatically configured)

### 5. Directory Structure

Post-installation directories:

```
/opt/keriguard/
├── venv/                              # Shared Python virtualenv (root:root, 755)
├── guardian/                          # Guardian working directory
└── sentinel/                          # Sentinel working directory

/var/log/keriguard-{guardian,sentinel}/    # Service logs
/var/lib/keriguard-{guardian,sentinel}/    # Runtime data (including KERI databases)
/etc/default/keriguard-{guardian,sentinel} # Configuration files
/etc/keriguard/sentinel.yaml               # Sentinel YAML config
```

### 6. Security

- Dedicated system users for each service
- Config files: 640 permissions (root:service-group)
- Log directories: 755 permissions (service:service)
- Virtualenv: 755 permissions (root:root, read-only for services)
- No auto-start (administrator must explicitly enable)

### 7. CLI Utilities

Installed at `/opt/keriguard/venv/bin/`:
- `kg` - Main KERIGuard CLI utility
- `kg-sentinel` - Sentinel-specific CLI utility
- `sentinel` - Sentinel command from package dependency

## Dependencies

### Build Dependencies

- debhelper-compat (= 13)
- dh-virtualenv
- python3.13, python3.13-dev, python3.13-venv
- build-essential, git
- libsodium-dev (KERI cryptography)
- libdbus-1-dev (dbus-fast Python package)

### Runtime Dependencies

- python3.13
- systemd
- adduser
- wireguard-tools (wg, wg-quick commands)
- dbus (system message bus)

## Build Process

### 1. Build Docker Image (one-time setup)

```bash
# For ARM64
docker build --platform linux/arm64 -t keriguard-builder:22.04-arm64 -f Dockerfile.builder .

# For AMD64
docker build --platform linux/amd64 -t keriguard-builder:22.04-amd64 -f Dockerfile.builder .
```

### 2. Build Package

```bash
# Build for ARM64 (default)
bash scripts/build-deb.sh arm64

# Build for AMD64
bash scripts/build-deb.sh amd64
```

### 3. Output

```
build/
├── keriguard_0.0.1-1+dev<commit>_arm64.deb
├── keriguard_0.0.1-1+dev<commit>_arm64.buildinfo
└── keriguard_0.0.1-1+dev<commit>_arm64.changes
```

## Installation Workflow

### 1. Install Package

```bash
sudo dpkg -i build/keriguard_*.deb
sudo apt-get install -f  # Fix dependencies if needed
```

### 2. Configure Guardian Service

```bash
sudo nano /etc/default/keriguard-guardian
```

Required configuration:
- `KERIGUARD_SENTINEL_AID`: Set to the sentinel's AID (REQUIRED)
- `KERIGUARD_EXPORT_DIR`: Directory where sentinel exports KERI events
- `KERIGUARD_POLL_INTERVAL`: Polling interval in seconds
- `KERIGUARD_CONFIG_DIR`: Wireguard configuration directory
- `KERIGUARD_BASE`: KERI base directory for guardian
- `KERIGUARD_LOGLEVEL`: Log level (INFO, DEBUG, etc.)

### 3. Configure Sentinel Service

```bash
sudo nano /etc/keriguard/sentinel.yaml
```

Required configuration:
- `export_dir`: Directory to export KERI events (must match guardian's EXPORT_DIR)
- `poll_interval`: Polling interval in seconds
- `base_dir`: KERI base directory for sentinel

### 4. Enable and Start Services

```bash
# Start sentinel first (guardian depends on its exports)
sudo systemctl enable keriguard-sentinel
sudo systemctl start keriguard-sentinel

# Check sentinel is running
sudo systemctl status keriguard-sentinel

# Then start guardian
sudo systemctl enable keriguard-guardian
sudo systemctl start keriguard-guardian

# Check guardian is running
sudo systemctl status keriguard-guardian
```

### 5. Verify Installation

```bash
# Check service status
sudo systemctl status keriguard-guardian
sudo systemctl status keriguard-sentinel

# View logs
tail -f /var/log/keriguard-guardian/guardian.log
tail -f /var/log/keriguard-sentinel/sentinel.log

# Test CLI utilities
/opt/keriguard/venv/bin/kg --help
/opt/keriguard/venv/bin/kg-sentinel --help
```

## Post-Installation Message

After installation, the postinst script displays comprehensive instructions including:
- Configuration file locations
- Service enablement commands
- Log file locations
- CLI utility paths

## What Happens During Installation

1. **Package extraction**: Files copied to filesystem
2. **User creation**: Creates `keriguard-guardian` and `keriguard-sentinel` system users
3. **Directory creation**: Creates log, lib, and config directories
4. **Permission setting**: Sets correct ownership for all directories
5. **Logrotate configuration**: Installs log rotation configs
6. **Default configuration**: Creates template config files (if they don't exist)
7. **Systemd reload**: Reloads systemd to recognize new services
8. **User instructions**: Displays next steps for configuration

## Verification Checklist

After building and installing, verify:

- [ ] Package builds successfully for target architecture
- [ ] Package installs without errors
- [ ] Both system users created (keriguard-guardian, keriguard-sentinel)
- [ ] Virtualenv installed at `/opt/keriguard/venv/`
- [ ] CLI utilities available: `kg`, `kg-sentinel`, `sentinel`
- [ ] Systemd services registered
- [ ] Log directories created with correct ownership
- [ ] Runtime data directories created
- [ ] Configuration files created
- [ ] Logrotate configs installed
- [ ] Services can be enabled and started (after configuration)
- [ ] Logs appear in `/var/log/keriguard-{guardian,sentinel}/`

## Differences from hkweb Multi-Package Approach

| Aspect | hkweb | keriguard |
|--------|-------|-----------|
| Package structure | Base + service packages | Single unified package |
| Number of packages | 1 base + N services | 1 package total |
| Virtualenv sharing | Base package, shared by services | Included in single package |
| Service installation | Each service is separate package | Both services in one package |
| User management | One user per service package | Two users in single package |
| Complexity | Higher (multiple packages) | Lower (single package) |

## Design Rationale

### Why Single Package?

1. **Simplicity**: Fewer packages to manage and install
2. **Atomic deployment**: Both services deployed together
3. **Version consistency**: Guardian and Sentinel always match versions
4. **Reduced complexity**: No base package dependency management
5. **Appropriate scale**: Only two services, not seven like hkweb

### Why Separate System Users?

1. **Security isolation**: Each service has minimal permissions
2. **Resource isolation**: Separate log and data directories
3. **Service independence**: Guardian and Sentinel can run independently
4. **Audit trail**: Clear separation of logs and activities

### Why File-Based Logging?

1. **Compatibility**: Works with traditional log shipping tools
2. **Simplicity**: Easy debugging with `tail -f`
3. **Performance**: No journald overhead
4. **Log management**: Standard logrotate integration

## Next Steps

1. **Test build**: Run `bash scripts/build-deb.sh arm64`
2. **Test installation**: Install on clean Ubuntu 22.04 VM
3. **Verify services**: Configure and start both services
4. **Integration testing**: Verify guardian and sentinel communicate correctly
5. **Documentation**: Update main README with installation instructions

## Troubleshooting

See `../debian/README.md` for detailed troubleshooting steps including:
- Service won't start
- Build failures
- Permission errors
- Configuration issues
- Log problems

## References

- Plan document: `PACKAGING_DESIGN.md` (hkweb multi-package approach)
- Debian packaging: `../debian/README.md`
- Build script: `../scripts/build-deb.sh`
- Dockerfile: `Dockerfile.builder`
- Project configuration: `../pyproject.toml`

## Status

✅ **Implementation Complete**

All files have been created and are ready for testing. The next step is to build the package and test installation on a target system.

---

**Implementation Date**: July 20, 2026
**Version**: 0.0.1
**Target Platforms**: Ubuntu 22.04 (ARM64, AMD64)
