# KERIGuard Guardian Configuration File Support

## Overview

The `kg guardian start` command supports loading configuration from a YAML file in addition to command-line arguments. This simplifies deployment and configuration management, especially for systemd services and production environments.

**Note**: The `kg up` command automatically generates a guardian configuration file during initialization. See [Guardian Config Generation](GUARDIAN_CONFIG_GENERATION.md) for details on automatic config generation.

## Usage

### Basic Usage with Config File

```bash
kg guardian start --config /etc/keriguard/guardian.yaml
```

### CLI Override

Command-line arguments take precedence over config file values:

```bash
# Override the sentinel AID from config file
kg guardian start --config /etc/keriguard/guardian.yaml --sentinel-aid "ENewAID..."

# Override log level
kg guardian start --config /etc/keriguard/guardian.yaml --loglevel DEBUG
```

### Backward Compatibility

The traditional CLI-only approach continues to work:

```bash
kg guardian start --sentinel-aid "EAid..." --sentinel-export-dir "/var/lib/sentinel/export"
```

## Configuration File Format

### Minimal Configuration

The minimal config requires only the two mandatory parameters:

```yaml
sentinel:
  aid: "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
  export_dir: "/var/lib/sentinel/export"
```

See [guardian-config-minimal.yaml](guardian-config-minimal.yaml) for a complete example.

### Full Configuration

A complete configuration with all available options:

```yaml
sentinel:
  aid: "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
  export_dir: "/var/lib/sentinel/export"
  poll_interval: 2.0

wireguard:
  config_dir: "/etc/wireguard"

keri:
  name: "keriguard"
  alias: "keriguard-sentinel"
  base: "/var/lib/keriguard/keri"
  passcode: "0123456789abcdefghijk"

logging:
  level: "INFO"
  file: "/var/log/keriguard/guardian.log"
```

See [guardian-config-full.yaml](guardian-config-full.yaml) for a complete example with documentation.

### Production Configuration

A typical production configuration:

```yaml
sentinel:
  aid: "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
  export_dir: "/var/lib/sentinel/export"
  poll_interval: 2.0

logging:
  level: "INFO"
  file: "/var/log/keriguard-guardian/guardian.log"
```

See [guardian-config-production.yaml](guardian-config-production.yaml) for a complete example.

## Configuration Parameters

### Sentinel Section

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `aid` | Yes | - | AID of the Sentinel to monitor |
| `export_dir` | Yes | - | Directory to monitor for KERI events (contains kel/, tel/, cred/ subdirs) |
| `poll_interval` | No | `2.0` | Polling interval in seconds |

### WireGuard Section

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `config_dir` | No | `/etc/wireguard` | Directory for WireGuard config files |

### KERI Section

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `name` | No | `keriguard` | KERI keystore name |
| `alias` | No | `keriguard-sentinel` | KERI identifier alias |
| `base` | No | `""` | KERI keystore base directory |
| `passcode` | No | `null` | 21-character encryption passcode for KERI keystore |

### Logging Section

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `level` | No | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR, or CRITICAL |
| `file` | No | `null` | Path to log file (if not specified, logs to console only) |

## Precedence Rules

Configuration values are resolved in the following order (highest to lowest precedence):

1. **Explicit CLI arguments** - When a CLI argument differs from its default value
2. **Config file values** - When `--config` is provided and the value is specified in the file
3. **Default values** - Built-in defaults from argparse and the config class

### Examples

```bash
# Use config file's poll_interval (2.0 from config)
kg guardian start --config guardian.yaml

# Override with CLI arg (uses 5.0, not config's 2.0)
kg guardian start --config guardian.yaml --poll-interval 5.0

# Mix config and CLI: sentinel_aid from CLI, everything else from config
kg guardian start --config guardian.yaml --sentinel-aid "ENewAID..."
```

## Systemd Integration

Using a config file simplifies systemd service files:

### Before (CLI arguments)

```ini
[Service]
ExecStart=/usr/local/bin/kg guardian start \
  --sentinel-aid "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip" \
  --sentinel-export-dir "/var/lib/sentinel/export" \
  --poll-interval 2.0 \
  --config-dir "/etc/wireguard" \
  --name "keriguard" \
  --alias "keriguard-sentinel" \
  --loglevel "INFO" \
  --logfile "/var/log/keriguard/guardian.log"
```

### After (config file)

```ini
[Service]
ExecStart=/usr/local/bin/kg guardian start --config /etc/keriguard/guardian.yaml
```

## Required Parameters

At least one of the following must be satisfied:

1. **Config file with both required parameters:**
   ```yaml
   sentinel:
     aid: "EAid..."
     export_dir: "/path"
   ```

2. **CLI arguments with both required parameters:**
   ```bash
   kg guardian start --sentinel-aid "EAid..." --sentinel-export-dir "/path"
   ```

3. **Mix of config file and CLI arguments** (as long as both are provided):
   ```bash
   kg guardian start --config partial.yaml --sentinel-aid "EAid..."
   ```

If either `sentinel_aid` or `sentinel_export_dir` is missing from both sources, the command will fail with an error message.

## Error Handling

### Config File Not Found

```bash
$ kg guardian start --config /nonexistent.yaml
Error: Configuration file not found: /nonexistent.yaml
```

### Invalid YAML

```bash
$ kg guardian start --config invalid.yaml
Error loading config file: while parsing a block mapping...
```

### Missing Required Parameters

```bash
$ kg guardian start --config minimal-incomplete.yaml
Error: Sentinel AID is required (via --sentinel-aid or config file)
```

## Migration Guide

### From CLI-Only to Config File

1. **Create a config file** with your current CLI arguments:
   ```bash
   # Current command
   kg guardian start --sentinel-aid "EAid..." --sentinel-export-dir "/path" --loglevel DEBUG

   # Equivalent config file (guardian.yaml)
   ```
   ```yaml
   sentinel:
     aid: "EAid..."
     export_dir: "/path"
   logging:
     level: "DEBUG"
   ```

2. **Update your scripts/services** to use the config file:
   ```bash
   kg guardian start --config /etc/keriguard/guardian.yaml
   ```

3. **Keep CLI overrides** for development/testing:
   ```bash
   kg guardian start --config production.yaml --loglevel DEBUG
   ```

## Best Practices

1. **Store config files in standard locations:**
   - `/etc/keriguard/guardian.yaml` for system-wide config
   - `~/.config/keriguard/guardian.yaml` for user-specific config

2. **Use minimal configs** with only required and changed parameters:
   - Easier to read and maintain
   - Defaults are documented and version-controlled

3. **Use CLI overrides for temporary changes:**
   - Testing different log levels
   - Pointing to alternate export directories
   - Development and debugging

4. **Version control your configs:**
   - Track configuration changes
   - Easy rollback if needed
   - Document environment-specific settings

5. **Secure sensitive values:**
   - Protect config files containing passcodes
   - Use appropriate file permissions (e.g., `chmod 600`)
   - Consider environment variables for secrets in production

## Examples

### Development Setup

```bash
# Use local config with debug logging
kg guardian start --config dev-guardian.yaml --loglevel DEBUG
```

### Production Setup

```bash
# Use production config
kg guardian start --config /etc/keriguard/guardian.yaml
```

### Testing Different Sentinels

```bash
# Override sentinel AID for testing
kg guardian start --config guardian.yaml --sentinel-aid "ETestAID..."
```

### Custom KERI Base

```bash
# Override KERI base directory
kg guardian start --config guardian.yaml --base "/tmp/test-keri"
```
