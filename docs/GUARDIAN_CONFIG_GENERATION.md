# Guardian Config Generation in `kg up`

## Overview

The `kg up` command now automatically generates a guardian configuration file that can be used with the `kg guardian start` command. This eliminates the need to manually create the configuration file and ensures all the necessary parameters are correctly set during initialization.

## Automatic Generation

When you run `kg up`, the command will automatically:

1. Create a guardian configuration file with all the necessary parameters
2. Save it to `/etc/keriguard/keriguard.yaml` by default
3. Set appropriate file permissions (0o640 - readable by owner and group)
4. Include all relevant settings from the initialization process

## Command-Line Options

### `--keriguard-config-path`

Override the default location for the guardian configuration file.

```bash
# Save to default location (/etc/keriguard/keriguard.yaml)
kg up --config init.yaml

# Save to custom location
kg up --config init.yaml --keriguard-config-path /custom/path/guardian.yaml
```

## Generated Configuration

The generated configuration file includes:

### Sentinel Configuration
- **aid**: The AID of the sentinel created during initialization
- **export_dir**: The sentinel export directory (defaults to `/usr/local/var/sentinel/{name}`)
- **poll_interval**: Polling interval in seconds (defaults to 2.0)

### WireGuard Configuration
- **config_dir**: WireGuard configuration directory (defaults to `/etc/wireguard`)

### KERI Configuration
- **name**: KERI keystore name (from `--name` argument)
- **alias**: KERI identifier alias (derived as `{alias}-sentinel`)
- **base**: KERI keystore base directory (from `--base` argument)
- **passcode**: Encryption passcode if provided (from `--passcode` argument)

### Logging Configuration
- **level**: Log level (defaults to INFO for guardian service)
- **file**: Log file path (optional, not set by default)

## Example Generated Configuration

When running:

```bash
kg up --config init.yaml --name mykeriguard --alias myguard
```

The generated `/etc/keriguard/keriguard.yaml` will look like:

```yaml
sentinel:
  aid: EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip
  export_dir: /usr/local/var/sentinel/mykeriguard
  poll_interval: 2.0
wireguard:
  config_dir: /etc/wireguard
keri:
  name: mykeriguard-sentinel
  alias: myguard-sentinel
  base: ''
logging:
  level: INFO
```

## Using the Generated Configuration

After running `kg up`, you can start the guardian service using the generated configuration:

```bash
# Use the default generated config
kg guardian start --config /etc/keriguard/keriguard.yaml

# Or with systemd (if configured)
systemctl start keriguard-guardian
```

## Customizing the Configuration

If you need to customize the generated configuration:

1. **Before initialization**: Use command-line arguments to `kg up`:
   ```bash
   kg up --config init.yaml --name custom --base /custom/path --passcode mypasscode
   ```

2. **After initialization**: Edit the generated file directly:
   ```bash
   sudo nano /etc/keriguard/keriguard.yaml
   ```

3. **Override at runtime**: Use CLI arguments with `kg guardian start`:
   ```bash
   kg guardian start --config /etc/keriguard/keriguard.yaml --loglevel DEBUG
   ```

## Location and Permissions

### Default Location
- **Path**: `/etc/keriguard/keriguard.yaml`
- **Permissions**: 0o640 (rw-r-----)
- **Owner**: User running `kg up` (typically root)
- **Directory**: Created automatically if it doesn't exist

### Custom Location
You can specify any location using `--keriguard-config-path`:

```bash
kg up --config init.yaml --keriguard-config-path /home/user/.keriguard/guardian.yaml
```

The parent directory will be created automatically if it doesn't exist.

## Integration with Systemd

The generated configuration file is designed to work seamlessly with systemd services:

```ini
[Unit]
Description=KERIGuard Guardian Service
After=network.target keriguard-sentinel.service

[Service]
Type=simple
ExecStart=/usr/local/bin/kg guardian start --config /etc/keriguard/keriguard.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Relationship with Initialization Config

The `kg up` command uses two different config files:

1. **Initialization Config** (input): Specified with `--config`
   - Contains registrar, issuer, and server information
   - Used to set up the KERIGuard instance
   - Example: `/etc/keriguard/init.yaml`

2. **Guardian Config** (output): Generated automatically
   - Contains guardian runtime parameters
   - Used by `kg guardian start`
   - Default: `/etc/keriguard/keriguard.yaml`

```bash
# init.yaml (input) -> kg up -> keriguard.yaml (output)
kg up --config /etc/keriguard/init.yaml
# Generates: /etc/keriguard/keriguard.yaml

# Then use the generated config:
kg guardian start --config /etc/keriguard/keriguard.yaml
```

## Sentinel Config vs Guardian Config

The `kg up` command generates **two** separate configuration files:

1. **Sentinel Config**: `/etc/sentinel/{name}.yaml`
   - Used by the sentinel service
   - Can be customized with `--sentinel-config-path`

2. **Guardian Config**: `/etc/keriguard/keriguard.yaml`
   - Used by the guardian service
   - Can be customized with `--keriguard-config-path`

Both files are generated automatically during the `kg up` initialization process.

## Troubleshooting

### Permission Denied

If you get a permission error when `kg up` tries to create the config file:

```bash
# Run with sudo to write to /etc/keriguard/
sudo kg up --config init.yaml

# Or specify a user-writable location
kg up --config init.yaml --keriguard-config-path ~/keriguard/guardian.yaml
```

### Config File Already Exists

The generated config will overwrite any existing file at the target location. To preserve an existing configuration:

1. Back it up before running `kg up`:
   ```bash
   sudo cp /etc/keriguard/keriguard.yaml /etc/keriguard/keriguard.yaml.backup
   ```

2. Or specify a different location:
   ```bash
   kg up --config init.yaml --keriguard-config-path /etc/keriguard/keriguard-new.yaml
   ```

### Missing Sentinel AID

If the guardian config doesn't have the correct sentinel AID, verify that the sentinel was created successfully during `kg up`:

```bash
# Check the generated config
cat /etc/keriguard/keriguard.yaml | grep aid

# Should show the sentinel's AID starting with 'E'
```

## Best Practices

1. **Run initialization once**: `kg up` should be run once during initial setup
2. **Keep generated config**: Don't delete the generated guardian config
3. **Version control**: Consider backing up configs after initialization
4. **Secure passcodes**: If using `--passcode`, ensure the config file has appropriate permissions
5. **Document customizations**: Note any manual edits to the generated config

## See Also

- [Guardian Configuration Reference](GUARDIAN_CONFIG.md) - Detailed config file documentation
- [SaaS Setup Guide](SAAS.md) - SaaS deployment instructions
