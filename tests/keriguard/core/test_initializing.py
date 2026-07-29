# -*- encoding: utf-8 -*-
"""
Tests for keriguard.core.guardian_config module
"""

import pytest
import tempfile
from pathlib import Path

import yaml

from keriguard.core.initializing import (
    KERIGuardConfig,
    generate_guardian_config,
    save_guardian_config,
)


class TestKERIGuardConfig:
    """Test KERIGuardConfig class."""

    def test_load_minimal_config(self):
        """Test loading a minimal config with only required parameters."""
        config_content = """
sentinel:
  aid: "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
  export_dir: "/var/lib/sentinel/export"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            config = KERIGuardConfig.load(config_path)
            assert config.sentinel_aid == "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
            assert config.sentinel_export_dir == "/var/lib/sentinel/export"
            # Check defaults
            assert config.poll_interval == 2.0
            assert config.config_dir == "/etc/wireguard"
            assert config.name == "keriguard"
            assert config.alias == "keriguard-sentinel"
            assert config.base == ""
            assert config.passcode is None
            assert config.loglevel == "INFO"
            assert config.logfile is None
        finally:
            Path(config_path).unlink()

    def test_load_full_config(self):
        """Test loading a full config with all parameters specified."""
        config_content = """
sentinel:
  aid: "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
  export_dir: "/var/lib/sentinel/export"
  poll_interval: 1.5

wireguard:
  config_dir: "/custom/wireguard"

keri:
  name: "custom-keriguard"
  alias: "custom-sentinel"
  base: "/custom/keri"
  passcode: "0123456789abcdefghijk"

logging:
  level: "DEBUG"
  file: "/var/log/keriguard/guardian.log"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            config = KERIGuardConfig.load(config_path)
            assert config.sentinel_aid == "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
            assert config.sentinel_export_dir == "/var/lib/sentinel/export"
            assert config.poll_interval == 1.5
            assert config.config_dir == "/custom/wireguard"
            assert config.name == "custom-keriguard"
            assert config.alias == "custom-sentinel"
            assert config.base == "/custom/keri"
            assert config.passcode == "0123456789abcdefghijk"
            assert config.loglevel == "DEBUG"
            assert config.logfile == "/var/log/keriguard/guardian.log"
        finally:
            Path(config_path).unlink()

    def test_load_empty_config(self):
        """Test loading an empty config file."""
        config_content = ""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            config = KERIGuardConfig.load(config_path)
            # All values should be defaults or None for required params
            assert config.sentinel_aid is None
            assert config.sentinel_export_dir is None
            assert config.poll_interval == 2.0
            assert config.config_dir == "/etc/wireguard"
            assert config.name == "keriguard"
            assert config.alias == "keriguard-sentinel"
            assert config.base == ""
            assert config.passcode is None
            assert config.loglevel == "INFO"
            assert config.logfile is None
        finally:
            Path(config_path).unlink()

    def test_load_partial_config(self):
        """Test loading a config with only some sections."""
        config_content = """
sentinel:
  aid: "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
  export_dir: "/var/lib/sentinel/export"

logging:
  level: "DEBUG"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            config = KERIGuardConfig.load(config_path)
            assert config.sentinel_aid == "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
            assert config.sentinel_export_dir == "/var/lib/sentinel/export"
            assert config.loglevel == "DEBUG"
            # Unspecified values should use defaults
            assert config.poll_interval == 2.0
            assert config.config_dir == "/etc/wireguard"
            assert config.name == "keriguard"
            assert config.logfile is None
        finally:
            Path(config_path).unlink()

    def test_file_not_found(self):
        """Test that loading a non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as excinfo:
            KERIGuardConfig.load("/nonexistent/path/config.yaml")
        assert "Configuration file not found" in str(excinfo.value)

    def test_invalid_yaml(self):
        """Test that loading invalid YAML raises an exception."""
        config_content = """
sentinel:
  aid: "EAid"
  invalid yaml content [[[
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            with pytest.raises(Exception):  # yaml.YAMLError or similar
                KERIGuardConfig.load(config_path)
        finally:
            Path(config_path).unlink()

    def test_missing_sections(self):
        """Test that missing sections use defaults."""
        config_content = """
sentinel:
  aid: "EAid"
  export_dir: "/path"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            config = KERIGuardConfig.load(config_path)
            # Missing sections should return defaults
            assert config.config_dir == "/etc/wireguard"
            assert config.name == "keriguard"
            assert config.alias == "keriguard-sentinel"
            assert config.base == ""
            assert config.loglevel == "INFO"
        finally:
            Path(config_path).unlink()

    def test_null_values(self):
        """Test handling of explicit null values in YAML."""
        config_content = """
sentinel:
  aid: "EAid"
  export_dir: "/path"

keri:
  passcode: null

logging:
  file: null
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            config = KERIGuardConfig.load(config_path)
            assert config.passcode is None
            assert config.logfile is None
        finally:
            Path(config_path).unlink()

    def test_override_defaults(self):
        """Test that config file values override defaults."""
        config_content = """
sentinel:
  aid: "EAid"
  export_dir: "/path"
  poll_interval: 5.0

wireguard:
  config_dir: "/custom/wg"

keri:
  name: "custom"
  alias: "custom-alias"
  base: "/custom/base"

logging:
  level: "ERROR"
  file: "/custom/log"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            config = KERIGuardConfig.load(config_path)
            # All values should be from config, not defaults
            assert config.poll_interval == 5.0
            assert config.config_dir == "/custom/wg"
            assert config.name == "custom"
            assert config.alias == "custom-alias"
            assert config.base == "/custom/base"
            assert config.loglevel == "ERROR"
            assert config.logfile == "/custom/log"
        finally:
            Path(config_path).unlink()

    def test_data_dir_and_heartbeat_file(self):
        """Test that data_dir and heartbeat_file round-trip through YAML."""
        config_content = """
sentinel:
  aid: "EAid"
  export_dir: "/path"

keri:
  data_dir: "/Users/test/Library/Application Support/KERIGuard/keystores"

guardian:
  heartbeat_file: "/Users/test/Library/Application Support/KERIGuard/guardian.heartbeat"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            config = KERIGuardConfig.load(config_path)
            assert config.data_dir == (
                "/Users/test/Library/Application Support/KERIGuard/keystores"
            )
            assert config.heartbeat_file == (
                "/Users/test/Library/Application Support/KERIGuard/guardian.heartbeat"
            )
        finally:
            Path(config_path).unlink()

    def test_data_dir_and_heartbeat_file_default_to_none(self):
        """Test that data_dir and heartbeat_file default to None when absent."""
        config_content = """
sentinel:
  aid: "EAid"
  export_dir: "/path"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            config = KERIGuardConfig.load(config_path)
            assert config.data_dir is None
            assert config.heartbeat_file is None
        finally:
            Path(config_path).unlink()


class TestGenerateGuardianConfig:
    """Test generate_guardian_config function."""

    def test_minimal_config(self):
        """Test generating a minimal guardian config."""
        config = generate_guardian_config(
            sentinel_aid="EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip",
            sentinel_export_dir="/var/lib/sentinel/export",
        )

        assert (
            config["sentinel"]["aid"] == "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
        )
        assert config["sentinel"]["export_dir"] == "/var/lib/sentinel/export"
        assert config["sentinel"]["poll_interval"] == 2.0
        assert config["wireguard"]["config_dir"] == "/etc/wireguard"
        assert config["keri"]["name"] == "keriguard"
        assert config["keri"]["alias"] == "keriguard-sentinel"
        assert config["keri"]["base"] == ""
        assert "passcode" not in config["keri"]  # Should not be present if None
        assert config["logging"]["level"] == "INFO"
        assert "file" not in config["logging"]  # Should not be present if None

    def test_full_config(self):
        """Test generating a full guardian config with all parameters."""
        config = generate_guardian_config(
            sentinel_aid="ETestAID",
            sentinel_export_dir="/custom/export",
            poll_interval=1.5,
            config_dir="/custom/wireguard",
            name="custom-keriguard",
            alias="custom-sentinel",
            base="/custom/base",
            passcode="0123456789abcdefghijk",
            loglevel="DEBUG",
            logfile="/var/log/guardian.log",
        )

        assert config["sentinel"]["aid"] == "ETestAID"
        assert config["sentinel"]["export_dir"] == "/custom/export"
        assert config["sentinel"]["poll_interval"] == 1.5
        assert config["wireguard"]["config_dir"] == "/custom/wireguard"
        assert config["keri"]["name"] == "custom-keriguard"
        assert config["keri"]["alias"] == "custom-sentinel"
        assert config["keri"]["base"] == "/custom/base"
        assert config["keri"]["passcode"] == "0123456789abcdefghijk"
        assert config["logging"]["level"] == "DEBUG"
        assert config["logging"]["file"] == "/var/log/guardian.log"

    def test_config_structure(self):
        """Test that config has the correct nested structure."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
        )

        # Verify all top-level sections exist
        assert "sentinel" in config
        assert "wireguard" in config
        assert "keri" in config
        assert "logging" in config

        # Verify sentinel section
        assert "aid" in config["sentinel"]
        assert "export_dir" in config["sentinel"]
        assert "poll_interval" in config["sentinel"]

        # Verify wireguard section
        assert "config_dir" in config["wireguard"]

        # Verify keri section
        assert "name" in config["keri"]
        assert "alias" in config["keri"]
        assert "base" in config["keri"]

        # Verify logging section
        assert "level" in config["logging"]

    def test_optional_passcode_included(self):
        """Test that passcode is included when provided."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
            passcode="test-passcode-123456",
        )

        assert "passcode" in config["keri"]
        assert config["keri"]["passcode"] == "test-passcode-123456"

    def test_optional_passcode_excluded(self):
        """Test that passcode is excluded when not provided."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
            passcode=None,
        )

        assert "passcode" not in config["keri"]

    def test_optional_logfile_included(self):
        """Test that logfile is included when provided."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
            logfile="/var/log/test.log",
        )

        assert "file" in config["logging"]
        assert config["logging"]["file"] == "/var/log/test.log"

    def test_optional_logfile_excluded(self):
        """Test that logfile is excluded when not provided."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
            logfile=None,
        )

        assert "file" not in config["logging"]

    def test_optional_data_dir_included(self):
        """Test that data_dir is included when provided."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
            data_dir="/Users/test/Library/Application Support/KERIGuard/keystores",
        )

        assert (
            config["keri"]["data_dir"]
            == "/Users/test/Library/Application Support/KERIGuard/keystores"
        )

    def test_optional_data_dir_excluded(self):
        """Test that data_dir is excluded when not provided."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
        )

        assert "data_dir" not in config["keri"]

    def test_optional_heartbeat_file_included(self):
        """Test that heartbeat_file is included when provided."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
            heartbeat_file="/var/run/keriguard/guardian.heartbeat",
        )

        assert config["guardian"]["heartbeat_file"] == (
            "/var/run/keriguard/guardian.heartbeat"
        )

    def test_optional_heartbeat_file_excluded(self):
        """Test that the guardian section is excluded when heartbeat_file is not provided."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
        )

        assert "guardian" not in config


class TestSaveGuardianConfig:
    """Test save_guardian_config function."""

    def test_save_config_to_file(self):
        """Test saving config to a file."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "guardian.yaml"
            save_guardian_config(config, str(config_path))

            # Verify file was created
            assert config_path.exists()

            # Verify content is valid YAML and matches
            with open(config_path, "r") as f:
                loaded = yaml.safe_load(f)

            assert loaded["sentinel"]["aid"] == "EAid"
            assert loaded["sentinel"]["export_dir"] == "/path"
            assert loaded["keri"]["name"] == "keriguard"

    def test_save_creates_parent_directories(self):
        """Test that save_guardian_config creates parent directories."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "nested" / "dir" / "guardian.yaml"
            save_guardian_config(config, str(config_path))

            # Verify file and parent directories were created
            assert config_path.exists()
            assert config_path.parent.exists()

    def test_save_preserves_structure(self):
        """Test that YAML structure is preserved when saved."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
            poll_interval=3.5,
            name="custom",
            passcode="test123",
            loglevel="DEBUG",
            logfile="/var/log/test.log",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "guardian.yaml"
            save_guardian_config(config, str(config_path))

            # Load and verify all values
            with open(config_path, "r") as f:
                loaded = yaml.safe_load(f)

            assert loaded["sentinel"]["poll_interval"] == 3.5
            assert loaded["keri"]["name"] == "custom"
            assert loaded["keri"]["passcode"] == "test123"
            assert loaded["logging"]["level"] == "DEBUG"
            assert loaded["logging"]["file"] == "/var/log/test.log"

    def test_save_overwrites_existing_file(self):
        """Test that save_guardian_config overwrites existing files."""
        config1 = generate_guardian_config(
            sentinel_aid="EAid1",
            sentinel_export_dir="/path1",
        )
        config2 = generate_guardian_config(
            sentinel_aid="EAid2",
            sentinel_export_dir="/path2",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "guardian.yaml"

            # Save first config
            save_guardian_config(config1, str(config_path))
            with open(config_path, "r") as f:
                loaded1 = yaml.safe_load(f)
            assert loaded1["sentinel"]["aid"] == "EAid1"

            # Save second config (should overwrite)
            save_guardian_config(config2, str(config_path))
            with open(config_path, "r") as f:
                loaded2 = yaml.safe_load(f)
            assert loaded2["sentinel"]["aid"] == "EAid2"
            assert loaded2["sentinel"]["export_dir"] == "/path2"

    def test_save_file_permissions(self):
        """Test that saved file has correct permissions (0o640)."""
        config = generate_guardian_config(
            sentinel_aid="EAid",
            sentinel_export_dir="/path",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "guardian.yaml"
            save_guardian_config(config, str(config_path))

            # Check file permissions
            import stat

            mode = config_path.stat().st_mode
            # Mask to get just the permission bits
            permissions = stat.S_IMODE(mode)
            assert permissions == 0o640

    def test_roundtrip_compatibility(self):
        """Test that saved config can be loaded by KERIGuardConfig."""
        from keriguard.core.initializing import KERIGuardConfig

        config = generate_guardian_config(
            sentinel_aid="ETestAID",
            sentinel_export_dir="/test/export",
            poll_interval=3.0,
            name="test-keriguard",
            alias="test-sentinel",
            loglevel="WARNING",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "guardian.yaml"
            save_guardian_config(config, str(config_path))

            # Load with KERIGuardConfig and verify
            loaded_config = KERIGuardConfig.load(str(config_path))
            assert loaded_config.sentinel_aid == "ETestAID"
            assert loaded_config.sentinel_export_dir == "/test/export"
            assert loaded_config.poll_interval == 3.0
            assert loaded_config.name == "test-keriguard"
            assert loaded_config.alias == "test-sentinel"
            assert loaded_config.loglevel == "WARNING"
