# -*- encoding: utf-8 -*-
"""
Unit tests for keriguard.core.systeming module
"""

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from keriguard.core.systeming import (
    WireGuardAction,
    WireGuardControlError,
    WireGuardNotApprovedError,
    _send_helper_request,
    _systemd_unit_active,
    call_systemd,
    control_wireguard,
    disable_wireguard,
    enable_wireguard,
    is_wireguard_up,
    reload_or_restart_wireguard,
    reload_wireguard,
    restart_wireguard,
    start_wireguard,
    stop_wireguard,
    supports_dbus_systemd,
    wg_quick_unit,
)

# ============================================================================
# Test supports_dbus_systemd
# ============================================================================


class TestSupportsDbusSystemd:
    """Test platform detection for D-Bus systemd support."""

    @patch("keriguard.core.systeming.platform.system")
    @patch("keriguard.core.systeming.os.path.exists")
    def test_supports_dbus_systemd_linux_with_all_requirements(
        self, mock_exists, mock_system
    ):
        """Test that Linux with both D-Bus and systemd returns True."""
        mock_system.return_value = "Linux"
        mock_exists.side_effect = lambda path: True

        result = supports_dbus_systemd()

        assert result is True
        mock_system.assert_called_once()
        assert mock_exists.call_count == 2

    @patch("keriguard.core.systeming.platform.system")
    def test_supports_dbus_systemd_non_linux(self, mock_system):
        """Test that non-Linux platforms return False."""
        for system in ["Darwin", "Windows", "FreeBSD", "OpenBSD", "NetBSD"]:
            mock_system.return_value = system

            result = supports_dbus_systemd()

            assert result is False

    @patch("keriguard.core.systeming.platform.system")
    @patch("keriguard.core.systeming.os.path.exists")
    def test_supports_dbus_systemd_missing_dbus_socket(self, mock_exists, mock_system):
        """Test that Linux without D-Bus socket returns False."""
        mock_system.return_value = "Linux"

        def exists_side_effect(path):
            if path == "/run/dbus/system_bus_socket":
                return False
            return True

        mock_exists.side_effect = exists_side_effect

        result = supports_dbus_systemd()

        assert result is False

    @patch("keriguard.core.systeming.platform.system")
    @patch("keriguard.core.systeming.os.path.exists")
    def test_supports_dbus_systemd_missing_systemd_dir(self, mock_exists, mock_system):
        """Test that Linux without systemd directory returns False."""
        mock_system.return_value = "Linux"

        def exists_side_effect(path):
            if path == "/run/systemd/system":
                return False
            return True

        mock_exists.side_effect = exists_side_effect

        result = supports_dbus_systemd()

        assert result is False

    @patch("keriguard.core.systeming.platform.system")
    @patch("keriguard.core.systeming.os.path.exists")
    def test_supports_dbus_systemd_missing_both(self, mock_exists, mock_system):
        """Test that Linux without D-Bus and systemd returns False."""
        mock_system.return_value = "Linux"
        mock_exists.return_value = False

        result = supports_dbus_systemd()

        assert result is False


# ============================================================================
# Test wg_quick_unit
# ============================================================================


class TestWgQuickUnit:
    """Test WireGuard interface name validation and unit generation."""

    def test_wg_quick_unit_valid_simple_name(self):
        """Test valid simple interface name."""
        result = wg_quick_unit("wg0")

        assert result == "wg-quick@wg0.service"

    def test_wg_quick_unit_valid_with_numbers(self):
        """Test valid interface name with numbers."""
        result = wg_quick_unit("wg123")

        assert result == "wg-quick@wg123.service"

    def test_wg_quick_unit_valid_with_underscore(self):
        """Test valid interface name with underscore."""
        result = wg_quick_unit("wg_vpn")

        assert result == "wg-quick@wg_vpn.service"

    def test_wg_quick_unit_valid_with_dash(self):
        """Test valid interface name with dash."""
        result = wg_quick_unit("wg-vpn")

        assert result == "wg-quick@wg-vpn.service"

    def test_wg_quick_unit_valid_with_dot(self):
        """Test valid interface name with dot."""
        result = wg_quick_unit("wg.vpn")

        assert result == "wg-quick@wg.vpn.service"

    def test_wg_quick_unit_valid_complex_name(self):
        """Test valid complex interface name."""
        result = wg_quick_unit("wg_vpn-1.prod")

        assert result == "wg-quick@wg_vpn-1.prod.service"

    def test_wg_quick_unit_invalid_empty(self):
        """Test that empty interface name raises ValueError."""
        with pytest.raises(ValueError, match="Invalid WireGuard interface name"):
            wg_quick_unit("")

    def test_wg_quick_unit_invalid_special_chars(self):
        """Test that interface name with special characters raises ValueError."""
        with pytest.raises(ValueError, match="Invalid WireGuard interface name"):
            wg_quick_unit("wg0!")

    def test_wg_quick_unit_invalid_space(self):
        """Test that interface name with space raises ValueError."""
        with pytest.raises(ValueError, match="Invalid WireGuard interface name"):
            wg_quick_unit("wg 0")

    def test_wg_quick_unit_invalid_slash(self):
        """Test that interface name with slash raises ValueError."""
        with pytest.raises(ValueError, match="Invalid WireGuard interface name"):
            wg_quick_unit("wg/0")

    def test_wg_quick_unit_invalid_unicode(self):
        """Test that interface name with unicode raises ValueError."""
        with pytest.raises(ValueError, match="Invalid WireGuard interface name"):
            wg_quick_unit("wg0\u00e9")


# ============================================================================
# Test call_systemd
# ============================================================================


class TestCallSystemd:
    """Test systemd D-Bus calls."""

    @pytest.mark.asyncio
    async def test_call_systemd_start(self):
        """Test starting a WireGuard interface via systemd."""
        # Mock the D-Bus message bus and manager
        mock_manager = AsyncMock()
        mock_manager.call_start_unit = AsyncMock(
            return_value="/org/freedesktop/systemd1/job/123"
        )

        mock_proxy = Mock()
        mock_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(return_value=mock_proxy)

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            result = await call_systemd(WireGuardAction.START, "wg0")

            assert result == "/org/freedesktop/systemd1/job/123"
            mock_manager.call_start_unit.assert_called_once_with(
                "wg-quick@wg0.service", "replace"
            )

    @pytest.mark.asyncio
    async def test_call_systemd_stop(self):
        """Test stopping a WireGuard interface via systemd."""
        mock_manager = AsyncMock()
        mock_manager.call_stop_unit = AsyncMock(
            return_value="/org/freedesktop/systemd1/job/124"
        )

        mock_proxy = Mock()
        mock_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(return_value=mock_proxy)

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            result = await call_systemd(WireGuardAction.STOP, "wg0")

            assert result == "/org/freedesktop/systemd1/job/124"
            mock_manager.call_stop_unit.assert_called_once_with(
                "wg-quick@wg0.service", "replace"
            )

    @pytest.mark.asyncio
    async def test_call_systemd_restart(self):
        """Test restarting a WireGuard interface via systemd."""
        mock_manager = AsyncMock()
        mock_manager.call_restart_unit = AsyncMock(
            return_value="/org/freedesktop/systemd1/job/125"
        )

        mock_proxy = Mock()
        mock_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(return_value=mock_proxy)

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            result = await call_systemd(WireGuardAction.RESTART, "wg0")

            assert result == "/org/freedesktop/systemd1/job/125"
            mock_manager.call_restart_unit.assert_called_once_with(
                "wg-quick@wg0.service", "replace"
            )

    @pytest.mark.asyncio
    async def test_call_systemd_reload(self):
        """Test reloading a WireGuard interface via systemd."""
        mock_manager = AsyncMock()
        mock_manager.call_reload_unit = AsyncMock(
            return_value="/org/freedesktop/systemd1/job/126"
        )

        mock_proxy = Mock()
        mock_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(return_value=mock_proxy)

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            result = await call_systemd(WireGuardAction.RELOAD, "wg0")

            assert result == "/org/freedesktop/systemd1/job/126"
            mock_manager.call_reload_unit.assert_called_once_with(
                "wg-quick@wg0.service", "replace"
            )

    @pytest.mark.asyncio
    async def test_call_systemd_reload_or_restart(self):
        """Test reload-or-restart a WireGuard interface via systemd."""
        mock_manager = AsyncMock()
        mock_manager.call_reload_or_restart_unit = AsyncMock(
            return_value="/org/freedesktop/systemd1/job/127"
        )

        mock_proxy = Mock()
        mock_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(return_value=mock_proxy)

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            result = await call_systemd(WireGuardAction.RELOAD_OR_RESTART, "wg0")

            assert result == "/org/freedesktop/systemd1/job/127"
            mock_manager.call_reload_or_restart_unit.assert_called_once_with(
                "wg-quick@wg0.service", "replace"
            )

    @pytest.mark.asyncio
    async def test_call_systemd_enable(self):
        """Test enabling a WireGuard interface via systemd."""
        mock_manager = AsyncMock()
        mock_manager.call_enable_unit_files = AsyncMock(
            return_value=(
                True,
                [("symlink", "/path/to/symlink", "wg-quick@wg0.service")],
            )
        )

        mock_proxy = Mock()
        mock_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(return_value=mock_proxy)

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            result = await call_systemd(WireGuardAction.ENABLE, "wg0")

            assert result[0] is True
            mock_manager.call_enable_unit_files.assert_called_once_with(
                ["wg-quick@wg0.service"], False, False
            )

    @pytest.mark.asyncio
    async def test_call_systemd_disable(self):
        """Test disabling a WireGuard interface via systemd."""
        mock_manager = AsyncMock()
        mock_manager.call_disable_unit_files = AsyncMock(
            return_value=[("symlink", "/path/to/symlink", "wg-quick@wg0.service")]
        )

        mock_proxy = Mock()
        mock_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(return_value=mock_proxy)

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            result = await call_systemd(WireGuardAction.DISABLE, "wg0")

            assert isinstance(result, list)
            mock_manager.call_disable_unit_files.assert_called_once_with(
                ["wg-quick@wg0.service"], False
            )

    @pytest.mark.asyncio
    async def test_call_systemd_invalid_action(self):
        """Test that invalid action raises ValueError."""
        mock_manager = AsyncMock()
        mock_proxy = Mock()
        mock_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(return_value=mock_proxy)

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            with pytest.raises(ValueError, match="Unsupported WireGuard action"):
                await call_systemd("invalid_action", "wg0")

    @pytest.mark.asyncio
    async def test_call_systemd_invalid_interface(self):
        """Test that invalid interface name raises ValueError."""
        with pytest.raises(ValueError, match="Invalid WireGuard interface name"):
            await call_systemd(WireGuardAction.START, "wg/0")


# ============================================================================
# Test control_wireguard
# ============================================================================


class TestControlWireguard:
    """Test cross-platform WireGuard control dispatcher."""

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.call_systemd")
    async def test_control_wireguard_linux_with_systemd(
        self, mock_call_systemd, mock_supports
    ):
        """Test that Linux with systemd uses D-Bus control."""
        mock_supports.return_value = True
        mock_call_systemd.return_value = "/org/freedesktop/systemd1/job/123"

        result = await control_wireguard(WireGuardAction.START, "wg0")

        assert result == "/org/freedesktop/systemd1/job/123"
        mock_supports.assert_called_once()
        mock_call_systemd.assert_called_once_with(WireGuardAction.START, "wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    async def test_control_wireguard_macos_missing_config_path(self, mock_supports):
        """Test that macOS raises error when config_path is not provided."""
        mock_supports.return_value = False

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            with pytest.raises(
                WireGuardControlError,
                match="config_path is required for macOS WireGuard control",
            ):
                await control_wireguard(WireGuardAction.START, "wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    async def test_control_wireguard_macos_enable_noop(self, mock_supports):
        """Test that macOS ENABLE action returns early (out of scope for PoC)."""
        mock_supports.return_value = False

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            result = await control_wireguard(
                WireGuardAction.ENABLE, "wg0", config_path="/etc/wireguard/wg0.conf"
            )
            assert result is None

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_control_wireguard_macos_start_sends_start_action(
        self, mock_send, mock_supports, tmp_path
    ):
        """Test that macOS START reads the config file and sends a 'start' IPC action."""
        mock_supports.return_value = False
        mock_send.return_value = {"ok": True, "state": "up"}

        config_path = tmp_path / "wg0.conf"
        config_path.write_text("[Interface]\nPrivateKey = abc\n")

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            result = await control_wireguard(
                WireGuardAction.START, "wg0", config_path=str(config_path)
            )

        assert result == {"ok": True, "state": "up"}
        mock_send.assert_called_once_with(
            "start", "wg0", config="[Interface]\nPrivateKey = abc\n"
        )

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_control_wireguard_macos_restart_sends_restart_action(
        self, mock_send, mock_supports, tmp_path
    ):
        """Test that RESTART maps to the 'restart' IPC action — the helper has
        no hot in-place reconfigure, so anything beyond an initial START is
        always a full stop-then-start."""
        mock_supports.return_value = False
        mock_send.return_value = {"ok": True, "state": "up"}

        config_path = tmp_path / "wg0.conf"
        config_path.write_text("[Interface]\nPrivateKey = abc\n")

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            await control_wireguard(
                WireGuardAction.RESTART, "wg0", config_path=str(config_path)
            )

        mock_send.assert_called_once_with(
            "restart", "wg0", config="[Interface]\nPrivateKey = abc\n"
        )

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_control_wireguard_macos_reload_sends_restart_action(
        self, mock_send, mock_supports, tmp_path
    ):
        """Test that RELOAD also maps to the 'restart' IPC action (no hot reconfigure)."""
        mock_supports.return_value = False
        mock_send.return_value = {"ok": True, "state": "up"}

        config_path = tmp_path / "wg0.conf"
        config_path.write_text("[Interface]\nPrivateKey = abc\n")

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            await control_wireguard(
                WireGuardAction.RELOAD, "wg0", config_path=str(config_path)
            )

        mock_send.assert_called_once_with(
            "restart", "wg0", config="[Interface]\nPrivateKey = abc\n"
        )

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_control_wireguard_macos_reload_or_restart_sends_restart_action(
        self, mock_send, mock_supports, tmp_path
    ):
        """Test that RELOAD_OR_RESTART also maps to the 'restart' IPC action."""
        mock_supports.return_value = False
        mock_send.return_value = {"ok": True, "state": "up"}

        config_path = tmp_path / "wg0.conf"
        config_path.write_text("[Interface]\nPrivateKey = abc\n")

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            await control_wireguard(
                WireGuardAction.RELOAD_OR_RESTART, "wg0", config_path=str(config_path)
            )

        mock_send.assert_called_once_with(
            "restart", "wg0", config="[Interface]\nPrivateKey = abc\n"
        )

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    async def test_control_wireguard_macos_start_missing_file(self, mock_supports):
        """Test that a config_path pointing at a nonexistent file raises WireGuardControlError."""
        mock_supports.return_value = False

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            with pytest.raises(
                WireGuardControlError, match="Could not read config file"
            ):
                await control_wireguard(
                    WireGuardAction.START,
                    "wg0",
                    config_path="/nonexistent/wg0.conf",
                )

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_control_wireguard_macos_start_propagates_helper_error(
        self, mock_send, mock_supports, tmp_path
    ):
        """Test that a WireGuardControlError from the helper propagates unchanged."""
        mock_supports.return_value = False
        mock_send.side_effect = WireGuardControlError(
            "KERIGuard Helper returned error: start_failed: timed out"
        )

        config_path = tmp_path / "wg0.conf"
        config_path.write_text("[Interface]\nPrivateKey = abc\n")

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            with pytest.raises(WireGuardControlError, match="start_failed"):
                await control_wireguard(
                    WireGuardAction.START, "wg0", config_path=str(config_path)
                )

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_control_wireguard_macos_start_not_approved(
        self, mock_send, mock_supports, tmp_path
    ):
        """Test that WireGuardNotApprovedError from the helper propagates distinctly."""
        mock_supports.return_value = False
        mock_send.side_effect = WireGuardNotApprovedError(
            "KERIGuard Helper's network extension has not been approved in System Settings"
        )

        config_path = tmp_path / "wg0.conf"
        config_path.write_text("[Interface]\nPrivateKey = abc\n")

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            with pytest.raises(WireGuardNotApprovedError):
                await control_wireguard(
                    WireGuardAction.START, "wg0", config_path=str(config_path)
                )

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_control_wireguard_macos_stop_sends_stop_action(
        self, mock_send, mock_supports, tmp_path
    ):
        """Test that macOS STOP sends a 'stop' IPC action with no config payload."""
        mock_supports.return_value = False
        mock_send.return_value = {"ok": True, "state": "down"}

        config_path = tmp_path / "wg0.conf"
        config_path.write_text("[Interface]\nPrivateKey = abc\n")

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            result = await control_wireguard(
                WireGuardAction.STOP, "wg0", config_path=str(config_path)
            )

        assert result == {"ok": True, "state": "down"}
        mock_send.assert_called_once_with("stop", "wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_control_wireguard_macos_disable_also_sends_stop_action(
        self, mock_send, mock_supports, tmp_path
    ):
        """Test that DISABLE (unlike the no-op ENABLE) actually stops the tunnel."""
        mock_supports.return_value = False
        mock_send.return_value = {"ok": True, "state": "down"}

        config_path = tmp_path / "wg0.conf"
        config_path.write_text("[Interface]\nPrivateKey = abc\n")

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            await control_wireguard(
                WireGuardAction.DISABLE, "wg0", config_path=str(config_path)
            )

        mock_send.assert_called_once_with("stop", "wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.platform.system")
    async def test_control_wireguard_windows(self, mock_system, mock_supports):
        """Test that Windows raises appropriate error."""
        mock_supports.return_value = False
        mock_system.return_value = "Windows"

        with pytest.raises(
            WireGuardControlError,
            match="Windows placeholder: implement WireGuardNT service control here",
        ):
            await control_wireguard(WireGuardAction.START, "wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.platform.system")
    async def test_control_wireguard_freebsd(self, mock_system, mock_supports):
        """Test that FreeBSD raises appropriate error."""
        mock_supports.return_value = False
        mock_system.return_value = "FreeBSD"

        with pytest.raises(
            WireGuardControlError,
            match="BSD placeholder: implement rc.d/service or native wg control here",
        ):
            await control_wireguard(WireGuardAction.START, "wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.platform.system")
    async def test_control_wireguard_openbsd(self, mock_system, mock_supports):
        """Test that OpenBSD raises appropriate error."""
        mock_supports.return_value = False
        mock_system.return_value = "OpenBSD"

        with pytest.raises(
            WireGuardControlError,
            match="BSD placeholder: implement rc.d/service or native wg control here",
        ):
            await control_wireguard(WireGuardAction.START, "wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.platform.system")
    async def test_control_wireguard_netbsd(self, mock_system, mock_supports):
        """Test that NetBSD raises appropriate error."""
        mock_supports.return_value = False
        mock_system.return_value = "NetBSD"

        with pytest.raises(
            WireGuardControlError,
            match="BSD placeholder: implement rc.d/service or native wg control here",
        ):
            await control_wireguard(WireGuardAction.START, "wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.platform.system")
    async def test_control_wireguard_unsupported_platform(
        self, mock_system, mock_supports
    ):
        """Test that unsupported platform raises error."""
        mock_supports.return_value = False
        mock_system.return_value = "SunOS"

        with pytest.raises(
            WireGuardControlError,
            match="Unsupported platform or missing system D-Bus/systemd: SunOS",
        ):
            await control_wireguard(WireGuardAction.START, "wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.platform.system")
    async def test_control_wireguard_linux_without_systemd(
        self, mock_system, mock_supports
    ):
        """Test that Linux without systemd raises error."""
        mock_supports.return_value = False
        mock_system.return_value = "Linux"

        with pytest.raises(
            WireGuardControlError,
            match="Unsupported platform or missing system D-Bus/systemd: Linux",
        ):
            await control_wireguard(WireGuardAction.START, "wg0")


# ============================================================================
# Test _send_helper_request (KERIGuard Helper IPC client)
# ============================================================================


class TestSendHelperRequest:
    """Test the Unix domain socket IPC client against a real local socket
    server, rather than mocking asyncio internals — this exercises the
    actual line-delimited JSON framing end to end.

    Uses a fixture rooted directly under /tmp rather than pytest's `tmp_path`
    (which nests under /private/var/folders/.../pytest-of-.../pytest-N/...) —
    AF_UNIX socket paths are capped at ~104 bytes on macOS/BSD and the deeper
    path reliably overflows that limit.
    """

    @pytest.fixture
    def socket_dir(self):
        d = tempfile.mkdtemp(dir="/tmp")
        try:
            yield Path(d)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    @staticmethod
    async def _serve_once(socket_path, response_line: bytes | None):
        """Start a one-shot Unix socket server that reads a request line and
        writes back `response_line` (or closes immediately if None)."""
        received = {}

        async def handle(reader, writer):
            line = await reader.readline()
            received["request"] = json.loads(line)
            if response_line is not None:
                writer.write(response_line)
                await writer.drain()
            writer.close()

        server = await asyncio.start_unix_server(handle, path=str(socket_path))
        return server, received

    @pytest.mark.asyncio
    async def test_send_helper_request_success(self, socket_dir):
        socket_path = socket_dir / "helper.sock"
        server, received = await self._serve_once(
            socket_path,
            json.dumps({"version": 1, "ok": True, "state": "up"}).encode() + b"\n",
        )
        try:
            with patch("keriguard.core.systeming._HELPER_SOCKET_PATH", socket_path):
                response = await _send_helper_request(
                    "start", "wg0", config="[Interface]\n"
                )
        finally:
            server.close()
            await server.wait_closed()

        assert response == {"version": 1, "ok": True, "state": "up"}
        assert received["request"] == {
            "version": 1,
            "action": "start",
            "interface": "wg0",
            "config": "[Interface]\n",
        }

    @pytest.mark.asyncio
    async def test_send_helper_request_omits_config_when_none(self, socket_dir):
        socket_path = socket_dir / "helper.sock"
        server, received = await self._serve_once(
            socket_path,
            json.dumps({"version": 1, "ok": True, "state": "down"}).encode() + b"\n",
        )
        try:
            with patch("keriguard.core.systeming._HELPER_SOCKET_PATH", socket_path):
                await _send_helper_request("stop", "wg0")
        finally:
            server.close()
            await server.wait_closed()

        assert received["request"] == {
            "version": 1,
            "action": "stop",
            "interface": "wg0",
        }

    @pytest.mark.asyncio
    async def test_send_helper_request_generic_error(self, socket_dir):
        socket_path = socket_dir / "helper.sock"
        server, _ = await self._serve_once(
            socket_path,
            json.dumps(
                {"version": 1, "ok": False, "error": "start_failed: boom"}
            ).encode()
            + b"\n",
        )
        try:
            with patch("keriguard.core.systeming._HELPER_SOCKET_PATH", socket_path):
                with pytest.raises(WireGuardControlError, match="start_failed: boom"):
                    await _send_helper_request("start", "wg0", config="[Interface]\n")
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_send_helper_request_not_approved(self, socket_dir):
        socket_path = socket_dir / "helper.sock"
        server, _ = await self._serve_once(
            socket_path,
            json.dumps({"version": 1, "ok": False, "error": "not_approved"}).encode()
            + b"\n",
        )
        try:
            with patch("keriguard.core.systeming._HELPER_SOCKET_PATH", socket_path):
                with pytest.raises(WireGuardNotApprovedError):
                    await _send_helper_request("start", "wg0", config="[Interface]\n")
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_send_helper_request_no_response_line(self, socket_dir):
        """Server closes the connection without writing anything back."""
        socket_path = socket_dir / "helper.sock"
        server, _ = await self._serve_once(socket_path, None)
        try:
            with patch("keriguard.core.systeming._HELPER_SOCKET_PATH", socket_path):
                with pytest.raises(WireGuardControlError, match="without a response"):
                    await _send_helper_request("status", "wg0")
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_send_helper_request_malformed_response(self, socket_dir):
        socket_path = socket_dir / "helper.sock"
        server, _ = await self._serve_once(socket_path, b"not json\n")
        try:
            with patch("keriguard.core.systeming._HELPER_SOCKET_PATH", socket_path):
                with pytest.raises(WireGuardControlError, match="Invalid response"):
                    await _send_helper_request("status", "wg0")
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_send_helper_request_socket_missing_is_not_approved(self, socket_dir):
        """A missing socket (helper not running) is the same signal as an
        explicit not_approved response, per keriguard-helper's PLAN.md."""
        socket_path = socket_dir / "does-not-exist.sock"
        with patch("keriguard.core.systeming._HELPER_SOCKET_PATH", socket_path):
            with pytest.raises(WireGuardNotApprovedError, match="not reachable"):
                await _send_helper_request("status", "wg0")


# ============================================================================
# Test _systemd_unit_active / is_wireguard_up
# ============================================================================


class TestSystemdUnitActive:
    """Test the D-Bus ActiveState lookup used by is_wireguard_up on Linux."""

    @pytest.mark.asyncio
    async def test_systemd_unit_active_true(self):
        mock_active_state = Mock()
        mock_active_state.value = "active"

        mock_props = AsyncMock()
        mock_props.call_get = AsyncMock(return_value=mock_active_state)

        mock_unit_proxy = Mock()
        mock_unit_proxy.get_interface = Mock(return_value=mock_props)

        mock_manager = AsyncMock()
        mock_manager.call_load_unit = AsyncMock(
            return_value="/org/freedesktop/systemd1/unit/wg_2dquick_40wg0_2eservice"
        )

        mock_manager_proxy = Mock()
        mock_manager_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(
            side_effect=[mock_manager_proxy, mock_unit_proxy]
        )

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            result = await _systemd_unit_active("wg0")

        assert result is True
        mock_manager.call_load_unit.assert_called_once_with("wg-quick@wg0.service")
        mock_props.call_get.assert_called_once_with(
            "org.freedesktop.systemd1.Unit", "ActiveState"
        )

    @pytest.mark.asyncio
    async def test_systemd_unit_active_inactive(self):
        mock_active_state = Mock()
        mock_active_state.value = "inactive"

        mock_props = AsyncMock()
        mock_props.call_get = AsyncMock(return_value=mock_active_state)

        mock_unit_proxy = Mock()
        mock_unit_proxy.get_interface = Mock(return_value=mock_props)

        mock_manager = AsyncMock()
        mock_manager.call_load_unit = AsyncMock(return_value="/some/unit/path")

        mock_manager_proxy = Mock()
        mock_manager_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(
            side_effect=[mock_manager_proxy, mock_unit_proxy]
        )

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            result = await _systemd_unit_active("wg0")

        assert result is False

    @pytest.mark.asyncio
    async def test_systemd_unit_active_no_such_unit(self):
        """A unit that was never started raises DBusError on load; treat as down."""
        from dbus_fast import DBusError

        mock_manager = AsyncMock()
        mock_manager.call_load_unit = AsyncMock(
            side_effect=DBusError("org.freedesktop.systemd1.NoSuchUnit", "not found")
        )

        mock_manager_proxy = Mock()
        mock_manager_proxy.get_interface = Mock(return_value=mock_manager)

        mock_bus = AsyncMock()
        mock_bus.introspect = AsyncMock(return_value="<introspection/>")
        mock_bus.get_proxy_object = Mock(return_value=mock_manager_proxy)

        with patch("keriguard.core.systeming.MessageBus") as mock_message_bus_class:
            mock_message_bus_instance = Mock()
            mock_message_bus_instance.connect = AsyncMock(return_value=mock_bus)
            mock_message_bus_class.return_value = mock_message_bus_instance

            result = await _systemd_unit_active("wg0")

        assert result is False


class TestIsWireguardUp:
    """Test the cross-platform is_wireguard_up dispatcher."""

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._systemd_unit_active")
    async def test_is_wireguard_up_linux(self, mock_active, mock_supports):
        mock_supports.return_value = True
        mock_active.return_value = True

        result = await is_wireguard_up("wg0")

        assert result is True
        mock_active.assert_called_once_with("wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.platform.system")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_is_wireguard_up_macos_up(
        self, mock_send, mock_system, mock_supports
    ):
        mock_supports.return_value = False
        mock_system.return_value = "Darwin"
        mock_send.return_value = {"ok": True, "state": "up"}

        result = await is_wireguard_up("wg0")

        assert result is True
        mock_send.assert_called_once_with("status", "wg0")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.platform.system")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_is_wireguard_up_macos_down(
        self, mock_send, mock_system, mock_supports
    ):
        mock_supports.return_value = False
        mock_system.return_value = "Darwin"
        mock_send.return_value = {"ok": True, "state": "down"}

        result = await is_wireguard_up("wg0")

        assert result is False

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.platform.system")
    @patch("keriguard.core.systeming._send_helper_request")
    async def test_is_wireguard_up_macos_not_approved_is_down(
        self, mock_send, mock_system, mock_supports
    ):
        """Helper unreachable/not-approved is treated as down, not raised."""
        mock_supports.return_value = False
        mock_system.return_value = "Darwin"
        mock_send.side_effect = WireGuardNotApprovedError("not approved")

        result = await is_wireguard_up("wg0")

        assert result is False

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.platform.system")
    async def test_is_wireguard_up_unsupported_platform(
        self, mock_system, mock_supports
    ):
        mock_supports.return_value = False
        mock_system.return_value = "SunOS"

        result = await is_wireguard_up("wg0")

        assert result is False


# ============================================================================
# Test wrapper functions
# ============================================================================


class TestWrapperFunctions:
    """Test convenience wrapper functions for WireGuard control."""

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.control_wireguard")
    async def test_start_wireguard(self, mock_control):
        """Test start_wireguard wrapper."""
        mock_control.return_value = "/org/freedesktop/systemd1/job/123"

        result = await start_wireguard("wg0")

        assert result == "/org/freedesktop/systemd1/job/123"
        mock_control.assert_called_once_with(WireGuardAction.START, "wg0", None)

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.control_wireguard")
    async def test_stop_wireguard(self, mock_control):
        """Test stop_wireguard wrapper."""
        mock_control.return_value = "/org/freedesktop/systemd1/job/124"

        result = await stop_wireguard("wg0")

        assert result == "/org/freedesktop/systemd1/job/124"
        mock_control.assert_called_once_with(WireGuardAction.STOP, "wg0", None)

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.control_wireguard")
    async def test_restart_wireguard(self, mock_control):
        """Test restart_wireguard wrapper."""
        mock_control.return_value = "/org/freedesktop/systemd1/job/125"

        result = await restart_wireguard("wg0")

        assert result == "/org/freedesktop/systemd1/job/125"
        mock_control.assert_called_once_with(WireGuardAction.RESTART, "wg0", None)

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.control_wireguard")
    async def test_reload_wireguard(self, mock_control):
        """Test reload_wireguard wrapper."""
        mock_control.return_value = "/org/freedesktop/systemd1/job/126"

        result = await reload_wireguard("wg0")

        assert result == "/org/freedesktop/systemd1/job/126"
        mock_control.assert_called_once_with(WireGuardAction.RELOAD, "wg0", None)

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.control_wireguard")
    async def test_reload_or_restart_wireguard(self, mock_control):
        """Test reload_or_restart_wireguard wrapper."""
        mock_control.return_value = "/org/freedesktop/systemd1/job/127"

        result = await reload_or_restart_wireguard("wg0")

        assert result == "/org/freedesktop/systemd1/job/127"
        mock_control.assert_called_once_with(
            WireGuardAction.RELOAD_OR_RESTART, "wg0", None
        )

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.control_wireguard")
    async def test_enable_wireguard(self, mock_control):
        """Test enable_wireguard wrapper."""
        mock_control.return_value = (True, [])

        result = await enable_wireguard("wg0")

        assert result == (True, [])
        mock_control.assert_called_once_with(WireGuardAction.ENABLE, "wg0", None)

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.control_wireguard")
    async def test_disable_wireguard(self, mock_control):
        """Test disable_wireguard wrapper."""
        mock_control.return_value = []

        result = await disable_wireguard("wg0")

        assert result == []
        mock_control.assert_called_once_with(WireGuardAction.DISABLE, "wg0", None)


# ============================================================================
# Test WireGuardAction enum
# ============================================================================


class TestWireGuardAction:
    """Test WireGuardAction enum."""

    def test_wireguard_action_values(self):
        """Test that WireGuardAction enum has expected values."""
        assert WireGuardAction.START == "start"
        assert WireGuardAction.STOP == "stop"
        assert WireGuardAction.RESTART == "restart"
        assert WireGuardAction.RELOAD == "reload"
        assert WireGuardAction.RELOAD_OR_RESTART == "reload-or-restart"
        assert WireGuardAction.ENABLE == "enable"
        assert WireGuardAction.DISABLE == "disable"

    def test_wireguard_action_membership(self):
        """Test WireGuardAction enum membership."""
        actions = list(WireGuardAction)
        assert len(actions) == 7
        assert WireGuardAction.START in actions
        assert WireGuardAction.STOP in actions
        assert WireGuardAction.RESTART in actions
        assert WireGuardAction.RELOAD in actions
        assert WireGuardAction.RELOAD_OR_RESTART in actions
        assert WireGuardAction.ENABLE in actions
        assert WireGuardAction.DISABLE in actions


# ============================================================================
# Test WireGuardControlError exception
# ============================================================================


class TestWireGuardControlError:
    """Test WireGuardControlError exception."""

    def test_wireguard_control_error_is_runtime_error(self):
        """Test that WireGuardControlError inherits from RuntimeError."""
        error = WireGuardControlError("test error")
        assert isinstance(error, RuntimeError)

    def test_wireguard_control_error_message(self):
        """Test that WireGuardControlError preserves message."""
        message = "Test error message"
        error = WireGuardControlError(message)
        assert str(error) == message

    def test_wireguard_control_error_can_be_raised(self):
        """Test that WireGuardControlError can be raised and caught."""
        with pytest.raises(WireGuardControlError, match="test"):
            raise WireGuardControlError("test")


class TestWireGuardNotApprovedError:
    """Test WireGuardNotApprovedError exception."""

    def test_wireguard_not_approved_error_is_control_error(self):
        """Test that WireGuardNotApprovedError is a WireGuardControlError, so
        existing generic `except WireGuardControlError` catches also catch it."""
        error = WireGuardNotApprovedError("not approved")
        assert isinstance(error, WireGuardControlError)

    def test_wireguard_not_approved_error_distinguishable(self):
        """Test that callers can distinguish it from a generic WireGuardControlError."""
        try:
            raise WireGuardNotApprovedError("not approved")
        except WireGuardControlError as e:
            assert isinstance(e, WireGuardNotApprovedError)
