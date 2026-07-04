# -*- encoding: utf-8 -*-
"""
Unit tests for keriguard.core.systeming module
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from keriguard.core.systeming import (
    WireGuardAction,
    WireGuardControlError,
    call_systemd,
    control_wireguard,
    disable_wireguard,
    enable_wireguard,
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
    @patch("keriguard.core.systeming._is_wireguard_up")
    @patch("keriguard.core.systeming.asyncio.create_subprocess_exec")
    async def test_control_wireguard_macos_start_fresh(
        self, mock_subprocess, mock_is_up, mock_supports
    ):
        """Test that macOS START calls wg-quick up when interface is down."""
        mock_supports.return_value = False
        mock_is_up.return_value = False

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0
        mock_subprocess.return_value = mock_proc

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            await control_wireguard(
                WireGuardAction.START, "wg0", config_path="/etc/wireguard/wg0.conf"
            )

        mock_is_up.assert_called_once_with("wg0")
        mock_subprocess.assert_called_once()
        # Verify the wg-quick up command args
        call_args = mock_subprocess.call_args[0]
        assert "sudo" in call_args
        assert "up" in call_args
        assert "/etc/wireguard/wg0.conf" in call_args

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._is_wireguard_up")
    @patch("keriguard.core.systeming._mac_syncconf")
    async def test_control_wireguard_macos_start_already_up(
        self, mock_syncconf, mock_is_up, mock_supports
    ):
        """Test that macOS START uses syncconf when interface is already up."""
        mock_supports.return_value = False
        mock_is_up.return_value = True
        mock_syncconf.return_value = None

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            await control_wireguard(
                WireGuardAction.START, "wg0", config_path="/etc/wireguard/wg0.conf"
            )

        mock_is_up.assert_called_once_with("wg0")
        mock_syncconf.assert_called_once_with("wg0", "/etc/wireguard/wg0.conf")

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._is_wireguard_up")
    @patch("keriguard.core.systeming.asyncio.create_subprocess_exec")
    async def test_control_wireguard_macos_start_failure(
        self, mock_subprocess, mock_is_up, mock_supports
    ):
        """Test that macOS START raises WireGuardControlError on wg-quick failure."""
        mock_supports.return_value = False
        mock_is_up.return_value = False

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"some error occurred"))
        mock_proc.returncode = 1
        mock_subprocess.return_value = mock_proc

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            with pytest.raises(
                WireGuardControlError,
                match="wg-quick up failed for",
            ):
                await control_wireguard(
                    WireGuardAction.START,
                    "wg0",
                    config_path="/etc/wireguard/wg0.conf",
                )

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming._is_wireguard_up")
    @patch("keriguard.core.systeming._mac_syncconf")
    @patch("keriguard.core.systeming.asyncio.create_subprocess_exec")
    async def test_control_wireguard_macos_start_already_exists_fallback(
        self, mock_subprocess, mock_syncconf, mock_is_up, mock_supports
    ):
        """Test that macOS START falls back to syncconf when wg-quick reports 'already exists'."""
        mock_supports.return_value = False
        mock_is_up.return_value = False
        mock_syncconf.return_value = None

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b"wg0' already exists as `utun4'")
        )
        mock_proc.returncode = 1
        mock_subprocess.return_value = mock_proc

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            await control_wireguard(
                WireGuardAction.START, "wg0", config_path="/etc/wireguard/wg0.conf"
            )

        mock_syncconf.assert_called_once_with(
            "wg0", "/etc/wireguard/wg0.conf", real_iface="utun4"
        )

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.asyncio.create_subprocess_exec")
    async def test_control_wireguard_macos_stop(self, mock_subprocess, mock_supports):
        """Test that macOS STOP calls wg-quick down."""
        mock_supports.return_value = False

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0
        mock_subprocess.return_value = mock_proc

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            await control_wireguard(
                WireGuardAction.STOP, "wg0", config_path="/etc/wireguard/wg0.conf"
            )

        call_args = mock_subprocess.call_args[0]
        assert "sudo" in call_args
        assert "down" in call_args
        assert "/etc/wireguard/wg0.conf" in call_args

    @pytest.mark.asyncio
    @patch("keriguard.core.systeming.supports_dbus_systemd")
    @patch("keriguard.core.systeming.asyncio.create_subprocess_exec")
    async def test_control_wireguard_macos_stop_failure(
        self, mock_subprocess, mock_supports
    ):
        """Test that macOS STOP raises WireGuardControlError on wg-quick down failure."""
        mock_supports.return_value = False

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"interface not found"))
        mock_proc.returncode = 1
        mock_subprocess.return_value = mock_proc

        with patch("keriguard.core.systeming.platform.system", return_value="Darwin"):
            with pytest.raises(
                WireGuardControlError,
                match="wg-quick down failed for",
            ):
                await control_wireguard(
                    WireGuardAction.STOP,
                    "wg0",
                    config_path="/etc/wireguard/wg0.conf",
                )

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
