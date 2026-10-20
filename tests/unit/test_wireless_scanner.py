"""Unit tests for Linux wireless scanner provider and pure 'iw' scan dump parser."""

import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from itsa_network_os.network.wifi import (
    AccessPointInfo,
    WifiSecurityProtocol,
    WifiStandard,
    WirelessSpectrumAnalyzer,
)
from itsa_network_os.network.wireless_scanner import (
    IwScanParser,
    LinuxWirelessScanner,
)


class TestIwScanParser(unittest.TestCase):
    """Unit tests verifying pure 'iw dev scan dump' text parsing without system or network calls."""

    FIXTURE_MULTI_BSS = """
BSS 00:27:0d:92:4a:10(on wlan0)
\tTSF: 1234567890123 usec (012d, 12:34:56)
\tfreq: 2437
\tbeacon interval: 100 TUs
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -42.00 dBm
\tlast seen: 120 ms ago
\tSSID: ITSA-Corp-Secure
\tSupported rates: 1.0* 2.0* 5.5* 11.0* 18.0 24.0 36.0 54.0
\tDS Parameter set: channel 6
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: SAE
\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x000c)
\tHT capabilities:
\t\tCapabilities: 0x18ef
\t\t\tHT20/HT40
\tHT operation:
\t\t * primary channel: 6
\t\t * secondary channel offset: no secondary
\t\t * STA channel width: 20 MHz

BSS 28:c6:8e:33:bb:02(on wlan0)
\tfreq: 5180
\tcapability: ESS Privacy (0x0011)
\tsignal: -68.00 dBm
\tSSID: Guest-5G
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK
\tVHT capabilities:
\t\tVHT Capabilities: 0x03c00032
\tVHT operation:
\t\t * channel width: 1 (80 MHz)
\t\t * center freq 1: 42
\tWPS:\t * Version: 2.0
\t\t * Wi-Fi Protected Setup State: 2 (Configured)

BSS 14:cc:20:a1:8f:99(on wlan0)
\tfreq: 2462
\tcapability: ESS Privacy (0x0011)
\tsignal: -75.00 dBm
\tSSID: Legacy-WEP
\tDS Parameter set: channel 11

BSS aa:bb:cc:dd:ee:ff(on wlan0)
\tfreq: 2412
\tcapability: ESS (0x0001)
\tsignal: -80.00 dBm
\tSSID: Open-Cafe
\tDS Parameter set: channel 1
"""

    def test_parse_multiple_bss_blocks(self) -> None:
        aps = IwScanParser.parse(self.FIXTURE_MULTI_BSS)
        self.assertEqual(len(aps), 4)

        ap1 = aps[0]
        self.assertEqual(ap1.bssid, "00:27:0d:92:4a:10")
        self.assertEqual(ap1.ssid, "ITSA-Corp-Secure")
        self.assertEqual(ap1.frequency_mhz, 2437)
        self.assertEqual(ap1.channel, 6)
        self.assertEqual(ap1.rssi_dbm, -42)
        self.assertEqual(ap1.channel_width_mhz, 20)
        self.assertEqual(ap1.security, WifiSecurityProtocol.WPA3_SAE)
        self.assertEqual(ap1.standard, WifiStandard.WIFI_4)
        self.assertFalse(ap1.wps_enabled)

        ap2 = aps[1]
        self.assertEqual(ap2.bssid, "28:c6:8e:33:bb:02")
        self.assertEqual(ap2.ssid, "Guest-5G")
        self.assertEqual(ap2.frequency_mhz, 5180)
        self.assertEqual(ap2.channel, 36)
        self.assertEqual(ap2.rssi_dbm, -68)
        self.assertEqual(ap2.channel_width_mhz, 80)
        self.assertEqual(ap2.security, WifiSecurityProtocol.WPA2_PSK)
        self.assertEqual(ap2.standard, WifiStandard.WIFI_5)
        self.assertTrue(ap2.wps_enabled)
        self.assertTrue(any("WPS" in w for w in ap2.security_warnings))

        ap3 = aps[2]
        self.assertEqual(ap3.bssid, "14:cc:20:a1:8f:99")
        self.assertEqual(ap3.ssid, "Legacy-WEP")
        self.assertEqual(ap3.security, WifiSecurityProtocol.WEP)
        self.assertEqual(ap3.standard, WifiStandard.LEGACY)
        self.assertTrue(any("WEP" in w for w in ap3.security_warnings))

        ap4 = aps[3]
        self.assertEqual(ap4.bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(ap4.ssid, "Open-Cafe")
        self.assertEqual(ap4.security, WifiSecurityProtocol.OPEN)
        self.assertTrue(any("Unencrypted" in w for w in ap4.security_warnings))

    def test_security_wpa2_wpa3_enterprise(self) -> None:
        fixture = """
BSS 00:11:22:33:44:55(on wlan0)
\tfreq: 5240
\tsignal: -52.00 dBm
\tSSID: Enterprise-Corp
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: IEEE 802.1X
"""
        aps = IwScanParser.parse(fixture)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0].security, WifiSecurityProtocol.ENTERPRISE)
        self.assertEqual(aps[0].channel, 48)

    def test_security_wpa1_psk_and_tkip_warning(self) -> None:
        fixture = """
BSS 11:22:33:44:55:66(on wlan0)
\tfreq: 2412
\tsignal: -60.00 dBm
\tSSID: Old-WPA1
\tWPA:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: TKIP
\t\t * Authentication suites: PSK
"""
        aps = IwScanParser.parse(fixture)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0].security, WifiSecurityProtocol.WPA_PSK)
        self.assertTrue(any("WPA1/TKIP is deprecated" in w for w in aps[0].security_warnings))

    def test_standards_wifi6_he_and_wifi7_eht(self) -> None:
        fixture_he = """
BSS 66:77:88:99:aa:bb(on wlan0)
\tfreq: 5500
\tsignal: -45.00 dBm
\tSSID: Wi-Fi6-AP
\tcapability: ESS Privacy (0x0011)
\tRSN:\t * Authentication suites: SAE
\tHE capabilities:
\t\tHE MAC Capabilities: 0x00000000
"""
        aps = IwScanParser.parse(fixture_he)
        self.assertEqual(aps[0].standard, WifiStandard.WIFI_6)
        self.assertEqual(aps[0].channel, 100)

        fixture_eht = """
BSS 77:88:99:aa:bb:cc(on wlan0)
\tfreq: 5745
\tsignal: -40.00 dBm
\tSSID: Wi-Fi7-AP
\tcapability: ESS Privacy (0x0011)
\tRSN:\t * Authentication suites: SAE
\tEHT capabilities:
\t\tEHT MAC Capabilities: 0x00000000
"""
        aps = IwScanParser.parse(fixture_eht)
        self.assertEqual(aps[0].standard, WifiStandard.WIFI_7)
        self.assertEqual(aps[0].channel, 149)

    def test_channel_width_160mhz(self) -> None:
        fixture_160 = """
BSS 88:99:aa:bb:cc:dd(on wlan0)
\tfreq: 5180
\tsignal: -50.00 dBm
\tSSID: WideBand-160
\tcapability: ESS Privacy (0x0011)
\tRSN:\t * Authentication suites: PSK
\tVHT operation:
\t\t * channel width: 2 (160 MHz)
"""
        aps = IwScanParser.parse(fixture_160)
        self.assertEqual(aps[0].channel_width_mhz, 160)

    def test_channel_width_40mhz_ht_secondary_offset(self) -> None:
        fixture_40 = """
BSS 99:aa:bb:cc:dd:ee(on wlan0)
\tfreq: 2437
\tsignal: -55.00 dBm
\tSSID: Channel40-AP
\tcapability: ESS Privacy (0x0011)
\tRSN:\t * Authentication suites: PSK
\tHT operation:
\t\t * primary channel: 6
\t\t * secondary channel offset: above
"""
        aps = IwScanParser.parse(fixture_40)
        self.assertEqual(aps[0].channel_width_mhz, 40)

    def test_frequency_2484_channel_14(self) -> None:
        fixture_ch14 = """
BSS 00:01:02:03:04:05(on wlan0)
\tfreq: 2484
\tsignal: -62.00 dBm
\tSSID: Japan-Ch14
\tcapability: ESS (0x0001)
"""
        aps = IwScanParser.parse(fixture_ch14)
        self.assertEqual(aps[0].channel, 14)

    def test_ssid_sanitization_legitimate_unicode(self) -> None:
        arabic_ssid = "شبكة_المنزل_الآمنة"
        cjk_ssid = "企业级无线网络"
        emoji_ssid = "Cafe ☕ & Bakery"

        self.assertEqual(IwScanParser.sanitize_ssid(arabic_ssid), arabic_ssid)
        self.assertEqual(IwScanParser.sanitize_ssid(cjk_ssid), cjk_ssid)
        self.assertEqual(IwScanParser.sanitize_ssid(emoji_ssid), emoji_ssid)

    def test_ssid_sanitization_removes_ansi_and_controls(self) -> None:
        malicious = "\x1b[31;1mRedHackerNet\x1b[0m\x07"
        cleaned = IwScanParser.sanitize_ssid(malicious)
        self.assertEqual(cleaned, "RedHackerNet")

        newlines = "Network\r\nInjection\tTab"
        cleaned_nl = IwScanParser.sanitize_ssid(newlines)
        self.assertEqual(cleaned_nl, "NetworkInjectionTab")

        nulls = "\\x00\\x00"
        cleaned_nulls = IwScanParser.sanitize_ssid(nulls)
        self.assertEqual(cleaned_nulls, "")

    def test_hidden_ssid_handling(self) -> None:
        fixture_hidden = (
            "\nBSS 00:22:33:44:55:66(on wlan0)\n"
            "\tfreq: 2412\n"
            "\tsignal: -70.00 dBm\n"
            "\tSSID:" + " \n"
            "\tcapability: ESS Privacy (0x0011)\n"
            "\tRSN:\t * Authentication suites: PSK\n"
        )
        aps = IwScanParser.parse(fixture_hidden)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0].ssid, "")
        self.assertTrue(any("Hidden SSID" in w for w in aps[0].security_warnings))

    def test_incomplete_beacon_security_warning(self) -> None:
        fixture_no_cap = """
BSS 11:22:33:44:55:77(on wlan0)
\tfreq: 2412
\tsignal: -70.00 dBm
\tSSID: Malformed-No-Cap
"""
        aps = IwScanParser.parse(fixture_no_cap)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0].security, WifiSecurityProtocol.UNKNOWN)
        self.assertTrue(any("Incomplete beacon telemetry: capability field absent; security status unknown." in w for w in aps[0].security_warnings))

    def test_invalid_bssid_skipped(self) -> None:
        fixture_invalid_mac = """
BSS not_a_real_mac(on wlan0)
\tfreq: 2412
\tsignal: -70.00 dBm
\tSSID: Bad-BSSID
"""
        aps = IwScanParser.parse(fixture_invalid_mac)
        self.assertEqual(len(aps), 0)

    def test_valid_capability_without_privacy_returns_open(self) -> None:
        fixture_valid_open = """
BSS 00:11:22:33:44:99(on wlan0)
\tfreq: 2412
\tsignal: -60.00 dBm
\tSSID: Truly-Open-AP
\tcapability: ESS ShortSlotTime (0x0401)
"""
        aps = IwScanParser.parse(fixture_valid_open)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0].security, WifiSecurityProtocol.OPEN)
        self.assertTrue(any("Unencrypted network" in w for w in aps[0].security_warnings))

    def test_valid_rsn_without_capability_line_returns_wpa2(self) -> None:
        fixture_rsn_no_cap = """
BSS 00:11:22:33:44:aa(on wlan0)
\tfreq: 5180
\tsignal: -55.00 dBm
\tSSID: Encrypted-No-Cap-Line
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK
"""
        aps = IwScanParser.parse(fixture_rsn_no_cap)
        self.assertEqual(len(aps), 1)
        # RSN affirmative evidence must not be converted to UNKNOWN or OPEN
        self.assertEqual(aps[0].security, WifiSecurityProtocol.WPA2_PSK)

    def test_empty_or_whitespace_capability_line_returns_unknown(self) -> None:
        fixture_empty_cap = (
            "\nBSS 00:11:22:33:44:bb(on wlan0)\n"
            "\tfreq: 2412\n"
            "\tsignal: -65.00 dBm\n"
            "\tSSID: Empty-Cap-Line\n"
            "\tcapability:" + "   \n"
        )
        aps = IwScanParser.parse(fixture_empty_cap)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0].security, WifiSecurityProtocol.UNKNOWN)
        self.assertTrue(any("security status unknown" in w for w in aps[0].security_warnings))


class TestLinuxWirelessScanner(unittest.TestCase):
    """Unit tests for LinuxWirelessScanner command execution and error handling."""

    @patch("shutil.which", return_value=None)
    def test_missing_iw_executable_returns_empty_and_logs(self, mock_which: MagicMock) -> None:
        with patch.object(LinuxWirelessScanner, "SYSFS_NET_PATH", Path("/tmp/nonexistent")):
            aps = LinuxWirelessScanner.get_access_points()
            self.assertEqual(aps, [])

    @patch("shutil.which", return_value="/usr/sbin/iw")
    @patch.object(LinuxWirelessScanner, "discover_wireless_interfaces", return_value=[])
    def test_no_wireless_interfaces_returns_empty(self, mock_disc: MagicMock, mock_which: MagicMock) -> None:
        aps = LinuxWirelessScanner.get_access_points()
        self.assertEqual(aps, [])

    @patch("shutil.which", return_value="/usr/sbin/iw")
    def test_invalid_interface_name_rejected_without_subprocess(self, mock_which: MagicMock) -> None:
        with patch("subprocess.run") as mock_run:
            aps = LinuxWirelessScanner.get_access_points(interface="wlan0;rm -rf /")
            self.assertEqual(aps, [])
            mock_run.assert_not_called()

    @patch("shutil.which", return_value="/usr/sbin/iw")
    @patch.object(LinuxWirelessScanner, "discover_wireless_interfaces", return_value=["wlan0"])
    @patch("subprocess.run")
    def test_command_invocation_strict_boundaries(
        self, mock_run: MagicMock, mock_disc: MagicMock, mock_which: MagicMock
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["/usr/sbin/iw", "dev", "wlan0", "scan", "dump"],
            returncode=0,
            stdout="BSS 00:11:22:33:44:55(on wlan0)\n\tfreq: 2412\n\tsignal: -50 dBm\n\tSSID: TestAP\n\tcapability: ESS (0x0001)\n",
            stderr="",
        )

        aps = LinuxWirelessScanner.get_access_points()
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0].ssid, "TestAP")

        # Verify command parameters: argument list, timeout, capture_output, text=True, check=False, NO shell=True
        mock_run.assert_called_once()
        call_args, call_kwargs = mock_run.call_args
        self.assertEqual(call_args[0], ["/usr/sbin/iw", "dev", "wlan0", "scan", "dump"])
        self.assertEqual(call_kwargs.get("timeout"), 3.0)
        self.assertTrue(call_kwargs.get("capture_output"))
        self.assertTrue(call_kwargs.get("text"))
        self.assertFalse(call_kwargs.get("check", True))
        self.assertFalse(call_kwargs.get("shell", False))

    @patch("shutil.which", return_value="/usr/sbin/iw")
    @patch.object(LinuxWirelessScanner, "discover_wireless_interfaces", return_value=["wlan0"])
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="iw dev wlan0 scan dump", timeout=3.0))
    def test_subprocess_timeout_handled_gracefully(
        self, mock_run: MagicMock, mock_disc: MagicMock, mock_which: MagicMock
    ) -> None:
        aps = LinuxWirelessScanner.get_access_points()
        self.assertEqual(aps, [])

    @patch("shutil.which", return_value="/usr/sbin/iw")
    @patch.object(LinuxWirelessScanner, "discover_wireless_interfaces", return_value=["wlan0"])
    @patch("subprocess.run", side_effect=PermissionError("Operation not permitted"))
    def test_subprocess_permission_error_handled_gracefully(
        self, mock_run: MagicMock, mock_disc: MagicMock, mock_which: MagicMock
    ) -> None:
        aps = LinuxWirelessScanner.get_access_points()
        self.assertEqual(aps, [])

    @patch("shutil.which", return_value="/usr/sbin/iw")
    @patch.object(LinuxWirelessScanner, "discover_wireless_interfaces", return_value=["wlan0"])
    @patch("subprocess.run", side_effect=FileNotFoundError("No such file"))
    def test_subprocess_file_not_found_handled_gracefully(
        self, mock_run: MagicMock, mock_disc: MagicMock, mock_which: MagicMock
    ) -> None:
        aps = LinuxWirelessScanner.get_access_points()
        self.assertEqual(aps, [])

    @patch("shutil.which", return_value="/usr/sbin/iw")
    @patch.object(LinuxWirelessScanner, "discover_wireless_interfaces", return_value=["wlan0"])
    @patch("subprocess.run")
    def test_subprocess_nonzero_exit_returns_empty(
        self, mock_run: MagicMock, mock_disc: MagicMock, mock_which: MagicMock
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["/usr/sbin/iw", "dev", "wlan0", "scan", "dump"],
            returncode=1,
            stdout="",
            stderr="command failed: Device or resource busy (-16)",
        )
        aps = LinuxWirelessScanner.get_access_points()
        self.assertEqual(aps, [])

    @patch("shutil.which", return_value="/usr/sbin/iw")
    @patch.object(LinuxWirelessScanner, "discover_wireless_interfaces", return_value=["wlan0"])
    @patch("subprocess.run")
    def test_empty_scan_cache_returns_empty(
        self, mock_run: MagicMock, mock_disc: MagicMock, mock_which: MagicMock
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["/usr/sbin/iw", "dev", "wlan0", "scan", "dump"],
            returncode=0,
            stdout="",
            stderr="",
        )
        aps = LinuxWirelessScanner.get_access_points()
        self.assertEqual(aps, [])


class TestPublicApiIntegration(unittest.TestCase):
    """Verify integration with WirelessSpectrumAnalyzer.get_access_points and Application orchestration."""

    def test_use_mock_true_returns_mock_dataset_unchanged(self) -> None:
        mock_aps = WirelessSpectrumAnalyzer.get_access_points(use_mock=True)
        self.assertIsInstance(mock_aps, list)
        self.assertEqual(len(mock_aps), 6)
        self.assertEqual(mock_aps[0].ssid, "ITSA-Corp-Secure")
        self.assertEqual(mock_aps[1].ssid, "ITSA-IoT-Devices")

    @patch.object(LinuxWirelessScanner, "get_access_points", return_value=[])
    def test_use_mock_false_never_falls_back_to_mock(self, mock_get: MagicMock) -> None:
        live_aps = WirelessSpectrumAnalyzer.get_access_points(use_mock=False)
        mock_get.assert_called_once()
        self.assertEqual(live_aps, [])

    @patch.object(LinuxWirelessScanner, "get_access_points")
    def test_use_mock_false_returns_live_results(self, mock_get: MagicMock) -> None:
        dummy_ap = AccessPointInfo(
            ssid="Live-AP-1",
            bssid="00:11:22:33:44:55",
            rssi_dbm=-45,
            signal_percent=78,
            channel=1,
            frequency_mhz=2412,
            channel_width_mhz=20,
            security=WifiSecurityProtocol.WPA2_PSK,
            standard=WifiStandard.WIFI_4,
            wps_enabled=False,
            security_warnings=[],
        )
        mock_get.return_value = [dummy_ap]

        live_aps = WirelessSpectrumAnalyzer.get_access_points(use_mock=False)
        self.assertEqual(len(live_aps), 1)
        self.assertEqual(live_aps[0].ssid, "Live-AP-1")


class TestSecuritySemanticsIntegration(unittest.TestCase):
    """Verify end-to-end integration of UNKNOWN security state across consumers, serialization, and persistence."""

    def test_access_point_serialization_unknown(self) -> None:
        ap = AccessPointInfo(
            ssid="Incomplete-AP",
            bssid="00:11:22:33:44:cc",
            rssi_dbm=-65,
            signal_percent=50,
            channel=6,
            frequency_mhz=2437,
            channel_width_mhz=20,
            security=WifiSecurityProtocol.UNKNOWN,
            standard=WifiStandard.LEGACY,
            wps_enabled=False,
            security_warnings=["Incomplete beacon telemetry: capability field absent; security status unknown."],
        )
        d = ap.to_dict()
        self.assertEqual(d["security"], "Unknown")
        self.assertEqual(d["standard"], "802.11b/g")
        self.assertIn("security status unknown", d["security_warnings"][0])

    def test_cli_formatter_displays_unknown(self) -> None:
        import io
        from unittest.mock import patch
        from itsa_network_os.ui.cli import TerminalFormatter

        ap = AccessPointInfo(
            ssid="Incomplete-AP",
            bssid="00:11:22:33:44:cc",
            rssi_dbm=-65,
            signal_percent=50,
            channel=6,
            frequency_mhz=2437,
            channel_width_mhz=20,
            security=WifiSecurityProtocol.UNKNOWN,
            standard=WifiStandard.LEGACY,
            wps_enabled=False,
            security_warnings=["Incomplete beacon telemetry: capability field absent; security status unknown."],
        )

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            TerminalFormatter.print_wifi_scan([ap])
            output = mock_stdout.getvalue()

        # Confirms Unknown is displayed in table and not Open (None)
        self.assertIn("Unknown", output)
        self.assertNotIn("Open (None)", output)
        self.assertIn("security status unknown", output)

    def test_database_persistence_and_open_stats_exclusion(self) -> None:
        from itsa_network_os.storage.database import DatabaseManager

        db = DatabaseManager(":memory:")
        session_id = db.record_wifi_scan_session(interface_name="wlan0", band="2.4 GHz", total_aps=2)

        # Record one UNKNOWN AP and one confirmed OPEN AP
        db.record_wifi_access_point(
            session_id=session_id,
            ssid="Unknown-AP",
            bssid="00:11:22:33:44:01",
            rssi_dbm=-60,
            signal_percent=57,
            channel=1,
            frequency_mhz=2412,
            channel_width_mhz=20,
            security=WifiSecurityProtocol.UNKNOWN.value,
            standard=WifiStandard.LEGACY.value,
            wps_enabled=False,
            security_warnings=["Incomplete beacon telemetry: capability field absent; security status unknown."],
        )
        db.record_wifi_access_point(
            session_id=session_id,
            ssid="Confirmed-Open-AP",
            bssid="00:11:22:33:44:02",
            rssi_dbm=-50,
            signal_percent=71,
            channel=6,
            frequency_mhz=2437,
            channel_width_mhz=20,
            security=WifiSecurityProtocol.OPEN.value,
            standard=WifiStandard.LEGACY.value,
            wps_enabled=False,
            security_warnings=["Unencrypted network: cleartext traffic susceptible to eavesdropping."],
        )

        # Retrieve recent APs
        recent = db.get_recent_wifi_aps(limit=10)
        self.assertEqual(len(recent), 2)

        unknown_records = [r for r in recent if r["bssid"] == "00:11:22:33:44:01"]
        open_records = [r for r in recent if r["bssid"] == "00:11:22:33:44:02"]

        self.assertEqual(unknown_records[0]["security"], "Unknown")
        self.assertEqual(open_records[0]["security"], "Open (None)")

        # Verify SQL queries for confirmed open networks strictly exclude Unknown
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM wifi_access_points WHERE security = ?", (WifiSecurityProtocol.OPEN.value,))
            open_count = cursor.fetchone()[0]
            self.assertEqual(open_count, 1)

            cursor.execute("SELECT COUNT(*) FROM wifi_access_points WHERE security = ?", (WifiSecurityProtocol.UNKNOWN.value,))
            unknown_count = cursor.fetchone()[0]
            self.assertEqual(unknown_count, 1)


if __name__ == "__main__":
    unittest.main()
