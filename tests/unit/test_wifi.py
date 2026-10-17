"""Unit tests for Wi-Fi scanning and wireless spectrum analysis."""

import unittest

from itsa_network_os.network.wifi import (
    AccessPointInfo,
    ChannelCongestionReport,
    SpectrumBand,
    WifiSecurityProtocol,
    WifiStandard,
    WirelessSpectrumAnalyzer,
)


class TestWirelessSpectrumAnalyzer(unittest.TestCase):
    """Test wireless domain models, RSSI mapping, and RF congestion analysis."""

    def test_rssi_to_quality_percent_boundary_conditions(self) -> None:
        self.assertEqual(WirelessSpectrumAnalyzer.rssi_to_quality_percent(-110), 0)
        self.assertEqual(WirelessSpectrumAnalyzer.rssi_to_quality_percent(-100), 0)
        self.assertEqual(WirelessSpectrumAnalyzer.rssi_to_quality_percent(-30), 100)
        self.assertEqual(WirelessSpectrumAnalyzer.rssi_to_quality_percent(-20), 100)
        self.assertEqual(WirelessSpectrumAnalyzer.rssi_to_quality_percent(-65), 50)

    def test_get_mock_access_points(self) -> None:
        aps = WirelessSpectrumAnalyzer.get_access_points(use_mock=True)
        self.assertIsInstance(aps, list)
        self.assertGreaterEqual(len(aps), 5)

        for ap in aps:
            self.assertIsInstance(ap.ssid, str)
            self.assertIsInstance(ap.bssid, str)
            self.assertIsInstance(ap.rssi_dbm, int)
            self.assertGreaterEqual(ap.signal_percent, 0)
            self.assertLessEqual(ap.signal_percent, 100)
            self.assertIn(ap.security, list(WifiSecurityProtocol))
            self.assertIn(ap.standard, list(WifiStandard))

    def test_access_point_serialization(self) -> None:
        ap = AccessPointInfo(
            ssid="TestNet",
            bssid="aa:bb:cc:dd:ee:ff",
            rssi_dbm=-50,
            signal_percent=71,
            channel=6,
            frequency_mhz=2437,
            channel_width_mhz=20,
            security=WifiSecurityProtocol.WPA3_SAE,
            standard=WifiStandard.WIFI_6,
            wps_enabled=False,
            security_warnings=[],
        )
        data = ap.to_dict()
        self.assertEqual(data["ssid"], "TestNet")
        self.assertEqual(data["security"], "WPA3-Personal (SAE)")
        self.assertEqual(data["standard"], "Wi-Fi 6 (802.11ax)")

    def test_analyze_spectrum_2_4_ghz(self) -> None:
        aps = WirelessSpectrumAnalyzer.get_access_points(use_mock=True)
        reports = WirelessSpectrumAnalyzer.analyze_spectrum(aps, band=SpectrumBand.BAND_2_4_GHZ)

        self.assertEqual(len(reports), 14)
        ch_map = {r.channel: r for r in reports}

        # Verify Channel 6 has detected APs
        self.assertIn(6, ch_map)
        self.assertGreaterEqual(ch_map[6].ap_count, 1)

        # Non-overlapping channels should have recommendations evaluated
        recommended = [r.channel for r in reports if r.recommended]
        self.assertTrue(any(ch in (1, 6, 11) for ch in recommended))

        # Check serialization
        r_dict = ch_map[1].to_dict()
        self.assertIn("congestion_level", r_dict)
        self.assertIn("recommended", r_dict)

    def test_analyze_spectrum_5_ghz(self) -> None:
        aps = WirelessSpectrumAnalyzer.get_access_points(use_mock=True)
        reports = WirelessSpectrumAnalyzer.analyze_spectrum(aps, band=SpectrumBand.BAND_5_GHZ)

        self.assertEqual(len(reports), len(WirelessSpectrumAnalyzer.CHANNELS_5_GHZ))
        ch_map = {r.channel: r for r in reports}

        self.assertIn(36, ch_map)
        self.assertIn(149, ch_map)

        # Unoccupied 5 GHz channels should report LOW congestion and be recommended
        unoccupied = [r for r in reports if r.ap_count == 0]
        self.assertTrue(all(r.congestion_level == "LOW" for r in unoccupied))
        self.assertTrue(all(r.recommended for r in unoccupied))

    def test_security_vulnerabilities_detected(self) -> None:
        aps = WirelessSpectrumAnalyzer.get_access_points(use_mock=True)
        wep_aps = [ap for ap in aps if ap.security == WifiSecurityProtocol.WEP]
        open_aps = [ap for ap in aps if ap.security == WifiSecurityProtocol.OPEN]

        self.assertGreater(len(wep_aps), 0)
        self.assertGreater(len(open_aps), 0)

        # Ensure warnings are populated for insecure protocols
        self.assertTrue(len(wep_aps[0].security_warnings) > 0)
        self.assertTrue(len(open_aps[0].security_warnings) > 0)


if __name__ == "__main__":
    unittest.main()
