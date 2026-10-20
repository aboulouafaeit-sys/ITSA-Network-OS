"""Wi-Fi airwave inspection, access point classification, and RF spectrum analysis."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


class WifiSecurityProtocol(str, Enum):
    """Wireless encryption and authentication protocol."""

    OPEN = "Open (None)"
    WEP = "WEP (Insecure)"
    WPA_PSK = "WPA-PSK (TKIP)"
    WPA2_PSK = "WPA2-PSK (AES/CCMP)"
    WPA3_SAE = "WPA3-Personal (SAE)"
    ENTERPRISE = "WPA2/WPA3-Enterprise (802.1X)"
    UNKNOWN = "Unknown"


class WifiStandard(str, Enum):
    """IEEE 802.11 generation standards."""

    LEGACY = "802.11b/g"
    WIFI_4 = "Wi-Fi 4 (802.11n)"
    WIFI_5 = "Wi-Fi 5 (802.11ac)"
    WIFI_6 = "Wi-Fi 6 (802.11ax)"
    WIFI_7 = "Wi-Fi 7 (802.11be)"


class SpectrumBand(str, Enum):
    """Radio frequency bands."""

    BAND_2_4_GHZ = "2.4 GHz"
    BAND_5_GHZ = "5 GHz"


@dataclass(frozen=True)
class AccessPointInfo:
    """Wireless Access Point telemetry and security profile."""

    ssid: str
    bssid: str
    rssi_dbm: int  # e.g., -45 dBm
    signal_percent: int  # 0 to 100%
    channel: int
    frequency_mhz: int
    channel_width_mhz: int  # 20, 40, 80, 160
    security: WifiSecurityProtocol
    standard: WifiStandard
    wps_enabled: bool = False
    security_warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["security"] = self.security.value
        data["standard"] = self.standard.value
        return data


@dataclass(frozen=True)
class ChannelCongestionReport:
    """Congestion metrics and evaluation for an individual RF channel."""

    channel: int
    frequency_mhz: int
    ap_count: int
    strongest_rssi_dbm: int
    co_channel_interference: int
    congestion_level: str  # LOW, MODERATE, HIGH, SEVERE
    recommended: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WirelessSpectrumAnalyzer:
    """Non-destructive Wi-Fi spectrum analysis and RF congestion evaluation engine."""

    # Standard non-overlapping channels in 2.4 GHz
    CHANNELS_2_4_GHZ: Dict[int, int] = {
        1: 2412,
        2: 2417,
        3: 2422,
        4: 2427,
        5: 2432,
        6: 2437,
        7: 2442,
        8: 2447,
        9: 2452,
        10: 2457,
        11: 2462,
        12: 2467,
        13: 2472,
        14: 2484,
    }

    # Common UNII 5 GHz channels
    CHANNELS_5_GHZ: Dict[int, int] = {
        36: 5180,
        40: 5200,
        44: 5220,
        48: 5240,
        52: 5260,
        56: 5280,
        60: 5300,
        64: 5320,
        100: 5500,
        104: 5520,
        108: 5540,
        112: 5560,
        116: 5580,
        132: 5660,
        136: 5680,
        140: 5700,
        149: 5745,
        153: 5765,
        157: 5785,
        161: 5805,
        165: 5825,
    }

    @staticmethod
    def rssi_to_quality_percent(rssi_dbm: int) -> int:
        """Translate RSSI dBm (-100 to -30) into human percentage (0 - 100%)."""
        if rssi_dbm <= -100:
            return 0
        if rssi_dbm >= -30:
            return 100
        # Linear approximation between -100 dBm (0%) and -30 dBm (100%)
        return int(((rssi_dbm + 100) / 70.0) * 100)

    @classmethod
    def get_access_points(
        cls,
        use_mock: bool = True,
        cancellation_check: Optional[Callable[[], bool]] = None,
    ) -> List[AccessPointInfo]:
        """Fetch discovered wireless access points."""
        if use_mock:
            # Deterministic mock fixtures for safe, offline analysis and testing
            return cls._mock_access_points()

        from itsa_network_os.network.wireless_scanner import LinuxWirelessScanner

        return LinuxWirelessScanner.get_access_points(cancellation_check=cancellation_check)

    @classmethod
    def analyze_spectrum(
        cls, access_points: List[AccessPointInfo], band: SpectrumBand = SpectrumBand.BAND_2_4_GHZ
    ) -> List[ChannelCongestionReport]:
        """Compute channel utilization, interference, and optimal channel recommendations."""
        channel_freq_map = cls.CHANNELS_2_4_GHZ if band == SpectrumBand.BAND_2_4_GHZ else cls.CHANNELS_5_GHZ
        reports: List[ChannelCongestionReport] = []

        # Count APs per channel
        channel_aps: Dict[int, List[AccessPointInfo]] = {ch: [] for ch in channel_freq_map}
        for ap in access_points:
            if ap.channel in channel_aps:
                channel_aps[ap.channel].append(ap)

        for ch, freq in channel_freq_map.items():
            aps_on_ch = channel_aps[ch]
            ap_count = len(aps_on_ch)
            strongest = max((ap.rssi_dbm for ap in aps_on_ch), default=-100)

            # In 2.4 GHz, adjacent channels within +/- 2 channels cause overlapping interference
            co_channel_interference = 0
            if band == SpectrumBand.BAND_2_4_GHZ:
                for adj in range(max(1, ch - 2), min(14, ch + 3)):
                    if adj != ch:
                        co_channel_interference += len(channel_aps.get(adj, []))

            # Determine congestion score
            total_interference = ap_count * 2 + co_channel_interference
            if total_interference == 0:
                congestion = "LOW"
            elif total_interference <= 2:
                congestion = "MODERATE"
            elif total_interference <= 4:
                congestion = "HIGH"
            else:
                congestion = "SEVERE"

            # Recommended channels in 2.4 GHz are standard non-overlapping channels (1, 6, 11) with lowest interference
            recommended = False
            if band == SpectrumBand.BAND_2_4_GHZ:
                if ch in (1, 6, 11) and congestion in ("LOW", "MODERATE"):
                    recommended = True
            elif band == SpectrumBand.BAND_5_GHZ:
                if congestion == "LOW":
                    recommended = True

            reports.append(
                ChannelCongestionReport(
                    channel=ch,
                    frequency_mhz=freq,
                    ap_count=ap_count,
                    strongest_rssi_dbm=strongest,
                    co_channel_interference=co_channel_interference,
                    congestion_level=congestion,
                    recommended=recommended,
                )
            )

        return reports

    @classmethod
    def _mock_access_points(cls) -> List[AccessPointInfo]:
        """Deterministic mock wireless access points representing diverse enterprise and residential environments."""
        return [
            AccessPointInfo(
                ssid="ITSA-Corp-Secure",
                bssid="00:27:0d:92:4a:10",
                rssi_dbm=-42,
                signal_percent=cls.rssi_to_quality_percent(-42),
                channel=6,
                frequency_mhz=2437,
                channel_width_mhz=20,
                security=WifiSecurityProtocol.WPA3_SAE,
                standard=WifiStandard.WIFI_6,
                wps_enabled=False,
                security_warnings=[],
            ),
            AccessPointInfo(
                ssid="ITSA-IoT-Devices",
                bssid="00:27:0d:92:4a:11",
                rssi_dbm=-55,
                signal_percent=cls.rssi_to_quality_percent(-55),
                channel=1,
                frequency_mhz=2412,
                channel_width_mhz=20,
                security=WifiSecurityProtocol.WPA2_PSK,
                standard=WifiStandard.WIFI_4,
                wps_enabled=False,
                security_warnings=[],
            ),
            AccessPointInfo(
                ssid="Public-Guest-WiFi",
                bssid="28:c6:8e:33:bb:02",
                rssi_dbm=-68,
                signal_percent=cls.rssi_to_quality_percent(-68),
                channel=6,
                frequency_mhz=2437,
                channel_width_mhz=20,
                security=WifiSecurityProtocol.OPEN,
                standard=WifiStandard.WIFI_5,
                wps_enabled=False,
                security_warnings=["Unencrypted network: cleartext traffic susceptible to eavesdropping."],
            ),
            AccessPointInfo(
                ssid="Legacy-Office-AP",
                bssid="14:cc:20:a1:8f:99",
                rssi_dbm=-75,
                signal_percent=cls.rssi_to_quality_percent(-75),
                channel=11,
                frequency_mhz=2462,
                channel_width_mhz=20,
                security=WifiSecurityProtocol.WEP,
                standard=WifiStandard.LEGACY,
                wps_enabled=True,
                security_warnings=[
                    "WEP encryption is cryptographically broken and trivial to crack in minutes.",
                    "WPS (Wi-Fi Protected Setup) enabled: vulnerable to offline brute-force attacks.",
                ],
            ),
            AccessPointInfo(
                ssid="HomeLab-5G-HyperFast",
                bssid="68:d7:9a:fe:12:44",
                rssi_dbm=-48,
                signal_percent=cls.rssi_to_quality_percent(-48),
                channel=36,
                frequency_mhz=5180,
                channel_width_mhz=80,
                security=WifiSecurityProtocol.WPA3_SAE,
                standard=WifiStandard.WIFI_6,
                wps_enabled=False,
                security_warnings=[],
            ),
            AccessPointInfo(
                ssid="Enterprise-Radius-8021X",
                bssid="68:d7:9a:fe:12:45",
                rssi_dbm=-52,
                signal_percent=cls.rssi_to_quality_percent(-52),
                channel=149,
                frequency_mhz=5745,
                channel_width_mhz=40,
                security=WifiSecurityProtocol.ENTERPRISE,
                standard=WifiStandard.WIFI_6,
                wps_enabled=False,
                security_warnings=[],
            ),
        ]
