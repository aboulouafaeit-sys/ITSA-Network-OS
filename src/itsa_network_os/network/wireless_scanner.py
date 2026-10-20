"""Non-destructive Linux wireless scanner provider and pure 'iw' scan dump parser."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from itsa_network_os.core.logger import get_logger
from itsa_network_os.network.inspector import HostNetworkProvider
from itsa_network_os.network.models import InterfaceType
from itsa_network_os.network.wifi import (
    AccessPointInfo,
    WifiSecurityProtocol,
    WifiStandard,
    WirelessSpectrumAnalyzer,
)
from itsa_network_os.security.validator import InputValidator, SecurityValidationError

logger = get_logger("itsa_network_os.network.wireless_scanner")


class IwScanParser:
    """Pure, deterministic parser converting 'iw dev <iface> scan dump' text into AccessPointInfo models."""

    BSSID_PATTERN = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
    ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    BSS_BLOCK_PATTERN = re.compile(
        r"(?:^|\n)\s*BSS\s+([0-9a-fA-F:]{17})(.*?)(?=(?:\n\s*BSS\s+[0-9a-fA-F:]{17}|\Z))",
        re.DOTALL,
    )

    @classmethod
    def sanitize_ssid(cls, raw_ssid: str) -> str:
        """Sanitize raw SSID text safely without destroying legitimate Unicode.

        Strips ANSI escape codes, unprintable ASCII control characters (0-31),
        and C1 control codes (127-159). Preserves legitimate spaces and all
        printable Unicode (Arabic, CJK, Emoji, Latin, etc.).
        """
        if not raw_ssid:
            return ""

        # Remove ANSI terminal escape sequences
        cleaned = cls.ANSI_ESCAPE_PATTERN.sub("", raw_ssid)

        # Remove raw null bytes represented as textual escapes like '\x00'
        cleaned = re.sub(r"\\x00", "", cleaned)

        # Filter out ASCII control characters and C1 controls, preserving printable Unicode (>= 32 except DEL/C1)
        safe_chars = []
        for ch in cleaned:
            code = ord(ch)
            if code == 32:  # Regular space
                safe_chars.append(ch)
            elif code < 32 or (127 <= code <= 159):
                continue
            else:
                safe_chars.append(ch)

        result = "".join(safe_chars).strip()
        # If string is entirely null bytes or empty after stripping, return empty string for hidden network
        if not result or all(c == "\0" for c in result):
            return ""
        return result

    @classmethod
    def parse_frequency_and_channel(cls, lines: List[str]) -> tuple[int, int]:
        """Extract frequency (MHz) and channel number from BSS lines."""
        freq_mhz = 0
        channel = 0

        for line in lines:
            line_stripped = line.strip()
            if not freq_mhz:
                m_freq = re.match(r"^freq:\s*(\d+)", line_stripped)
                if m_freq:
                    freq_mhz = int(m_freq.group(1))

            if not channel:
                m_chan = re.search(r"(?:DS Parameter set:\s*channel|\*\s*primary channel:)\s*(\d+)", line_stripped)
                if m_chan:
                    channel = int(m_chan.group(1))

        # Calculate channel from frequency if channel was not explicitly announced
        if not channel and freq_mhz:
            if freq_mhz == 2484:
                channel = 14
            elif 2412 <= freq_mhz <= 2472:
                channel = (freq_mhz - 2407) // 5
            elif 5160 <= freq_mhz <= 5885:
                channel = (freq_mhz - 5000) // 5
            elif 5955 <= freq_mhz <= 7115:
                channel = (freq_mhz - 5940) // 5

        return freq_mhz, channel

    @classmethod
    def parse_signal(cls, lines: List[str]) -> int:
        """Extract signal level in dBm from BSS lines."""
        for line in lines:
            m_sig = re.search(r"signal:\s*(-?\d+(?:\.\d+)?)\s*dBm", line)
            if m_sig:
                try:
                    return int(float(m_sig.group(1)))
                except (ValueError, TypeError):
                    pass
        return -100

    @classmethod
    def parse_channel_width(cls, lines: List[str]) -> int:
        """Determine operating channel width in MHz (20, 40, 80, 160)."""
        width = 20
        for line in lines:
            line_lower = line.lower()
            if "channel width:" in line_lower or "sta channel width:" in line_lower:
                if "160" in line_lower or "160/80+80" in line_lower:
                    return 160
                if "80" in line_lower:
                    return 80
                if "40" in line_lower:
                    width = 40
                elif "20" in line_lower and width < 40:
                    width = 20
            elif "secondary channel offset:" in line_lower:
                if "above" in line_lower or "below" in line_lower:
                    if width < 40:
                        width = 40
        return width

    @classmethod
    def parse_security(cls, block_text: str, lines: List[str]) -> tuple[WifiSecurityProtocol, List[str]]:
        """Determine wireless security protocol and associated security warnings."""
        warnings: List[str] = []

        has_rsn = "RSN:" in block_text
        has_wpa = "WPA:" in block_text

        # Extract capability line
        capability_line = ""
        for line in lines:
            if line.strip().startswith("capability:"):
                capability_line = line.strip()
                break

        has_privacy = "Privacy" in capability_line if capability_line else False

        # Extract authentication suites from RSN and WPA sections
        rsn_suites: List[str] = []
        wpa_suites: List[str] = []
        current_section = ""

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("RSN:"):
                current_section = "RSN"
            elif stripped.startswith("WPA:"):
                current_section = "WPA"
            elif stripped.startswith(("WPS:", "HT capabilities:", "VHT capabilities:", "HE capabilities:", "EHT capabilities:")):
                current_section = ""

            if "Authentication suites:" in stripped:
                suites = stripped.split("Authentication suites:", 1)[1].strip()
                if current_section == "RSN":
                    rsn_suites.append(suites)
                elif current_section == "WPA":
                    wpa_suites.append(suites)

        rsn_text = " ".join(rsn_suites).upper()
        wpa_text = " ".join(wpa_suites).upper()

        protocol = WifiSecurityProtocol.OPEN

        if has_rsn:
            if "SAE" in rsn_text:
                protocol = WifiSecurityProtocol.WPA3_SAE
            elif "802.1X" in rsn_text or "IEEE 802.1X" in rsn_text:
                protocol = WifiSecurityProtocol.ENTERPRISE
            elif "PSK" in rsn_text:
                protocol = WifiSecurityProtocol.WPA2_PSK
            else:
                # Default for RSN if specific suite not isolated
                protocol = WifiSecurityProtocol.WPA2_PSK
        elif has_wpa:
            if "802.1X" in wpa_text or "IEEE 802.1X" in wpa_text:
                protocol = WifiSecurityProtocol.ENTERPRISE
            else:
                protocol = WifiSecurityProtocol.WPA_PSK
                warnings.append("WPA1/TKIP is deprecated and vulnerable to cryptographic attacks.")
        elif has_privacy:
            protocol = WifiSecurityProtocol.WEP
            warnings.append("WEP encryption is cryptographically broken and trivial to crack in minutes.")
        else:
            has_valid_capability = bool(re.search(r"capability:\s*\S+", capability_line))
            if not has_valid_capability and not has_rsn and not has_wpa:
                protocol = WifiSecurityProtocol.UNKNOWN
                warnings.append("Incomplete beacon telemetry: capability field absent; security status unknown.")
            else:
                protocol = WifiSecurityProtocol.OPEN
                warnings.append("Unencrypted network: cleartext traffic susceptible to eavesdropping.")

        return protocol, warnings

    @classmethod
    def parse_standard(cls, block_text: str) -> WifiStandard:
        """Infer IEEE 802.11 generation standard based strictly on capability evidence."""
        if "EHT capabilities:" in block_text or "EHT operation:" in block_text:
            return WifiStandard.WIFI_7
        if "HE capabilities:" in block_text or "HE operation:" in block_text:
            return WifiStandard.WIFI_6
        if "VHT capabilities:" in block_text or "VHT operation:" in block_text:
            return WifiStandard.WIFI_5
        if "HT capabilities:" in block_text or "HT operation:" in block_text:
            return WifiStandard.WIFI_4
        return WifiStandard.LEGACY

    @classmethod
    def parse_wps(cls, block_text: str) -> bool:
        """Check for affirmative evidence of Wi-Fi Protected Setup (WPS)."""
        return "WPS:" in block_text

    @classmethod
    def parse_bss_block(cls, bssid: str, block_text: str) -> Optional[AccessPointInfo]:
        """Parse a single isolated BSS text block into an AccessPointInfo model."""
        clean_bssid = bssid.strip().lower()
        if not cls.BSSID_PATTERN.match(clean_bssid):
            return None

        lines = block_text.splitlines()

        # Parse SSID
        raw_ssid = ""
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("SSID:"):
                raw_ssid = stripped[len("SSID:"):].strip()
                break

        ssid = cls.sanitize_ssid(raw_ssid)

        freq_mhz, channel = cls.parse_frequency_and_channel(lines)
        rssi_dbm = cls.parse_signal(lines)
        signal_percent = WirelessSpectrumAnalyzer.rssi_to_quality_percent(rssi_dbm)
        channel_width_mhz = cls.parse_channel_width(lines)

        security_proto, warnings = cls.parse_security(block_text, lines)
        standard = cls.parse_standard(block_text)
        wps_enabled = cls.parse_wps(block_text)

        if wps_enabled:
            warnings.append("WPS (Wi-Fi Protected Setup) enabled: vulnerable to offline brute-force attacks.")

        if not ssid:
            warnings.append("Hidden SSID (network name broadcast is suppressed).")

        return AccessPointInfo(
            ssid=ssid,
            bssid=clean_bssid,
            rssi_dbm=rssi_dbm,
            signal_percent=signal_percent,
            channel=channel,
            frequency_mhz=freq_mhz,
            channel_width_mhz=channel_width_mhz,
            security=security_proto,
            standard=standard,
            wps_enabled=wps_enabled,
            security_warnings=warnings,
        )

    @classmethod
    def parse(cls, output: str) -> List[AccessPointInfo]:
        """Parse complete 'iw dev <iface> scan dump' text into a list of AccessPointInfo objects."""
        if not output or not output.strip():
            return []

        access_points: List[AccessPointInfo] = []
        for match in cls.BSS_BLOCK_PATTERN.finditer(output):
            bssid = match.group(1)
            block_body = match.group(2)
            ap = cls.parse_bss_block(bssid, block_body)
            if ap is not None:
                access_points.append(ap)

        return access_points


class LinuxWirelessScanner:
    """Non-destructive, unprivileged Linux wireless scan provider using 'iw dev <iface> scan dump'."""

    SYSFS_NET_PATH = Path("/sys/class/net")
    COMMAND_TIMEOUT_SECONDS: float = 3.0
    TOTAL_SCAN_DEADLINE_SECONDS: float = 8.0

    @classmethod
    def _execute_interruptible_scan(
        cls,
        cmd: List[str],
        timeout: float,
        cancellation_check: Optional[Callable[[], bool]] = None,
    ) -> tuple[Optional[str], Optional[str], Optional[int], bool]:
        """Execute subprocess with bounded polling for cooperative cancellation and child process reaping.

        Returns:
            (stdout, stderr, returncode, was_cancelled)
        """
        if cancellation_check and cancellation_check():
            return None, None, -1, True

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        poll_interval = 0.05
        start_time = time.monotonic()
        was_cancelled = False
        timed_out = False

        try:
            while proc.poll() is None:
                if cancellation_check and cancellation_check():
                    was_cancelled = True
                    break
                elapsed = time.monotonic() - start_time
                if elapsed >= timeout:
                    timed_out = True
                    break
                time.sleep(poll_interval)

            if was_cancelled:
                try:
                    proc.terminate()
                    proc.wait(timeout=0.4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=0.4)
                except Exception:
                    pass
                try:
                    proc.communicate(timeout=0.2)
                except Exception:
                    pass
                return None, None, -1, True

            if timed_out:
                try:
                    proc.terminate()
                    proc.wait(timeout=0.4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=0.4)
                except Exception:
                    pass
                try:
                    proc.communicate(timeout=0.2)
                except Exception:
                    pass
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)

            stdout, stderr = proc.communicate()
            return stdout, stderr, proc.returncode, False

        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=0.2)
                except Exception:
                    pass

    @classmethod
    def discover_wireless_interfaces(cls) -> List[str]:
        """Discover available Linux wireless interfaces safely via sysfs without root privileges."""
        interfaces: List[str] = []

        if cls.SYSFS_NET_PATH.is_dir():
            try:
                for iface_dir in cls.SYSFS_NET_PATH.iterdir():
                    if not iface_dir.is_dir():
                        continue

                    name = iface_dir.name
                    # Check for kernel wireless attribute directory
                    is_wireless = (iface_dir / "phy80211").is_dir() or (iface_dir / "wireless").is_dir()
                    if not is_wireless:
                        # Fall back to established interface classification
                        classified = HostNetworkProvider.classify_interface_type(name)
                        if classified == InterfaceType.WIRELESS:
                            is_wireless = True

                    if is_wireless:
                        try:
                            valid_name = InputValidator.validate_interface_name(name)
                            interfaces.append(valid_name)
                        except SecurityValidationError:
                            logger.warning("Discovered wireless interface name failed validation: '%s'", name)
            except Exception as exc:
                logger.debug("Error enumerating sysfs network interfaces: %s", exc)

        return sorted(interfaces)

    @classmethod
    def get_access_points(
        cls,
        interface: Optional[str] = None,
        cancellation_check: Optional[Callable[[], bool]] = None,
    ) -> List[AccessPointInfo]:
        """Read available cached wireless scan results non-destructively.

        Executes strictly 'iw dev <iface> scan dump'. Never runs active scans,
        never modifies interface state, and never requests elevated privileges.
        Returns an empty list when no wireless card or scan data is present.
        """
        # Step 1: Preflight check for 'iw' executable
        if cancellation_check and cancellation_check():
            return []

        iw_path = shutil.which("iw")
        if not iw_path:
            logger.warning("Wireless inspection unavailable: 'iw' executable not found in PATH")
            return []

        # Step 2: Determine target wireless interface(s)
        candidates: List[str] = []
        if interface:
            try:
                valid_iface = InputValidator.validate_interface_name(interface)
                iface_dir = cls.SYSFS_NET_PATH / valid_iface
                if not iface_dir.is_dir():
                    logger.warning("Requested wireless interface does not exist: '%s'", valid_iface)
                    return []
                candidates = [valid_iface]
            except SecurityValidationError as exc:
                logger.warning("Invalid wireless interface parameter: %s", exc)
                return []
        else:
            candidates = cls.discover_wireless_interfaces()

        if not candidates:
            logger.info("No wireless interfaces detected on host; returning empty scan results")
            return []

        # Step 3: Query scan dump on candidate wireless interfaces non-destructively
        deadline = time.monotonic() + cls.TOTAL_SCAN_DEADLINE_SECONDS
        for iface in candidates:
            if cancellation_check and cancellation_check():
                logger.info("Wireless scan dump cancelled before querying interface '%s'", iface)
                return []

            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                logger.warning(
                    "Wireless scan overall deadline (%.1fs) expired before querying '%s'",
                    cls.TOTAL_SCAN_DEADLINE_SECONDS,
                    iface,
                )
                break

            cmd_timeout = min(cls.COMMAND_TIMEOUT_SECONDS, remaining_time)
            cmd = [iw_path, "dev", iface, "scan", "dump"]

            try:
                if cancellation_check is not None:
                    stdout, stderr, returncode, was_cancelled = cls._execute_interruptible_scan(
                        cmd,
                        timeout=cmd_timeout,
                        cancellation_check=cancellation_check,
                    )
                    if was_cancelled:
                        logger.info("Wireless scan dump cancelled during execution on '%s'", iface)
                        return []
                else:
                    res = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=cmd_timeout,
                    )
                    stdout = res.stdout
                    stderr = res.stderr
                    returncode = res.returncode
            except subprocess.TimeoutExpired:
                logger.warning("iw scan dump on '%s' timed out after %.1fs", iface, cmd_timeout)
                continue
            except (FileNotFoundError, PermissionError, OSError) as exc:
                logger.warning("iw scan dump on '%s' failed to execute: %s", iface, exc)
                continue

            if cancellation_check and cancellation_check():
                logger.info("Wireless scan dump cancelled post-execution on '%s'", iface)
                return []

            if returncode != 0:
                logger.warning(
                    "iw scan dump on '%s' exited with code %d: %s",
                    iface,
                    returncode,
                    stderr.strip() if stderr else "unknown error",
                )
                continue

            parsed_aps = IwScanParser.parse(stdout or "")
            if parsed_aps:
                logger.info("Discovered %d cached access points on wireless interface '%s'", len(parsed_aps), iface)
                return parsed_aps
            else:
                logger.info("iw scan dump on '%s' returned 0 cached access points", iface)

        return []
