"""Unit tests for EvidenceRecord, EvidenceProtocol, confidence boundaries, and ManagedDevice integration."""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
import unittest

from itsa_network_os.network.models import EvidenceProtocol, EvidenceRecord
from itsa_network_os.network.vendor_manager import (
    DeviceCategory,
    DeviceSecurityStatus,
    ManagedDevice,
    VendorDiscoveryReport,
    VendorManagerEngine,
)


class TestEvidenceModel(unittest.TestCase):
    """Exhaustive test suite for EvidenceRecord data model, validation invariants, and serialization."""

    # 1. Valid construction
    def test_valid_construction_basic(self) -> None:
        """Verify valid instantiation of EvidenceRecord with required and optional fields."""
        rec = EvidenceRecord(
            source_protocol=EvidenceProtocol.ONVIF,
            timestamp="2026-10-19T12:00:00Z",
            confidence=0.95,
            is_verified_fact=True,
            attribute="model",
            details="Direct ONVIF ProbeMatch responder",
        )
        self.assertEqual(rec.source_protocol, "ONVIF")
        self.assertEqual(rec.timestamp, "2026-10-19T12:00:00+00:00")
        self.assertEqual(rec.confidence, 0.95)
        self.assertTrue(rec.is_verified_fact)
        self.assertEqual(rec.attribute, "model")
        self.assertEqual(rec.details, "Direct ONVIF ProbeMatch responder")

    # 2. Confidence boundaries 0.0 and 1.0
    def test_confidence_boundaries_min_and_max(self) -> None:
        """Verify boundary confidence values 0.0 and 1.0 are accepted and normalized to float."""
        rec_min = EvidenceRecord(
            source_protocol="MOCK",
            timestamp="2026-10-19T00:00:00+00:00",
            confidence=0.0,
            is_verified_fact=False,
        )
        self.assertEqual(rec_min.confidence, 0.0)
        self.assertIsInstance(rec_min.confidence, float)

        rec_max = EvidenceRecord(
            source_protocol="TLS",
            timestamp="2026-10-19T00:00:00+00:00",
            confidence=1.0,
            is_verified_fact=True,
        )
        self.assertEqual(rec_max.confidence, 1.0)
        self.assertIsInstance(rec_max.confidence, float)

        # Also verify integer 0 and 1 are accepted and cast to float
        rec_int0 = EvidenceRecord(
            source_protocol="MOCK",
            timestamp="2026-10-19T00:00:00+00:00",
            confidence=0,
            is_verified_fact=False,
        )
        self.assertEqual(rec_int0.confidence, 0.0)
        self.assertIsInstance(rec_int0.confidence, float)

        rec_int1 = EvidenceRecord(
            source_protocol="MNDP",
            timestamp="2026-10-19T00:00:00+00:00",
            confidence=1,
            is_verified_fact=True,
        )
        self.assertEqual(rec_int1.confidence, 1.0)
        self.assertIsInstance(rec_int1.confidence, float)

    # 3. A valid intermediate confidence value
    def test_valid_intermediate_confidence_value(self) -> None:
        """Verify arbitrary intermediate values between 0.0 and 1.0."""
        for val in (0.0001, 0.25, 0.5, 0.773, 0.9999):
            rec = EvidenceRecord(
                source_protocol="ARP",
                timestamp="2026-10-19T10:00:00+00:00",
                confidence=val,
                is_verified_fact=False,
            )
            self.assertAlmostEqual(rec.confidence, val)

    # 4. Rejection of values below and above range
    def test_rejection_of_out_of_range_confidence(self) -> None:
        """Verify ValueError is raised when confidence is strictly outside [0.0, 1.0]."""
        invalid_scores = (-0.0001, -1.0, -100.0, 1.0001, 2.0, 99.0)
        for bad_score in invalid_scores:
            with self.subTest(score=bad_score):
                with self.assertRaises(ValueError) as ctx:
                    EvidenceRecord(
                        source_protocol="MOCK",
                        timestamp="2026-10-19T10:00:00+00:00",
                        confidence=bad_score,
                        is_verified_fact=False,
                    )
                self.assertIn("between 0.0 and 1.0", str(ctx.exception))

    # 5. Rejection of NaN and infinities
    def test_rejection_of_nan_and_infinities(self) -> None:
        """Verify ValueError is raised for NaN, +inf, and -inf."""
        non_finites = (float("nan"), float("inf"), float("-inf"))
        for nf in non_finites:
            with self.subTest(non_finite=nf):
                with self.assertRaises(ValueError) as ctx:
                    EvidenceRecord(
                        source_protocol="MOCK",
                        timestamp="2026-10-19T10:00:00+00:00",
                        confidence=nf,
                        is_verified_fact=False,
                    )
                self.assertIn("finite number", str(ctx.exception))

    def test_rejection_of_invalid_confidence_types(self) -> None:
        """Verify TypeError is raised when confidence is a boolean, string, or arbitrary object."""
        bad_types = (True, False, "0.5", "1.0", None, [0.5], {"score": 1.0})
        for bt in bad_types:
            with self.subTest(bad_type=bt):
                with self.assertRaises(TypeError) as ctx:
                    EvidenceRecord(
                        source_protocol="MOCK",
                        timestamp="2026-10-19T10:00:00+00:00",
                        confidence=bt,  # type: ignore[arg-type]
                        is_verified_fact=False,
                    )
                self.assertIn("float or int", str(ctx.exception))

    # 6. Timestamp validation and UTC handling
    def test_timestamp_validation_and_utc_normalization(self) -> None:
        """Verify valid ISO 8601 parsing, non-UTC conversion, naive UTC fallback, and invalid rejection."""
        # 1. Standard ISO with Z
        r1 = EvidenceRecord(
            source_protocol="ONVIF",
            timestamp="2026-10-19T15:30:00Z",
            confidence=1.0,
            is_verified_fact=True,
        )
        self.assertEqual(r1.timestamp, "2026-10-19T15:30:00+00:00")

        # 2. Offset timestamp converted to UTC instant
        r2 = EvidenceRecord(
            source_protocol="ONVIF",
            timestamp="2026-10-19T17:30:00+02:00",
            confidence=1.0,
            is_verified_fact=True,
        )
        self.assertEqual(r2.timestamp, "2026-10-19T15:30:00+00:00")

        # 3. Naive timestamp assumed UTC
        r3 = EvidenceRecord(
            source_protocol="ONVIF",
            timestamp="2026-10-19T15:30:00",
            confidence=1.0,
            is_verified_fact=True,
        )
        self.assertEqual(r3.timestamp, "2026-10-19T15:30:00+00:00")

        # 4. datetime object with tzinfo
        dt_utc = datetime(2026, 10, 19, 15, 30, 0, tzinfo=timezone.utc)
        r4 = EvidenceRecord(
            source_protocol="ONVIF",
            timestamp=dt_utc,
            confidence=1.0,
            is_verified_fact=True,
        )
        self.assertEqual(r4.timestamp, "2026-10-19T15:30:00+00:00")

        # 5. datetime object naive
        dt_naive = datetime(2026, 10, 19, 15, 30, 0)
        r5 = EvidenceRecord(
            source_protocol="ONVIF",
            timestamp=dt_naive,
            confidence=1.0,
            is_verified_fact=True,
        )
        self.assertEqual(r5.timestamp, "2026-10-19T15:30:00+00:00")

        # 6. Rejection of invalid timestamp strings and types
        bad_timestamps = ("", "   ", "not-a-date", "2026-99-99", "yesterday")
        for bad_ts in bad_timestamps:
            with self.subTest(bad_ts=bad_ts):
                with self.assertRaises(ValueError):
                    EvidenceRecord(
                        source_protocol="ONVIF",
                        timestamp=bad_ts,
                        confidence=1.0,
                        is_verified_fact=True,
                    )

        bad_types = (12345, 1729350000.0, None, ["2026-10-19"])
        for bt in bad_types:
            with self.subTest(bad_type=bt):
                with self.assertRaises(TypeError):
                    EvidenceRecord(
                        source_protocol="ONVIF",
                        timestamp=bt,  # type: ignore[arg-type]
                        confidence=1.0,
                        is_verified_fact=True,
                    )

    # 7. Boolean validation for is_verified_fact
    def test_boolean_validation_for_is_verified_fact(self) -> None:
        """Verify that is_verified_fact must be strictly a boolean and rejects truthy/falsy non-bools."""
        # Genuine booleans pass
        r_true = EvidenceRecord(
            source_protocol="MOCK",
            timestamp="2026-10-19T12:00:00+00:00",
            confidence=1.0,
            is_verified_fact=True,
        )
        self.assertIs(r_true.is_verified_fact, True)

        r_false = EvidenceRecord(
            source_protocol="MOCK",
            timestamp="2026-10-19T12:00:00+00:00",
            confidence=0.5,
            is_verified_fact=False,
        )
        self.assertIs(r_false.is_verified_fact, False)

        # Non-boolean types must be rejected
        bad_bools = (1, 0, "True", "False", None, [True], 1.0)
        for bb in bad_bools:
            with self.subTest(bad_bool=bb):
                with self.assertRaises(TypeError) as ctx:
                    EvidenceRecord(
                        source_protocol="MOCK",
                        timestamp="2026-10-19T12:00:00+00:00",
                        confidence=1.0,
                        is_verified_fact=bb,  # type: ignore[arg-type]
                    )
                self.assertIn("must be a bool", str(ctx.exception))

    # 8. Protocol representation and serialization
    def test_protocol_representation_and_serialization(self) -> None:
        """Verify EvidenceProtocol enum values, custom string protocols, and empty rejection."""
        # Using enum
        r1 = EvidenceRecord(
            source_protocol=EvidenceProtocol.MNDP,
            timestamp="2026-10-19T12:00:00+00:00",
            confidence=1.0,
            is_verified_fact=True,
        )
        self.assertEqual(r1.source_protocol, "MNDP")

        # Using custom string protocol
        r2 = EvidenceRecord(
            source_protocol="CUSTOM_PROPRIETARY_DISCOVERY",
            timestamp="2026-10-19T12:00:00+00:00",
            confidence=0.8,
            is_verified_fact=False,
        )
        self.assertEqual(r2.source_protocol, "CUSTOM_PROPRIETARY_DISCOVERY")

        # Dataclass equality matches regardless of enum vs. string initialization
        r3 = EvidenceRecord(
            source_protocol="MNDP",
            timestamp="2026-10-19T12:00:00+00:00",
            confidence=1.0,
            is_verified_fact=True,
        )
        self.assertEqual(r1, r3)

        # Empty or whitespace rejection
        for empty_proto in ("", "   ", "\t\n"):
            with self.subTest(empty=empty_proto):
                with self.assertRaises(ValueError):
                    EvidenceRecord(
                        source_protocol=empty_proto,
                        timestamp="2026-10-19T12:00:00+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                    )

        # Invalid type rejection
        with self.assertRaises(TypeError):
            EvidenceRecord(
                source_protocol=123,  # type: ignore[arg-type]
                timestamp="2026-10-19T12:00:00+00:00",
                confidence=1.0,
                is_verified_fact=True,
            )

    # 9. EvidenceRecord dictionary and JSON round-trip
    def test_evidence_record_dict_and_json_roundtrip(self) -> None:
        """Verify that EvidenceRecord converts to dictionary and serializes cleanly with json.dumps()."""
        rec = EvidenceRecord(
            source_protocol=EvidenceProtocol.TLS,
            timestamp="2026-10-19T14:20:00Z",
            confidence=0.99,
            is_verified_fact=True,
            attribute="security_status",
            details="Validated X.509 certificate expiry 2027-01-01",
        )
        d = rec.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["source_protocol"], "TLS")
        self.assertEqual(d["timestamp"], "2026-10-19T14:20:00+00:00")
        self.assertEqual(d["confidence"], 0.99)
        self.assertTrue(d["is_verified_fact"])
        self.assertEqual(d["attribute"], "security_status")
        self.assertEqual(d["details"], "Validated X.509 certificate expiry 2027-01-01")

        # JSON round-trip
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)
        loaded = json.loads(json_str)
        self.assertEqual(loaded, d)

    # 10. ManagedDevice serialization with evidence
    def test_managed_device_serialization_with_evidence(self) -> None:
        """Verify that ManagedDevice serializes evidence records to a list of dicts."""
        ev1 = EvidenceRecord(
            source_protocol=EvidenceProtocol.ONVIF,
            timestamp="2026-10-19T12:00:00+00:00",
            confidence=1.0,
            is_verified_fact=True,
            attribute="device_identity",
        )
        ev2 = EvidenceRecord(
            source_protocol=EvidenceProtocol.HTTP,
            timestamp="2026-10-19T12:00:01+00:00",
            confidence=0.85,
            is_verified_fact=False,
            attribute="model",
        )
        dev = ManagedDevice(
            device_id="DEV-TEST-01",
            name="Test Dome Camera",
            category=DeviceCategory.IP_CAMERA,
            vendor="Hikvision",
            model="DS-2CD2143G2-I",
            ip_address="192.168.1.50",
            mac_address="00:11:22:33:44:55",
            firmware_version="v5.7.0",
            discovery_protocol="ONVIF",
            security_status=DeviceSecurityStatus.SECURE,
            evidence=[ev1, ev2],
        )

        d = dev.to_dict()
        self.assertIn("evidence", d)
        self.assertEqual(len(d["evidence"]), 2)
        self.assertEqual(d["evidence"][0]["source_protocol"], "ONVIF")
        self.assertTrue(d["evidence"][0]["is_verified_fact"])
        self.assertEqual(d["evidence"][1]["source_protocol"], "HTTP")
        self.assertFalse(d["evidence"][1]["is_verified_fact"])

        # JSON round-trip
        json_str = json.dumps(d)
        self.assertIn('"source_protocol": "ONVIF"', json_str)
        self.assertIn('"is_verified_fact": true', json_str)

    # 11. Existing ManagedDevice construction and serialization compatibility
    def test_managed_device_backward_compatibility_without_evidence_arg(self) -> None:
        """Verify ManagedDevice instantiates without evidence argument and defaults to empty list."""
        dev = ManagedDevice(
            device_id="LEGACY-01",
            name="Legacy Hardware Unit",
            category=DeviceCategory.LINUX_SERVER,
            vendor="Ubuntu",
            model="Server",
            ip_address="192.168.1.100",
            mac_address="AA:BB:CC:DD:EE:FF",
            firmware_version="6.8.0",
            discovery_protocol="SSH",
            security_status=DeviceSecurityStatus.SECURE,
        )
        self.assertEqual(dev.evidence, [])
        d = dev.to_dict()
        self.assertIn("evidence", d)
        self.assertEqual(d["evidence"], [])
        self.assertEqual(d["name"], "Legacy Hardware Unit")

    # 12. Independence of evidence lists across different device instances
    def test_independence_of_evidence_lists_across_instances(self) -> None:
        """Ensure evidence default factory does not leak or share mutable collections across instances."""
        dev1 = ManagedDevice(
            device_id="D1",
            name="Device 1",
            category=DeviceCategory.MIKROTIK,
            vendor="MikroTik",
            model="hEX",
            ip_address="192.168.1.1",
            mac_address="11:22:33:44:55:66",
            firmware_version="7.14",
            discovery_protocol="MNDP",
            security_status=DeviceSecurityStatus.SECURE,
        )
        dev2 = ManagedDevice(
            device_id="D2",
            name="Device 2",
            category=DeviceCategory.UBIQUITI,
            vendor="Ubiquiti",
            model="LiteBeam",
            ip_address="192.168.1.2",
            mac_address="22:33:44:55:66:77",
            firmware_version="8.7",
            discovery_protocol="UBNT",
            security_status=DeviceSecurityStatus.SECURE,
        )
        self.assertIsNot(dev1.evidence, dev2.evidence)
        self.assertEqual(dev1.evidence, [])
        self.assertEqual(dev2.evidence, [])

    # 13. Regression behavior for VendorDiscoveryReport and VendorManagerEngine
    def test_vendor_discovery_report_regression_with_evidence(self) -> None:
        """Verify VendorDiscoveryReport encapsulates devices with evidence and serializes properly."""
        report = VendorManagerEngine.discover_devices(use_mock=True)
        self.assertIsInstance(report, VendorDiscoveryReport)
        self.assertEqual(report.total_devices, 8)

        # Every mock device has illustrative evidence populated
        for dev in report.devices:
            self.assertGreater(len(dev.evidence), 0, f"Device {dev.device_id} must have evidence.")
            for ev in dev.evidence:
                self.assertIsInstance(ev, EvidenceRecord)
                self.assertIsInstance(ev.source_protocol, str)
                self.assertIsInstance(ev.timestamp, str)
                self.assertIsInstance(ev.confidence, float)
                self.assertIsInstance(ev.is_verified_fact, bool)
                self.assertGreaterEqual(ev.confidence, 0.0)
                self.assertLessEqual(ev.confidence, 1.0)

        # Verify full report serialization to dict and JSON
        report_dict = report.to_dict()
        self.assertIn("devices", report_dict)
        self.assertEqual(len(report_dict["devices"]), 8)
        self.assertIn("evidence", report_dict["devices"][0])

        json_out = json.dumps(report_dict)
        self.assertIsInstance(json_out, str)

    # 14. Decoupling of confidence score from is_verified_fact invariant
    def test_confidence_and_is_verified_fact_are_independent(self) -> None:
        """Verify that high confidence does not enforce verified fact and low confidence does not enforce inference."""
        # 1. High confidence inference (e.g. 0.95 confidence MAC OUI inference)
        high_conf_inference = EvidenceRecord(
            source_protocol=EvidenceProtocol.ARP,
            timestamp="2026-10-19T12:00:00+00:00",
            confidence=0.99,
            is_verified_fact=False,
            details="Strong MAC OUI heuristic vendor match",
        )
        self.assertEqual(high_conf_inference.confidence, 0.99)
        self.assertFalse(high_conf_inference.is_verified_fact)

        # 2. Lower confidence fact (e.g. verified protocol response over noisy RF link)
        lower_conf_fact = EvidenceRecord(
            source_protocol=EvidenceProtocol.ONVIF,
            timestamp="2026-10-19T12:00:00+00:00",
            confidence=0.50,
            is_verified_fact=True,
            details="Direct ONVIF ProbeMatch received but packet had transport retransmissions",
        )
        self.assertEqual(lower_conf_fact.confidence, 0.50)
        self.assertTrue(lower_conf_fact.is_verified_fact)


if __name__ == "__main__":
    unittest.main()
