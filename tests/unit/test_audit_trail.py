"""Unit tests for diagnostic session recording, audit trail, and secret redaction (TASK-012)."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.network.scope import ScopeEnclosure
from itsa_network_os.storage.database import DatabaseManager
from itsa_network_os.storage.redaction import RedactionError


class TestAuditTrailAndSessionRecording(unittest.TestCase):
    """Exhaustive tests for diagnostic sessions, snapshots, cascades, and automated redaction."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_sessions.sqlite3")
        self.db = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_session_creation_with_metadata_and_scope(self) -> None:
        """Requirement: Session creation generates unique UUID, persists metadata, and neutral operator."""
        scope = ScopeEnclosure.from_strings(cidrs=["192.168.1.0/24"], allow_loopback=True)
        session_id = self.db.create_diagnostic_session(
            name="Quarterly Core Network Audit",
            operator="auditor-01",
            scope_enclosure=scope,
            metadata={"environment": "staging", "api_key": "secret_key_12345"},
        )
        self.assertGreater(session_id, 0)

        # Retrieve session
        session = self.db.get_diagnostic_session(session_id)
        self.assertIsNotNone(session)
        self.assertEqual(session["name"], "Quarterly Core Network Audit")
        self.assertEqual(session["operator"], "auditor-01")
        self.assertEqual(session["status"], "IN_PROGRESS")
        self.assertIn("192.168.1.0/24", session["scope_enclosure"]["cidrs"])

        # Verify metadata was sanitized before storage
        self.assertEqual(session["metadata"]["environment"], "staging")
        self.assertEqual(session["metadata"]["api_key"], "***REDACTED***")
        self.assertNotIn("secret_key_12345", json.dumps(session))

    def test_session_creation_validation(self) -> None:
        """Requirement: Empty or whitespace-only session name is rejected."""
        with self.assertRaises(ValueError):
            self.db.create_diagnostic_session(name="")

        with self.assertRaises(ValueError):
            self.db.create_diagnostic_session(name="   ")

    def test_record_snapshot_with_automated_redaction(self) -> None:
        """Requirement: Snapshot payloads undergo mandatory secret redaction before database persistence."""
        sess_id = self.db.create_diagnostic_session(name="Surveillance Camera Audit")

        camera_payload = {
            "device_id": "CAM-01",
            "model": "Hikvision DS-2CD2143G2-I",
            "ip_address": "192.168.1.50",
            "camera_info": {
                "rtsp_uri": "rtsp://admin:CameraPassword2026!@192.168.1.50:554/live",
                "codec": "H.265",
            },
            "credentials": {
                "admin_password": "PlaintextPasswordShouldBeRedacted!",
                "snmp_community": "private_corp_ro",
            },
            "security_notes": [
                "Found token Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secretToken",
            ],
        }

        snap_id = self.db.record_session_snapshot(
            session_id=sess_id,
            snapshot_type="DEVICE_INVENTORY",
            payload=camera_payload,
            target="192.168.1.50",
            status="WARNING",
        )
        self.assertGreater(snap_id, 0)

        # Retrieve session with snapshots
        session = self.db.get_diagnostic_session(sess_id)
        self.assertEqual(len(session["snapshots"]), 1)
        snap = session["snapshots"][0]
        self.assertEqual(snap["snapshot_type"], "DEVICE_INVENTORY")
        self.assertEqual(snap["target"], "192.168.1.50")
        self.assertEqual(snap["status"], "WARNING")
        self.assertEqual(snap["redacted_fields_count"], 4)

        # Inspect raw SQL row directly to verify secrets never reached SQLite disk
        with self.db._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT payload_json FROM diagnostic_snapshots WHERE id = ?;", (snap_id,))
            raw_payload_json = cur.fetchone()[0]

        self.assertNotIn("CameraPassword2026!", raw_payload_json)
        self.assertNotIn("PlaintextPasswordShouldBeRedacted!", raw_payload_json)
        self.assertNotIn("private_corp_ro", raw_payload_json)
        self.assertNotIn("secretToken", raw_payload_json)

        # Verify redacted markers in parsed payload
        parsed = json.loads(raw_payload_json)
        self.assertEqual(
            parsed["camera_info"]["rtsp_uri"],
            "rtsp://admin:***REDACTED***@192.168.1.50:554/live",
        )
        self.assertEqual(parsed["credentials"]["admin_password"], "***REDACTED***")
        self.assertEqual(parsed["credentials"]["snmp_community"], "***REDACTED***")
        self.assertIn("Authorization: Bearer ***REDACTED***", parsed["security_notes"][0])

    def test_snapshot_rejection_for_non_existent_session(self) -> None:
        """Requirement: Snapshot fails closed when linked to a non-existent session."""
        with self.assertRaises(ValueError) as cm:
            self.db.record_session_snapshot(
                session_id=99999,
                snapshot_type="HEALTH_CHECK",
                payload={"status": "OK"},
            )
        self.assertIn("does not exist", str(cm.exception))

    def test_session_completion_with_sanitized_summary(self) -> None:
        """Requirement: Session completion sets status, timestamp, and sanitizes summary payload."""
        sess_id = self.db.create_diagnostic_session(name="Site Readiness Assessment")

        summary_payload = {
            "total_devices": 12,
            "vulnerabilities": 2,
            "remediation_token": "secret_remediation_token_abc",
        }

        self.db.complete_diagnostic_session(
            session_id=sess_id,
            status="COMPLETED",
            summary=summary_payload,
        )

        session = self.db.get_diagnostic_session(sess_id)
        self.assertEqual(session["status"], "COMPLETED")
        self.assertIsNotNone(session["completed_at"])
        self.assertEqual(session["summary"]["total_devices"], 12)
        self.assertEqual(session["summary"]["remediation_token"], "***REDACTED***")

    def test_session_deletion_cascade_to_snapshots(self) -> None:
        """Requirement: Deleting a diagnostic session cascades to all attached snapshots."""
        sess_id = self.db.create_diagnostic_session(name="Temporary Assessment Session")
        self.db.record_session_snapshot(
            session_id=sess_id,
            snapshot_type="LATENCY",
            payload={"avg_ms": 12.5},
        )
        self.db.record_session_snapshot(
            session_id=sess_id,
            snapshot_type="DNS",
            payload={"status": "SUCCESS"},
        )

        snapshots_before = self.db.get_session_snapshots(sess_id)
        self.assertEqual(len(snapshots_before), 2)

        # Delete session
        deleted = self.db.delete_diagnostic_session(sess_id)
        self.assertTrue(deleted)

        # Session and snapshots must be gone
        self.assertIsNone(self.db.get_diagnostic_session(sess_id))
        snapshots_after = self.db.get_session_snapshots(sess_id)
        self.assertEqual(len(snapshots_after), 0)

        # Check directly with SQL
        with self.db._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM diagnostic_snapshots WHERE session_id = ?;", (sess_id,))
            self.assertEqual(cur.fetchone()[0], 0)

    def test_list_sessions_pagination_and_status_filtering(self) -> None:
        """Requirement: list_diagnostic_sessions supports pagination and status filtering."""
        s1 = self.db.create_diagnostic_session(name="Run 1")
        s2 = self.db.create_diagnostic_session(name="Run 2")
        s3 = self.db.create_diagnostic_session(name="Run 3")

        self.db.complete_diagnostic_session(s1, status="COMPLETED")
        self.db.complete_diagnostic_session(s2, status="FAILED")
        # s3 remains IN_PROGRESS

        # Filter by status
        completed = self.db.list_diagnostic_sessions(status_filter="COMPLETED")
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["name"], "Run 1")

        failed = self.db.list_diagnostic_sessions(status_filter="FAILED")
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["name"], "Run 2")

        in_progress = self.db.list_diagnostic_sessions(status_filter="IN_PROGRESS")
        self.assertEqual(len(in_progress), 1)
        self.assertEqual(in_progress[0]["name"], "Run 3")

        # Pagination test
        all_paginated = self.db.list_diagnostic_sessions(limit=2, offset=0)
        self.assertEqual(len(all_paginated), 2)

    def test_lookup_by_uuid(self) -> None:
        """Requirement: Session lookup works by both integer ID and external UUID string."""
        s_id = self.db.create_diagnostic_session(name="UUID Lookup Test")
        session_by_id = self.db.get_diagnostic_session(s_id)
        s_uuid = session_by_id["session_uuid"]

        session_by_uuid = self.db.get_diagnostic_session(s_uuid)
        self.assertIsNotNone(session_by_uuid)
        self.assertEqual(session_by_id["id"], session_by_uuid["id"])
        self.assertEqual(session_by_id["name"], session_by_uuid["name"])

    def test_application_orchestration_delegation(self) -> None:
        """Requirement: Application class orchestration methods delegate cleanly to DatabaseManager."""
        config = AppConfig(database_file=":memory:")
        app = Application(config=config)

        # Set authorized scope enclosure on Application
        app.set_authorized_scope(scope="10.0.0.0/16")

        # Start session
        session_id = app.start_diagnostic_session(
            name="App-Orchestrated Full Diagnostic Audit",
            operator="netadmin",
            metadata={"notes": "Initiated via Application controller", "secret_token": "abc12345"},
        )
        self.assertGreater(session_id, 0)

        # Record snapshot through app
        snap_id = app.record_session_snapshot(
            session_id=session_id,
            snapshot_type="WIFI_SCAN",
            payload={
                "interface": "wlan0",
                "aps": [{"ssid": "Internal-Corp", "wpa_key": "SuperSecretPassphrase!"}],
            },
            target="wlan0",
        )
        self.assertGreater(snap_id, 0)

        # Complete session
        app.complete_diagnostic_session(
            session_id=session_id,
            status="COMPLETED",
            summary={"score": 98, "admin_pwd": "pass"},
        )

        # Verify through app retrieval
        sess = app.get_diagnostic_session(session_id)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["name"], "App-Orchestrated Full Diagnostic Audit")
        self.assertEqual(sess["status"], "COMPLETED")
        self.assertEqual(sess["operator"], "netadmin")
        self.assertEqual(sess["metadata"]["secret_token"], "***REDACTED***")
        self.assertEqual(sess["snapshots"][0]["payload"]["aps"][0]["wpa_key"], "***REDACTED***")
        self.assertEqual(sess["summary"]["admin_pwd"], "***REDACTED***")

        # Verify session listing
        sess_list = app.list_diagnostic_sessions()
        self.assertEqual(len(sess_list), 1)


if __name__ == "__main__":
    unittest.main()
