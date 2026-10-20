"""Unit tests for multi-format technical report exporter (TASK-013).

Covers:
- JSON export completeness, schema versioning, determinism, and empty session handling.
- CSV export RFC 4180 quoting, fixed column layout, dynamic payload.<key> columns,
  and lossless nested payload_json preservation.
- Markdown report structure, executive summary metrics, scope enclosures, snapshot catalog,
  detailed findings, and heuristic redaction disclaimer.
- Unicode and multiline content handling.
- Mandatory pre-export credential redaction (defense-in-depth).
- Filesystem safety: path traversal rejection, directory creation controls, race-safe
  non-overwrite behavior, atomic replacement, permissions, and temp-file cleanup on failure.
- Database read-only immutability.
- Application-level export delegation.
- Backward compatibility for legacy ReportExporter methods.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, Union
from unittest.mock import patch

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.network.scope import ScopeEnclosure
from itsa_network_os.reports.exporter import (
    ExportError,
    ExportPathError,
    ReportExporter,
    SessionNotFoundError,
    UnsupportedFormatError,
)
from itsa_network_os.storage.database import DatabaseManager


def split_markdown_table_row(row_line: str) -> list[str]:
    """Parse a Markdown table row into its cell contents by splitting on unescaped pipes.

    A pipe is considered escaped if and only if it is preceded by an odd number of backslashes.
    Leading and trailing boundary pipes are ignored per GFM table row syntax.
    """
    line = row_line.strip()
    cells: list[str] = []
    current_cell: list[str] = []
    consecutive_backslashes = 0

    for ch in line:
        if ch == "\\":
            consecutive_backslashes += 1
            current_cell.append(ch)
        elif ch == "|":
            if consecutive_backslashes % 2 == 1:
                # Odd number of backslashes: pipe is escaped
                current_cell.append(ch)
            else:
                # Even number of backslashes (including 0): pipe is cell boundary
                cells.append("".join(current_cell))
                current_cell = []
            consecutive_backslashes = 0
        else:
            consecutive_backslashes = 0
            current_cell.append(ch)

    cells.append("".join(current_cell))

    # Remove outer empty strings resulting from leading/trailing boundary pipes
    if cells and cells[0].strip() == "":
        cells.pop(0)
    if cells and cells[-1].strip() == "":
        cells.pop()

    return [c.strip() for c in cells]


class TestReportExporter(unittest.TestCase):
    """Test suite for ReportExporter formatting, security, and filesystem persistence."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = str(self.temp_path / "test_exporter.sqlite3")
        self.db = DatabaseManager(self.db_path)

        # Create sample session in database
        self.scope = ScopeEnclosure.from_strings(
            cidrs=["10.0.0.0/24"],
            interfaces=["eth0"],
            allow_loopback=True,
            allow_global_internet=False,
        )
        self.session_id = self.db.create_diagnostic_session(
            name="Core Infrastructure Health Check",
            operator="netadmin",
            scope_enclosure=self.scope,
            metadata={"datacenter": "DC-NORTH", "cluster": "prod-k8s"},
        )

        # Record snapshots
        self.snap_1 = self.db.record_session_snapshot(
            session_id=self.session_id,
            snapshot_type="INTERFACE_TELEMETRY",
            payload={
                "interface": "eth0",
                "mtu": 1500,
                "speed_mbps": 10000,
                "rx_errors": 0,
                "tx_errors": 0,
                "carrier": True,
                "flags": ["UP", "BROADCAST", "RUNNING"],
            },
            target="10.0.0.1",
            status="SUCCESS",
        )

        self.snap_2 = self.db.record_session_snapshot(
            session_id=self.session_id,
            snapshot_type="SERVICE_DISCOVERY",
            payload={
                "service": "api-gateway",
                "port": 443,
                "tls_version": "TLSv1.3",
                "latency_ms": 1.45,
                "endpoints": [
                    {"ip": "10.0.0.10", "healthy": True},
                    {"ip": "10.0.0.11", "healthy": True},
                ],
            },
            target="10.0.0.10",
            status="SUCCESS",
        )

        self.db.complete_diagnostic_session(
            session_id=self.session_id,
            status="SUCCESS",
            summary={"interfaces_evaluated": 1, "services_healthy": 2, "findings_count": 0},
        )

        # Fetch loaded session dict
        self.session_data = self.db.get_diagnostic_session(self.session_id)
        assert self.session_data is not None

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # Legacy Compatibility
    # -------------------------------------------------------------------------

    def test_legacy_to_json_compatibility(self) -> None:
        """Verify legacy ReportExporter.to_json() preserves behavior and formatting."""
        payload = {"status": "OK", "count": 42}
        result = ReportExporter.to_json(payload)
        parsed = json.loads(result)
        self.assertEqual(parsed, payload)
        self.assertEqual(result, json.dumps(payload, indent=2))

    def test_legacy_format_subnet_text_compatibility(self) -> None:
        """Verify legacy ReportExporter.format_subnet_text() preserves exact template format."""
        subnet_data = {
            "cidr": "192.168.1.0/24",
            "ip_version": 4,
            "network_address": "192.168.1.0",
            "netmask": "255.255.255.0",
            "wildcard_mask": "0.0.0.255",
            "broadcast_address": "192.168.1.255",
            "total_hosts": 256,
            "usable_hosts": 254,
            "first_usable_ip": "192.168.1.1",
            "last_usable_ip": "192.168.1.254",
        }
        text = ReportExporter.format_subnet_text(subnet_data)
        self.assertIn("Subnet Report: 192.168.1.0/24", text)
        self.assertIn("Total Host Space   : 256", text)
        self.assertIn("Usable Host Space  : 254", text)
        self.assertIn("192.168.1.1 -> 192.168.1.254", text)

    # -------------------------------------------------------------------------
    # JSON Export Tests
    # -------------------------------------------------------------------------

    def test_json_export_structure_and_completeness(self) -> None:
        """Verify JSON export contains canonical schema, export version, metadata, and snapshots."""
        custom_time = "2026-10-20T12:00:00Z"
        json_output = ReportExporter.to_json_report(self.session_data, exported_at=custom_time)
        doc = json.loads(json_output)

        self.assertEqual(doc["export_version"], "1.0.0")
        self.assertEqual(doc["exported_at"], custom_time)
        self.assertEqual(doc["snapshots_count"], 2)

        session_node = doc["session"]
        self.assertEqual(session_node["name"], "Core Infrastructure Health Check")
        self.assertEqual(session_node["operator"], "netadmin")
        self.assertEqual(session_node["status"], "SUCCESS")
        self.assertEqual(session_node["metadata"]["datacenter"], "DC-NORTH")

        snapshots_node = doc["snapshots"]
        self.assertEqual(len(snapshots_node), 2)
        self.assertEqual(snapshots_node[0]["snapshot_type"], "INTERFACE_TELEMETRY")
        self.assertEqual(snapshots_node[0]["payload"]["speed_mbps"], 10000)
        self.assertEqual(snapshots_node[1]["snapshot_type"], "SERVICE_DISCOVERY")
        self.assertEqual(snapshots_node[1]["payload"]["tls_version"], "TLSv1.3")

    def test_json_export_empty_session(self) -> None:
        """Verify JSON export handles a session with zero snapshots cleanly."""
        empty_id = self.db.create_diagnostic_session(name="Empty Test Session")
        empty_session = self.db.get_diagnostic_session(empty_id)
        assert empty_session is not None

        json_output = ReportExporter.to_json_report(empty_session)
        doc = json.loads(json_output)

        self.assertEqual(doc["export_version"], "1.0.0")
        self.assertEqual(doc["snapshots_count"], 0)
        self.assertEqual(doc["snapshots"], [])
        self.assertEqual(doc["session"]["name"], "Empty Test Session")

    # -------------------------------------------------------------------------
    # CSV Export Tests
    # -------------------------------------------------------------------------

    def test_csv_export_layout_and_quoting(self) -> None:
        """Verify CSV export produces valid RFC 4180 layout, headers, and correct quoting."""
        csv_output = ReportExporter.to_csv_report(self.session_data)
        reader = csv.reader(io.StringIO(csv_output))
        rows = list(reader)

        self.assertGreaterEqual(len(rows), 3)  # Header + 2 snapshot rows
        headers = rows[0]

        # Verify base columns are present in order
        for col in ReportExporter.CSV_BASE_COLUMNS:
            self.assertIn(col, headers)

        # Verify dynamic scalar keys are derived in sorted order
        # Scalar keys in payloads: interface, mtu, speed_mbps, rx_errors, tx_errors, carrier, service, port, tls_version, latency_ms
        self.assertIn("payload.interface", headers)
        self.assertIn("payload.mtu", headers)
        self.assertIn("payload.service", headers)
        self.assertIn("payload.port", headers)
        self.assertIn("payload.tls_version", headers)

        # Dynamic scalar headers must be sorted
        dynamic_cols = [h for h in headers if h.startswith("payload.")]
        self.assertEqual(dynamic_cols, sorted(dynamic_cols))

        # Check snapshot row contents
        snap1_row = rows[1]
        self.assertEqual(snap1_row[headers.index("session_name")], "Core Infrastructure Health Check")
        self.assertEqual(snap1_row[headers.index("snapshot_type")], "INTERFACE_TELEMETRY")
        self.assertEqual(snap1_row[headers.index("payload.interface")], "eth0")
        self.assertEqual(snap1_row[headers.index("payload.speed_mbps")], "10000")

    def test_csv_export_nested_payload_preservation(self) -> None:
        """Verify CSV preserves nested dicts/arrays losslessly in the payload_json column."""
        csv_output = ReportExporter.to_csv_report(self.session_data)
        reader = csv.reader(io.StringIO(csv_output))
        rows = list(reader)
        headers = rows[0]
        json_col_idx = headers.index("payload_json")

        # Snapshot 2 has nested endpoints list: [{"ip": "10.0.0.10", "healthy": True}, ...]
        snap2_row = rows[2]
        payload_raw = snap2_row[json_col_idx]
        self.assertTrue(payload_raw)
        rehydrated = json.loads(payload_raw)
        self.assertEqual(rehydrated["service"], "api-gateway")
        self.assertEqual(len(rehydrated["endpoints"]), 2)
        self.assertEqual(rehydrated["endpoints"][0]["ip"], "10.0.0.10")

    def test_csv_export_empty_session(self) -> None:
        """Verify empty session writes exactly 1 metadata row with blank snapshot fields."""
        empty_id = self.db.create_diagnostic_session(name="Standalone Empty Session")
        empty_session = self.db.get_diagnostic_session(empty_id)
        assert empty_session is not None

        csv_output = ReportExporter.to_csv_report(empty_session)
        reader = csv.reader(io.StringIO(csv_output))
        rows = list(reader)

        self.assertEqual(len(rows), 2)  # Header + exactly 1 data row
        headers = rows[0]
        data_row = rows[1]

        self.assertEqual(data_row[headers.index("session_name")], "Standalone Empty Session")
        self.assertEqual(data_row[headers.index("snapshot_id")], "")
        self.assertEqual(data_row[headers.index("snapshot_type")], "")
        self.assertEqual(data_row[headers.index("payload_json")], "")

    # -------------------------------------------------------------------------
    # Markdown Export Tests
    # -------------------------------------------------------------------------

    def test_markdown_export_structure_and_findings(self) -> None:
        """Verify Markdown export contains executive summary, scope, catalog, findings, and disclaimer."""
        md_output = ReportExporter.to_markdown_report(self.session_data)

        self.assertIn("# Diagnostic Assessment Report: Core Infrastructure Health Check", md_output)
        self.assertIn("**Session UUID:**", md_output)
        self.assertIn("## 1. Executive Summary", md_output)
        self.assertIn("Authorized Diagnostic Scope Enclosure", md_output)
        self.assertIn("10.0.0.0/24", md_output)
        self.assertIn("## 2. Diagnostic Snapshot Catalog", md_output)
        self.assertIn("| `INTERFACE_TELEMETRY` |", md_output)
        self.assertIn("| `SERVICE_DISCOVERY` |", md_output)
        self.assertIn("## 3. Detailed Snapshot Findings", md_output)
        self.assertIn("```json", md_output)
        self.assertIn("Automated Secret Redaction Notice", md_output)

    def test_markdown_export_empty_session(self) -> None:
        """Verify Markdown export provides a clear no-snapshots notice when session is empty."""
        empty_id = self.db.create_diagnostic_session(name="Zero Snapshot Assessment")
        empty_session = self.db.get_diagnostic_session(empty_id)
        assert empty_session is not None

        md_output = ReportExporter.to_markdown_report(empty_session)
        self.assertIn("# Diagnostic Assessment Report: Zero Snapshot Assessment", md_output)
        self.assertIn("*No diagnostic snapshots were recorded for this session.*", md_output)
        self.assertNotIn("## 3. Detailed Snapshot Findings", md_output)
        self.assertIn("Automated Secret Redaction Notice", md_output)

    # -------------------------------------------------------------------------
    # Unicode and Multiline Handling
    # -------------------------------------------------------------------------

    def test_unicode_and_multiline_content(self) -> None:
        """Verify Unicode (CJK, accents, emojis) and multiline strings across JSON, CSV, and Markdown."""
        unicode_session = {
            "id": 999,
            "session_uuid": "unicode-uuid-001",
            "name": "Audit 診察 🌐 Réseau-Centre",
            "operator": "operatör_⚡",
            "status": "COMPLETED",
            "started_at": "2026-10-20T10:00:00Z",
            "completed_at": "2026-10-20T10:05:00Z",
            "summary": {"notes": "Line 1\nLine 2 with | pipe character"},
            "snapshots": [
                {
                    "id": 1,
                    "session_id": 999,
                    "snapshot_type": "UNICODE_TEST",
                    "target": "192.168.1.1\nMultitarget",
                    "status": "SUCCESS",
                    "redacted_fields_count": 0,
                    "created_at": "2026-10-20T10:01:00Z",
                    "payload": {
                        "device_label": "スイッチ-Switch_01",
                        "comment": "Description with quotes \"test\" and | pipe and \nnewline",
                    },
                }
            ],
        }

        # JSON: Ensure Unicode characters are NOT escaped to \uXXXX
        json_out = ReportExporter.to_json_report(unicode_session)
        self.assertIn("Audit 診察 🌐 Réseau-Centre", json_out)
        self.assertIn("スイッチ-Switch_01", json_out)

        # CSV: Quoting handles internal newlines and quotes
        csv_out = ReportExporter.to_csv_report(unicode_session)
        reader = csv.reader(io.StringIO(csv_out))
        rows = list(reader)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][2], "Audit 診察 🌐 Réseau-Centre")

        # Markdown: Pipes escaped and newlines flattened in tables
        md_out = ReportExporter.to_markdown_report(unicode_session)
        self.assertIn("Audit 診察 🌐 Réseau-Centre", md_out)
        self.assertNotIn("Line 1\nLine 2", md_out)  # Newlines in table cells collapsed

    # -------------------------------------------------------------------------
    # Secret Redaction Defense-in-Depth
    # -------------------------------------------------------------------------

    def test_credential_redaction_defense_in_depth(self) -> None:
        """Verify exporter scrubs unredacted secrets before writing JSON, CSV, or Markdown."""
        leaky_session = {
            "id": 777,
            "session_uuid": "leaky-001",
            "name": "Leaky Memory Session",
            "operator": "admin",
            "status": "OPEN",
            "started_at": "2026-10-20T10:00:00Z",
            "metadata": {"api_key": "super_secret_token_123"},
            "snapshots": [
                {
                    "id": 1,
                    "snapshot_type": "ROUTER_AUTH",
                    "target": "10.0.0.1",
                    "status": "SUCCESS",
                    "payload": {
                        "device": "cisco-core",
                        "enable_password": "PlaintextSecret999!",
                        "radius_secret": "radius_p@ss",
                        "auth_header": "Authorization: Bearer bearer_secret_token_xyz",
                    },
                }
            ],
        }

        # JSON Check
        json_out = ReportExporter.to_json_report(leaky_session)
        self.assertNotIn("super_secret_token_123", json_out)
        self.assertNotIn("PlaintextSecret999!", json_out)
        self.assertNotIn("radius_p@ss", json_out)
        self.assertNotIn("bearer_secret_token_xyz", json_out)
        self.assertIn("***REDACTED***", json_out)

        # CSV Check
        csv_out = ReportExporter.to_csv_report(leaky_session)
        self.assertNotIn("PlaintextSecret999!", csv_out)
        self.assertNotIn("radius_p@ss", csv_out)
        self.assertIn("***REDACTED***", csv_out)

        # Markdown Check
        md_out = ReportExporter.to_markdown_report(leaky_session)
        self.assertNotIn("PlaintextSecret999!", md_out)
        self.assertNotIn("radius_p@ss", md_out)
        self.assertIn("***REDACTED***", md_out)

    # -------------------------------------------------------------------------
    # Unsupported Formats and Path Traversal
    # -------------------------------------------------------------------------

    def test_unsupported_format_raises_exception(self) -> None:
        """Verify requesting unsupported formats raises UnsupportedFormatError."""
        for invalid_fmt in ["xml", "pdf", "yaml", "html", "", "   "]:
            with self.assertRaises(UnsupportedFormatError):
                ReportExporter.export_session(self.session_data, format=invalid_fmt)

    def test_path_validation_and_traversal_rejection(self) -> None:
        """Verify invalid paths, null bytes, and path traversal sequences are rejected."""
        invalid_paths = [
            None,
            "",
            "   ",
            "../etc/passwd",
            "reports/../../secret.txt",
            "/tmp/test\0file.json",
        ]
        for p in invalid_paths:
            with self.assertRaises(ExportPathError):
                ReportExporter.write_report_file("content", destination=p)  # type: ignore[arg-type]

    def test_directory_creation_controls(self) -> None:
        """Verify non-existent directory is rejected when create_dirs=False, created when True."""
        sub_dir = self.temp_path / "deep" / "nested" / "reports"
        target_file = sub_dir / "report.json"

        # Fails closed when create_dirs=False
        with self.assertRaises(ExportPathError) as ctx:
            ReportExporter.write_report_file("test", target_file, create_dirs=False)
        self.assertIn("does not exist", str(ctx.exception))

        # Succeeds when create_dirs=True
        written = ReportExporter.write_report_file("test", target_file, create_dirs=True)
        self.assertTrue(written.exists())
        self.assertEqual(written.read_text(encoding="utf-8"), "test")

    # -------------------------------------------------------------------------
    # Overwrite Refusal and Atomic Replacement
    # -------------------------------------------------------------------------

    def test_overwrite_refusal_race_safe(self) -> None:
        """Verify overwrite=False refuses to overwrite existing file and preserves original content."""
        target_file = self.temp_path / "protected_report.json"
        target_file.write_text("INITIAL_CONTENT", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            ReportExporter.write_report_file(
                content="ATTEMPTED_OVERWRITE",
                destination=target_file,
                overwrite=False,
            )

        # Content must remain intact
        self.assertEqual(target_file.read_text(encoding="utf-8"), "INITIAL_CONTENT")

    def test_atomic_replacement_when_overwrite_true(self) -> None:
        """Verify overwrite=True atomically replaces destination and sets 0o600 permissions."""
        target_file = self.temp_path / "atomic_report.json"
        target_file.write_text("OLD_VERSION", encoding="utf-8")

        new_content = json.dumps({"version": 2})
        written = ReportExporter.write_report_file(
            content=new_content,
            destination=target_file,
            overwrite=True,
        )

        self.assertEqual(written, target_file.resolve())
        self.assertEqual(target_file.read_text(encoding="utf-8"), new_content)

        # Check permissions: 0o600 (owner read/write only)
        file_mode = stat.S_IMODE(os.stat(target_file).st_mode)
        self.assertEqual(file_mode, 0o600)

    def test_atomic_write_failure_cleanup(self) -> None:
        """Verify temporary files are cleaned up if an error occurs during overwrite."""
        target_file = self.temp_path / "fail_cleanup.json"

        with patch("os.replace", side_effect=OSError("Simulated rename error")):
            with self.assertRaises(ExportPathError):
                ReportExporter.write_report_file(
                    content="FAIL_DATA",
                    destination=target_file,
                    overwrite=True,
                )

        # Confirm no temporary files left in directory
        temp_files = list(self.temp_path.glob(".export_tmp_*"))
        self.assertEqual(temp_files, [])

    # -------------------------------------------------------------------------
    # Database Immutability & Application Delegation
    # -------------------------------------------------------------------------

    def test_database_immutability_during_export(self) -> None:
        """Verify exporting a session does NOT modify session or snapshot database records."""
        # Record initial row counts and hashes
        with self.db._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, status, started_at, completed_at FROM diagnostic_sessions WHERE id = ?", (self.session_id,))
            session_before = cur.fetchone()
            cur.execute("SELECT COUNT(*) FROM diagnostic_snapshots WHERE session_id = ?", (self.session_id,))
            snap_count_before = cur.fetchone()[0]

        # Perform all three export types
        app_config = AppConfig(database_file=self.db_path)
        app = Application(app_config)

        app.export_diagnostic_session(self.session_id, format="json")
        app.export_diagnostic_session(self.session_id, format="csv")
        app.export_diagnostic_session(self.session_id, format="markdown")

        # Verify database records are identical
        with self.db._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, status, started_at, completed_at FROM diagnostic_sessions WHERE id = ?", (self.session_id,))
            session_after = cur.fetchone()
            cur.execute("SELECT COUNT(*) FROM diagnostic_snapshots WHERE session_id = ?", (self.session_id,))
            snap_count_after = cur.fetchone()[0]

        self.assertEqual(session_before, session_after)
        self.assertEqual(snap_count_before, snap_count_after)

    def test_app_export_nonexistent_session_raises_error(self) -> None:
        """Verify exporting nonexistent session ID raises SessionNotFoundError."""
        app_config = AppConfig(database_file=self.db_path)
        app = Application(app_config)

        with self.assertRaises(SessionNotFoundError):
            app.export_diagnostic_session(session_id=999999, format="json")

    def test_app_export_file_persistence(self) -> None:
        """Verify Application.export_diagnostic_session persists file when path provided."""
        app_config = AppConfig(database_file=self.db_path)
        app = Application(app_config)

        dest = self.temp_path / "app_exported.md"
        content, path = app.export_diagnostic_session(
            session_id=self.session_id,
            format="md",
            output_path=dest,
        )

        self.assertIsNotNone(path)
        assert path is not None
        self.assertTrue(path.exists())
        self.assertEqual(path.read_text(encoding="utf-8"), content)
        self.assertIn("# Diagnostic Assessment Report:", content)

    def test_destination_parent_is_not_a_directory(self) -> None:
        """Verify ExportPathError is raised when destination's parent is an existing regular file."""
        fake_parent = self.temp_path / "not_a_dir.txt"
        fake_parent.write_text("I am a file", encoding="utf-8")
        target_file = fake_parent / "report.json"

        with self.assertRaises(ExportPathError) as ctx:
            ReportExporter.write_report_file("content", target_file)
        self.assertIn("not a directory", str(ctx.exception))

    def test_overwrite_false_write_failure_cleans_up_file(self) -> None:
        """Verify if publication fails when overwrite=False, partial file is deleted and temp cleaned."""
        target_file = self.temp_path / "midflight_fail.json"

        # Patch os.link to simulate I/O or link failure
        with patch("os.link", side_effect=OSError("Disk full or link failed")):
            with self.assertRaises(ExportPathError):
                ReportExporter.write_report_file("data", target_file, overwrite=False)

        self.assertFalse(target_file.exists())
        self.assertEqual(list(self.temp_path.glob(".export_tmp_*")), [])

    def test_markdown_with_string_summary_and_no_scope(self) -> None:
        """Verify Markdown generation works when summary is a raw string and scope is None."""
        raw_session = {
            "id": 101,
            "session_uuid": "str-sum-101",
            "name": "String Summary Session",
            "operator": "analyst",
            "status": "COMPLETED",
            "started_at": "2026-10-20T10:00:00Z",
            "completed_at": "2026-10-20T10:02:00Z",
            "scope_enclosure": None,
            "summary": "Overall system status is nominal with minor packet drop on eth1.",
            "snapshots": [
                {
                    "id": 1,
                    "snapshot_type": "NULL_PAYLOAD_TEST",
                    "target": "10.0.0.2",
                    "status": "INFO",
                    "redacted_fields_count": 0,
                    "created_at": "2026-10-20T10:01:00Z",
                    "payload": None,
                }
            ],
        }

        md = ReportExporter.to_markdown_report(raw_session)
        self.assertIn("Overall system status is nominal with minor packet drop on eth1.", md)
        self.assertNotIn("Authorized Diagnostic Scope Enclosure", md)
        self.assertIn("null", md)

        # Also test CSV with None payload
        csv_out = ReportExporter.to_csv_report(raw_session)
        self.assertIn("NULL_PAYLOAD_TEST", csv_out)

        # Also test JSON with None payload
        json_out = ReportExporter.to_json_report(raw_session)
        parsed = json.loads(json_out)
        self.assertIsNone(parsed["snapshots"][0]["payload"])

    def test_export_session_dispatch_all_formats(self) -> None:
        """Verify export_session dispatcher handles json, csv, and md to files."""
        formats_and_exts = [
            ("json", ".json", "export_version"),
            ("csv", ".csv", "session_id"),
            ("markdown", ".md", "# Diagnostic Assessment Report"),
            ("md", ".markdown", "# Diagnostic Assessment Report"),
        ]

        for fmt, ext, needle in formats_and_exts:
            out_file = self.temp_path / f"export_{fmt}{ext}"
            content, path = ReportExporter.export_session(
                session=self.session_data,
                format=fmt,
                output_path=out_file,
            )
            self.assertIsNotNone(path)
            assert path is not None
            self.assertTrue(path.exists())
            self.assertIn(needle, content)
            self.assertEqual(path.read_text(encoding="utf-8"), content)

    # -------------------------------------------------------------------------
    # Targeted Security Regression Tests (TASK-013 Remediation)
    # -------------------------------------------------------------------------

    def test_split_markdown_table_row_parser_invariants(self) -> None:
        """Verify the test table parser correctly handles 0, 1, 2, 3, and 4 backslashes before pipe."""
        # 0 backslashes: unescaped pipe -> acts as cell delimiter (2 cells)
        self.assertEqual(split_markdown_table_row("| alpha | beta |"), ["alpha", "beta"])
        # 1 backslash (odd): escaped pipe -> content within single cell (2 cells)
        self.assertEqual(split_markdown_table_row(r"| alpha | beta \| gamma |"), ["alpha", r"beta \| gamma"])
        # 2 backslashes (even): first backslash escapes second, pipe is unescaped -> breakout (3 cells)
        self.assertEqual(split_markdown_table_row(r"| alpha | beta \\| gamma |"), ["alpha", r"beta \\", "gamma"])
        # 3 backslashes (odd): two form escaped backslash, third escapes pipe -> escaped (2 cells)
        self.assertEqual(split_markdown_table_row(r"| alpha | beta \\\| gamma |"), ["alpha", r"beta \\\| gamma"])
        # 4 backslashes (even): two escaped backslashes, pipe is unescaped -> breakout (3 cells)
        self.assertEqual(split_markdown_table_row(r"| alpha | beta \\\\| gamma |"), ["alpha", r"beta \\\\", "gamma"])

    def test_session_status_with_pipes_and_newlines(self) -> None:
        """Security: Session status containing pipes and newlines cannot break table layout."""
        malicious_session = {
            "name": "Audit Session",
            "status": "OPEN | INJECTED_COLUMN | MALICIOUS\nROW_BREAK",
            "operator": "auditor | ADMIN",
            "snapshots": [],
        }
        md = ReportExporter.to_markdown_report(malicious_session)
        # Check executive summary table rows
        found_status = False
        found_operator = False
        for line in md.splitlines():
            if line.startswith("| **Session Lifecycle Status** |"):
                found_status = True
                cells = split_markdown_table_row(line)
                self.assertEqual(len(cells), 2, f"Table row corrupted by unescaped pipes: {line}")
                self.assertEqual(cells[0], "**Session Lifecycle Status**")
                self.assertNotIn("\n", line)
                self.assertIn("OPEN", cells[1])
                self.assertIn("INJECTED_COLUMN", cells[1])
            elif line.startswith("| **Operator Attribution** |"):
                found_operator = True
                cells = split_markdown_table_row(line)
                self.assertEqual(len(cells), 2, f"Operator row corrupted by unescaped pipes: {line}")
                self.assertEqual(cells[0], "**Operator Attribution**")
                self.assertIn("auditor", cells[1])
                self.assertIn("ADMIN", cells[1])

        self.assertTrue(found_status, "Session Lifecycle Status row not found in markdown")
        self.assertTrue(found_operator, "Operator Attribution row not found in markdown")

        # Verify Document Metadata blockquote does not contain spurious escaped backslashes before pipes
        found_doc_status = False
        found_doc_op = False
        for line in md.splitlines():
            if line.startswith("> - **Status:**"):
                found_doc_status = True
                self.assertNotIn(r"\|", line)
                self.assertIn("OPEN | INJECTED_COLUMN", line)
            elif line.startswith("> - **Operator:**"):
                found_doc_op = True
                self.assertNotIn(r"\|", line)
                self.assertIn("auditor | ADMIN", line)
        self.assertTrue(found_doc_status)
        self.assertTrue(found_doc_op)

    def test_scope_cidrs_with_pipes_backticks_newlines(self) -> None:
        """Security: Scope CIDR entries containing pipes, backticks, and newlines cannot inject columns."""
        scoped_session = {
            "name": "Scope Audit",
            "scope_enclosure": {
                "cidrs": [
                    "10.0.0.0/24 | EXTRA_COL",
                    "192.168.1.0/24`backtick`",
                    "172.16.0.0/16\nNEWLINE",
                ],
                "interfaces": ["eth0"],
            },
            "snapshots": [],
        }
        md = ReportExporter.to_markdown_report(scoped_session)
        # Verify the table row in Authorized Diagnostic Scope Enclosure
        found_scope = False
        for line in md.splitlines():
            if line.startswith("| **Authorized CIDR Networks** |"):
                found_scope = True
                cells = split_markdown_table_row(line)
                self.assertEqual(len(cells), 2, f"Scope table row corrupted: {line}")
                self.assertEqual(cells[0], "**Authorized CIDR Networks**")
                self.assertNotIn("\n", line)
                self.assertIn("10.0.0.0/24", cells[1])
                self.assertIn("EXTRA_COL", cells[1])
        self.assertTrue(found_scope)

    def test_interface_names_with_metacharacters_and_newlines(self) -> None:
        """Security: Interface names containing Markdown metacharacters and line breaks are sanitized."""
        scoped_session = {
            "name": "Interface Audit",
            "scope_enclosure": {
                "cidrs": ["10.0.0.0/24"],
                "interfaces": [
                    "eth0 | INJECT",
                    "wlan0`backtick`",
                    "br0\nLINEBREAK",
                ],
            },
            "snapshots": [],
        }
        md = ReportExporter.to_markdown_report(scoped_session)
        found_ifaces = False
        for line in md.splitlines():
            if line.startswith("| **Bound Network Interfaces** |"):
                found_ifaces = True
                cells = split_markdown_table_row(line)
                self.assertEqual(len(cells), 2, f"Interfaces row corrupted: {line}")
                self.assertEqual(cells[0], "**Bound Network Interfaces**")
                self.assertIn("eth0", cells[1])
                self.assertIn("INJECT", cells[1])
        self.assertTrue(found_ifaces)

    def test_snapshot_type_and_status_heading_injection(self) -> None:
        """Security: Snapshot type and status with newlines and heading syntax cannot create new headings."""
        spoofed_session = {
            "name": "Heading Injection Test",
            "snapshots": [
                {
                    "id": 1,
                    "snapshot_type": "DISCOVERY\n\n# SPOOFED TOP HEADING\n### SUB",
                    "status": "STATUS\n## MALICIOUS SUBHEADING",
                    "target": "10.0.0.1",
                    "payload": {"result": "ok"},
                }
            ],
        }
        md = ReportExporter.to_markdown_report(spoofed_session)
        # Verify no line starts with '# SPOOFED TOP HEADING' or '## MALICIOUS SUBHEADING'
        for line in md.splitlines():
            self.assertFalse(
                line.startswith("# SPOOFED"),
                f"Unescaped top-level heading injected: {line}",
            )
            self.assertFalse(
                line.startswith("## MALICIOUS"),
                f"Unescaped subheading injected: {line}",
            )
        # Heading line must retain sanitized components on a single line
        self.assertIn("### Snapshot #1: DISCOVERY # SPOOFED TOP HEADING ### SUB [STATUS ## MALICIOUS SUBHEADING]", md)

    def test_snapshot_target_with_links_html_pipes_backticks(self) -> None:
        """Security: Snapshot targets with Markdown links, HTML, pipes, and backticks cannot execute injection."""
        malicious_session = {
            "name": "Target Injection Test",
            "snapshots": [
                {
                    "id": 1,
                    "snapshot_type": "PORT_SCAN",
                    "status": "SUCCESS",
                    "target": "[Click To Login](https://attacker.site) | <script>alert(1)</script> `target_code`",
                    "payload": {},
                }
            ],
        }
        md = ReportExporter.to_markdown_report(malicious_session)
        # Catalog table check
        found_target_row = False
        for line in md.splitlines():
            if line.startswith("| 1 |"):
                found_target_row = True
                cells = split_markdown_table_row(line)
                # Columns: '1', 'PORT_SCAN', 'target', 'status', 'redactions', 'time' (6 cells)
                self.assertEqual(len(cells), 6, f"Catalog table row corrupted by pipes: {line}")
                # Target must be rendered within inline code, preventing live link / HTML execution
                self.assertIn("Click To Login", cells[2])
                self.assertTrue(cells[2].startswith("`") and cells[2].endswith("`"))
        self.assertTrue(found_target_row)

    def test_summary_findings_markdown_link_and_html_injection(self) -> None:
        """Security: Untrusted summary values cannot render active Markdown links or raw HTML."""
        malicious_session = {
            "name": "Summary Injection Test",
            "summary": {
                "Alert": "[Security Portal](https://example.invalid)",
                "Script": "<script>alert(1)</script>",
                "Combined": "[Admin Console](https://attacker.com/login) | `sub_code` | <img src=x>",
                "SafeCount": 42,
                "SafeUnicode": "スイッチ-Switch_01 正常",
            },
            "snapshots": [],
        }
        md = ReportExporter.to_markdown_report(malicious_session)

        # Executive Findings table checks
        found_alert = False
        found_script = False
        found_combined = False
        found_safe = False

        for line in md.splitlines():
            if line.startswith("| **Alert** |"):
                found_alert = True
                cells = split_markdown_table_row(line)
                self.assertEqual(len(cells), 2)
                # The link is inside inline code, preventing it from rendering as an active link
                self.assertIn("`[Security Portal](https://example.invalid)`", cells[1])
            elif line.startswith("| **Script** |"):
                found_script = True
                cells = split_markdown_table_row(line)
                self.assertEqual(len(cells), 2)
                self.assertIn("`<script>alert(1)</script>`", cells[1])
            elif line.startswith("| **Combined** |"):
                found_combined = True
                cells = split_markdown_table_row(line)
                self.assertEqual(len(cells), 2, f"Combined summary corrupted table columns: {line}")
            elif line.startswith("| **SafeUnicode** |"):
                found_safe = True
                cells = split_markdown_table_row(line)
                self.assertEqual(len(cells), 2)
                self.assertIn("スイッチ-Switch_01 正常", cells[1])

        self.assertTrue(found_alert)
        self.assertTrue(found_script)
        self.assertTrue(found_combined)
        self.assertTrue(found_safe)

        # Also test raw string summary
        raw_summary_session = {
            "name": "Raw String Summary Injection",
            "summary": "Check [Malicious Link](https://attacker.site) and <script>alert(1)</script> | pipe",
            "snapshots": [],
        }
        raw_md = ReportExporter.to_markdown_report(raw_summary_session)
        # Brackets and angle brackets escaped
        self.assertNotIn("<script>", raw_md)
        self.assertIn("&lt;script&gt;", raw_md)
        self.assertIn(r"\[Malicious Link\]", raw_md)

    def test_json_payload_with_backtick_sequences_fencing(self) -> None:
        """Security: JSON payload containing triple or quadruple backticks dynamically expands fence delimiter."""
        tricky_payload = {
            "code_sample": "```\n# INJECTED HEADING\n```",
            "extra_backticks": "````\n`````\n",
        }
        session = {
            "name": "Backtick Fencing Test",
            "snapshots": [
                {
                    "id": 1,
                    "snapshot_type": "CODE_INSPECTION",
                    "status": "INFO",
                    "target": "10.0.0.1",
                    "payload": tricky_payload,
                }
            ],
        }
        md = ReportExporter.to_markdown_report(session)
        # Content has a run of 5 backticks, so the outer code fence must use at least 6 backticks
        self.assertIn("``````json\n", md)
        self.assertIn("\n``````", md)
        # Verify no line inside the code block prematurely terminates the block
        lines = md.splitlines()
        fence_indices = [idx for idx, line in enumerate(lines) if line.startswith("``````")]
        self.assertEqual(len(fence_indices), 2, "Code block was prematurely closed by internal payload backticks")

    def test_unicode_and_device_identifiers_readability(self) -> None:
        """Quality: Valid international Unicode and ordinary device names remain clean and legible."""
        device_session = {
            "name": "Audit Tokyo-東京 Core-スイッチ",
            "operator": "técnico_01",
            "status": "COMPLETED",
            "snapshots": [
                {
                    "id": 1,
                    "snapshot_type": "DEVICE_INFO",
                    "status": "OK",
                    "target": "Cisco-Catalyst-9300-48P-東京",
                    "payload": {"device": "MikroTik CCR2004-1G-12S+2XS", "mode": "BGP-ピア"},
                }
            ],
        }
        md = ReportExporter.to_markdown_report(device_session)
        self.assertIn("Audit Tokyo-東京 Core-スイッチ", md)
        self.assertIn("técnico_01", md)
        self.assertIn("Cisco-Catalyst-9300-48P-東京", md)
        self.assertIn("MikroTik CCR2004-1G-12S+2XS", md)

    def test_redaction_before_serialization_all_formats(self) -> None:
        """Security: Secret credentials in session and payload are redacted across JSON, CSV, and Markdown."""
        secret_session = {
            "name": "Secret Audit",
            "metadata": {"token": "Bearer secret_api_token_12345"},
            "snapshots": [
                {
                    "id": 1,
                    "snapshot_type": "AUTH_AUDIT",
                    "target": "10.0.0.1",
                    "status": "SUCCESS",
                    "payload": {"admin_password": "SuperSecretPass!", "safe_field": 100},
                }
            ],
        }
        json_out = ReportExporter.to_json_report(secret_session)
        self.assertNotIn("secret_api_token_12345", json_out)
        self.assertNotIn("SuperSecretPass!", json_out)
        self.assertIn("***REDACTED***", json_out)

        csv_out = ReportExporter.to_csv_report(secret_session)
        self.assertNotIn("SuperSecretPass!", csv_out)
        self.assertIn("***REDACTED***", csv_out)

        md_out = ReportExporter.to_markdown_report(secret_session)
        self.assertNotIn("SuperSecretPass!", md_out)
        self.assertIn("***REDACTED***", md_out)

    def test_overwrite_false_preserves_destination_byte_for_byte(self) -> None:
        """Security: overwrite=False preserves existing destination file byte-for-byte on conflict."""
        dest_file = self.temp_path / "byte_preserve.json"
        original_bytes = b"ORIGINAL_BYTES_IMMUTABLE_1234567890"
        dest_file.write_bytes(original_bytes)

        with self.assertRaises(FileExistsError):
            ReportExporter.write_report_file(
                content="ATTEMPTED_NEW_CONTENT",
                destination=dest_file,
                overwrite=False,
            )

        self.assertEqual(dest_file.read_bytes(), original_bytes)

    def test_overwrite_false_does_not_expose_partially_written_content(self) -> None:
        """Security: overwrite=False creates destination via atomic link only after temp is completely written."""
        dest_file = self.temp_path / "atomic_publication_check.json"
        target_existed_before_link = []
        real_link = os.link

        def spy_link(src, dst):
            # Check whether dst exists at the instant link is about to be called
            target_existed_before_link.append(Path(dst).exists())
            return real_link(src, dst)

        with patch("os.link", side_effect=spy_link):
            written = ReportExporter.write_report_file(
                content="FULL_AND_COMPLETE_REPORT_DATA",
                destination=dest_file,
                overwrite=False,
            )

        self.assertEqual(written, dest_file.resolve())
        # Destination did NOT exist on filesystem while data was being written!
        self.assertEqual(target_existed_before_link, [False])
        self.assertEqual(dest_file.read_text(encoding="utf-8"), "FULL_AND_COMPLETE_REPORT_DATA")

    def test_concurrent_publish_race_safety(self) -> None:
        """Security: Concurrent writers attempting to publish to same previously absent destination cannot overwrite."""
        dest_file = self.temp_path / "concurrent_test.json"
        barrier = threading.Barrier(2)
        real_os_link = os.link

        def synchronized_link(src: Union[str, bytes, os.PathLike[Any]], dst: Union[str, bytes, os.PathLike[Any]], **kwargs: Any) -> None:
            # Synchronize both threads right before the kernel link call
            # so both threads have already passed the initial exists() check
            # and prepared their temporary files in the destination directory.
            if Path(dst) == dest_file.resolve():
                try:
                    barrier.wait(timeout=5.0)
                except threading.BrokenBarrierError:
                    pass
            real_os_link(src, dst, **kwargs)

        results: list[tuple[str, Path]] = []
        errors: list[tuple[str, Exception]] = []

        def worker(payload: str) -> None:
            try:
                written = ReportExporter.write_report_file(
                    content=payload,
                    destination=dest_file,
                    overwrite=False,
                )
                results.append((payload, written))
            except Exception as exc:
                errors.append((payload, exc))

        with patch("os.link", side_effect=synchronized_link):
            t1 = threading.Thread(target=worker, args=("WRITER_ALPHA_PAYLOAD",))
            t2 = threading.Thread(target=worker, args=("WRITER_BETA_PAYLOAD",))
            t1.start()
            t2.start()
            t1.join(timeout=5.0)
            t2.join(timeout=5.0)

        # Invariant 1: Exactly one writer successfully publishes
        self.assertEqual(len(results), 1, f"Expected exactly 1 successful writer, got {len(results)}")
        winning_payload, written_path = results[0]
        self.assertEqual(written_path, dest_file.resolve())

        # Invariant 2: Exactly one writer fails with FileExistsError
        self.assertEqual(len(errors), 1, f"Expected exactly 1 error, got {len(errors)}")
        losing_payload, error = errors[0]
        self.assertIsInstance(error, FileExistsError)

        # Invariant 3: Destination content strictly matches winning payload byte-for-byte
        final_content = dest_file.read_text(encoding="utf-8")
        self.assertEqual(final_content, winning_payload)
        self.assertIn(winning_payload, ["WRITER_ALPHA_PAYLOAD", "WRITER_BETA_PAYLOAD"])

        # Invariant 4: No temporary files left behind in destination directory
        temp_files = list(self.temp_path.glob(".export_tmp_*"))
        self.assertEqual(temp_files, [])

        # Invariant 5: Subsequent sequential write also fails cleanly
        with self.assertRaises(FileExistsError):
            ReportExporter.write_report_file(
                content="LATE_WRITER_PAYLOAD",
                destination=dest_file,
                overwrite=False,
            )
        self.assertEqual(dest_file.read_text(encoding="utf-8"), winning_payload)

    def test_temp_file_cleanup_on_write_and_link_failures(self) -> None:
        """Safety: Temporary files in destination directory are cleaned up on all failure paths."""
        dest_file = self.temp_path / "cleanup_on_fail.json"

        # 1. Failure during link
        with patch("os.link", side_effect=OSError("Simulated link failure")):
            with self.assertRaises(ExportPathError):
                ReportExporter.write_report_file("CONTENT", dest_file, overwrite=False)

        self.assertFalse(dest_file.exists())
        self.assertEqual(list(self.temp_path.glob(".export_tmp_*")), [])

        # 2. Failure during write
        with patch("os.fsync", side_effect=OSError("Disk sync failed")):
            with self.assertRaises(ExportPathError):
                ReportExporter.write_report_file("CONTENT", dest_file, overwrite=False)

        self.assertFalse(dest_file.exists())
        self.assertEqual(list(self.temp_path.glob(".export_tmp_*")), [])

    def test_output_permissions_0600(self) -> None:
        """Security: Output file permissions are 0o600 for both overwrite=False and overwrite=True."""
        file_non_overwrite = self.temp_path / "perm_no_overwrite.json"
        ReportExporter.write_report_file("DATA", file_non_overwrite, overwrite=False)
        mode_1 = stat.S_IMODE(os.stat(file_non_overwrite).st_mode)
        self.assertEqual(mode_1, 0o600)

        file_overwrite = self.temp_path / "perm_overwrite.json"
        file_overwrite.write_text("OLD", encoding="utf-8")
        ReportExporter.write_report_file("NEW", file_overwrite, overwrite=True)
        mode_2 = stat.S_IMODE(os.stat(file_overwrite).st_mode)
        self.assertEqual(mode_2, 0o600)

    def test_overwrite_true_atomic_replacement(self) -> None:
        """Safety: overwrite=True replaces an existing file atomically and preserves established behavior."""
        dest_file = self.temp_path / "atomic_replace.json"
        dest_file.write_text("INITIAL_VERSION", encoding="utf-8")

        new_data = "UPDATED_VERSION_CONTENT"
        written = ReportExporter.write_report_file(new_data, dest_file, overwrite=True)

        self.assertEqual(written, dest_file.resolve())
        self.assertEqual(dest_file.read_text(encoding="utf-8"), new_data)
        self.assertEqual(stat.S_IMODE(os.stat(dest_file).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()


