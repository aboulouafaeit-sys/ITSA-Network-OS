"""Local SQLite storage engine for diagnostic persistence and versioned migrations."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from itsa_network_os.storage.redaction import CredentialRedactor, RedactionError
from itsa_network_os.storage.migrations import (
    ALL_MIGRATIONS,
    MIGRATION_001_BASELINE_SQL,
    DatabaseCorruptionError,
    IncompatibleSchemaError,
    Migration,
    MigrationChecksumError,
    MigrationError,
    MigrationRunner,
    SchemaVersionError,
)


class DatabaseManager:
    """Manages local SQLite database operations and versioned schema migrations safely."""

    # Preserved for backward compatibility with existing tests and callers
    SCHEMA = MIGRATION_001_BASELINE_SQL

    def __init__(
        self,
        db_path: str = ":memory:",
        migration_runner: Optional[MigrationRunner] = None,
        auto_migrate: bool = True,
    ) -> None:
        self.db_path = db_path
        self._mem_conn: Optional[sqlite3.Connection] = None
        self.migration_runner = migration_runner or MigrationRunner()

        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:")
            self._configure_connection(self._mem_conn)

        if auto_migrate:
            self._init_db()

    def _configure_connection(self, conn: sqlite3.Connection) -> None:
        """Apply required performance and integrity pragmas to the SQLite connection."""
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")

    def close(self) -> None:
        """Close active in-memory connection if allocated."""
        if self._mem_conn is not None:
            self._mem_conn.close()
            self._mem_conn = None

    def _get_connection(self) -> sqlite3.Connection:
        """Acquire an active SQLite connection."""
        if self._mem_conn is not None:
            return self._mem_conn
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        self._configure_connection(conn)
        return conn

    def _init_db(self) -> None:
        """Apply all pending migrations to bring database schema to the latest version."""
        conn = self._get_connection()
        try:
            self.migration_runner.apply(conn)
        finally:
            if self._mem_conn is None:
                conn.close()

    def get_schema_version(self) -> int:
        """Return the current schema migration version of the database."""
        conn = self._get_connection()
        try:
            return self.migration_runner.get_schema_version(conn)
        finally:
            if self._mem_conn is None:
                conn.close()

    def get_applied_migrations(self) -> List[Dict[str, Any]]:
        """Return details of all applied migrations in chronological order."""
        conn = self._get_connection()
        try:
            return self.migration_runner.get_applied_migrations(conn)
        finally:
            if self._mem_conn is None:
                conn.close()

    def apply_migrations(self, target_version: Optional[int] = None) -> List[int]:
        """Manually trigger forward migrations up to target_version."""
        conn = self._get_connection()
        try:
            return self.migration_runner.apply(conn, target_version=target_version)
        finally:
            if self._mem_conn is None:
                conn.close()

    # -------------------------------------------------------------------------
    # Legacy Diagnostic and Subnet Records (Preserved for compatibility)
    # -------------------------------------------------------------------------

    def record_subnet_query(self, cidr: str, usable_hosts: int, net_addr: str, bcast_addr: str) -> int:
        """Store subnet calculation event in local database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO subnet_history (cidr, usable_hosts, network_address, broadcast_address)
                VALUES (?, ?, ?, ?)
                """,
                (cidr, usable_hosts, net_addr, bcast_addr),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def record_dns_query(self, host: str, status: str, response_time_ms: float, records_json: str) -> int:
        """Store DNS diagnostic query event in local database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO dns_history (host, status, response_time_ms, records_json)
                VALUES (?, ?, ?, ?)
                """,
                (host, status, response_time_ms, records_json),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def record_latency_benchmark(
        self, host: str, port: int, packet_loss: float, avg_latency_ms: float, jitter_ms: float
    ) -> int:
        """Store latency benchmark event in local database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO latency_history (host, port, packet_loss, avg_latency_ms, jitter_ms)
                VALUES (?, ?, ?, ?, ?)
                """,
                (host, port, packet_loss, avg_latency_ms, jitter_ms),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def get_recent_subnets(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve recent subnet calculation history."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, cidr, usable_hosts, network_address, broadcast_address, calculated_at
                FROM subnet_history
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    # -------------------------------------------------------------------------
    # Target Domain Persistence: Discovered Device Inventory (Migration 002)
    # -------------------------------------------------------------------------

    def record_discovered_device(
        self,
        device_id: str,
        name: str,
        category: str,
        vendor: str,
        model: str,
        ip_address: str,
        mac_address: str,
        firmware_version: str,
        discovery_protocol: str,
        security_status: str,
        security_notes: Optional[List[str]] = None,
        telemetry: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Store discovered multi-vendor device profile in local inventory."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO discovered_devices (
                    device_id, name, category, vendor, model, ip_address,
                    mac_address, firmware_version, discovery_protocol,
                    security_status, security_notes_json, telemetry_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    name,
                    category,
                    vendor,
                    model,
                    ip_address,
                    mac_address,
                    firmware_version,
                    discovery_protocol,
                    security_status,
                    json.dumps(security_notes) if security_notes is not None else None,
                    json.dumps(telemetry) if telemetry is not None else None,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def record_device_evidence(
        self,
        device_row_id: int,
        source_protocol: str,
        timestamp: str,
        confidence: float,
        is_verified_fact: bool,
        attribute: Optional[str] = None,
        details: Optional[str] = None,
    ) -> int:
        """Store evidence record linked to a discovered device row."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO device_evidence_records (
                    device_row_id, source_protocol, timestamp, confidence,
                    is_verified_fact, attribute, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_row_id,
                    source_protocol,
                    timestamp,
                    float(confidence),
                    1 if is_verified_fact else 0,
                    attribute,
                    details,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def get_discovered_devices(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve stored multi-vendor devices with their associated evidence records."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, device_id, name, category, vendor, model, ip_address,
                       mac_address, firmware_version, discovery_protocol,
                       security_status, security_notes_json, telemetry_json, discovered_at
                FROM discovered_devices
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            )
            devices = [dict(r) for r in cursor.fetchall()]
            for dev in devices:
                cursor.execute(
                    """
                    SELECT id, source_protocol, timestamp, confidence, is_verified_fact, attribute, details
                    FROM device_evidence_records
                    WHERE device_row_id = ?
                    ORDER BY id ASC
                    """,
                    (dev["id"],),
                )
                evidence_rows = [dict(e) for e in cursor.fetchall()]
                # Decode boolean for is_verified_fact
                for e in evidence_rows:
                    e["is_verified_fact"] = bool(e["is_verified_fact"])
                dev["evidence"] = evidence_rows
                if dev.get("security_notes_json"):
                    dev["security_notes"] = json.loads(dev["security_notes_json"])
                if dev.get("telemetry_json"):
                    dev["telemetry"] = json.loads(dev["telemetry_json"])
            return devices

    # -------------------------------------------------------------------------
    # Target Domain Persistence: Wi-Fi Scans (Migration 003)
    # -------------------------------------------------------------------------

    def record_wifi_scan_session(
        self,
        interface_name: Optional[str] = None,
        band: Optional[str] = None,
        total_aps: int = 0,
    ) -> int:
        """Store Wi-Fi spectrum scan session metadata."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO wifi_scan_sessions (interface_name, band, total_aps)
                VALUES (?, ?, ?)
                """,
                (interface_name, band, total_aps),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def record_wifi_access_point(
        self,
        session_id: Optional[int],
        ssid: str,
        bssid: str,
        rssi_dbm: int,
        signal_percent: int,
        channel: int,
        frequency_mhz: int,
        channel_width_mhz: int,
        security: str,
        standard: str,
        wps_enabled: bool = False,
        security_warnings: Optional[List[str]] = None,
    ) -> int:
        """Store individual wireless access point observation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO wifi_access_points (
                    session_id, ssid, bssid, rssi_dbm, signal_percent, channel,
                    frequency_mhz, channel_width_mhz, security, standard,
                    wps_enabled, security_warnings_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    ssid,
                    bssid,
                    rssi_dbm,
                    signal_percent,
                    channel,
                    frequency_mhz,
                    channel_width_mhz,
                    security,
                    standard,
                    1 if wps_enabled else 0,
                    json.dumps(security_warnings) if security_warnings is not None else None,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def get_recent_wifi_aps(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent Wi-Fi access points."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, session_id, ssid, bssid, rssi_dbm, signal_percent,
                       channel, frequency_mhz, channel_width_mhz, security,
                       standard, wps_enabled, security_warnings_json, recorded_at
                FROM wifi_access_points
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            )
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                r["wps_enabled"] = bool(r["wps_enabled"])
                if r.get("security_warnings_json"):
                    r["security_warnings"] = json.loads(r["security_warnings_json"])
            return rows

    # -------------------------------------------------------------------------
    # Target Domain Persistence: TLS Audits (Migration 004)
    # -------------------------------------------------------------------------

    def record_tls_inspection_report(
        self,
        target_host: str,
        target_port: int,
        negotiated_protocol: str,
        negotiated_cipher: str,
        cipher_security: str,
        overall_score: int,
        vulnerabilities: Optional[List[str]] = None,
        recommendations: Optional[List[str]] = None,
    ) -> int:
        """Store TLS/SSL cryptographic inspection report."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO tls_inspection_reports (
                    target_host, target_port, negotiated_protocol, negotiated_cipher,
                    cipher_security, overall_score, vulnerabilities_json, recommendations_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target_host,
                    target_port,
                    negotiated_protocol,
                    negotiated_cipher,
                    cipher_security,
                    overall_score,
                    json.dumps(vulnerabilities) if vulnerabilities is not None else None,
                    json.dumps(recommendations) if recommendations is not None else None,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def record_tls_certificate(
        self,
        report_id: int,
        subject_cn: str,
        issuer_cn: str,
        valid_from: str,
        valid_to: str,
        days_until_expiration: int,
        is_expired: bool,
        is_self_signed: bool,
        issuer_organization: Optional[str] = None,
        chain_position: int = 0,
        serial_number: str = "",
        fingerprint_sha256: str = "",
        key_type: str = "RSA",
        key_bits: int = 2048,
        signature_algorithm: str = "sha256WithRSAEncryption",
        san_list: Optional[List[str]] = None,
    ) -> int:
        """Store public key X.509 certificate attached to a TLS report."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO tls_certificates (
                    report_id, chain_position, subject_cn, issuer_cn, issuer_organization,
                    valid_from, valid_to, days_until_expiration, is_expired, is_self_signed,
                    serial_number, fingerprint_sha256, key_type, key_bits,
                    signature_algorithm, san_list_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    chain_position,
                    subject_cn,
                    issuer_cn,
                    issuer_organization,
                    valid_from,
                    valid_to,
                    days_until_expiration,
                    1 if is_expired else 0,
                    1 if is_self_signed else 0,
                    serial_number,
                    fingerprint_sha256,
                    key_type,
                    key_bits,
                    signature_algorithm,
                    json.dumps(san_list) if san_list is not None else None,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def get_recent_tls_reports(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent TLS inspection reports with attached certificates."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, target_host, target_port, negotiated_protocol, negotiated_cipher,
                       cipher_security, overall_score, vulnerabilities_json, recommendations_json,
                       inspected_at
                FROM tls_inspection_reports
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            )
            reports = [dict(r) for r in cursor.fetchall()]
            for rep in reports:
                cursor.execute(
                    """
                    SELECT id, chain_position, subject_cn, issuer_cn, issuer_organization,
                           valid_from, valid_to, days_until_expiration, is_expired, is_self_signed,
                           serial_number, fingerprint_sha256, key_type, key_bits,
                           signature_algorithm, san_list_json
                    FROM tls_certificates
                    WHERE report_id = ?
                    ORDER BY chain_position ASC
                    """,
                    (rep["id"],),
                )
                certs = [dict(c) for c in cursor.fetchall()]
                for c in certs:
                    c["is_expired"] = bool(c["is_expired"])
                    c["is_self_signed"] = bool(c["is_self_signed"])
                    if c.get("san_list_json"):
                        c["san_list"] = json.loads(c["san_list_json"])
                rep["certificates"] = certs
                if rep.get("vulnerabilities_json"):
                    rep["vulnerabilities"] = json.loads(rep["vulnerabilities_json"])
                if rep.get("recommendations_json"):
                    rep["recommendations"] = json.loads(rep["recommendations_json"])
            return reports

    # -------------------------------------------------------------------------
    # Target Domain Persistence: Audit Trail & Diagnostic Sessions (Migration 005)
    # -------------------------------------------------------------------------

    def create_diagnostic_session(
        self,
        name: str,
        operator: Optional[str] = "system",
        scope_enclosure: Optional[Union[Dict[str, Any], Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        session_uuid: Optional[str] = None,
    ) -> int:
        """Create a new diagnostic assessment session record.

        Args:
            name: Human-readable diagnostic session title.
            operator: Identifier for operator or system agent (neutral default: 'system').
            scope_enclosure: ScopeEnclosure dict or object defining authorized boundaries.
            metadata: Additional execution context metadata (sanitized before storage).
            session_uuid: Optional pre-generated UUID4 string; auto-generated if omitted.

        Returns:
            int: The primary key ID of the created session record.
        """
        if not name or not isinstance(name, str) or not name.strip():
            raise ValueError("Session name must be a non-empty string.")

        s_uuid = session_uuid or str(uuid.uuid4())
        op_val = operator if operator is not None else "system"

        scope_dict = None
        if scope_enclosure is not None:
            if hasattr(scope_enclosure, "to_dict") and callable(getattr(scope_enclosure, "to_dict")):
                scope_dict = scope_enclosure.to_dict()
            elif isinstance(scope_enclosure, dict):
                scope_dict = scope_enclosure
            else:
                scope_dict = {"scope": str(scope_enclosure)}

        # Sanitize metadata before storage
        sanitized_meta = None
        if metadata is not None:
            redacted_meta, _ = CredentialRedactor.redact(metadata)
            sanitized_meta = json.dumps(redacted_meta)

        scope_json = json.dumps(scope_dict) if scope_dict is not None else None

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO diagnostic_sessions (
                    session_uuid, name, operator, scope_enclosure_json, status, metadata_json
                ) VALUES (?, ?, ?, ?, 'IN_PROGRESS', ?)
                """,
                (s_uuid, name.strip(), op_val, scope_json, sanitized_meta),
            )
            conn.commit()
            return cursor.lastrowid or 0
        finally:
            if self._mem_conn is None:
                conn.close()

    def record_session_snapshot(
        self,
        session_id: int,
        snapshot_type: str,
        payload: Union[Dict[str, Any], List[Any], Any],
        target: Optional[str] = None,
        status: str = "COMPLETED",
    ) -> int:
        """Record a sanitized diagnostic snapshot linked to an active session.

        Mandatory Security Invariant:
        Every snapshot payload is strictly scrubbed by CredentialRedactor before
        serialization and database insertion. If redaction fails, the payload is
        never persisted (fail-closed).
        """
        if not snapshot_type or not isinstance(snapshot_type, str):
            raise ValueError("snapshot_type must be a non-empty string.")

        # 1. Mandatory secret redaction before serialization
        try:
            sanitized_payload, redacted_count = CredentialRedactor.redact(payload)
            payload_json = json.dumps(sanitized_payload)
        except Exception as exc:
            raise RedactionError(f"Snapshot payload failed mandatory sanitization: {exc}") from exc

        # 2. Verify session exists and insert snapshot atomically
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM diagnostic_sessions WHERE id = ?;", (session_id,))
            if not cur.fetchone():
                raise ValueError(f"Diagnostic session with id={session_id} does not exist.")

            cur.execute(
                """
                INSERT INTO diagnostic_snapshots (
                    session_id, snapshot_type, target, status, payload_json, redacted_fields_count
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, snapshot_type.strip(), target, status, payload_json, redacted_count),
            )
            conn.commit()
            return cur.lastrowid or 0
        finally:
            if self._mem_conn is None:
                conn.close()

    def complete_diagnostic_session(
        self,
        session_id: int,
        status: str = "COMPLETED",
        summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Finalize an active diagnostic session with completion timestamp and summary."""
        sanitized_summary_json = None
        if summary is not None:
            try:
                sanitized_summary, _ = CredentialRedactor.redact(summary)
                sanitized_summary_json = json.dumps(sanitized_summary)
            except Exception as exc:
                raise RedactionError(f"Session summary failed mandatory sanitization: {exc}") from exc

        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM diagnostic_sessions WHERE id = ?;", (session_id,))
            if not cur.fetchone():
                raise ValueError(f"Diagnostic session with id={session_id} does not exist.")

            cur.execute(
                """
                UPDATE diagnostic_sessions
                SET status = ?, completed_at = CURRENT_TIMESTAMP, summary_json = ?
                WHERE id = ?
                """,
                (status, sanitized_summary_json, session_id),
            )
            conn.commit()
        finally:
            if self._mem_conn is None:
                conn.close()

    def get_diagnostic_session(
        self,
        session_id: Union[int, str],
        include_snapshots: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a diagnostic session record and its attached snapshots."""
        conn = self._get_connection()
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            if isinstance(session_id, int) or (isinstance(session_id, str) and session_id.isdigit()):
                cur.execute(
                    "SELECT * FROM diagnostic_sessions WHERE id = ?;",
                    (int(session_id),),
                )
            else:
                cur.execute(
                    "SELECT * FROM diagnostic_sessions WHERE session_uuid = ?;",
                    (str(session_id),),
                )
            row = cur.fetchone()
            if not row:
                return None

            sess = dict(row)
            if sess.get("scope_enclosure_json"):
                sess["scope_enclosure"] = json.loads(sess["scope_enclosure_json"])
            if sess.get("summary_json"):
                sess["summary"] = json.loads(sess["summary_json"])
            if sess.get("metadata_json"):
                sess["metadata"] = json.loads(sess["metadata_json"])

            if include_snapshots:
                cur.execute(
                    """
                    SELECT id, session_id, snapshot_type, target, status, payload_json,
                           redacted_fields_count, created_at
                    FROM diagnostic_snapshots
                    WHERE session_id = ?
                    ORDER BY id ASC
                    """,
                    (sess["id"],),
                )
                snapshots = []
                for s_row in cur.fetchall():
                    snap = dict(s_row)
                    if snap.get("payload_json"):
                        snap["payload"] = json.loads(snap["payload_json"])
                    snapshots.append(snap)
                sess["snapshots"] = snapshots

            return sess
        finally:
            if self._mem_conn is None:
                conn.close()

    def list_diagnostic_sessions(
        self,
        limit: int = 50,
        offset: int = 0,
        status_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent diagnostic sessions ordered by creation date."""
        conn = self._get_connection()
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            if status_filter:
                cur.execute(
                    """
                    SELECT * FROM diagnostic_sessions
                    WHERE status = ?
                    ORDER BY id DESC LIMIT ? OFFSET ?
                    """,
                    (status_filter, limit, offset),
                )
            else:
                cur.execute(
                    """
                    SELECT * FROM diagnostic_sessions
                    ORDER BY id DESC LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("scope_enclosure_json"):
                    r["scope_enclosure"] = json.loads(r["scope_enclosure_json"])
                if r.get("summary_json"):
                    r["summary"] = json.loads(r["summary_json"])
                if r.get("metadata_json"):
                    r["metadata"] = json.loads(r["metadata_json"])
            return rows
        finally:
            if self._mem_conn is None:
                conn.close()

    def get_session_snapshots(
        self,
        session_id: int,
        snapshot_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve snapshots attached to a specific session."""
        conn = self._get_connection()
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            if snapshot_type:
                cur.execute(
                    """
                    SELECT id, session_id, snapshot_type, target, status, payload_json,
                           redacted_fields_count, created_at
                    FROM diagnostic_snapshots
                    WHERE session_id = ? AND snapshot_type = ?
                    ORDER BY id ASC LIMIT ?
                    """,
                    (session_id, snapshot_type, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT id, session_id, snapshot_type, target, status, payload_json,
                           redacted_fields_count, created_at
                    FROM diagnostic_snapshots
                    WHERE session_id = ?
                    ORDER BY id ASC LIMIT ?
                    """,
                    (session_id, limit),
                )
            snapshots = []
            for s_row in cur.fetchall():
                snap = dict(s_row)
                if snap.get("payload_json"):
                    snap["payload"] = json.loads(snap["payload_json"])
                snapshots.append(snap)
            return snapshots
        finally:
            if self._mem_conn is None:
                conn.close()

    def delete_diagnostic_session(self, session_id: int) -> bool:
        """Delete a diagnostic session and cascade deletion to all snapshots."""
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM diagnostic_sessions WHERE id = ?;", (session_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()
