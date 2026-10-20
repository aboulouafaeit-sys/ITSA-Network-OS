"""SQLite Schema Migration Engine for ITSA Network OS.

Provides version-controlled, atomic, forward-only database schema migrations
with SHA-256 checksum verification, pre-migration integrity checks, and
support for fresh, in-memory, and pre-existing baseline databases.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set

logger = logging.getLogger("itsa_network_os.storage.migrations")


class MigrationError(RuntimeError):
    """Base exception for all database migration failures."""
    pass


class MigrationChecksumError(MigrationError):
    """Raised when an applied migration checksum does not match the canonical definition."""
    pass


class DatabaseCorruptionError(MigrationError):
    """Raised when pre-migration integrity checks detect a corrupt or unreadable database."""
    pass


class SchemaVersionError(MigrationError):
    """Raised when migration sequence is invalid or an unsupported downgrade is requested."""
    pass


class IncompatibleSchemaError(MigrationError):
    """Raised when a pre-existing database schema is incompatible with migration baseline."""
    pass


# -----------------------------------------------------------------------------
# Pre-TASK-011 Legacy Schema Specifications (for baseline compatibility validation)
# -----------------------------------------------------------------------------

LEGACY_TABLE_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "diagnostic_runs": {
        "required_columns": {"id", "run_type", "status", "details", "created_at"},
        "primary_key": "id",
        "column_types": {
            "id": {"INTEGER"},
            "run_type": {"TEXT"},
            "status": {"TEXT"},
        },
    },
    "subnet_history": {
        "required_columns": {"id", "cidr", "usable_hosts", "network_address", "broadcast_address", "calculated_at"},
        "primary_key": "id",
        "column_types": {
            "id": {"INTEGER"},
            "cidr": {"TEXT"},
            "usable_hosts": {"INTEGER"},
            "network_address": {"TEXT"},
            "broadcast_address": {"TEXT"},
        },
    },
    "dns_history": {
        "required_columns": {"id", "host", "status", "response_time_ms", "records_json", "queried_at"},
        "primary_key": "id",
        "column_types": {
            "id": {"INTEGER"},
            "host": {"TEXT"},
            "status": {"TEXT"},
            "response_time_ms": {"REAL", "FLOAT", "NUMERIC"},
        },
    },
    "latency_history": {
        "required_columns": {"id", "host", "port", "packet_loss", "avg_latency_ms", "jitter_ms", "tested_at"},
        "primary_key": "id",
        "column_types": {
            "id": {"INTEGER"},
            "host": {"TEXT"},
            "port": {"INTEGER"},
            "packet_loss": {"REAL", "FLOAT", "NUMERIC"},
            "avg_latency_ms": {"REAL", "FLOAT", "NUMERIC"},
            "jitter_ms": {"REAL", "FLOAT", "NUMERIC"},
        },
    },
}

# -----------------------------------------------------------------------------
# Migration 005 Pre-Existing Schema Specifications (SEC-008)
# -----------------------------------------------------------------------------

MIGRATION_005_TABLE_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "diagnostic_sessions": {
        "required_columns": {
            "id",
            "session_uuid",
            "name",
            "operator",
            "scope_enclosure_json",
            "status",
            "started_at",
            "completed_at",
            "summary_json",
            "metadata_json",
        },
        "primary_key": "id",
        "column_types": {
            "id": {"INTEGER"},
            "session_uuid": {"TEXT"},
            "name": {"TEXT"},
            "operator": {"TEXT"},
            "status": {"TEXT"},
        },
        "unique_columns": {"session_uuid"},
    },
    "diagnostic_snapshots": {
        "required_columns": {
            "id",
            "session_id",
            "snapshot_type",
            "target",
            "status",
            "payload_json",
            "redacted_fields_count",
            "created_at",
        },
        "primary_key": "id",
        "column_types": {
            "id": {"INTEGER"},
            "session_id": {"INTEGER"},
            "snapshot_type": {"TEXT"},
            "status": {"TEXT"},
            "payload_json": {"TEXT"},
            "redacted_fields_count": {"INTEGER"},
        },
        "foreign_keys": [
            {
                "table": "diagnostic_sessions",
                "from": "session_id",
                "to": "id",
                "on_delete": "CASCADE",
            }
        ],
    },
}


@dataclass(frozen=True)
class Migration:
    """Immutable representation of a versioned database schema migration."""

    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        """Deterministic SHA-256 checksum of the migration SQL."""
        # Normalize line endings and strip surrounding whitespace
        normalized = "\n".join(line.rstrip() for line in self.sql.strip().splitlines())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# -----------------------------------------------------------------------------
# Canonical Migration Definitions
# -----------------------------------------------------------------------------

MIGRATION_001_BASELINE_SQL = """
-- Baseline adoption of legacy history tables (diagnostic_runs, subnet_history, dns_history, latency_history)
CREATE TABLE IF NOT EXISTS diagnostic_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_type TEXT NOT NULL,
    status TEXT NOT NULL,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subnet_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL,
    usable_hosts INTEGER NOT NULL,
    network_address TEXT NOT NULL,
    broadcast_address TEXT NOT NULL,
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    status TEXT NOT NULL,
    response_time_ms REAL NOT NULL,
    records_json TEXT,
    queried_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS latency_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    packet_loss REAL NOT NULL,
    avg_latency_ms REAL NOT NULL,
    jitter_ms REAL NOT NULL,
    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

MIGRATION_002_DEVICE_INVENTORY_SQL = """
-- Multi-Vendor Discovered Hardware Inventory and Evidence Attribution
CREATE TABLE IF NOT EXISTS discovered_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    vendor TEXT NOT NULL,
    model TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    firmware_version TEXT NOT NULL,
    discovery_protocol TEXT NOT NULL,
    security_status TEXT NOT NULL,
    security_notes_json TEXT,
    telemetry_json TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_evidence_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_row_id INTEGER NOT NULL REFERENCES discovered_devices(id) ON DELETE CASCADE,
    source_protocol TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    confidence REAL NOT NULL,
    is_verified_fact INTEGER NOT NULL,
    attribute TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_discovered_devices_mac ON discovered_devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_discovered_devices_ip ON discovered_devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_discovered_devices_category ON discovered_devices(category);
CREATE INDEX IF NOT EXISTS idx_device_evidence_device_id ON device_evidence_records(device_row_id);
"""

MIGRATION_003_WIFI_SCANS_SQL = """
-- Wireless Airwave Scans and Access Point Security Telemetry
CREATE TABLE IF NOT EXISTS wifi_scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_name TEXT,
    band TEXT,
    total_aps INTEGER NOT NULL DEFAULT 0,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS wifi_access_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES wifi_scan_sessions(id) ON DELETE CASCADE,
    ssid TEXT NOT NULL,
    bssid TEXT NOT NULL,
    rssi_dbm INTEGER NOT NULL,
    signal_percent INTEGER NOT NULL,
    channel INTEGER NOT NULL,
    frequency_mhz INTEGER NOT NULL,
    channel_width_mhz INTEGER NOT NULL,
    security TEXT NOT NULL,
    standard TEXT NOT NULL,
    wps_enabled INTEGER NOT NULL DEFAULT 0,
    security_warnings_json TEXT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_wifi_aps_bssid ON wifi_access_points(bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_aps_session ON wifi_access_points(session_id);
"""

MIGRATION_004_TLS_AUDITS_SQL = """
-- TLS / SSL Cryptographic Handshake and X.509 Certificate Chain Inspection
CREATE TABLE IF NOT EXISTS tls_inspection_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    negotiated_protocol TEXT NOT NULL,
    negotiated_cipher TEXT NOT NULL,
    cipher_security TEXT NOT NULL,
    overall_score INTEGER NOT NULL,
    vulnerabilities_json TEXT,
    recommendations_json TEXT,
    inspected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tls_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL REFERENCES tls_inspection_reports(id) ON DELETE CASCADE,
    chain_position INTEGER NOT NULL DEFAULT 0,
    subject_cn TEXT NOT NULL,
    issuer_cn TEXT NOT NULL,
    issuer_organization TEXT,
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    days_until_expiration INTEGER NOT NULL,
    is_expired INTEGER NOT NULL,
    is_self_signed INTEGER NOT NULL,
    serial_number TEXT,
    fingerprint_sha256 TEXT,
    key_type TEXT,
    key_bits INTEGER,
    signature_algorithm TEXT,
    san_list_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_tls_reports_host_port ON tls_inspection_reports(target_host, target_port);
CREATE INDEX IF NOT EXISTS idx_tls_certs_report_id ON tls_certificates(report_id);
"""

MIGRATION_005_AUDIT_TRAIL_SESSIONS_SQL = """
-- Diagnostic Audit Trail, Historical Sessions, and Secret-Redacted Snapshots
CREATE TABLE IF NOT EXISTS diagnostic_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_uuid TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    operator TEXT DEFAULT 'system',
    scope_enclosure_json TEXT,
    status TEXT NOT NULL DEFAULT 'IN_PROGRESS',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    summary_json TEXT,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS diagnostic_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES diagnostic_sessions(id) ON DELETE CASCADE,
    snapshot_type TEXT NOT NULL,
    target TEXT,
    status TEXT NOT NULL DEFAULT 'COMPLETED',
    payload_json TEXT NOT NULL,
    redacted_fields_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_diagnostic_sessions_uuid ON diagnostic_sessions(session_uuid);
CREATE INDEX IF NOT EXISTS idx_diagnostic_sessions_status ON diagnostic_sessions(status);
CREATE INDEX IF NOT EXISTS idx_diagnostic_snapshots_session ON diagnostic_snapshots(session_id);
CREATE INDEX IF NOT EXISTS idx_diagnostic_snapshots_type ON diagnostic_snapshots(snapshot_type);
"""

ALL_MIGRATIONS: Sequence[Migration] = (
    Migration(1, "001_baseline_history_tables", MIGRATION_001_BASELINE_SQL),
    Migration(2, "002_device_inventory", MIGRATION_002_DEVICE_INVENTORY_SQL),
    Migration(3, "003_wifi_scans", MIGRATION_003_WIFI_SCANS_SQL),
    Migration(4, "004_tls_audits", MIGRATION_004_TLS_AUDITS_SQL),
    Migration(5, "005_audit_trail_sessions", MIGRATION_005_AUDIT_TRAIL_SESSIONS_SQL),
)


class MigrationRunner:
    """Executes version-controlled schema migrations atomically against a SQLite connection."""

    SCHEMA_MIGRATIONS_TABLE = """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        checksum TEXT NOT NULL
    );
    """

    def __init__(self, migrations: Optional[Sequence[Migration]] = None) -> None:
        self.migrations: Sequence[Migration] = migrations if migrations is not None else ALL_MIGRATIONS
        # Validate that migrations are strictly 1-indexed, contiguous, and sequential
        for idx, m in enumerate(self.migrations, start=1):
            if m.version != idx:
                raise SchemaVersionError(
                    f"Invalid migration sequence: expected version {idx}, got {m.version} ({m.name})"
                )

    @staticmethod
    def check_integrity(conn: sqlite3.Connection) -> None:
        """Run non-destructive integrity check on the SQLite database before migration.

        Uses PRAGMA quick_check which scans B-trees and cell structures rapidly
        without the full multi-minute overhead of PRAGMA integrity_check on massive databases.
        """
        cursor = conn.cursor()
        try:
            cursor.execute("PRAGMA quick_check;")
            rows = cursor.fetchall()
        except sqlite3.DatabaseError as exc:
            raise DatabaseCorruptionError(
                f"Database integrity check failed: unreadable or corrupt file ({exc}). "
                "Safe recovery: restore from backup or inspect file with 'sqlite3 <path> .recover'."
            ) from exc

        if not rows or rows[0][0] != "ok":
            diag = rows[0][0] if rows else "unknown failure"
            raise DatabaseCorruptionError(
                f"Database integrity check failed: {diag}. "
                "Safe recovery: do not modify corrupt database. Restore from backup or run 'sqlite3 .recover'."
            )

    @classmethod
    def get_applied_migrations(cls, conn: sqlite3.Connection) -> List[Dict[str, Any]]:
        """Retrieve list of previously applied migrations ordered by version."""
        cursor = conn.cursor()
        # Check if schema_migrations table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations';"
        )
        if not cursor.fetchone():
            return []

        cursor.execute(
            "SELECT version, name, applied_at, checksum FROM schema_migrations ORDER BY version ASC;"
        )
        return [
            {
                "version": row[0],
                "name": row[1],
                "applied_at": row[2],
                "checksum": row[3],
            }
            for row in cursor.fetchall()
        ]

    @classmethod
    def get_schema_version(cls, conn: sqlite3.Connection) -> int:
        """Return the highest applied migration version, or 0 if none applied."""
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations';"
        )
        if not cursor.fetchone():
            return 0
        cursor.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations;")
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    @classmethod
    def validate_legacy_schemas(cls, conn: sqlite3.Connection) -> None:
        """Validate pre-existing legacy tables before baseline migration adoption (SEC-001).

        Inspects sqlite_master and PRAGMA table_info to ensure any pre-existing
        legacy tables strictly match the expected columns, primary keys, and types.
        Raises IncompatibleSchemaError and fails closed if incompatible structures are found.
        """
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        existing_tables = {row[0] for row in cursor.fetchall()}

        for table_name, schema in LEGACY_TABLE_SCHEMAS.items():
            if table_name not in existing_tables:
                continue

            cursor.execute(f"PRAGMA table_info({table_name});")
            col_rows = cursor.fetchall()
            col_info = {
                row[1]: {
                    "type": (row[2] or "").upper(),
                    "notnull": bool(row[3]),
                    "dflt_value": row[4],
                    "pk": row[5],
                }
                for row in col_rows
            }

            # 1. Validate required columns exist
            required_cols: Set[str] = schema["required_columns"]
            missing_cols = required_cols - set(col_info.keys())
            if missing_cols:
                raise IncompatibleSchemaError(
                    f"Pre-existing legacy table '{table_name}' is incompatible: "
                    f"missing required column(s) {sorted(missing_cols)}. Baseline adoption rejected."
                )

            # 2. Validate primary key
            pk_col = schema["primary_key"]
            if col_info[pk_col]["pk"] != 1:
                raise IncompatibleSchemaError(
                    f"Pre-existing legacy table '{table_name}' is incompatible: "
                    f"column '{pk_col}' must be declared as PRIMARY KEY."
                )

            # 3. Validate declared types
            for col, allowed_types in schema.get("column_types", {}).items():
                actual_type = col_info[col]["type"]
                if actual_type and not any(allowed in actual_type for allowed in allowed_types):
                    raise IncompatibleSchemaError(
                        f"Pre-existing legacy table '{table_name}' is incompatible: "
                        f"column '{col}' has type '{actual_type}' (expected one of {sorted(allowed_types)})."
                    )

    @classmethod
    def validate_migration_005_schemas(cls, conn: sqlite3.Connection) -> None:
        """Validate pre-existing audit trail tables before Migration 005 execution (SEC-008).

        Ensures that if either 'diagnostic_sessions' or 'diagnostic_snapshots' already
        exists in the database prior to applying migration 5:
        1. Both tables must exist together (partial pre-existing schemas fail closed).
        2. All required columns exist with compatible declared types.
        3. 'diagnostic_sessions' has 'id' as PRIMARY KEY and a UNIQUE constraint on 'session_uuid'.
        4. 'diagnostic_snapshots' has 'id' as PRIMARY KEY and a valid foreign key to
           'diagnostic_sessions(id)' with 'ON DELETE CASCADE'.

        Raises IncompatibleSchemaError and fails closed if incompatible structures are found.
        """
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        existing_tables = {row[0] for row in cursor.fetchall()}

        has_sessions = "diagnostic_sessions" in existing_tables
        has_snapshots = "diagnostic_snapshots" in existing_tables

        if not has_sessions and not has_snapshots:
            return

        if has_sessions != has_snapshots:
            present = "diagnostic_sessions" if has_sessions else "diagnostic_snapshots"
            missing = "diagnostic_snapshots" if has_sessions else "diagnostic_sessions"
            raise IncompatibleSchemaError(
                f"Incompatible pre-existing schema for migration 5: table '{present}' exists but '{missing}' is missing. "
                "Audit trail tables must either both be absent for fresh creation or both fully compatible."
            )

        for table_name, schema in MIGRATION_005_TABLE_SCHEMAS.items():
            cursor.execute(f"PRAGMA table_info({table_name});")
            col_rows = cursor.fetchall()
            col_info = {
                row[1]: {
                    "type": (row[2] or "").upper(),
                    "notnull": bool(row[3]),
                    "dflt_value": row[4],
                    "pk": row[5],
                }
                for row in col_rows
            }

            # 1. Validate required columns exist
            required_cols: Set[str] = schema["required_columns"]
            missing_cols = required_cols - set(col_info.keys())
            if missing_cols:
                raise IncompatibleSchemaError(
                    f"Pre-existing table '{table_name}' is incompatible: "
                    f"missing required column(s) {sorted(missing_cols)}. Migration 005 rejected."
                )

            # 2. Validate primary key
            pk_col = schema["primary_key"]
            if col_info[pk_col]["pk"] != 1:
                raise IncompatibleSchemaError(
                    f"Pre-existing table '{table_name}' is incompatible: "
                    f"column '{pk_col}' must be declared as PRIMARY KEY."
                )

            # 3. Validate declared types
            for col, allowed_types in schema.get("column_types", {}).items():
                actual_type = col_info[col]["type"]
                if actual_type and not any(allowed in actual_type for allowed in allowed_types):
                    raise IncompatibleSchemaError(
                        f"Pre-existing table '{table_name}' is incompatible: "
                        f"column '{col}' has type '{actual_type}' (expected one of {sorted(allowed_types)})."
                    )

            # 4. Validate unique columns if required
            for unique_col in schema.get("unique_columns", set()):
                cursor.execute(f"PRAGMA index_list({table_name});")
                indexes = cursor.fetchall()
                found_unique = False
                for idx_row in indexes:
                    idx_name = idx_row[1]
                    is_unique = bool(idx_row[2])
                    if is_unique:
                        cursor.execute(f"PRAGMA index_info({idx_name});")
                        idx_cols = [c[2] for c in cursor.fetchall()]
                        if unique_col in idx_cols:
                            found_unique = True
                            break
                if not found_unique:
                    raise IncompatibleSchemaError(
                        f"Pre-existing table '{table_name}' is incompatible: "
                        f"column '{unique_col}' must have a UNIQUE constraint."
                    )

            # 5. Validate foreign keys if required
            for fk in schema.get("foreign_keys", []):
                cursor.execute(f"PRAGMA foreign_key_list({table_name});")
                fk_rows = cursor.fetchall()
                found_fk = False
                for fk_row in fk_rows:
                    target_table = fk_row[2]
                    from_col = fk_row[3]
                    to_col = fk_row[4]
                    on_delete = (fk_row[6] or "").upper()
                    if (
                        target_table == fk["table"]
                        and from_col == fk["from"]
                        and to_col == fk["to"]
                        and on_delete == fk["on_delete"].upper()
                    ):
                        found_fk = True
                        break
                if not found_fk:
                    raise IncompatibleSchemaError(
                        f"Pre-existing table '{table_name}' is incompatible: "
                        f"missing foreign key referencing '{fk['table']}({fk['to']})' with ON DELETE {fk['on_delete']}."
                    )

    def validate_applied_history(self, conn: sqlite3.Connection) -> int:
        """Validate continuity, ordering, names, and checksums of applied migrations (SEC-002).

        Returns the highest valid applied migration version, or 0 if none.
        Fails closed on gaps, duplicate versions, unknown future versions, name mismatches,
        or checksum tampering.
        """
        applied_rows = self.get_applied_migrations(conn)
        if not applied_rows:
            return 0

        versions = [r["version"] for r in applied_rows]

        # 1. Check for duplicates
        if len(versions) != len(set(versions)):
            raise SchemaVersionError("Duplicate migration version detected in schema_migrations.")

        # 2. Check for ordering
        if versions != sorted(versions):
            raise SchemaVersionError("Out-of-order migration history detected in schema_migrations.")

        # 3. Check for contiguous 1-indexed sequence and unknown future versions
        max_v = max(versions)
        if min(versions) < 1:
            raise SchemaVersionError(
                f"Invalid migration version {min(versions)} in schema_migrations (versions must be >= 1)."
            )

        # Reject unknown future versions (SEC-002)
        known_by_version = {m.version: m for m in self.migrations}
        max_known = max(known_by_version.keys(), default=0)
        if max_v > max_known:
            raise SchemaVersionError(
                f"Database schema version {max_v} is newer than maximum known migration version {max_known}."
            )

        expected_sequence = list(range(1, max_v + 1))
        if versions != expected_sequence:
            missing = sorted(set(expected_sequence) - set(versions))
            raise SchemaVersionError(
                f"Non-contiguous migration history: missing intermediate version(s) {missing}. "
                "Automatic gap filling is strictly prohibited."
            )

        # 4. Check names and checksums against definitions
        for r in applied_rows:
            v = r["version"]
            m = known_by_version[v]
            if r["name"] != m.name:
                raise SchemaVersionError(
                    f"Migration name mismatch for v{v}: recorded '{r['name']}', expected '{m.name}'."
                )
            if r["checksum"] != m.checksum:
                raise MigrationChecksumError(
                    f"Checksum mismatch for previously applied migration v{v} ('{m.name}'). "
                    f"Stored: {r['checksum'][:12]}..., Canonical: {m.checksum[:12]}... "
                    "The migration definition was modified after application. Refusing to run."
                )

        return max_v

    @staticmethod
    def split_statements(sql: str) -> List[str]:
        """Split SQL script into discrete statements using SQLite statement completeness (SEC-007)."""
        statements: List[str] = []
        current: List[str] = []
        for part in sql.split(";"):
            if not part.strip():
                continue
            current.append(part)
            candidate = ";".join(current) + ";"
            if sqlite3.complete_statement(candidate):
                statements.append(candidate.strip())
                current = []
        trailing = ";".join(current).strip()
        if trailing:
            statements.append(trailing)
        return statements

    def apply(self, conn: sqlite3.Connection, target_version: Optional[int] = None) -> List[int]:
        """Apply pending migrations sequentially up to target_version (or latest).

        Invariants:
        - Runs PRAGMA quick_check prior to execution.
        - Enforces PRAGMA foreign_keys = ON and PRAGMA busy_timeout = 5000.
        - Preserves caller connection isolation_level in a finally block (SEC-004).
        - Validates complete applied history continuity and checksums (SEC-002).
        - Validates pre-existing legacy schemas before adopting baseline v1 (SEC-001).
        - Acquires BEGIN IMMEDIATE before re-reading version state for safe concurrency (SEC-003).
        - Executes each migration atomically within BEGIN IMMEDIATE ... COMMIT.
        - Rolls back completely on failure without leaving partial tables or corrupt state.
        """
        self.check_integrity(conn)

        # Set connection pragmas
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")

        orig_isolation = conn.isolation_level
        try:
            conn.isolation_level = None  # Manual explicit transaction control

            # Ensure schema_migrations exists in its own atomic transaction
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute(self.SCHEMA_MIGRATIONS_TABLE)
                conn.execute("COMMIT;")
            except Exception as exc:
                conn.execute("ROLLBACK;")
                raise MigrationError(f"Failed to initialize schema_migrations table: {exc}") from exc

            # Validate complete recorded history up-front (SEC-002)
            current_version = self.validate_applied_history(conn)

            target = target_version if target_version is not None else len(self.migrations)
            if target < current_version:
                raise SchemaVersionError(
                    f"Requested target version {target} is lower than current database version {current_version}. "
                    "Automatic downgrades are strictly prohibited."
                )

            applied_versions: List[int] = []

            for m in self.migrations:
                if m.version > target:
                    break

                conn.execute("BEGIN IMMEDIATE;")
                try:
                    # While holding write lock, re-read migration state (SEC-003)
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT version, name, checksum FROM schema_migrations WHERE version = ?;",
                        (m.version,),
                    )
                    row = cur.fetchone()
                    if row is not None:
                        # Already applied by another connection/worker
                        rec_name, rec_checksum = row[1], row[2]
                        if rec_name != m.name:
                            raise SchemaVersionError(
                                f"Concurrent migration name mismatch for v{m.version}: "
                                f"recorded '{rec_name}', expected '{m.name}'"
                            )
                        if rec_checksum != m.checksum:
                            raise MigrationChecksumError(
                                f"Concurrent checksum mismatch for previously applied migration v{m.version} ('{m.name}'). "
                                f"Stored: {rec_checksum[:12]}..., Canonical: {m.checksum[:12]}..."
                            )
                        conn.execute("COMMIT;")
                        continue

                    # If applying baseline v1, validate pre-existing legacy tables (SEC-001)
                    if m.version == 1:
                        self.validate_legacy_schemas(conn)
                    elif m.version == 5:
                        self.validate_migration_005_schemas(conn)

                    logger.info("Applying database migration v%d: %s", m.version, m.name)

                    # Execute individual statements using SQLite-aware statement parser (SEC-007)
                    statements = self.split_statements(m.sql)
                    for stmt in statements:
                        conn.execute(stmt)

                    # Record migration metadata
                    conn.execute(
                        """
                        INSERT INTO schema_migrations (version, name, checksum)
                        VALUES (?, ?, ?);
                        """,
                        (m.version, m.name, m.checksum),
                    )
                    conn.execute("COMMIT;")
                    applied_versions.append(m.version)
                except Exception as exc:
                    conn.execute("ROLLBACK;")
                    logger.error("Migration v%d ('%s') failed and was rolled back: %s", m.version, m.name, exc)
                    if isinstance(exc, MigrationError):
                        raise
                    raise MigrationError(
                        f"Migration v{m.version} ('{m.name}') failed during execution: {exc}. "
                        "Transaction rolled back; previous schema and data remain intact."
                    ) from exc

            # Revalidate overall history consistency after loop
            self.validate_applied_history(conn)
            return applied_versions
        finally:
            conn.isolation_level = orig_isolation
