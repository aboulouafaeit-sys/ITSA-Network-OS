# ITSA Network OS — Storage Subsystem & Migration Engine Specification

> **Document ID:** DOC-STORAGE-001  
> **Status:** Active Baseline  
> **Version:** 1.0.0  
> **Last Updated:** 2026-10-19  

---

## 1. Overview & Architecture

The storage subsystem (`src/itsa_network_os/storage/`) provides local, unprivileged SQLite persistence for ITSA Network OS. It manages both ephemeral in-memory databases (`:memory:`) for CLI runs and persistent file-backed storage (`~/.config/itsa-network-os/data.sqlite3`).

### Core Components
- **`database.py` (`DatabaseManager`):** Central database controller providing connection lifecycle management, transaction boundaries, performance pragmas, and domain data access helpers.
- **`migrations.py` (`MigrationRunner`, `Migration`):** Deterministic schema migration engine that executes ordered, transactional, and checksum-verified DDL migrations.

---

## 2. Migration Framework Design

### 2.1 Ordering & Discovery
Migrations are defined as immutable `Migration` dataclasses with strictly ordered, 1-indexed, contiguous version numbers:
- `Migration(1, "001_baseline_history_tables", ...)`
- `Migration(2, "002_device_inventory", ...)`
- `Migration(3, "003_wifi_scans", ...)`
- `Migration(4, "004_tls_audits", ...)`
- `Migration(5, "005_audit_trail_sessions", ...)`

Migrations are applied forward-only. Automatic database downgrades are strictly prohibited (`SchemaVersionError`).

### 2.2 Version & Checksum Tracking
Applied migrations are recorded in a dedicated metadata table:

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    checksum TEXT NOT NULL
);
```

- **Checksum Computation:** Deterministic SHA-256 hash computed over normalized migration SQL text (normalized line endings and trimmed whitespace).
- **History Continuity & Identity Validation:** Before applying pending migrations, `MigrationRunner.validate_applied_history()` verifies:
  1. No duplicate versions exist in `schema_migrations`.
  2. Applied migrations form a strictly contiguous, 1-indexed sequence `1..N` (gaps raise `SchemaVersionError`).
  3. No unknown future versions exceed the maximum known migration version.
  4. Recorded migration names match canonical definitions line-for-line.
  5. Recorded checksums match canonical SHA-256 digests. If mismatched, fails closed with `MigrationChecksumError`.

### 2.3 Transactional Application, Atomicity & Concurrency
Every migration is executed inside an atomic transaction:
1. `conn.isolation_level = None` is set for manual transaction control, and the caller's original `isolation_level` is deterministically restored in a `finally` block upon completion or failure.
2. `BEGIN IMMEDIATE;` acquires a reserved write lock to prevent concurrent write collisions.
3. While holding the transaction lock, the runner re-queries `schema_migrations` for the current version: if a concurrent worker has already committed the migration, it verifies recorded name/checksum and cleanly commits the no-op transaction without raising uniqueness errors.
4. Individual DDL statements are executed sequentially.
5. An entry is inserted into `schema_migrations`.
6. `COMMIT;` finalizes the migration.

**Failure Behavior:** If any statement in the migration fails, `ROLLBACK;` is immediately executed. The database returns to its pre-migration state with no partial tables or corrupted metadata.

### 2.4 Pre-Migration Integrity Checks
Before modifying any database file, `MigrationRunner` executes:
```sql
PRAGMA quick_check;
```
If the check returns anything other than `ok` (or raises `sqlite3.DatabaseError`), the engine raises `DatabaseCorruptionError` and aborts immediately. The database file is **never** deleted, wiped, or overwritten.

### 2.5 SQLite-Aware Statement Splitting
Individual statements within a migration script are split using SQLite's native statement completeness parser (`sqlite3.complete_statement`). This accurately handles semicolons nested inside quotes, string literals, or SQL comments without third-party dependencies.

---

## 3. Existing Database Adoption & Pre-Migration Schema Validation

Pre-existing databases may already contain legacy tables created prior to versioned migrations:
- `diagnostic_runs`
- `subnet_history`
- `dns_history`
- `latency_history`

**Baseline Adoption (Migration 001):**
- **Pre-Migration Structural Validation:** Before recording baseline version 1, `validate_legacy_schemas()` inspects `sqlite_master` and `PRAGMA table_info` for all pre-existing legacy tables.
  - Verifies presence of all required columns (`cidr`, `usable_hosts`, `network_address`, `broadcast_address` on `subnet_history`, etc.).
  - Verifies primary key constraints (`id INTEGER PRIMARY KEY`).
  - Verifies compatible column types.
  - If any pre-existing table has an incompatible or corrupt structure, raises `IncompatibleSchemaError` and fails closed without creating a version 1 record or altering existing user rows.
- **Clean Adoption:** When pre-existing tables pass validation, Migration 001 creates `schema_migrations`, establishes version 1, safely creates any missing legacy tables, and preserves 100% of existing rows, primary keys, and data without interruption or recreation.

**Audit Trail Pre-Migration Validation (Migration 005 / SEC-008):**
- **Pre-Migration Structural Validation:** Before applying version 5, `validate_migration_005_schemas()` inspects `sqlite_master` for pre-existing `diagnostic_sessions` or `diagnostic_snapshots` tables.
  - Verifies that both tables either do not exist (clean creation) or both exist with 100% compatible schemas (partial pre-existing schemas fail closed).
  - Verifies all required columns, primary keys, and compatible types on both tables.
  - Verifies `session_uuid` has a `UNIQUE` constraint on `diagnostic_sessions`.
  - Verifies foreign key referencing `diagnostic_sessions(id)` with `ON DELETE CASCADE` on `diagnostic_snapshots`.
  - If any check fails, raises `IncompatibleSchemaError` and rolls back atomically, leaving pre-existing data intact and preventing migration 005 from being falsely recorded as applied.

---

## 4. Target Domain Schemas

### 4.1 Multi-Vendor Discovered Device Inventory (Migration 002)
- **`discovered_devices`:** Stores hardware profiles, category enums, vendor, model, MAC, IP, firmware version, and JSON telemetry attributes.
- **`device_evidence_records`:** Stores protocol attribution records (`MNDP`, `ONVIF`, etc.), confidence score (0.0 to 1.0), and the crucial `is_verified_fact` boolean flag distinguishing direct observations from heuristic claims.
- **Foreign Keys:** `device_evidence_records.device_row_id` references `discovered_devices(id)` with `ON DELETE CASCADE`.

### 4.2 Wireless Airwave Scans (Migration 003)
- **`wifi_scan_sessions`:** Metadata for airwave inspection runs (interface, band, scan timestamp, total APs).
- **`wifi_access_points`:** Access point telemetry (SSID, BSSID, RSSI, channel, frequency, channel width, security protocol, 802.11 generation, WPS status).
- **Foreign Keys:** `wifi_access_points.session_id` references `wifi_scan_sessions(id)` with `ON DELETE CASCADE`.

### 4.3 TLS / SSL Cryptographic Audits (Migration 004)
- **`tls_inspection_reports`:** Handshake diagnostics, negotiated protocol/cipher, cryptographic security rating, overall posture score (0–100), and vulnerability findings.
- **`tls_certificates`:** Public X.509 certificate chain records (subject CN, issuer, validity period, days to expiration, expired/self-signed flags, SHA-256 fingerprint, key size).
- **Foreign Keys:** `tls_certificates.report_id` references `tls_inspection_reports(id)` with `ON DELETE CASCADE`.

### 4.4 Audit Trail & Diagnostic Sessions (Migration 005)
- **`diagnostic_sessions`:** Encapsulates an operator-initiated or automated diagnostic run with scoped lifecycle metadata.
  - Columns: `id` (INTEGER PRIMARY KEY), `session_uuid` (TEXT UNIQUE NOT NULL), `name` (TEXT NOT NULL), `operator` (TEXT NOT NULL DEFAULT 'system'), `scope_enclosure_json` (TEXT), `status` (TEXT NOT NULL DEFAULT 'running'), `started_at` (TIMESTAMP DEFAULT CURRENT_TIMESTAMP), `completed_at` (TIMESTAMP), `summary_json` (TEXT), `metadata_json` (TEXT).
  - Indexes: `idx_diag_sessions_uuid` (`session_uuid`), `idx_diag_sessions_status` (`status`), `idx_diag_sessions_started` (`started_at`).
- **`diagnostic_snapshots`:** Granular time-series diagnostic findings and domain payloads captured during an active session.
  - Columns: `id` (INTEGER PRIMARY KEY), `session_id` (INTEGER NOT NULL), `snapshot_type` (TEXT NOT NULL), `target` (TEXT), `status` (TEXT NOT NULL), `payload_json` (TEXT NOT NULL), `redacted_fields_count` (INTEGER NOT NULL DEFAULT 0), `created_at` (TIMESTAMP DEFAULT CURRENT_TIMESTAMP).
  - Foreign Keys: `session_id` references `diagnostic_sessions(id)` with `ON DELETE CASCADE`. Foreign key enforcement (`PRAGMA foreign_keys = ON;`) is mandated on all connections.
  - Indexes: `idx_diag_snapshots_session` (`session_id`), `idx_diag_snapshots_type` (`snapshot_type`), `idx_diag_snapshots_created` (`created_at`).

---

## 5. Credential Redaction & Security Boundary (`CredentialRedactor`)

### 5.1 Mandatory Pre-Persistence Redaction
Every session snapshot payload, summary, and metadata structure must pass through `CredentialRedactor.redact()` before being serialized and committed to SQLite storage. The storage layer (`record_session_snapshot`, `create_diagnostic_session`, `complete_diagnostic_session`) strictly enforces this boundary: payloads that bypass sanitization are rejected before any SQL write occurs.

### 5.2 Standard Redaction Marker
All detected secrets are sanitized with the uniform, unambiguous marker:
`***REDACTED***`
Consistent with the application logging conventions. No deterministic hashing or HMAC secret correlation is performed, ensuring uninvertible protection.

### 5.3 Supported Detection Patterns
The redactor scrubs nested data structures (dictionaries, lists, tuples, primitives) and free-form diagnostic text:
1. **Case-Insensitive & Normalized Sensitive Keys:** Keys such as `password`, `passwd`, `pwd`, `secret`, `client_secret`, `token`, `access_token`, `refresh_token`, `api_key`, `apikey`, `authorization`, `proxy_authorization`, `wpa_key`, `psk`, `pre_shared_key`, `snmp_community`, `community`, `private_key`, `privateKey`, `credential`, `credentials` (and variations with hyphens, underscores, or camelCase).
2. **URI Embedded Credentials & Sensitive Query Parameters:**
   - **Userinfo:** Userinfo in camera and network URIs (`rtsp://user:pass@host/path`, `http://...`, `https://...`, `ftp://...`, `ssh://...`), supporting percent-encoded userinfo, IPv6 host literals (`rtsp://user:pass@[::1]:554/live`), optional ports, and username-only / password-only userinfo.
   - **Query Parameters:** Sensitive query parameters including `token`, `access_token`, `api_key`, `password`, `secret`, `community` (and variations with hyphens, underscores, or URL-encoding like `api%5Fkey`). Non-sensitive query parameters (e.g. `format=json`, `page=1`, `limit=50`) and URL fragments (`#section`) are safely preserved.
   - **Hash Fragments:** Sensitive OAuth2/token hash fragments (`#access_token=SECRET`) are sanitized.
3. **HTTP Authorization Headers & Tokens:** `Authorization: Bearer <token>`, `Authorization: Basic <base64>`, and standalone bearer tokens.
4. **PEM Cryptographic Private Keys:** PKCS#1, PKCS#8, EC, OpenSSH, and encrypted private key blocks (`-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN PRIVATE KEY-----`, etc.). Public certificates (`-----BEGIN CERTIFICATE-----`) are preserved.
5. **Wireless & IoT Credentials:** PSK, WPA passphrases, and RTSP stream credentials.
6. **SNMP Community Strings:** Structured SNMP configuration and key-value occurrences (`community: public`, `snmp_community=secret`).

### 5.4 Redaction Accounting
`RedactionResult.redacted_fields_count` tracks occurrences of sanitized secrets:
- Increments per dictionary sensitive key/value sanitized.
- Increments per URI userinfo, query parameter, or sensitive fragment sanitized.
- Increments per PEM private key block, Bearer token, Basic credential, or in-string key-value replaced.
- Idempotent: already redacted markers (`***REDACTED***`) are not counted again.

### 5.5 Fail-Closed Safety & Non-Guarantees
- **Fail-Closed Behavior:** If redaction fails or encounters un-serializable/invalid structures (e.g., circular references, unsupported types), a `RedactionError` is raised. The storage layer catches this and aborts persistence without writing raw data.
- **Exception Cleanliness:** Original sensitive payloads are never included in exception messages, traceback contexts, or system logs.
- **Limitations & Non-Guarantees:** Redaction relies on pattern recognition, known key vocabularies, and regex parsing. It **does not guarantee** universal or infallible detection of arbitrary, unstructured secrets, obfuscated credentials, or unknown custom encodings. High-risk credentials must not be introduced into untrusted diagnostic contexts.

---

## 6. Session Lifecycle Semantics & API Usage

### 6.1 Lifecycle State Machine
1. **Creation (`create_diagnostic_session`):** Generates a UUIDv4 session identifier, records non-secret session metadata, and sets initial status to `'running'` (or requested valid status).
2. **Snapshot Capture (`record_session_snapshot`):** Records point-in-time diagnostic findings. Validates parent session existence, redacts the payload, serializes to JSON, and stores the redacted field count atomically.
3. **Completion (`complete_diagnostic_session`):** Finalizes session status (`'completed'`, `'failed'`, `'aborted'`), records `completed_at` timestamp, and attaches an optional sanitized summary.
4. **Cascading Deletion (`delete_diagnostic_session`):** Deleting a session record cascades automatically to all associated snapshots via SQLite foreign key triggers.

### 6.2 API Usage Examples (Synthetic, Non-Sensitive Data)
```python
from itsa_network_os.storage.database import DatabaseManager

# Initialize isolated or persistent database
db = DatabaseManager(":memory:")
db.initialize()

# 1. Create a diagnostic session
session = db.create_diagnostic_session(
    name="Interface Health Audit",
    operator="net-admin",
    metadata={"scope": "edge-switch-01", "vlan": 100},
)
session_id = session["id"]

# 2. Record a diagnostic snapshot with sensitive data (auto-redacted)
snapshot = db.record_session_snapshot(
    session_id=session_id,
    snapshot_type="interface_status",
    target="sw01.internal",
    payload={
        "interface": "eth0",
        "status": "up",
        "api_key": "synth-key-abcdef123456",
        "rtsp_url": "rtsp://camera_user:synthetic_pass@192.0.2.10:554/live",
    },
)
# snapshot["redacted_fields_count"] == 2
# Payload in database:
# {
#   "interface": "eth0",
#   "status": "up",
#   "api_key": "***REDACTED***",
#   "rtsp_url": "rtsp://***REDACTED***@192.0.2.10:554/live"
# }

# 3. Complete the diagnostic session
db.complete_diagnostic_session(
    session_id=session_id,
    status="completed",
    summary={"total_interfaces": 1, "errors": 0},
)

# 4. Query session audit trail
session_record = db.get_diagnostic_session(session_id)
snapshots = db.get_session_snapshots(session_id)
```

---

## 7. Backup & Recovery Guidance

### 7.1 Routine Backup
To create a safe online backup of an active SQLite database:
```bash
sqlite3 ~/.config/itsa-network-os/data.sqlite3 ".backup ~/.config/itsa-network-os/data_backup.sqlite3"
```

### 7.2 Recovery from Corruption
If `DatabaseCorruptionError` is raised:
1. Do not delete the database file.
2. Inspect the file with SQLite's recovery tool:
   ```bash
   sqlite3 ~/.config/itsa-network-os/data.sqlite3 ".recover" | sqlite3 ~/.config/itsa-network-os/data_recovered.sqlite3
   ```
3. Test integrity on the recovered file:
   ```bash
   sqlite3 ~/.config/itsa-network-os/data_recovered.sqlite3 "PRAGMA integrity_check;"
   ```
4. Replace the corrupt file with the verified recovered copy or restore from backup.
