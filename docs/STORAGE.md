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

---

## 5. Backup & Recovery Guidance

### 5.1 Routine Backup
To create a safe online backup of an active SQLite database:
```bash
sqlite3 ~/.config/itsa-network-os/data.sqlite3 ".backup ~/.config/itsa-network-os/data_backup.sqlite3"
```

### 5.2 Recovery from Corruption
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
