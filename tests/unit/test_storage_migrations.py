"""Unit and integration tests for SQLite schema migration engine (TASK-011)."""

import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from itsa_network_os.storage.database import DatabaseManager
from itsa_network_os.storage.migrations import (
    ALL_MIGRATIONS,
    DatabaseCorruptionError,
    IncompatibleSchemaError,
    Migration,
    MigrationChecksumError,
    MigrationError,
    MigrationRunner,
    SchemaVersionError,
)


class TestStorageMigrations(unittest.TestCase):
    """Exhaustive tests for SQLite schema migrations, integrity, and compatibility."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_data.sqlite3")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_fresh_database_initialization(self) -> None:
        """Requirement 1: Fresh database initialization creates all target tables and migrations."""
        db = DatabaseManager(self.db_path)
        self.assertEqual(db.get_schema_version(), 5)

        # Inspect all created tables
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
            tables = [r[0] for r in cursor.fetchall()]

        expected_tables = {
            "schema_migrations",
            "diagnostic_runs",
            "subnet_history",
            "dns_history",
            "latency_history",
            "discovered_devices",
            "device_evidence_records",
            "wifi_scan_sessions",
            "wifi_access_points",
            "tls_inspection_reports",
            "tls_certificates",
            "diagnostic_sessions",
            "diagnostic_snapshots",
        }
        self.assertTrue(expected_tables.issubset(set(tables)))

    def test_sequential_migration_application(self) -> None:
        """Requirement 2: Migrations apply strictly sequentially up to specified target versions."""
        db = DatabaseManager(self.db_path, auto_migrate=False)
        self.assertEqual(db.get_schema_version(), 0)

        # Step 1: Apply Migration 1
        applied_v1 = db.apply_migrations(target_version=1)
        self.assertEqual(applied_v1, [1])
        self.assertEqual(db.get_schema_version(), 1)
        with db._get_connection() as conn:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
        self.assertIn("subnet_history", tables)
        self.assertNotIn("discovered_devices", tables)

        # Step 2: Apply Migration 2
        applied_v2 = db.apply_migrations(target_version=2)
        self.assertEqual(applied_v2, [2])
        self.assertEqual(db.get_schema_version(), 2)
        with db._get_connection() as conn:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
        self.assertIn("discovered_devices", tables)
        self.assertNotIn("wifi_access_points", tables)

        # Step 3: Apply Migration 3
        applied_v3 = db.apply_migrations(target_version=3)
        self.assertEqual(applied_v3, [3])
        self.assertEqual(db.get_schema_version(), 3)
        with db._get_connection() as conn:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
        self.assertIn("wifi_access_points", tables)
        self.assertNotIn("tls_certificates", tables)

        # Step 4: Apply Migration 4
        applied_v4 = db.apply_migrations(target_version=4)
        self.assertEqual(applied_v4, [4])
        self.assertEqual(db.get_schema_version(), 4)
        with db._get_connection() as conn:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
        self.assertIn("tls_certificates", tables)
        self.assertNotIn("diagnostic_sessions", tables)

        # Step 5: Apply Migration 5 (TASK-012)
        applied_v5 = db.apply_migrations(target_version=5)
        self.assertEqual(applied_v5, [5])
        self.assertEqual(db.get_schema_version(), 5)
        with db._get_connection() as conn:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
        self.assertIn("diagnostic_sessions", tables)
        self.assertIn("diagnostic_snapshots", tables)

    def test_repeated_initialization_idempotency(self) -> None:
        """Requirement 3: Repeated instantiation is completely idempotent without duplicate migrations."""
        db1 = DatabaseManager(self.db_path)
        self.assertEqual(db1.get_schema_version(), 5)
        migrations_first = db1.get_applied_migrations()
        self.assertEqual(len(migrations_first), 5)

        # Re-open database with a second manager
        db2 = DatabaseManager(self.db_path)
        self.assertEqual(db2.get_schema_version(), 5)
        migrations_second = db2.get_applied_migrations()
        self.assertEqual(migrations_first, migrations_second)

    def test_existing_schema_baseline_adoption_without_data_loss(self) -> None:
        """Requirement 4 & SEC-005: Pre-existing tables and rows in all 4 legacy tables are adopted cleanly."""
        # Simulate legacy database created before migration engine existed, seeding all 4 tables
        raw_conn = sqlite3.connect(self.db_path)
        raw_conn.executescript(
            """
            CREATE TABLE diagnostic_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_type TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE subnet_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cidr TEXT NOT NULL,
                usable_hosts INTEGER NOT NULL,
                network_address TEXT NOT NULL,
                broadcast_address TEXT NOT NULL,
                calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE dns_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                status TEXT NOT NULL,
                response_time_ms REAL NOT NULL,
                records_json TEXT,
                queried_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE latency_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                packet_loss REAL NOT NULL,
                avg_latency_ms REAL NOT NULL,
                jitter_ms REAL NOT NULL,
                tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            INSERT INTO diagnostic_runs (id, run_type, status, details)
            VALUES (1, 'PING_SWEEP', 'COMPLETED', 'All 10 hosts reached');
            INSERT INTO subnet_history (id, cidr, usable_hosts, network_address, broadcast_address)
            VALUES (1, '10.0.0.0/24', 254, '10.0.0.0', '10.0.0.255');
            INSERT INTO dns_history (id, host, status, response_time_ms, records_json)
            VALUES (1, 'example.com', 'SUCCESS', 12.5, '["93.184.216.34"]');
            INSERT INTO latency_history (id, host, port, packet_loss, avg_latency_ms, jitter_ms)
            VALUES (1, '8.8.8.8', 53, 0.0, 15.2, 1.1);
            """
        )
        raw_conn.commit()
        raw_conn.close()

        # Open with DatabaseManager and let migration runner adopt baseline
        db = DatabaseManager(self.db_path)
        self.assertEqual(db.get_schema_version(), 5)

        # Verify pre-existing data in all 4 tables was preserved with exact primary keys and fields
        with db._get_connection() as conn:
            cur = conn.cursor()

            # 1. diagnostic_runs
            cur.execute("SELECT id, run_type, status, details FROM diagnostic_runs WHERE id = 1;")
            d_row = cur.fetchone()
            self.assertIsNotNone(d_row)
            self.assertEqual(d_row[0], 1)
            self.assertEqual(d_row[1], "PING_SWEEP")
            self.assertEqual(d_row[2], "COMPLETED")
            self.assertEqual(d_row[3], "All 10 hosts reached")

            # 2. subnet_history
            cur.execute("SELECT id, cidr, usable_hosts, network_address, broadcast_address FROM subnet_history WHERE id = 1;")
            s_row = cur.fetchone()
            self.assertIsNotNone(s_row)
            self.assertEqual(s_row[0], 1)
            self.assertEqual(s_row[1], "10.0.0.0/24")
            self.assertEqual(s_row[2], 254)
            self.assertEqual(s_row[3], "10.0.0.0")
            self.assertEqual(s_row[4], "10.0.0.255")

            # 3. dns_history
            cur.execute("SELECT id, host, status, response_time_ms, records_json FROM dns_history WHERE id = 1;")
            dns_row = cur.fetchone()
            self.assertIsNotNone(dns_row)
            self.assertEqual(dns_row[0], 1)
            self.assertEqual(dns_row[1], "example.com")
            self.assertEqual(dns_row[2], "SUCCESS")
            self.assertEqual(dns_row[3], 12.5)

            # 4. latency_history
            cur.execute("SELECT id, host, port, packet_loss, avg_latency_ms, jitter_ms FROM latency_history WHERE id = 1;")
            lat_row = cur.fetchone()
            self.assertIsNotNone(lat_row)
            self.assertEqual(lat_row[0], 1)
            self.assertEqual(lat_row[1], "8.8.8.8")
            self.assertEqual(lat_row[2], 53)
            self.assertEqual(lat_row[3], 0.0)
            self.assertEqual(lat_row[4], 15.2)
            self.assertEqual(lat_row[5], 1.1)

        # Verify helper query also works
        recent = db.get_recent_subnets()
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["id"], 1)
        self.assertEqual(recent[0]["cidr"], "10.0.0.0/24")

    def test_migration_checksum_mismatch(self) -> None:
        """Requirement 5: Modified migration definition is detected and fails closed with diagnostic."""
        db = DatabaseManager(self.db_path)
        self.assertEqual(db.get_schema_version(), 5)

        # Define an altered runner where migration 2 has tampered SQL
        tampered_m2 = Migration(2, "002_device_inventory", "-- TAMPERED SQL CONTENT")
        tampered_migrations = [
            ALL_MIGRATIONS[0],
            tampered_m2,
            ALL_MIGRATIONS[2],
            ALL_MIGRATIONS[3],
            ALL_MIGRATIONS[4],
        ]
        tampered_runner = MigrationRunner(migrations=tampered_migrations)

        # Attempting to initialize with tampered runner must raise MigrationChecksumError
        with self.assertRaises(MigrationChecksumError) as cm:
            DatabaseManager(self.db_path, migration_runner=tampered_runner)

        self.assertIn("Checksum mismatch", str(cm.exception))
        self.assertIn("v2", str(cm.exception))

    def test_transaction_rollback_after_failing_migration(self) -> None:
        """Requirement 6: Migration failure triggers atomic rollback leaving prior schema intact."""
        # Create a custom runner with a failing migration at version 3
        failing_m3_sql = """
        CREATE TABLE canary_table_should_rollback (id INTEGER PRIMARY KEY);
        INSERT INTO canary_table_should_rollback VALUES (1);
        SYNTAX ERROR INTENTIONAL FAILURE;
        """
        custom_migrations = [
            ALL_MIGRATIONS[0],
            ALL_MIGRATIONS[1],
            Migration(3, "003_failing_migration", failing_m3_sql),
        ]
        runner = MigrationRunner(migrations=custom_migrations)

        db = DatabaseManager(self.db_path, migration_runner=runner, auto_migrate=False)
        # Apply v1 and v2 successfully
        db.apply_migrations(target_version=2)
        self.assertEqual(db.get_schema_version(), 2)

        # Attempting to apply v3 should fail and rollback
        with self.assertRaises(MigrationError) as cm:
            db.apply_migrations(target_version=3)

        self.assertIn("failed during execution", str(cm.exception))
        # Schema version remains at 2
        self.assertEqual(db.get_schema_version(), 2)

        # Verify canary table does not exist
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='canary_table_should_rollback';"
            )
            self.assertIsNone(cursor.fetchone())

    def test_schema_version_and_downgrade_prohibition(self) -> None:
        """Requirement 7: Schema version queries work, and database downgrades are rejected."""
        db = DatabaseManager(self.db_path)
        self.assertEqual(db.get_schema_version(), 5)

        applied = db.get_applied_migrations()
        self.assertEqual(len(applied), 5)
        self.assertEqual(applied[0]["version"], 1)
        self.assertEqual(applied[4]["version"], 5)

        # Requesting lower target version than current must raise SchemaVersionError
        with self.assertRaises(SchemaVersionError) as cm:
            db.apply_migrations(target_version=2)
        self.assertIn("downgrades are strictly prohibited", str(cm.exception))

    def test_foreign_key_and_cascade_constraints(self) -> None:
        """Requirement 8: Foreign keys and cascading deletes are strictly enforced."""
        db = DatabaseManager(self.db_path)

        # Test foreign key enforcement: cannot add evidence to non-existent device
        with self.assertRaises(sqlite3.IntegrityError):
            db.record_device_evidence(
                device_row_id=99999,
                source_protocol="MNDP",
                timestamp="2026-10-19T12:00:00Z",
                confidence=1.0,
                is_verified_fact=True,
            )

        # Insert valid device
        dev_row_id = db.record_discovered_device(
            device_id="TEST-01",
            name="Test Router",
            category="MikroTik RouterOS",
            vendor="MikroTik",
            model="RB4011",
            ip_address="192.168.88.1",
            mac_address="48:8F:5A:11:22:33",
            firmware_version="7.12",
            discovery_protocol="MNDP",
            security_status="SECURE",
        )
        self.assertGreater(dev_row_id, 0)

        # Insert valid evidence record
        ev_id = db.record_device_evidence(
            device_row_id=dev_row_id,
            source_protocol="MNDP",
            timestamp="2026-10-19T12:00:00Z",
            confidence=1.0,
            is_verified_fact=True,
            attribute="model",
            details="RB4011",
        )
        self.assertGreater(ev_id, 0)

        devices = db.get_discovered_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(len(devices[0]["evidence"]), 1)
        self.assertTrue(devices[0]["evidence"][0]["is_verified_fact"])

        # Test cascade delete: deleting device removes evidence records
        with db._get_connection() as conn:
            conn.execute("DELETE FROM discovered_devices WHERE id = ?;", (dev_row_id,))
            conn.commit()

        devices_after = db.get_discovered_devices()
        self.assertEqual(len(devices_after), 0)
        with db._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM device_evidence_records;")
            self.assertEqual(cur.fetchone()[0], 0)

    def test_corrupt_database_behavior(self) -> None:
        """Requirement 9: Corrupted database file fails closed without destructive overwrite."""
        # Create a file filled with garbage random bytes
        with open(self.db_path, "wb") as f:
            f.write(b"CORRUPT_RANDOM_GARBAGE_HEADER_DATA" * 50)

        with self.assertRaises(DatabaseCorruptionError) as cm:
            DatabaseManager(self.db_path)

        self.assertIn("Database integrity check failed", str(cm.exception))
        self.assertIn("restore from backup", str(cm.exception).lower())

        # Ensure the file was not deleted or replaced
        self.assertTrue(os.path.exists(self.db_path))
        with open(self.db_path, "rb") as f:
            content = f.read()
        self.assertTrue(content.startswith(b"CORRUPT_RANDOM_GARBAGE"))

    def test_in_memory_database_initialization(self) -> None:
        """Requirement 10: In-memory database initializes all migrations and retains state."""
        db = DatabaseManager(":memory:")
        self.assertEqual(db.get_schema_version(), 5)

        # Record data
        sub_id = db.record_subnet_query("192.168.1.0/24", 254, "192.168.1.0", "192.168.1.255")
        self.assertGreater(sub_id, 0)

        # Retrieve data from same in-memory manager
        recent = db.get_recent_subnets()
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["cidr"], "192.168.1.0/24")

    def test_concurrent_access_busy_timeout(self) -> None:
        """Requirement 11: Busy timeout pragma handles concurrent connections safely."""
        db = DatabaseManager(self.db_path)
        self.assertEqual(db.get_schema_version(), 5)

        # Connect with a second independent connection
        conn2 = sqlite3.connect(self.db_path)
        conn2.execute("PRAGMA foreign_keys = ON;")
        conn2.execute("PRAGMA busy_timeout = 5000;")

        # Write on conn1
        db.record_subnet_query("10.1.0.0/16", 65534, "10.1.0.0", "10.1.255.255")

        # Read on conn2
        cur2 = conn2.cursor()
        cur2.execute("SELECT count(*) FROM subnet_history;")
        self.assertEqual(cur2.fetchone()[0], 1)
        conn2.close()

    def test_target_domain_helpers(self) -> None:
        """Requirement 12: Storage helpers for Device Inventory, Wi-Fi Scans, and TLS Audits work accurately."""
        db = DatabaseManager(self.db_path)

        # 1. Device Inventory helper
        dev_id = db.record_discovered_device(
            device_id="CAM-01",
            name="Front Gate Camera",
            category="IP Camera / CCTV",
            vendor="Hikvision",
            model="DS-2CD2143G2-I",
            ip_address="192.168.1.120",
            mac_address="BC:54:36:11:A2:99",
            firmware_version="V5.7.12",
            discovery_protocol="ONVIF WS-Discovery (UDP 3702)",
            security_status="Warning (Default Credentials / Port Exposed)",
            security_notes=["Default password active"],
            telemetry={"rtsp_uri": "rtsp://192.168.1.120:554/live"},
        )
        self.assertGreater(dev_id, 0)
        devices = db.get_discovered_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["vendor"], "Hikvision")
        self.assertEqual(devices[0]["security_notes"], ["Default password active"])
        self.assertEqual(devices[0]["telemetry"]["rtsp_uri"], "rtsp://192.168.1.120:554/live")

        # 2. Wi-Fi Scans helper
        sess_id = db.record_wifi_scan_session(interface_name="wlan0", band="5 GHz", total_aps=1)
        ap_id = db.record_wifi_access_point(
            session_id=sess_id,
            ssid="Office-WiFi",
            bssid="00:11:22:33:44:55",
            rssi_dbm=-62,
            signal_percent=78,
            channel=36,
            frequency_mhz=5180,
            channel_width_mhz=80,
            security="WPA2-PSK (AES/CCMP)",
            standard="Wi-Fi 5 (802.11ac)",
            wps_enabled=False,
            security_warnings=[],
        )
        self.assertGreater(ap_id, 0)
        aps = db.get_recent_wifi_aps()
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0]["ssid"], "Office-WiFi")
        self.assertEqual(aps[0]["channel"], 36)

        # 3. TLS Audits helper
        rep_id = db.record_tls_inspection_report(
            target_host="gateway.local",
            target_port=443,
            negotiated_protocol="TLSv1.3",
            negotiated_cipher="TLS_AES_256_GCM_SHA384",
            cipher_security="Strong (PFS/AEAD)",
            overall_score=95,
            vulnerabilities=[],
            recommendations=["Enable HSTS"],
        )
        self.assertGreater(rep_id, 0)
        cert_id = db.record_tls_certificate(
            report_id=rep_id,
            chain_position=0,
            subject_cn="gateway.local",
            issuer_cn="Local Internal CA",
            valid_from="2026-01-01",
            valid_to="2027-01-01",
            days_until_expiration=73,
            is_expired=False,
            is_self_signed=False,
        )
        self.assertGreater(cert_id, 0)
        reports = db.get_recent_tls_reports()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["target_host"], "gateway.local")
        self.assertEqual(len(reports[0]["certificates"]), 1)
        self.assertEqual(reports[0]["certificates"][0]["subject_cn"], "gateway.local")

    # -------------------------------------------------------------------------
    # Regressions & Acceptance Tests for Audit Findings (SEC-001 to SEC-005)
    # -------------------------------------------------------------------------

    def test_incompatible_legacy_schema_missing_column(self) -> None:
        """SEC-001: Pre-existing legacy table missing required column fails closed without creating baseline."""
        conn = sqlite3.connect(self.db_path)
        # Missing 'cidr', 'usable_hosts', 'network_address', 'broadcast_address'
        conn.execute("CREATE TABLE subnet_history (id INTEGER PRIMARY KEY, corrupted_notes TEXT);")
        conn.execute("INSERT INTO subnet_history (id, corrupted_notes) VALUES (1, 'sentinel_user_data');")
        conn.commit()
        conn.close()

        # DatabaseManager must fail closed with IncompatibleSchemaError
        with self.assertRaises(IncompatibleSchemaError) as cm:
            DatabaseManager(self.db_path)

        self.assertIn("missing required column", str(cm.exception))
        self.assertIn("subnet_history", str(cm.exception))

        # Verify no baseline version record was created
        check_conn = sqlite3.connect(self.db_path)
        cur = check_conn.cursor()
        cur.execute("SELECT count(*) FROM schema_migrations WHERE version = 1;")
        self.assertEqual(cur.fetchone()[0], 0)

        # Verify existing user data was NOT deleted or overwritten
        cur.execute("SELECT corrupted_notes FROM subnet_history WHERE id = 1;")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "sentinel_user_data")
        check_conn.close()

    def test_incompatible_legacy_schema_invalid_primary_key(self) -> None:
        """SEC-001: Pre-existing legacy table with invalid primary key is rejected."""
        conn = sqlite3.connect(self.db_path)
        # diagnostic_runs where id is not primary key
        conn.execute(
            """
            CREATE TABLE diagnostic_runs (
                id INTEGER,
                run_type TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.commit()
        conn.close()

        with self.assertRaises(IncompatibleSchemaError) as cm:
            DatabaseManager(self.db_path)

        self.assertIn("must be declared as PRIMARY KEY", str(cm.exception))

    def test_partially_existing_compatible_legacy_schema(self) -> None:
        """SEC-001: Partially existing but compatible legacy schema adopts valid tables and creates missing ones."""
        conn = sqlite3.connect(self.db_path)
        # Create only 2 of the 4 legacy tables with compatible schemas
        conn.execute(
            """
            CREATE TABLE diagnostic_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_type TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE subnet_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cidr TEXT NOT NULL,
                usable_hosts INTEGER NOT NULL,
                network_address TEXT NOT NULL,
                broadcast_address TEXT NOT NULL,
                calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            "INSERT INTO subnet_history (cidr, usable_hosts, network_address, broadcast_address) VALUES ('172.16.0.0/12', 1048574, '172.16.0.0', '172.31.255.255');"
        )
        conn.commit()
        conn.close()

        # DatabaseManager must validate the 2 existing tables and create the 2 missing legacy tables cleanly
        db = DatabaseManager(self.db_path)
        self.assertEqual(db.get_schema_version(), 5)

        # Confirm all 4 legacy tables now exist
        with db._get_connection() as c:
            tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()}
        self.assertTrue({"diagnostic_runs", "subnet_history", "dns_history", "latency_history"}.issubset(tables))

        # Confirm seeded data was preserved
        recent = db.get_recent_subnets()
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["cidr"], "172.16.0.0/12")

    def test_non_contiguous_migration_history_fails(self) -> None:
        """SEC-002: Non-contiguous migration history gaps are detected and rejected."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, checksum TEXT NOT NULL);"
        )
        runner = MigrationRunner()
        m1 = runner.migrations[0]
        m3 = runner.migrations[2]
        # Insert v1 and v3 directly, omitting v2
        conn.execute("INSERT INTO schema_migrations (version, name, checksum) VALUES (1, ?, ?);", (m1.name, m1.checksum))
        conn.execute("INSERT INTO schema_migrations (version, name, checksum) VALUES (3, ?, ?);", (m3.name, m3.checksum))
        conn.commit()
        conn.close()

        with self.assertRaises(SchemaVersionError) as cm:
            DatabaseManager(self.db_path)

        self.assertIn("Non-contiguous migration history", str(cm.exception))
        self.assertIn("missing intermediate version(s) [2]", str(cm.exception))

    def test_unknown_future_migration_version_fails(self) -> None:
        """SEC-002: Unknown future database version is rejected."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, checksum TEXT NOT NULL);"
        )
        # Record unknown future version 99
        conn.execute("INSERT INTO schema_migrations (version, name, checksum) VALUES (99, '999_future_migration', 'dummy');")
        conn.commit()
        conn.close()

        with self.assertRaises(SchemaVersionError) as cm:
            DatabaseManager(self.db_path)

        self.assertIn("newer than maximum known migration version", str(cm.exception))

    def test_migration_name_mismatch_fails(self) -> None:
        """SEC-002: Recorded migration name mismatch fails closed."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, checksum TEXT NOT NULL);"
        )
        runner = MigrationRunner()
        m1 = runner.migrations[0]
        # Insert v1 with corrupted name
        conn.execute("INSERT INTO schema_migrations (version, name, checksum) VALUES (1, '001_corrupted_name', ?);", (m1.checksum,))
        conn.commit()
        conn.close()

        with self.assertRaises(SchemaVersionError) as cm:
            DatabaseManager(self.db_path)

        self.assertIn("Migration name mismatch for v1", str(cm.exception))

    def test_concurrent_initialization_separate_connections(self) -> None:
        """SEC-003: Concurrent initializations with independent connections complete safely without duplicate errors."""
        barrier = threading.Barrier(5)
        errors: list[tuple[int, Exception]] = []

        def worker(thread_idx: int) -> None:
            try:
                barrier.wait()
                db = DatabaseManager(self.db_path)
                self.assertEqual(db.get_schema_version(), 5)
            except Exception as e:
                errors.append((thread_idx, e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent initializations encountered errors: {errors}")

        # Verify final state
        db = DatabaseManager(self.db_path)
        self.assertEqual(db.get_schema_version(), 5)
        applied = db.get_applied_migrations()
        self.assertEqual(len(applied), 5)
        self.assertEqual([m["version"] for m in applied], [1, 2, 3, 4, 5])

        with db._get_connection() as c:
            tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()}
        expected = {
            "schema_migrations", "diagnostic_runs", "subnet_history", "dns_history", "latency_history",
            "discovered_devices", "device_evidence_records", "wifi_scan_sessions", "wifi_access_points",
            "tls_inspection_reports", "tls_certificates", "diagnostic_sessions", "diagnostic_snapshots",
        }
        self.assertTrue(expected.issubset(tables))

    def test_connection_isolation_level_restoration(self) -> None:
        """SEC-004: MigrationRunner.apply restores connection isolation_level on success and failure."""
        runner = MigrationRunner()

        # 1. Test success path
        conn = sqlite3.connect(self.db_path)
        initial_isolation = conn.isolation_level
        runner.apply(conn)
        self.assertEqual(conn.isolation_level, initial_isolation)
        conn.close()

        # 2. Test failure path: isolation_level is restored and transaction is rolled back
        failing_runner = MigrationRunner(
            migrations=[
                ALL_MIGRATIONS[0],
                ALL_MIGRATIONS[1],
                ALL_MIGRATIONS[2],
                ALL_MIGRATIONS[3],
                ALL_MIGRATIONS[4],
                Migration(6, "006_failing", "CREATE TABLE canary_fail (id INT); SYNTAX ERROR;"),
            ]
        )
        conn2 = sqlite3.connect(self.db_path)
        initial_isolation_2 = conn2.isolation_level
        with self.assertRaises(MigrationError):
            failing_runner.apply(conn2)

        self.assertEqual(conn2.isolation_level, initial_isolation_2)
        # Canary table rolled back
        cur = conn2.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='canary_fail';")
        self.assertIsNone(cur.fetchone())
        conn2.close()

        # 3. Test in-memory database retains transactional capability with with conn:
        mem_db = DatabaseManager(":memory:")
        self.assertEqual(mem_db._mem_conn.isolation_level, "")

        with self.assertRaises(RuntimeError):
            with mem_db._mem_conn as m_conn:
                m_conn.execute(
                    "INSERT INTO subnet_history (cidr, usable_hosts, network_address, broadcast_address) "
                    "VALUES ('192.168.100.0/24', 254, '192.168.100.0', '192.168.100.255');"
                )
                raise RuntimeError("intentional abort")

        cur_mem = mem_db._mem_conn.cursor()
        cur_mem.execute("SELECT count(*) FROM subnet_history WHERE cidr = '192.168.100.0/24';")
        self.assertEqual(cur_mem.fetchone()[0], 0)
        mem_db.close()

    def test_upgrade_from_v4_to_v5(self) -> None:
        """Requirement: Upgrade from schema version 4 to 5 preserves all prior data and tables."""
        # 1. Initialize runner strictly up to v4
        db = DatabaseManager(self.db_path, auto_migrate=False)
        db.apply_migrations(target_version=4)
        self.assertEqual(db.get_schema_version(), 4)

        # Seed data across v1-v4 tables
        dev_id = db.record_discovered_device(
            device_id="ROUTER-01",
            name="Core Router",
            category="MikroTik RouterOS",
            vendor="MikroTik",
            model="CCR1009",
            ip_address="192.168.88.1",
            mac_address="E4:8D:8C:01:02:03",
            firmware_version="7.10",
            discovery_protocol="MNDP",
            security_status="SECURE",
        )
        self.assertGreater(dev_id, 0)

        # 2. Upgrade to v5
        applied = db.apply_migrations(target_version=5)
        self.assertEqual(applied, [5])
        self.assertEqual(db.get_schema_version(), 5)

        # Verify prior data intact
        devices = db.get_discovered_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["name"], "Core Router")

        # Verify v5 functionality operational
        sess_id = db.create_diagnostic_session(name="Post-Upgrade Audit")
        self.assertGreater(sess_id, 0)
        snap_id = db.record_session_snapshot(
            session_id=sess_id,
            snapshot_type="UPGRADE_VERIFY",
            payload={"status": "OK", "token": "secret123"},
        )
        self.assertGreater(snap_id, 0)
        sess = db.get_diagnostic_session(sess_id)
        self.assertEqual(sess["snapshots"][0]["payload"]["token"], "***REDACTED***")
        db.close()

    def test_migration_005_fails_when_sessions_table_incompatible(self) -> None:
        """Check 1: Pre-existing incompatible diagnostic_sessions table fails closed on migration 5."""
        db = DatabaseManager(self.db_path, auto_migrate=False)
        db.apply_migrations(target_version=4)
        self.assertEqual(db.get_schema_version(), 4)

        # Inject incompatible diagnostic_sessions table (missing session_uuid, operator, etc.)
        conn = db._get_connection()
        try:
            conn.execute("CREATE TABLE diagnostic_sessions (id INTEGER PRIMARY KEY, legacy_notes TEXT);")
            conn.execute("INSERT INTO diagnostic_sessions (id, legacy_notes) VALUES (1, 'Legacy run');")
            conn.commit()
        finally:
            conn.close()

        # Attempt to migrate to v5: must fail closed with IncompatibleSchemaError
        with self.assertRaises(MigrationError) as cm:
            db.apply_migrations(target_version=5)
        self.assertIn("Incompatible pre-existing schema for migration 5", str(cm.exception))

        # Schema version must remain at 4
        self.assertEqual(db.get_schema_version(), 4)

        # Legacy data must remain intact and unmodified
        conn2 = db._get_connection()
        try:
            row = conn2.execute("SELECT legacy_notes FROM diagnostic_sessions WHERE id = 1;").fetchone()
            self.assertEqual(row[0], "Legacy run")
        finally:
            conn2.close()
        db.close()

    def test_migration_005_fails_when_sessions_uuid_not_unique(self) -> None:
        """Check 1: Pre-existing diagnostic_sessions lacking UNIQUE constraint on session_uuid fails closed."""
        db = DatabaseManager(self.db_path, auto_migrate=False)
        db.apply_migrations(target_version=4)
        self.assertEqual(db.get_schema_version(), 4)

        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE diagnostic_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_uuid TEXT NOT NULL,
                    name TEXT NOT NULL,
                    operator TEXT DEFAULT 'system',
                    scope_enclosure_json TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    summary_json TEXT,
                    metadata_json TEXT
                );
            """)
            conn.execute("""
                CREATE TABLE diagnostic_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL REFERENCES diagnostic_sessions(id) ON DELETE CASCADE,
                    snapshot_type TEXT NOT NULL,
                    target TEXT,
                    status TEXT NOT NULL DEFAULT 'COMPLETED',
                    payload_json TEXT NOT NULL,
                    redacted_fields_count INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(MigrationError) as cm:
            db.apply_migrations(target_version=5)
        self.assertIn("must have a UNIQUE constraint", str(cm.exception))
        self.assertEqual(db.get_schema_version(), 4)
        db.close()

    def test_migration_005_fails_when_snapshots_lacks_cascade_fk(self) -> None:
        """Check 1: Pre-existing diagnostic_snapshots lacking ON DELETE CASCADE foreign key fails closed."""
        db = DatabaseManager(self.db_path, auto_migrate=False)
        db.apply_migrations(target_version=4)
        self.assertEqual(db.get_schema_version(), 4)

        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE diagnostic_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_uuid TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    operator TEXT DEFAULT 'system',
                    scope_enclosure_json TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    summary_json TEXT,
                    metadata_json TEXT
                );
            """)
            conn.execute("""
                CREATE TABLE diagnostic_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL REFERENCES diagnostic_sessions(id),
                    snapshot_type TEXT NOT NULL,
                    target TEXT,
                    status TEXT NOT NULL DEFAULT 'COMPLETED',
                    payload_json TEXT NOT NULL,
                    redacted_fields_count INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(MigrationError) as cm:
            db.apply_migrations(target_version=5)
        self.assertIn("with ON DELETE CASCADE", str(cm.exception))
        self.assertEqual(db.get_schema_version(), 4)
        db.close()

    def test_migration_005_fails_when_only_one_table_exists(self) -> None:
        """Check 1: Pre-existing state where one audit trail table exists but the other does not fails closed."""
        db = DatabaseManager(self.db_path, auto_migrate=False)
        db.apply_migrations(target_version=4)

        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE diagnostic_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    snapshot_type TEXT NOT NULL,
                    target TEXT,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    redacted_fields_count INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(MigrationError) as cm:
            db.apply_migrations(target_version=5)
        self.assertIn("exists but 'diagnostic_sessions' is missing", str(cm.exception))
        self.assertEqual(db.get_schema_version(), 4)
        db.close()

    def test_migration_005_safely_adopts_fully_compatible_preexisting_tables(self) -> None:
        """Check 1: Fully compatible pre-existing audit trail tables are safely adopted without data loss."""
        db = DatabaseManager(self.db_path, auto_migrate=False)
        db.apply_migrations(target_version=4)

        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE diagnostic_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_uuid TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    operator TEXT DEFAULT 'system',
                    scope_enclosure_json TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    summary_json TEXT,
                    metadata_json TEXT
                );
            """)
            conn.execute("""
                CREATE TABLE diagnostic_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL REFERENCES diagnostic_sessions(id) ON DELETE CASCADE,
                    snapshot_type TEXT NOT NULL,
                    target TEXT,
                    status TEXT NOT NULL DEFAULT 'COMPLETED',
                    payload_json TEXT NOT NULL,
                    redacted_fields_count INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("INSERT INTO diagnostic_sessions (id, session_uuid, name) VALUES (1, 'pre-existing-uuid-1', 'Pre-Session');")
            conn.commit()
        finally:
            conn.close()

        # Migrate to v5: should cleanly adopt without error
        applied = db.apply_migrations(target_version=5)
        self.assertEqual(applied, [5])
        self.assertEqual(db.get_schema_version(), 5)

        # Pre-existing session data must remain intact
        sess = db.get_diagnostic_session(1)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["name"], "Pre-Session")
        db.close()

if __name__ == "__main__":
    unittest.main()
