"""Local SQLite storage engine for diagnostic persistence."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


class DatabaseManager:
    """Manages local SQLite database operations safely."""

    SCHEMA = """
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

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:")
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        conn = self._get_connection()
        conn.executescript(self.SCHEMA)
        conn.commit()
        if self._mem_conn is None:
            conn.close()

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
