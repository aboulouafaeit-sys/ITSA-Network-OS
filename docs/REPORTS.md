# Technical Reports & Multi-Format Exporter

## 1. Overview

The Technical Report Exporter subsystem (`src/itsa_network_os/reports/exporter.py`) provides standardized multi-format export capabilities for diagnostic sessions and audit trail records recorded by ITSA Network OS (TASK-013).

It satisfies requirements **REQ-STOR-002** and **REQ-STOR-003**, enabling network engineers and security auditors to extract audit trails, diagnostic snapshots, and device evidence into:

1. **JSON (`json`)**: Structured, machine-readable envelope with schema versioning (`1.0.0`), Unicode preservation, and complete nested hierarchy.
2. **CSV (`csv`)**: RFC 4180 compliant tabular format suitable for spreadsheet analysis, featuring dynamic scalar column expansion alongside a lossless `payload_json` column.
3. **Markdown (`markdown` / `md`)**: Human-readable technical assessment report formatted in GitHub Flavored Markdown (GFM), including executive metrics, authorized scope enclosures, snapshot catalogs, detailed JSON code blocks, and automated secret redaction disclosures.

---

## 2. Core Architecture & Workflow

```
+-------------------------------------------------------------+
|                     Application Controller                  |
|                 app.export_diagnostic_session()             |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                      DatabaseManager                        |
|             get_diagnostic_session(include_snapshots=True)  |
+------------------------------+------------------------------+
                               | Read-Only Query
                               v
+-------------------------------------------------------------+
|                       ReportExporter                        |
|                                                             |
|   1. Defense-in-Depth Redaction (CredentialRedactor)        |
|   2. Format Serializer (JSON / CSV / Markdown)              |
|   3. Filesystem Persistence (write_report_file)             |
|      - Path Traversal & Null-Byte Rejection                 |
|      - Race-Safe O_CREAT | O_EXCL (overwrite=False)         |
|      - Atomic Tempfile + os.replace (overwrite=True)        |
|      - 0o600 File Permissions / Failure Cleanup             |
+-------------------------------------------------------------+
```

### Defense-in-Depth Secret Scrubbing

While snapshots recorded into SQLite are scrubbed prior to database storage (TASK-012), the exporter applies `CredentialRedactor.redact()` immediately prior to formatting and file persistence. This guarantees that unpersisted in-memory objects or sessions imported from external contexts never leak API tokens, passwords, private keys, or URL credentials into exported artifacts.

---

## 3. Supported Formats & Specifications

### 3.1 JSON Format Specification

The JSON exporter (`ReportExporter.to_json_report()`) produces UTF-8 encoded JSON with 2-space indentation and deterministic sorted keys (`sort_keys=True`).

#### Envelope Structure
```json
{
  "export_version": "1.0.0",
  "exported_at": "2026-10-20T10:45:00.123456+00:00",
  "session": {
    "id": 1,
    "session_uuid": "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
    "name": "Core Switch Infrastructure Assessment",
    "operator": "netadmin",
    "status": "COMPLETED",
    "started_at": "2026-10-20T10:00:00",
    "completed_at": "2026-10-20T10:15:00",
    "scope_enclosure": {
      "cidrs": ["10.0.0.0/24"],
      "interfaces": ["eth0"],
      "allow_loopback": true,
      "allow_global_internet": false
    },
    "summary": {
      "devices_scanned": 12,
      "anomalies_detected": 0
    },
    "metadata": {
      "facility": "DC-EAST",
      "rack": "A-12"
    }
  },
  "snapshots_count": 1,
  "snapshots": [
    {
      "id": 101,
      "session_id": 1,
      "snapshot_type": "INTERFACE_TELEMETRY",
      "target": "10.0.0.1",
      "status": "SUCCESS",
      "redacted_fields_count": 0,
      "created_at": "2026-10-20T10:05:00",
      "payload": {
        "interface": "eth0",
        "speed_mbps": 10000,
        "rx_errors": 0,
        "tx_errors": 0
      }
    }
  ]
}
```

- **Empty Session Behavior:** When `snapshots` is empty, `snapshots_count` is `0` and `snapshots` is `[]`.
- **Unicode:** Emitted with `ensure_ascii=False` so non-ASCII and international characters are preserved natively without `\uXXXX` escaping.

---

### 3.2 CSV Format Specification

The CSV exporter (`ReportExporter.to_csv_report()`) produces RFC 4180 compliant CSV using standard Python `csv.writer` with `lineterminator="\n"` and minimal quoting.

#### Column Architecture

1. **Fixed Session & Snapshot Metadata Columns (`CSV_BASE_COLUMNS`):**
   - `session_id`: Database primary key.
   - `session_uuid`: Canonical UUID of diagnostic session.
   - `session_name`: User-assigned assessment name.
   - `operator`: User or automated agent identifier.
   - `session_status`: Lifecycle status (`IN_PROGRESS`, `COMPLETED`, `FAILED`, `ABORTED`).
   - `session_started_at`: UTC start timestamp.
   - `session_completed_at`: UTC completion timestamp (empty string if active).
   - `snapshot_id`: Snapshot primary key.
   - `snapshot_type`: Telemetry or inspection type (e.g. `INTERFACE_TELEMETRY`).
   - `snapshot_target`: Target host, IP, or CIDR.
   - `snapshot_status`: Snapshot execution outcome (`SUCCESS`, `WARNING`, `FAILED`).
   - `redacted_fields_count`: Number of sensitive fields sanitized by redactor.
   - `snapshot_created_at`: UTC snapshot timestamp.
   - `payload_json`: Complete canonical serialized JSON string of snapshot payload.

2. **Lossless Payload Preservation (`payload_json`):**
   The `payload_json` column guarantees zero information loss. Even if snapshot payloads contain arbitrarily deep nested dicts or lists of objects, the complete payload is preserved verbatim in this column.

3. **Dynamic Scalar Payload Columns (`payload.<key>`):**
   Before emitting rows, the exporter derives a sorted union of all top-level scalar keys (`str`, `int`, `float`, `bool`) across all snapshots in the session. Each snapshot populates matching scalar columns and leaves unpopulated columns empty.

4. **Empty Session Representation:**
   For a session with zero snapshots, exactly one row is emitted containing the session metadata and blank snapshot/payload columns.

---

### 3.3 Markdown Format Specification

The Markdown exporter (`ReportExporter.to_markdown_report()`) creates an executive technical assessment report using GitHub Flavored Markdown (GFM).

#### Structure

1. **Header & Document Metadata:**
   - Report title with session name.
   - Blockquote metadata badge list (`Session UUID`, `Operator`, `Status`, `Started At`, `Completed At`, `Total Snapshots`, `Total Secrets Redacted`).
2. **Section 1: Executive Summary:**
   - Summary metrics table.
   - Authorized Scope Enclosure boundary table (CIDRs, interfaces, loopback/internet policy).
   - Executive findings key-value table or formatted notes.
3. **Section 2: Diagnostic Snapshot Catalog:**
   - Tabular overview of all snapshots (`#`, `Type`, `Target`, `Status`, `Redactions`, `Timestamp`).
   - When no snapshots exist: Displays `*No diagnostic snapshots were recorded for this session.*`
4. **Section 3: Detailed Snapshot Findings:**
   - Subsections for each snapshot with metadata summary and formatted JSON code blocks (` ```json `).
5. **Security Disclosure:**
   - Standardized alert note disclosing automated secret redaction heuristics and scope limitations.

#### Context-Specific Output Sanitization
User- and device-controlled values placed inside Markdown reports undergo context-aware sanitization:
- **Headings (`_sanitize_md_heading`):** Line breaks (`\r`, `\n`) are collapsed to single spaces to prevent terminating headings and injecting top-level `#` document sections. HTML brackets (`<`, `>`) and link brackets (`[`, `]`) are escaped.
- **Table Cells (`_escape_md_table_cell`):** Newlines are collapsed to spaces, pipes (`|`) are backslash-escaped (`\|`), HTML tag brackets are entity-escaped (`&lt;`, `&gt;`), and square brackets (`[`, `]`) are backslash-escaped (`\[`, `\]`) to prevent column misalignment, raw HTML execution, and unintended markdown links.
- **Inline Code Spans (`_format_md_inline_code`):** CommonMark-compliant dynamic backtick fencing. If content contains internal backticks, the enclosing delimiter length is dynamically increased ($N+1$). When placed inside tables (`in_table=True`), pipes are backslash-escaped.
- **Fenced JSON Code Blocks (`_format_md_fenced_code`):** The code block fence dynamically scales to $\max(3, N+1)$ backticks where $N$ is the maximum consecutive backtick run in the payload, preventing arbitrary JSON data from prematurely terminating the code block.

---

## 4. Filesystem Persistence & Security Controls

Report writing via `ReportExporter.write_report_file()` enforces strict security invariants:

### 4.1 Path Traversal Prevention
Target paths are inspected prior to filesystem access. The method explicitly rejects:
- `None` or whitespace-only paths.
- Paths containing null bytes (`\0`).
- Directory traversal sequences (`..`).

### 4.2 Explicit Directory Creation
Parent directories must exist prior to writing. The exporter will **not** silently create directories unless `create_dirs=True` is explicitly passed by the caller. Created directories receive restrictive `0o700` permissions.

### 4.3 Race-Safe Atomic Overwrite Protection
- **`overwrite=False` (Default - Atomic Hardlink Publication):**
  1. The complete report is staged into a uniquely named temporary file (`.export_tmp_*`) in the destination directory with restrictive `0o600` permissions.
  2. Data is written, flushed, and synchronized to disk (`os.fsync`).
  3. The completed file is atomically published to the destination path using `os.link()`.
  4. If the destination already exists, `os.link()` immediately raises `FileExistsError` without modifying the existing file.
  5. The temporary file is unlinked. Concurrent readers never observe empty or partially written files, and concurrent writers cannot overwrite each other.
- **`overwrite=True` (Atomic Replacement):**
  The report is staged into a temporary file in the destination directory, permissions are set to `0o600`, flushed, fsynced, and atomically replaced via `os.replace()`.
- **Failure Cleanup:** If an error occurs during write, flush, link, or replacement, temporary files are deterministically cleaned up. Existing destination content is untouched.

### 4.4 Permissions
All created report files are restricted to `0o600` (readable and writable by the file owner only).

### 4.5 Database Immutability
All export operations are strictly read-only with respect to the SQLite database. Session records, snapshot records, and migration tables are never altered, deleted, or updated during report generation.

---

## 5. API Reference & Usage Examples

### 5.1 Application Service Delegation (Recommended)

```python
from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig

app = Application()

# Export session 1 to JSON string
json_str, _ = app.export_diagnostic_session(session_id=1, format="json")

# Export session 1 to Markdown file with race-safe atomic creation
md_str, out_path = app.export_diagnostic_session(
    session_id=1,
    format="markdown",
    output_path="/home/user/reports/audit_20261020.md",
    overwrite=False,
    create_dirs=True,
)
print(f"Report written to: {out_path}")
```

### 5.2 Direct Exporter API

```python
from itsa_network_os.reports.exporter import ReportExporter

# Format session dictionary to CSV string
csv_data = ReportExporter.to_csv_report(session_dict)

# Format and write to filesystem atomically
content, path = ReportExporter.export_session(
    session=session_dict,
    format="csv",
    output_path="/tmp/diagnostic_export.csv",
    overwrite=True,
)
```

### 5.3 Legacy Method Backward Compatibility

The legacy helper methods remain fully preserved:

```python
# Legacy JSON formatter
json_text = ReportExporter.to_json({"key": "value"})

# Legacy Subnet summary formatter
subnet_text = ReportExporter.format_subnet_text(subnet_result_dict)
```
