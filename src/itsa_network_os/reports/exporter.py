"""Export formatters for diagnostic results and network data (TASK-013).

Provides multi-format technical exporters (JSON, CSV, Markdown) for diagnostic
sessions and audit trail snapshots with mandatory pre-export credential redaction,
RFC 4180 CSV compliance, and race-safe atomic filesystem persistence.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from itsa_network_os.storage.redaction import CredentialRedactor


class ExportError(RuntimeError):
    """Base exception for all report export failures."""
    pass


class UnsupportedFormatError(ExportError):
    """Raised when an unsupported export format is requested."""
    pass


class SessionNotFoundError(ExportError):
    """Raised when the specified diagnostic session does not exist."""
    pass


class ExportPathError(ExportError):
    """Raised when an export destination path is invalid or attempts path traversal."""
    pass


class ReportExporter:
    """Format and export diagnostic sessions and reports into standardized representations."""

    SUPPORTED_FORMATS: Tuple[str, ...] = ("json", "csv", "markdown", "md")

    CSV_BASE_COLUMNS: Tuple[str, ...] = (
        "session_id",
        "session_uuid",
        "session_name",
        "operator",
        "session_status",
        "session_started_at",
        "session_completed_at",
        "snapshot_id",
        "snapshot_type",
        "snapshot_target",
        "snapshot_status",
        "redacted_fields_count",
        "snapshot_created_at",
        "payload_json",
    )

    # -------------------------------------------------------------------------
    # Legacy Methods (Preserved for Backward Compatibility)
    # -------------------------------------------------------------------------

    @staticmethod
    def to_json(data: Dict[str, Any] | list[Any], indent: int = 2) -> str:
        """Export data structure as formatted JSON (legacy helper)."""
        return json.dumps(data, indent=indent)

    @staticmethod
    def format_subnet_text(result_dict: Dict[str, Any]) -> str:
        """Render subnet calculation as clean key-value text (legacy helper)."""
        lines = [
            "============================================================",
            f" Subnet Report: {result_dict.get('cidr')}",
            "============================================================",
            f" IP Version         : IPv{result_dict.get('ip_version')}",
            f" Network Address    : {result_dict.get('network_address')}",
            f" Subnet Netmask     : {result_dict.get('netmask')}",
            f" Wildcard Hostmask  : {result_dict.get('wildcard_mask')}",
            f" Broadcast Address  : {result_dict.get('broadcast_address')}",
            f" Total Host Space   : {result_dict.get('total_hosts'):,}",
            f" Usable Host Space  : {result_dict.get('usable_hosts'):,}",
            f" Usable Host Range  : {result_dict.get('first_usable_ip')} -> {result_dict.get('last_usable_ip')}",
            "============================================================",
        ]
        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Multi-Format Technical Exporters (TASK-013)
    # -------------------------------------------------------------------------

    @classmethod
    def to_json_report(
        cls,
        session: Dict[str, Any],
        indent: int = 2,
        exported_at: Optional[str] = None,
    ) -> str:
        """Export full diagnostic session and attached snapshots as structured JSON.

        Mandatory Invariants:
        - Applies CredentialRedactor pre-export scrubbing as defense-in-depth.
        - Emits stable schema version ("1.0.0").
        - Distinguishes export metadata from deterministic session payload.
        - Preserves all nested dictionaries, lists, and Unicode strings.
        - Handles empty sessions (snapshots: []) cleanly.
        """
        # 1. Defense-in-depth secret scrubbing before serialization
        redacted_session, _ = CredentialRedactor.redact(session)

        # 2. Build canonical export envelope
        export_time = exported_at or datetime.now(timezone.utc).isoformat()
        snapshots_raw = redacted_session.get("snapshots") or []

        envelope: Dict[str, Any] = {
            "export_version": "1.0.0",
            "exported_at": export_time,
            "session": {
                "id": redacted_session.get("id"),
                "session_uuid": redacted_session.get("session_uuid"),
                "name": redacted_session.get("name"),
                "operator": redacted_session.get("operator", "system"),
                "status": redacted_session.get("status"),
                "started_at": redacted_session.get("started_at"),
                "completed_at": redacted_session.get("completed_at"),
                "scope_enclosure": redacted_session.get("scope_enclosure"),
                "summary": redacted_session.get("summary"),
                "metadata": redacted_session.get("metadata"),
            },
            "snapshots_count": len(snapshots_raw),
            "snapshots": [
                {
                    "id": s.get("id"),
                    "session_id": s.get("session_id"),
                    "snapshot_type": s.get("snapshot_type"),
                    "target": s.get("target"),
                    "status": s.get("status"),
                    "redacted_fields_count": s.get("redacted_fields_count", 0),
                    "created_at": s.get("created_at"),
                    "payload": s.get("payload"),
                }
                for s in snapshots_raw
            ],
        }

        return json.dumps(envelope, indent=indent, sort_keys=True, ensure_ascii=False)

    @classmethod
    def to_csv_report(cls, session: Dict[str, Any]) -> str:
        """Export diagnostic session and snapshots into RFC 4180 compliant CSV.

        Representation & Integrity Invariants:
        - Each row represents one diagnostic snapshot, prefixed with parent session metadata.
        - The 'payload_json' column contains the complete canonical JSON string,
          guaranteeing zero silent data loss for nested dicts and lists.
        - Dynamically extracts a sorted union of top-level scalar payload keys
          (payload.<key>) across all snapshots.
        - For a session with zero snapshots, exactly one row is written containing
          session metadata with empty snapshot and payload fields.
        """
        # 1. Defense-in-depth secret scrubbing
        redacted_session, _ = CredentialRedactor.redact(session)
        snapshots = redacted_session.get("snapshots") or []

        # 2. Derive sorted union of eligible top-level scalar payload keys
        scalar_keys: set[str] = set()
        for s in snapshots:
            p = s.get("payload")
            if isinstance(p, dict):
                for k, v in p.items():
                    if isinstance(v, (str, int, float, bool)):
                        scalar_keys.add(k)
        sorted_scalar_keys = sorted(scalar_keys)

        headers = list(cls.CSV_BASE_COLUMNS) + [f"payload.{k}" for k in sorted_scalar_keys]

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
        writer.writerow(headers)

        sess_id = redacted_session.get("id", "")
        sess_uuid = redacted_session.get("session_uuid", "")
        sess_name = redacted_session.get("name", "")
        sess_operator = redacted_session.get("operator", "system")
        sess_status = redacted_session.get("status", "")
        sess_started = redacted_session.get("started_at", "")
        sess_completed = redacted_session.get("completed_at", "") or ""

        # 3. Handle empty session: write exactly 1 metadata row
        if not snapshots:
            empty_row = [
                sess_id,
                sess_uuid,
                sess_name,
                sess_operator,
                sess_status,
                sess_started,
                sess_completed,
                "",  # snapshot_id
                "",  # snapshot_type
                "",  # snapshot_target
                "",  # snapshot_status
                "",  # redacted_fields_count
                "",  # snapshot_created_at
                "",  # payload_json
            ] + ["" for _ in sorted_scalar_keys]
            writer.writerow(empty_row)
            return output.getvalue()

        # 4. Write one row per snapshot
        for s in snapshots:
            p = s.get("payload")
            payload_json_str = (
                json.dumps(p, sort_keys=True, ensure_ascii=False) if p is not None else ""
            )
            row = [
                sess_id,
                sess_uuid,
                sess_name,
                sess_operator,
                sess_status,
                sess_started,
                sess_completed,
                s.get("id", ""),
                s.get("snapshot_type", ""),
                s.get("target") or "",
                s.get("status", ""),
                s.get("redacted_fields_count", 0),
                s.get("created_at", ""),
                payload_json_str,
            ]
            for k in sorted_scalar_keys:
                if isinstance(p, dict) and k in p and isinstance(p[k], (str, int, float, bool)):
                    row.append(str(p[k]))
                else:
                    row.append("")
            writer.writerow(row)

        return output.getvalue()

    @classmethod
    def to_markdown_report(cls, session: Dict[str, Any]) -> str:
        """Export diagnostic assessment into a human-readable Markdown report.

        Includes:
        - Document title and execution metadata badge block.
        - Executive summary metrics table and authorized scope enclosure.
        - Snapshot summary catalog table.
        - Detailed findings per snapshot with sanitized code blocks.
        - Mandatory secret redaction advisory note.
        """
        # 1. Defense-in-depth secret scrubbing
        redacted_session, _ = CredentialRedactor.redact(session)

        sess_name = cls._sanitize_md_heading(redacted_session.get("name") or "Diagnostic Assessment")
        sess_uuid = cls._sanitize_text(str(redacted_session.get("session_uuid") or "N/A"))
        raw_op = redacted_session.get("operator") or "system"
        raw_status = redacted_session.get("status") or "UNKNOWN"
        sess_started = cls._sanitize_text(str(redacted_session.get("started_at") or "N/A"))
        sess_completed = cls._sanitize_text(str(redacted_session.get("completed_at") or "In Progress"))

        snapshots = redacted_session.get("snapshots") or []
        total_redactions = sum(int(s.get("redacted_fields_count") or 0) for s in snapshots)

        lines: List[str] = [
            f"# Diagnostic Assessment Report: {sess_name}",
            "",
            "> **Document Metadata**  ",
            f"> - **Session UUID:** {cls._format_md_inline_code(sess_uuid)}  ",
            f"> - **Operator:** {cls._format_md_inline_code(raw_op, in_table=False)}  ",
            f"> - **Status:** {cls._format_md_inline_code(raw_status, in_table=False)}  ",
            f"> - **Started At:** {cls._format_md_inline_code(sess_started)}  ",
            f"> - **Completed At:** {cls._format_md_inline_code(sess_completed)}  ",
            f"> - **Total Snapshots:** `{len(snapshots)}`  ",
            f"> - **Total Secrets Redacted:** `{total_redactions}`",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            "| Metric | Assessment Result |",
            "|:---|:---|",
            f"| **Session Lifecycle Status** | {cls._format_md_inline_code(raw_status, in_table=True)} |",
            f"| **Operator Attribution** | {cls._format_md_inline_code(raw_op, in_table=True)} |",
            f"| **Diagnostic Snapshots Recorded** | `{len(snapshots)}` |",
            f"| **Sanitized Secret Fields** | `{total_redactions}` |",
            "",
        ]

        # Scope enclosure details
        scope = redacted_session.get("scope_enclosure")
        if scope and isinstance(scope, dict):
            cidr_list = scope.get("cidrs", [])
            cidrs = (
                ", ".join(cls._format_md_inline_code(c, in_table=True) for c in cidr_list)
                if cidr_list
                else "None (Unrestricted)"
            )
            iface_list = scope.get("interfaces", [])
            ifaces = (
                ", ".join(cls._format_md_inline_code(i, in_table=True) for i in iface_list)
                if iface_list
                else "All Interfaces"
            )
            lines.extend([
                "### Authorized Diagnostic Scope Enclosure",
                "",
                "| Enclosure Boundary | Configuration |",
                "|:---|:---|",
                f"| **Authorized CIDR Networks** | {cidrs} |",
                f"| **Bound Network Interfaces** | {ifaces} |",
                f"| **Loopback Permitted** | `{bool(scope.get('allow_loopback', True))}` |",
                f"| **Global Internet Permitted** | `{bool(scope.get('allow_global_internet', False))}` |",
                "",
            ])

        # Summary findings
        summary = redacted_session.get("summary")
        if summary:
            lines.extend(["### Executive Findings", ""])
            if isinstance(summary, dict):
                lines.append("| Category / Metric | Summary Value |")
                lines.append("|:---|:---|")
                for k, v in summary.items():
                    k_str = cls._escape_md_table_cell(str(k))
                    v_str = cls._format_md_inline_code(v, in_table=True)
                    lines.append(f"| **{k_str}** | {v_str} |")
                lines.append("")
            else:
                lines.extend([cls._escape_md_table_cell(str(summary)), ""])

        # 2. Diagnostic Snapshot Catalog
        lines.extend([
            "---",
            "",
            "## 2. Diagnostic Snapshot Catalog",
            "",
        ])

        if not snapshots:
            lines.extend([
                "*No diagnostic snapshots were recorded for this session.*",
                "",
            ])
        else:
            lines.extend([
                "| # | Type | Target | Status | Redactions | Timestamp |",
                "|---|:---|:---|:---|:---:|:---|",
            ])
            for s in snapshots:
                s_id = s.get("id", "")
                s_type = cls._format_md_inline_code(s.get("snapshot_type") or "", in_table=True)
                raw_target = s.get("target")
                s_target = (
                    cls._format_md_inline_code(raw_target, in_table=True)
                    if raw_target
                    else "—"
                )
                s_stat = cls._format_md_inline_code(s.get("status") or "", in_table=True)
                s_red = int(s.get("redacted_fields_count") or 0)
                s_time = cls._escape_md_table_cell(s.get("created_at") or "")
                lines.append(f"| {s_id} | {s_type} | {s_target} | {s_stat} | {s_red} | {s_time} |")
            lines.append("")

            # Detailed Findings
            lines.extend([
                "---",
                "",
                "## 3. Detailed Snapshot Findings",
                "",
            ])
            for s in snapshots:
                s_id = s.get("id", "")
                s_type_heading = cls._sanitize_md_heading(s.get("snapshot_type") or "")
                s_stat_heading = cls._sanitize_md_heading(s.get("status") or "")
                raw_target = s.get("target")
                s_target_code = (
                    cls._format_md_inline_code(raw_target, in_table=False)
                    if raw_target
                    else "`—`"
                )
                s_time = cls._sanitize_text(str(s.get("created_at") or ""))
                s_red = int(s.get("redacted_fields_count") or 0)
                p = s.get("payload")
                payload_json_str = (
                    json.dumps(p, indent=2, sort_keys=True, ensure_ascii=False)
                    if p is not None
                    else "null"
                )

                lines.extend([
                    f"### Snapshot #{s_id}: {s_type_heading} [{s_stat_heading}]",
                    "",
                    f"- **Target:** {s_target_code}",
                    f"- **Created At:** `{s_time}`",
                    f"- **Redacted Fields:** `{s_red}`",
                    "",
                    cls._format_md_fenced_code(payload_json_str, language="json"),
                    "",
                ])

        # 3. Security Disclosure
        lines.extend([
            "---",
            "",
            "> [!NOTE]",
            "> **Automated Secret Redaction Notice:** All sensitive credentials (passwords, tokens, "
            "private keys, embedded URI credentials) were automatically sanitized using `***REDACTED***` "
            "prior to persistence and export. Redaction relies on pattern recognition and vocabulary filtering; "
            "it cannot guarantee universal detection of arbitrary or custom-obfuscated secrets.",
            "",
        ])

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Filesystem Persistence & Safety
    # -------------------------------------------------------------------------

    @classmethod
    def write_report_file(
        cls,
        content: str,
        destination: Union[str, Path],
        overwrite: bool = False,
        create_dirs: bool = False,
    ) -> Path:
        """Write report content to filesystem with atomic replacement and race-safe overwrite protection.

        Security Invariants:
        - Validates against path traversal (../) and null bytes.
        - If destination directory does not exist: fails closed unless create_dirs=True.
        - When overwrite=False: writes to a secure temporary file in destination directory,
          then atomically publishes using os.link(). Guarantees no reader observes a partially
          written file and no existing file is overwritten (FileExistsError).
        - When overwrite=True: uses atomic temporary file replacement (os.replace) in same directory.
        - Restricts file permissions to 0o600 (owner read/write only).
        - Deterministically cleans up temporary files on all error and failure paths.
        """
        dest_path = cls._validate_safe_path(destination)
        parent_dir = dest_path.parent

        # 1. Directory presence validation
        if not parent_dir.exists():
            if not create_dirs:
                raise ExportPathError(
                    f"Export destination directory does not exist: '{parent_dir}'. "
                    "Set create_dirs=True to allow directory creation."
                )
            try:
                os.makedirs(parent_dir, mode=0o700, exist_ok=True)
            except OSError as exc:
                raise ExportPathError(f"Failed to create export directory '{parent_dir}': {exc}") from exc

        if not parent_dir.is_dir():
            raise ExportPathError(f"Export parent path is not a directory: '{parent_dir}'")

        if not os.access(parent_dir, os.W_OK):
            raise ExportPathError(f"Export destination directory is not writable: '{parent_dir}'")

        encoded_bytes = content.encode("utf-8")

        # Early check for non-overwrite mode to fail quickly if destination already exists
        if not overwrite and dest_path.exists():
            raise FileExistsError(
                f"Export destination file already exists: '{dest_path}'. Set overwrite=True to allow replacement."
            )

        # Stage full content into a secure temporary file in destination directory
        temp_file = tempfile.NamedTemporaryFile(
            mode="wb",
            dir=parent_dir,
            prefix=".export_tmp_",
            delete=False,
        )
        temp_path = Path(temp_file.name)
        try:
            temp_file.write(encoded_bytes)
            temp_file.flush()
            os.fsync(temp_file.fileno())
            temp_file.close()

            # Set 0o600 permissions
            os.chmod(temp_path, 0o600)

            if not overwrite:
                # Atomically publish without replacing existing destination
                try:
                    os.link(temp_path, dest_path)
                except FileExistsError as exc:
                    raise FileExistsError(
                        f"Export destination file already exists: '{dest_path}'. Set overwrite=True to allow replacement."
                    ) from exc
                except OSError as exc:
                    raise ExportPathError(f"Failed to publish export file '{dest_path}': {exc}") from exc
                finally:
                    if temp_path.exists():
                        try:
                            temp_path.unlink()
                        except OSError:
                            pass
                return dest_path
            else:
                # Overwrite Mode: Atomic Replacement via os.replace()
                os.replace(temp_path, dest_path)
                return dest_path
        except FileExistsError:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise
        except Exception as exc:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise ExportPathError(f"Atomic file write failed for '{dest_path}': {exc}") from exc

    @classmethod
    def export_session(
        cls,
        session: Dict[str, Any],
        format: str,
        output_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
        create_dirs: bool = False,
    ) -> Tuple[str, Optional[Path]]:
        """Format and optionally persist a diagnostic assessment session.

        Supported formats: 'json', 'csv', 'markdown', 'md'.
        Returns a tuple of (formatted_string_content, Optional[written_file_path]).
        """
        fmt = (format or "").strip().lower()
        if fmt not in cls.SUPPORTED_FORMATS:
            raise UnsupportedFormatError(
                f"Unsupported export format '{format}'. Supported formats: {', '.join(cls.SUPPORTED_FORMATS)}"
            )

        if fmt == "json":
            content = cls.to_json_report(session)
        elif fmt == "csv":
            content = cls.to_csv_report(session)
        elif fmt in ("markdown", "md"):
            content = cls.to_markdown_report(session)
        else:
            raise UnsupportedFormatError(f"Unsupported export format '{format}'.")

        written_path: Optional[Path] = None
        if output_path is not None:
            written_path = cls.write_report_file(
                content=content,
                destination=output_path,
                overwrite=overwrite,
                create_dirs=create_dirs,
            )

        return content, written_path

    # -------------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _validate_safe_path(path: Union[str, Path]) -> Path:
        """Validate and resolve target path against path traversal and illegal characters."""
        if path is None:
            raise ExportPathError("Export destination path cannot be None.")

        str_path = str(path).strip()
        if not str_path:
            raise ExportPathError("Export destination path cannot be empty.")

        # Reject null bytes
        if "\0" in str_path:
            raise ExportPathError("Export destination path contains invalid null byte.")

        # Reject obvious path traversal patterns in un-normalized string
        parts = Path(str_path).parts
        if ".." in parts:
            raise ExportPathError(f"Path traversal sequence '..' detected in destination path: '{str_path}'")

        try:
            return Path(str_path).expanduser().resolve()
        except Exception as exc:
            raise ExportPathError(f"Invalid export destination path '{str_path}': {exc}") from exc

    @staticmethod
    def _sanitize_text(text: Any) -> str:
        """Normalize multiline text into single-line safe text by collapsing line breaks."""
        if text is None:
            return ""
        return re.sub(r"[\r\n]+", " ", str(text)).strip()

    @staticmethod
    def _escape_md_table_cell(text: Any) -> str:
        """Escape characters that break Markdown table rows or columns, or inject markup."""
        if text is None:
            return ""
        escaped = re.sub(r"[\r\n]+", " ", str(text))
        # Escape pipe characters for table cell boundaries
        escaped = escaped.replace("|", "\\|")
        # Escape HTML tag brackets to prevent raw HTML interpretation in table cells
        escaped = escaped.replace("<", "&lt;").replace(">", "&gt;")
        # Escape square brackets to prevent unintended markdown links
        escaped = escaped.replace("[", "\\[").replace("]", "\\]")
        return escaped.strip()

    @staticmethod
    def _sanitize_md_heading(text: Any) -> str:
        """Sanitize arbitrary strings for safe inclusion in Markdown headings."""
        if text is None:
            return ""
        # Collapse all line breaks to prevent terminating the heading and starting new blocks
        str_val = re.sub(r"[\r\n]+", " ", str(text)).strip()
        # Escape HTML brackets and link brackets
        str_val = str_val.replace("<", "&lt;").replace(">", "&gt;")
        str_val = str_val.replace("[", "\\[").replace("]", "\\]")
        return str_val

    @staticmethod
    def _format_md_inline_code(text: Any, in_table: bool = False) -> str:
        """Format text as a safe CommonMark inline code span with dynamic backtick fencing.

        Handles embedded backticks by using a delimiter of length greater than any
        consecutive backtick run in the content, adding padding if needed.
        When in_table=True, escapes pipe characters (\\|) to preserve GFM table cell boundaries.
        """
        if text is None:
            return "`—`" if not in_table else "—"
        str_val = re.sub(r"[\r\n]+", " ", str(text))
        if in_table:
            str_val = str_val.replace("|", "\\|")
        backtick_runs = re.findall(r"`+", str_val)
        max_run = max(len(r) for r in backtick_runs) if backtick_runs else 0
        delim = "`" * (max_run + 1 if max_run > 0 else 1)
        needs_padding = str_val.startswith("`") or str_val.endswith("`")
        padding = " " if needs_padding else ""
        return f"{delim}{padding}{str_val}{padding}{delim}"

    @staticmethod
    def _format_md_fenced_code(content: str, language: str = "json") -> str:
        """Format multi-line content in a fenced code block using a delimiter longer than any internal backtick run."""
        backtick_runs = re.findall(r"`+", content)
        max_run = max(len(r) for r in backtick_runs) if backtick_runs else 0
        fence_len = max(3, max_run + 1)
        fence = "`" * fence_len
        return f"{fence}{language}\n{content}\n{fence}"

    @classmethod
    def _escape_md(cls, text: str) -> str:
        """Legacy helper: escape Markdown pipe characters and collapse line breaks for table cells."""
        return cls._escape_md_table_cell(text)
