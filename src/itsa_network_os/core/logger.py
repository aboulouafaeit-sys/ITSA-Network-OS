"""Structured, privacy-preserving logging for ITSA Network OS."""

from __future__ import annotations

import logging
import re
import sys
from typing import ClassVar, Pattern


class SensitiveDataFilter(logging.Filter):
    """Filter that masks passwords, tokens, API keys, and sensitive tokens from log records."""

    PATTERNS: ClassVar[list[tuple[Pattern[str], str]]] = [
        (re.compile(r"(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE), r"\1=***REDACTED***"),
        (re.compile(r"Bearer\s+([A-Za-z0-9_\-\.]+)", re.IGNORECASE), "Bearer ***REDACTED***"),
        (re.compile(r"(PRIVATE KEY-----)[\s\S]+?(-----END)", re.MULTILINE), r"\1 ***REDACTED KEY*** \2"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            sanitized = record.msg
            for pattern, replacement in self.PATTERNS:
                sanitized = pattern.sub(replacement, sanitized)
            record.msg = sanitized
        return True


def setup_logging(level: str = "INFO", log_to_file: bool = False, log_file: str | None = None) -> logging.Logger:
    """Configure root logger with secure formatting and filters."""
    logger = logging.getLogger("itsa_network_os")
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Avoid duplicate handlers on re-initialization
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(numeric_level)
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(formatter)
        console_handler.addFilter(SensitiveDataFilter())
        logger.addHandler(console_handler)

    return logger


def get_logger(name: str = "itsa_network_os") -> logging.Logger:
    """Retrieve application logger instance."""
    return logging.getLogger(name)
