"""Automated credential and sensitive data redaction engine for ITSA Network OS.

Provides robust, recursive secret scrubbing across structured diagnostic
payloads (dictionaries, lists, strings, and URLs) before SQLite persistence
or export. Enforces strict fail-closed security invariants and caller immutability.
"""

from __future__ import annotations

import copy
import dataclasses
import re
import urllib.parse
from typing import Any, ClassVar, Dict, List, NamedTuple, Pattern, Set, Tuple, Union


class RedactionError(RuntimeError):
    """Raised when an object or payload cannot be safely sanitized (fail-closed)."""
    pass


class RedactionResult(NamedTuple):
    """Immutable result of a redaction operation containing sanitized data and count."""

    data: Any
    redacted_count: int


class CredentialRedactor:
    """Automated secret scrubbing engine for structured payloads and text."""

    REDACTION_MARKER: ClassVar[str] = "***REDACTED***"
    PRIVATE_KEY_MARKER: ClassVar[str] = "-----BEGIN PRIVATE KEY----- ***REDACTED KEY*** -----END PRIVATE KEY-----"

    # Exact normalized sensitive key names (lowercase with non-alphanumeric stripped)
    SENSITIVE_KEY_EXACT: ClassVar[Set[str]] = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "clientsecret",
        "token",
        "accesstoken",
        "refreshtoken",
        "authtoken",
        "idtoken",
        "sessiontoken",
        "bearertoken",
        "csrftoken",
        "apikey",
        "authorization",
        "proxyauthorization",
        "wpakey",
        "psk",
        "presharedkey",
        "passphrase",
        "wpapassphrase",
        "wpspin",
        "snmpcommunity",
        "community",
        "readcommunity",
        "writecommunity",
        "privatekey",
        "credential",
        "credentials",
    }

    # Suffixes that indicate a sensitive key when normalized
    SENSITIVE_KEY_SUFFIXES: ClassVar[Tuple[str, ...]] = (
        "password",
        "passwd",
        "pwd",
        "secret",
        "apikey",
        "privatekey",
        "presharedkey",
        "wpakey",
        "psk",
        "passphrase",
        "snmpcommunity",
        "token",
        "credentials",
    )

    # Patterns matching URLs and URIs (with userinfo, query parameters, or fragments)
    URL_FIND_PATTERN: ClassVar[Pattern[str]] = re.compile(
        r"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>\x22\x27{}|\\^`]+"
    )
    URL_USERINFO_PATTERN: ClassVar[Pattern[str]] = re.compile(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s@]+@)([^/\s,;\"']+)"
    )

    # Patterns for strings containing secrets
    STRING_SECRET_PATTERNS: ClassVar[List[Tuple[Pattern[str], Union[str, Any]]]] = [
        # PEM private key blocks (generic, RSA, EC, DSA, OPENSSH, ENCRYPTED)
        (
            re.compile(
                r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"
            ),
            PRIVATE_KEY_MARKER,
        ),
        # Bearer tokens (at least 8 chars)
        (
            re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9_\-\.]{8,})"),
            r"\1***REDACTED***",
        ),
        # Basic auth header
        (
            re.compile(r"(?i)\b(basic\s+)([A-Za-z0-9+/=]{8,})"),
            r"\1***REDACTED***",
        ),
        # In-string key-value assignments (e.g. password=..., api_key: "...", access_token=...)
        (
            re.compile(
                r"""(?i)\b(password|passwd|pwd|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|api[_-]?key|apikey|wpa[_-]?key|psk|snmp[_-]?community|community)\s*([:=])\s*(['"]?)([^'"\s,;&]+)\3"""
            ),
            r"\1\2\3***REDACTED***\3",
        ),
    ]

    @classmethod
    def is_sensitive_key(cls, key: Any) -> bool:
        """Evaluate whether a dictionary key corresponds to a sensitive credential."""
        if not isinstance(key, str):
            key_str = str(key)
        else:
            key_str = key

        # Normalize key: remove underscores, hyphens, spaces, dots, and lowercase
        norm = re.sub(r"[_\-\s\.]+", "", key_str).lower()
        if not norm:
            return False

        if norm in cls.SENSITIVE_KEY_EXACT:
            return True

        # Check suffixes, but avoid overbroad false positives (e.g. token_count)
        for suffix in cls.SENSITIVE_KEY_SUFFIXES:
            if norm.endswith(suffix):
                return True

        return False

    @classmethod
    def redact_url_credentials(cls, text: str) -> Tuple[str, int]:
        """Redact embedded credentials in URLs/URIs, including userinfo, query parameters, and fragments."""
        count = 0

        def _replace_url(match: re.Match[str]) -> str:
            nonlocal count
            raw = match.group(0)

            # Strip trailing punctuation that is likely sentence punctuation rather than part of URL
            trail = ""
            m_trail = re.search(r"[,;.:\)]+$", raw)
            if m_trail:
                clean = raw[: m_trail.start()]
                trail = m_trail.group(0)
            else:
                clean = raw

            try:
                parts = urllib.parse.urlsplit(clean)
                if not parts.scheme or not (parts.netloc or parts.path):
                    return raw
            except Exception:
                # Fail closed on malformed or dangerous URIs
                count += 1
                return f"{cls.REDACTION_MARKER}{trail}"

            # 1. Sanitize userinfo in netloc
            new_netloc = parts.netloc
            if "@" in parts.netloc:
                userinfo, _, host_port = parts.netloc.rpartition("@")
                if cls.REDACTION_MARKER not in userinfo:
                    count += 1
                    if ":" in userinfo:
                        user, _, _ = userinfo.partition(":")
                        new_userinfo = f"{user}:{cls.REDACTION_MARKER}"
                    else:
                        new_userinfo = cls.REDACTION_MARKER
                    new_netloc = f"{new_userinfo}@{host_port}"

            # 2. Sanitize sensitive query parameters
            new_query = parts.query
            if parts.query:
                pairs = parts.query.split("&")
                new_pairs = []
                for pair in pairs:
                    if not pair:
                        continue
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        unquoted_k = urllib.parse.unquote(k)
                        if cls.is_sensitive_key(unquoted_k):
                            if v != cls.REDACTION_MARKER:
                                count += 1
                            new_pairs.append(f"{k}={cls.REDACTION_MARKER}")
                        else:
                            new_pairs.append(pair)
                    else:
                        unquoted_k = urllib.parse.unquote(pair)
                        if cls.is_sensitive_key(unquoted_k):
                            new_pairs.append(f"{pair}={cls.REDACTION_MARKER}")
                            count += 1
                        else:
                            new_pairs.append(pair)
                new_query = "&".join(new_pairs)

            # 3. Sanitize sensitive hash fragment parameters (e.g. OAuth2 hash fragments)
            new_fragment = parts.fragment
            if parts.fragment and "=" in parts.fragment:
                pairs = parts.fragment.split("&")
                new_pairs = []
                for pair in pairs:
                    if not pair:
                        continue
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        unquoted_k = urllib.parse.unquote(k)
                        if cls.is_sensitive_key(unquoted_k):
                            if v != cls.REDACTION_MARKER:
                                count += 1
                            new_pairs.append(f"{k}={cls.REDACTION_MARKER}")
                        else:
                            new_pairs.append(pair)
                    else:
                        unquoted_k = urllib.parse.unquote(pair)
                        if cls.is_sensitive_key(unquoted_k):
                            new_pairs.append(f"{pair}={cls.REDACTION_MARKER}")
                            count += 1
                        else:
                            new_pairs.append(pair)
                new_fragment = "&".join(new_pairs)

            sanitized = urllib.parse.urlunsplit(
                (parts.scheme, new_netloc, parts.path, new_query, new_fragment)
            )
            return f"{sanitized}{trail}"

        sanitized_text = cls.URL_FIND_PATTERN.sub(_replace_url, text)
        return sanitized_text, count

    @classmethod
    def redact_string(cls, text: str) -> Tuple[str, int]:
        """Sanitize sensitive patterns, URLs, keys, and tokens within a text string."""
        total_count = 0

        # 1. Sanitize URLs first
        text, url_count = cls.redact_url_credentials(text)
        total_count += url_count

        # 2. Sanitize structured string patterns
        for pattern, replacement in cls.STRING_SECRET_PATTERNS:
            def _sub_handler(match: re.Match[str]) -> str:
                nonlocal total_count
                matched_text = match.group(0)
                # Check if already redacted
                if cls.REDACTION_MARKER in matched_text or cls.PRIVATE_KEY_MARKER in matched_text:
                    return matched_text
                total_count += 1
                if callable(replacement):
                    return replacement(match)
                elif isinstance(replacement, str) and "\\" in replacement:
                    return match.expand(replacement)
                return replacement

            text = pattern.sub(_sub_handler, text)

        return text, total_count

    @classmethod
    def redact(cls, obj: Any) -> RedactionResult:
        """Deeply sanitize an arbitrary structured object or diagnostic payload.

        Returns a RedactionResult(data, redacted_count) where:
        - data is a sanitized deep copy (caller's input is never mutated).
        - redacted_count is the accurate count of redacted secret occurrences.

        Raises:
            RedactionError: If the payload cannot be safely inspected or contains
                            unsupported non-serializable objects.
        """
        try:
            # We track redaction count locally during recursive traversal
            count = 0

            def _traverse(val: Any) -> Any:
                nonlocal count

                if val is None or isinstance(val, (bool, int, float)):
                    return val

                if isinstance(val, str):
                    sanitized_str, str_count = cls.redact_string(val)
                    count += str_count
                    return sanitized_str

                if isinstance(val, dict):
                    new_dict: Dict[str, Any] = {}
                    for k, v in val.items():
                        key_str = str(k)
                        if cls.is_sensitive_key(key_str):
                            # Sensitive key detected
                            if v is None:
                                new_dict[k] = None
                            elif isinstance(v, (dict, list, tuple, set)) and key_str.lower() in (
                                "credentials", "credential", "auth", "authorization"
                            ):
                                # Container of credentials: recurse to sanitize specific fields
                                new_dict[k] = _traverse(v)
                            else:
                                # Scalar or generic secret value
                                if isinstance(v, str) and v == cls.REDACTION_MARKER:
                                    new_dict[k] = cls.REDACTION_MARKER
                                else:
                                    count += 1
                                    new_dict[k] = cls.REDACTION_MARKER
                        else:
                            new_dict[k] = _traverse(v)
                    return new_dict

                if isinstance(val, list):
                    return [_traverse(item) for item in val]

                if isinstance(val, tuple):
                    return tuple(_traverse(item) for item in val)

                if isinstance(val, set):
                    return {_traverse(item) for item in val}

                # Support dataclass instances by converting to dict
                if dataclasses.is_dataclass(val) and not isinstance(val, type):
                    as_dict = dataclasses.asdict(val)
                    return _traverse(as_dict)

                # Objects providing a custom to_dict() method
                if hasattr(val, "to_dict") and callable(getattr(val, "to_dict")):
                    return _traverse(val.to_dict())

                raise RedactionError(
                    f"Unsupported payload type for redaction: {type(val).__name__}"
                )

            sanitized_data = _traverse(obj)
            return RedactionResult(data=sanitized_data, redacted_count=count)

        except Exception as exc:
            if isinstance(exc, RedactionError):
                raise
            raise RedactionError(f"Redaction failed: {exc}") from exc


def redact_sensitive_data(obj: Any) -> RedactionResult:
    """Convenience function to redact secrets from an object."""
    return CredentialRedactor.redact(obj)
