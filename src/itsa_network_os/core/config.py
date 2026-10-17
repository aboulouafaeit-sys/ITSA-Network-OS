"""Centralized configuration manager for ITSA Network OS with safe defaults."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict


@dataclass(frozen=True)
class AppConfig:
    """Immutable application configuration."""

    app_name: str = "ITSA Network OS"
    version: str = "0.1.0"
    offline_mode: bool = True
    enable_telemetry: bool = False
    log_level: str = "INFO"
    log_to_file: bool = False
    use_mock_network: bool = True
    config_dir: str = field(default_factory=lambda: str(Path.home() / ".config" / "itsa-network-os"))
    database_file: str = field(
        default_factory=lambda: str(Path.home() / ".config" / "itsa-network-os" / "data.sqlite3")
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary representation."""
        return asdict(self)


def get_default_config() -> AppConfig:
    """Return default safe configuration instance."""
    return AppConfig()


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load configuration from a file or fallback to safe defaults.

    Does not raise exceptions if configuration file is missing or invalid.
    """
    if config_path is None:
        config_path = Path.home() / ".config" / "itsa-network-os" / "config.json"

    if not config_path.is_file():
        return get_default_config()

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return get_default_config()

        return AppConfig(
            app_name=str(data.get("app_name", "ITSA Network OS")),
            version=str(data.get("version", "0.1.0")),
            offline_mode=bool(data.get("offline_mode", True)),
            enable_telemetry=False,  # strictly enforce telemetry false
            log_level=str(data.get("log_level", "INFO")),
            log_to_file=bool(data.get("log_to_file", False)),
            use_mock_network=bool(data.get("use_mock_network", True)),
            config_dir=str(data.get("config_dir", str(Path.home() / ".config" / "itsa-network-os"))),
            database_file=str(
                data.get("database_file", str(Path.home() / ".config" / "itsa-network-os" / "data.sqlite3"))
            ),
        )
    except Exception:
        # Fallback cleanly to safe defaults on any parse/read error
        return get_default_config()
