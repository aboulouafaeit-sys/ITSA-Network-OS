"""System health inspection service for ITSA Network OS."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict


class HealthStatus(str, Enum):
    """Overall status of system health check."""

    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True)
class SystemHealthReport:
    """Diagnostic system health report representation."""

    status: HealthStatus
    python_version: str
    is_virtual_env: bool
    platform_name: str
    architecture: str
    user_non_root: bool
    disk_free_gb: float
    issues: list[str]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


class HealthCheckService:
    """Service to evaluate system health safely and non-destructively."""

    @staticmethod
    def is_in_virtual_environment() -> bool:
        """Detect whether the current process runs inside an isolated virtual environment."""
        return sys.prefix != getattr(sys, "base_prefix", sys.prefix)

    @staticmethod
    def is_non_root() -> bool:
        """Check if running as an unprivileged user."""
        if hasattr(os, "geteuid"):
            return os.geteuid() != 0
        return True

    @classmethod
    def run_health_check(cls) -> SystemHealthReport:
        """Execute non-destructive health checks and compile report."""
        issues: list[str] = []
        status = HealthStatus.HEALTHY

        # 1. Python version check
        py_version_str = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        if sys.version_info < (3, 10):
            issues.append(f"Python version {py_version_str} is below recommended 3.10+")
            status = HealthStatus.WARNING

        # 2. Virtual environment isolation check
        is_venv = cls.is_in_virtual_environment()
        if not is_venv:
            issues.append("Application is running directly in system interpreter (virtualenv recommended)")
            if status != HealthStatus.DEGRADED:
                status = HealthStatus.WARNING

        # 3. Privilege level check
        non_root = cls.is_non_root()
        if not non_root:
            issues.append("Running as root/superuser is strongly discouraged for regular operations")
            status = HealthStatus.WARNING

        # 4. Storage check
        disk_free_gb = 0.0
        try:
            usage = shutil.disk_usage(Path.home())
            disk_free_gb = round(usage.free / (1024**3), 2)
            if disk_free_gb < 1.0:
                issues.append(f"Low free storage space ({disk_free_gb} GB remaining)")
                status = HealthStatus.DEGRADED
        except Exception:
            disk_free_gb = -1.0

        return SystemHealthReport(
            status=status,
            python_version=py_version_str,
            is_virtual_env=is_venv,
            platform_name=f"{platform.system()} {platform.release()}",
            architecture=platform.machine(),
            user_non_root=non_root,
            disk_free_gb=disk_free_gb,
            issues=issues,
        )
