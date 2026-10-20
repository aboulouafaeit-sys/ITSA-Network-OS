"""PolicyKit authorization verification abstraction and test authorizer."""

from __future__ import annotations

import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Set

from itsa_network_os.core.logger import get_logger
from itsa_network_os.security.privilege.protocol import POLKIT_ACTION_CAPTURE

logger = get_logger("itsa_network_os.security.privilege.authorizer")


class AuthorizationResult(str, Enum):
    """Authorization determination returned by PolicyKit verifier."""

    AUTHORIZED = "AUTHORIZED"
    DENIED = "DENIED"
    CHALLENGE_REQUIRED = "CHALLENGE_REQUIRED"
    UNAVAILABLE = "UNAVAILABLE"


class BaseAuthorizer(ABC):
    """Abstract interface for checking PolicyKit authorizations."""

    @abstractmethod
    def check_authorization(
        self,
        action_id: str,
        pid: int,
        uid: int,
        allow_user_interaction: bool = False,
    ) -> AuthorizationResult:
        """Determine whether process (pid, uid) is authorized for action_id."""
        raise NotImplementedError


class PolkitAuthorizer(BaseAuthorizer):
    """Linux PolicyKit integration using system 'pkcheck' binary."""

    def __init__(self, pkcheck_binary: Optional[str] = None) -> None:
        self.pkcheck_path = pkcheck_binary or shutil.which("pkcheck")

    def check_authorization(
        self,
        action_id: str = POLKIT_ACTION_CAPTURE,
        pid: int = 0,
        uid: int = 0,
        allow_user_interaction: bool = False,
    ) -> AuthorizationResult:
        """Query system PolicyKit daemon via 'pkcheck' tool."""
        if not self.pkcheck_path or not os.path.exists(self.pkcheck_path):
            logger.warning("PolicyKit authorization check unavailable: 'pkcheck' not found in PATH")
            return AuthorizationResult.UNAVAILABLE

        cmd = [
            self.pkcheck_path,
            "--action-id",
            action_id,
            "--process",
            str(pid),
        ]
        if allow_user_interaction:
            cmd.append("--allow-user-interaction")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            if res.returncode == 0:
                logger.info("PolicyKit authorization granted for action '%s' (PID=%d, UID=%d)", action_id, pid, uid)
                return AuthorizationResult.AUTHORIZED
            elif res.returncode in (1, 2):
                logger.warning("PolicyKit authorization denied for action '%s' (PID=%d, UID=%d)", action_id, pid, uid)
                return AuthorizationResult.DENIED
            elif res.returncode == 3:
                return AuthorizationResult.CHALLENGE_REQUIRED
            else:
                logger.error("pkcheck exited with unexpected return code %d: %s", res.returncode, res.stderr)
                return AuthorizationResult.DENIED
        except subprocess.TimeoutExpired:
            logger.warning("PolicyKit verification timed out for PID %d", pid)
            return AuthorizationResult.DENIED
        except Exception as exc:
            logger.error("Failed to execute pkcheck: %s", exc)
            return AuthorizationResult.UNAVAILABLE


class MockAuthorizer(BaseAuthorizer):
    """Deterministic, test-isolated mock authorizer for automated test suites."""

    def __init__(
        self,
        default_result: AuthorizationResult = AuthorizationResult.AUTHORIZED,
        allowed_uids: Optional[Set[int]] = None,
        allowed_actions: Optional[Set[str]] = None,
    ) -> None:
        self.default_result = default_result
        self.allowed_uids = allowed_uids
        self.allowed_actions = allowed_actions or {POLKIT_ACTION_CAPTURE}

    def check_authorization(
        self,
        action_id: str,
        pid: int,
        uid: int,
        allow_user_interaction: bool = False,
    ) -> AuthorizationResult:
        if self.allowed_actions and action_id not in self.allowed_actions:
            return AuthorizationResult.DENIED

        if self.allowed_uids is not None and uid not in self.allowed_uids:
            return AuthorizationResult.DENIED

        return self.default_result
