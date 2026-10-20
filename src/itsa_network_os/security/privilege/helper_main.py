"""Privileged helper executable entry point for PolicyKit / systemd activation."""

from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
from typing import Any

from itsa_network_os.core.logger import get_logger
from itsa_network_os.security.privilege.authorizer import PolkitAuthorizer
from itsa_network_os.security.privilege.client import DEFAULT_HELPER_SOCKET
from itsa_network_os.security.privilege.server import PrivilegedCaptureServer

logger = get_logger("itsa-priv-helper")


def main(argv: Any = None) -> int:
    """Run privileged capture helper daemon."""
    parser = argparse.ArgumentParser(description="ITSA Network OS Privileged Packet Capture Helper")
    parser.add_argument(
        "--socket",
        dest="socket_path",
        default=os.environ.get("ITSA_HELPER_SOCKET", DEFAULT_HELPER_SOCKET),
        help=f"Path to Unix domain socket (default: {DEFAULT_HELPER_SOCKET})",
    )
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Run in synthetic capture mode (for test fixtures / non-root verification)",
    )

    args = parser.parse_args(argv)

    server = PrivilegedCaptureServer(
        socket_path=args.socket_path,
        authorizer=PolkitAuthorizer(),
        use_synthetic_capture=args.synthetic,
    )

    def _sig_handler(signum: int, frame: Any) -> None:
        logger.info("Received signal %d, shutting down helper...", signum)
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    try:
        server.start_socket()
    except Exception as exc:
        logger.error("Failed to bind helper socket on '%s': %s", args.socket_path, exc)
        return 1

    logger.info("Helper operational. Waiting for authorized client connections...")
    try:
        while server._is_running and server._server_sock:
            try:
                client_sock, _ = server._server_sock.accept()
                server.handle_connection_threaded(client_sock)
            except (TimeoutError, socket.timeout):
                continue
            except OSError as exc:
                if not server._is_running:
                    break
                logger.debug("Socket accept interrupted: %s", exc)
    except SystemExit:
        pass
    finally:
        server.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
