"""Safe, non-privileged network latency and connectivity benchmarking."""

from __future__ import annotations

import socket
import statistics
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from itsa_network_os.network.scope import (
    ScopeGuard,
    ScopeViolationError,
    check_interface_route,
    get_interface_source_ip,
)


@dataclass(frozen=True)
class LatencyProbe:
    """Individual probe timing sample."""

    sequence: int
    success: bool
    latency_ms: float
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LatencyBenchmarkResult:
    """Consolidated latency benchmark report."""

    target_host: str
    target_port: int
    probes_sent: int
    probes_received: int
    packet_loss_percent: float
    min_latency_ms: float
    max_latency_ms: float
    avg_latency_ms: float
    jitter_ms: float
    probes: List[LatencyProbe] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["probes"] = [p.to_dict() for p in self.probes]
        return data


class LatencyTester:
    """Safe latency benchmarking using non-root TCP handshake connection timing."""

    @classmethod
    def benchmark(
        cls,
        host: str,
        port: int = 443,
        count: int = 4,
        timeout: float = 2.0,
        interval: float = 0.2,
        use_mock: bool = False,
        interface: Optional[str] = None,
        scope_guard: Optional[ScopeGuard] = None,
    ) -> LatencyBenchmarkResult:
        """Measure round-trip connection latency across multiple samples.

        In live mode (use_mock=False), verifies and resolves target strictly through
        ScopeGuard, connecting to the validated IP to prevent DNS rebinding.
        """
        host_clean = host.strip()

        if use_mock:
            return cls._mock_benchmark(host_clean, port, count)

        # In live mode, require authorized ScopeGuard compliance
        guard = scope_guard or ScopeGuard()
        target_ip = guard.resolve_and_verify_target(
            host_clean, interface=interface, check_unicast=True
        )

        source_address: Optional[Tuple[str, int]] = None
        if interface is not None:
            check_interface_route(interface, target_ip, use_mock=use_mock)
            source_ip = get_interface_source_ip(interface, target_ip)
            if source_ip is None:
                raise ScopeViolationError(
                    f"Cannot guarantee binding to authorized interface '{interface}': no compatible local IP address found"
                )
            source_address = (source_ip, 0)

        probes: List[LatencyProbe] = []
        latencies: List[float] = []

        for seq in range(1, count + 1):
            start = time.perf_counter()
            success = False
            error_msg: Optional[str] = None
            sample_ms = 0.0

            try:
                with socket.create_connection(
                    (target_ip, port), timeout=timeout, source_address=source_address
                ):
                    sample_ms = round((time.perf_counter() - start) * 1000, 2)
                    success = True
                    latencies.append(sample_ms)
            except (socket.timeout, OSError) as exc:
                sample_ms = round((time.perf_counter() - start) * 1000, 2)
                error_msg = str(exc)

            probes.append(
                LatencyProbe(
                    sequence=seq,
                    success=success,
                    latency_ms=sample_ms if success else 0.0,
                    error=error_msg,
                )
            )

            if seq < count and interval > 0:
                time.sleep(interval)

        received = len(latencies)
        loss = round(((count - received) / count) * 100, 1)

        if latencies:
            min_lat = min(latencies)
            max_lat = max(latencies)
            avg_lat = round(statistics.mean(latencies), 2)
            jitter = round(statistics.stdev(latencies), 2) if len(latencies) > 1 else 0.0
        else:
            min_lat = 0.0
            max_lat = 0.0
            avg_lat = 0.0
            jitter = 0.0

        return LatencyBenchmarkResult(
            target_host=host_clean,
            target_port=port,
            probes_sent=count,
            probes_received=received,
            packet_loss_percent=loss,
            min_latency_ms=min_lat,
            max_latency_ms=max_lat,
            avg_latency_ms=avg_lat,
            jitter_ms=jitter,
            probes=probes,
        )

    @classmethod
    def _mock_benchmark(cls, host: str, port: int, count: int) -> LatencyBenchmarkResult:
        """Return deterministic mock latency samples for offline testing."""
        mock_samples = [14.2, 15.1, 14.8, 15.5][:count]
        probes = [
            LatencyProbe(sequence=i + 1, success=True, latency_ms=lat)
            for i, lat in enumerate(mock_samples)
        ]
        return LatencyBenchmarkResult(
            target_host=host,
            target_port=port,
            probes_sent=count,
            probes_received=len(mock_samples),
            packet_loss_percent=0.0,
            min_latency_ms=min(mock_samples),
            max_latency_ms=max(mock_samples),
            avg_latency_ms=round(statistics.mean(mock_samples), 2),
            jitter_ms=round(statistics.stdev(mock_samples), 2) if len(mock_samples) > 1 else 0.0,
            probes=probes,
        )
