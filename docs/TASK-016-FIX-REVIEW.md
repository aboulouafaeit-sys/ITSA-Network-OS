# TASK-016-FIX-REVIEW — Independent Security Re-Audit

**Document ID:** DOC-AUDIT-TASK016-FIX-001  
**Project:** ITSA Network OS  
**Platform:** Debian 13 (Trixie) | Linux x86_64 | Python 3.13 | PySide6 / Qt 6  
**Auditor Mode:** Strictly Read-Only Independent Security Audit  
**Target Commit (HEAD):** `ca8006e81eac091225faac3f8b0dc870fbc904ab`  
**Expected Reported Commit:** `3c6d9ee8c0e7d9ea5051df50fb329efc84067631`  
**Previous Baseline:** `edf831833dcbdf5a4df56355991af363cd533edf`  
**Decision:** `ACCEPTED — ALL REQUIRED SECURITY GATES PASSED`  

---

## 1. Repository Identity & Change Provenance

### 1.1 Git State Verification
A read-only inspection was conducted prior to code and test analysis:
- **`git rev-parse HEAD`:** `ca8006e81eac091225faac3f8b0dc870fbc904ab`
- **`git branch --show-current`:** `master`
- **`git status --short`:** Clean (no unstaged or staged modifications prior to this review deliverable).
- **`git diff --stat`:** Clean (0 lines).
- **`git diff --cached --stat`:** Clean (0 lines).
- **Ancestry Verification:**
  ```bash
  git merge-base --is-ancestor edf831833dcbdf5a4df56355991af363cd533edf HEAD && echo "Ancestor verified"
  # Output: Ancestor verified
  ```
- **Commit History & Lineage:**
  - `edf8318`: Baseline accepted commit (`feat: add cancellable asynchronous Wi-Fi scanning worker and UI integration`).
  - `b90bcd5`: Initial TASK-016 implementation (`feat: add PolicyKit-based privilege separation framework...`).
  - `3c6d9ee`: Hardened documentation updates (`docs: update TASK-016 threat model, IPC specification...`).
  - `ca8006e` (Current `HEAD`): Fix report deliverable commit (`fix: harden privilege boundaries and implement secure capture session lifecycle management`).

All TASK-016-FIX changes are completely accounted for in the commit history descending linearly from baseline `edf8318`. Unrelated prior work (TASK-014 wireless scanner provider and TASK-015 Qt worker lifecycle) remains completely untouched and verified by regression test suites.

---

## 2. Inspected Files & Code Paths

The following files and execution paths were audited:
- `src/itsa_network_os/security/privilege/protocol.py`: Message schemas, length limits, finite action allowlists, mandatory scope enclosure rules, and session ID regexes.
- `src/itsa_network_os/security/privilege/filter.py`: Packet filter grammar compilation, token parsing, contradiction rejection, and layer/endpoint matching.
- `src/itsa_network_os/security/privilege/server.py`: `SO_PEERCRED` credential retrieval, fail-closed handling, `SessionRegistry` lifecycle, threaded connection handling, in-loop scope and filter evaluation.
- `src/itsa_network_os/security/privilege/client.py`: Client-side session management, asynchronous start/stop/results lifecycle, and targeted cancellation.
- `src/itsa_network_os/security/privilege/helper_main.py`: Privileged daemon entry point, signal handlers, and threaded connection accept loop.
- `src/itsa_network_os/app.py`: Desktop application integration, pre-IPC scope guard enforcement, and `ScopeViolationError` propagation.
- `src/itsa_network_os/ui/desktop/app_window.py`: GUI exception handling and unprivileged status display.
- `tests/unit/test_privilege_ipc.py`: Focused security test suites for findings F-01 through F-04.
- `docs/TASK-016-IPC-SPECIFICATION.md`: Protocol specification, error codes, and session schemas.
- `docs/TASK-016-PRIVILEGE-AUDIT.md`: System privilege catalog and capability mappings.
- `docs/TASK-016-THREAT-MODEL.md`: STRIDE security assessment.
- `docs/TASK-016-FIX-REPORT.md`: Implementation report.

---

## 3. Finding-by-Finding Status & Analysis

### 3.1 Finding F-01: Capture-Session Ownership and Cancellation
- **Original Severity:** Critical
- **Audit Determination:** **RESOLVED**
- **Analysis:**
  1. **Threaded Accept Loop:** In `helper_main.py` (line 62) and `server.py` (line 286), incoming client sockets are dispatched to worker threads via `handle_connection_threaded()`. The server accept loop is no longer blocked by ongoing packet captures.
  2. **Cryptographic Identity & Capability Tokens:** In `server.py` (`_handle_start_capture` / `_execute_packet_capture`), each session is assigned a cryptographically random session identifier (`secrets.token_hex(16)`) and a high-entropy capability token (`secrets.token_urlsafe(32)`, providing 256 bits of entropy from the OS CSPRNG).
  3. **Thread-Safe Session Registry:** `SessionRegistry` (lines 125–216) protects session registration, lookup, cancellation, and pruning under `self._lock = threading.Lock()`. Bounded active session concurrency is enforced (`max_active_sessions = 16`).
  4. **Dual-Factor Ownership Enforcement:** In `SessionRegistry.cancel_session()` (lines 148–179) and `_handle_get_capture_results()` (lines 450–502):
     - Peer UID extracted from kernel `SO_PEERCRED` must match `session.owner_uid`.
     - Caller capability token must match `session.session_token` using constant-time comparison (`hmac.compare_digest`).
     - A different process under the same local UID cannot cancel or inspect another process's session without the unguessable capability token.
  5. **Dedicated Cancellation Primitives:** Each `CaptureSession` maintains an isolated `cancellation_event: threading.Event`. No global cancellation event remains.
  6. **Idempotence & deterministic teardown:** Multiple concurrent stop requests succeed deterministically (`ALREADY_TERMINAL`). Server shutdown (`shutdown_all()`) joins worker threads, closes open sockets, and clears registry entries.
  7. **Token Redaction:** Capability tokens are never printed in logger statements or echoed back in error responses.

### 3.2 Finding F-02: Permissive `SO_PEERCRED` Fallback
- **Original Severity:** Critical
- **Audit Determination:** **RESOLVED**
- **Analysis:**
  1. **Fail-Closed Implementation:** In `server.py` (`get_socket_peer_credentials`, lines 58–84):
     - `getsockopt(SOL_SOCKET, SO_PEERCRED, 12)` is called.
     - Any `OSError`, `AttributeError`, `struct.error`, or unexpected byte length raises `PeerCredentialError`.
     - Extracted values are validated (`pid > 0`, `uid >= 0`, `gid >= 0`). Non-positive PIDs or negative UIDs/GIDs raise `PeerCredentialError`.
  2. **Elimination of Permissive Fallback:** All fallback to `os.geteuid()`, `os.getpid()`, or assumed UID 0/1000 was completely removed.
  3. **Front-Door Rejection:** In `handle_client_connection()` (lines 309–324), `PeerCredentialError` is caught before reading any frame bytes, before PolicyKit authorization, and before request dispatch. The server immediately returns `status=DENIED, error_code=UNAUTHORIZED` and closes the socket.
  4. **Explicit Test Injection:** Test-specific credential extraction is exposed strictly through explicit dependency injection (`credential_extractor` parameter on `PrivilegedCaptureServer`), preventing permissive fallbacks in production execution paths.

### 3.3 Finding F-03: Packet Filter Ignored in Capture Engine
- **Original Severity:** High
- **Audit Determination:** **RESOLVED**
- **Analysis:**
  1. **Deterministic Filter Engine:** Implemented in `filter.py` (`PacketFilter`).
  2. **Supported Grammar:**
     - Protocols: `tcp`, `udp`, `icmp`, `arp`.
     - Ports: `port <N>`, `src port <N>`, `dst port <N>` (1 ≤ N ≤ 65535, TCP/UDP only).
     - Compound: `<proto> and [src|dst] port <N>`.
  3. **Contradiction Rejection:** Incompatible predicates (`icmp and port 80`, `arp and dst port 1`) and unsupported operators (`or`, `not`) fail closed with `FilterSyntaxError`.
  4. **Server-Side Enforcement:** In `server.py` (`_capture_loop`, lines 588, 650), every frame captured in both synthetic and live raw socket modes is evaluated against `packet_filter.matches(dissected)`. Non-matching packets are discarded.
  5. **Defensive Parsing:** Protocol and port fields are extracted from `PacketLayer` fields and endpoint strings without raising unhandled exceptions on runts or fragmented frames.
  6. **Zero Shell Execution:** Pure string tokenization and integer parsing; no `eval()`, `exec()`, or subshell invocation.

### 3.4 Finding F-04: Scope Filter Bypass on Omission
- **Original Severity:** Critical
- **Audit Determination:** **RESOLVED**
- **Analysis:**
  1. **Mandatory Schema Validation:** In `protocol.py` (`validate_request_dict`, lines 187–208), `scope_cidrs` is strictly required. Missing (`None`), non-list, or empty (`[]`) inputs immediately raise `ProtocolError`.
  2. **Pre-flight Enforcement:** In `app.py` (`get_packet_lab_trace`, lines 368–373), an unconfigured or empty scope enclosure raises `ScopeViolationError` before contacting the helper socket.
  3. **Server-Side Guard Construction:** In `server.py` (`_handle_start_capture`, lines 353–370; `_execute_packet_capture`, lines 525–545), missing or empty `scope_cidrs` returns `SCOPE_VIOLATION`. `ScopeEnclosure` and `ScopeGuard` are constructed and validated before opening any raw socket or launching any worker.
  4. **In-Loop Endpoint Verification:** In `server.py` (`_capture_loop`, lines 590–605, 638–647):
     - Every admitted frame must have at least one verified address satisfying `scope_guard.is_authorized(src_ip, interface)` or `scope_guard.is_authorized(dst_ip, interface)`.
     - Frames lacking verified IP addresses (runt frames, malformed headers) fail closed and are dropped.
     - ARP addresses (`spa`, `tpa`) are evaluated against authorized scope.
     - IPv6 addresses require explicit IPv6 CIDR authorization in the scope enclosure.

---

## 4. Session State-Transition & Concurrency Analysis

### 4.1 State-Transition Matrix
| Current State | Input / Event | Preconditions | Next State | Resource Actions |
|---|---|---|---|---|
| None | `OP_START_CAPTURE` | Authorized Polkit, valid iface, non-empty scope | `ACTIVE` | `session_id`, `session_token` generated; worker thread spawned |
| `ACTIVE` | `OP_STOP_CAPTURE` | Matching `session_id`, matching `session_token`, caller UID == owner UID | `CANCELLED` | `cancellation_event.set()`; socket closed; `completion_event.set()` |
| `ACTIVE` | Packet Count Met | `len(packets) >= packet_count` | `COMPLETED` | Socket closed; `completion_event.set()` |
| `ACTIVE` | Timeout Expired | `time.monotonic() >= deadline` | `TIMED_OUT` | Socket closed; `completion_event.set()` |
| `ACTIVE` | Capture Error | `OSError` / `PermissionError` on socket | `FAILED` | Error recorded; socket closed; `completion_event.set()` |
| `CANCELLED` | `OP_STOP_CAPTURE` | Matching `session_id` and token | `CANCELLED` | Idempotent response (`ALREADY_TERMINAL`) |
| `COMPLETED` | `OP_STOP_CAPTURE` | Matching `session_id` and token | `COMPLETED` | Idempotent response (`ALREADY_TERMINAL`) |
| Any Terminal | Retention Expired | Monotonic delta > 30s | Evicted | Removed from `SessionRegistry` |
| Any Active | Server `stop()` | Server shutdown | `CANCELLED` | Sockets closed, threads joined, registry cleared |

### 4.2 Concurrency & Denial-of-Service Resistance
1. **Thread Saturation Defense:** `SessionRegistry` enforces `max_active_sessions = 16`. Attempts to spawn beyond 16 concurrent sessions fail closed with `SYSTEM_ERROR` without leaking resources.
2. **Listen Backlog:** The Unix domain socket sets `listen(10)` with restrictive permissions (`0600`), preventing local connection flood attacks.
3. **Framing & Payload Bounds:** Requests are capped at 64 KB; responses at 1 MB. Oversized frames are dropped immediately before memory allocation.
4. **Accept Loop Non-Blocking Guarantee:** Because accepted sockets are handed off to `handle_connection_threaded()`, connection 2 can issue `OP_STOP_CAPTURE` concurrently while connection 1 is actively blocked inside a capture loop.

---

## 5. Packet Filter Correctness Matrix

| Filter Input | Target Packet | Evaluation Path | Expected Outcome | Actual Result |
|---|---|---|---|---|
| `tcp` | IPv4 TCP SYN (port 443) | `PacketFilter.matches()` protocol check | Admitted | **PASS** |
| `tcp` | IPv4 UDP DNS (port 53) | `PacketFilter.matches()` protocol check | Excluded | **PASS** |
| `tcp` | ICMP Echo Request | `PacketFilter.matches()` protocol check | Excluded | **PASS** |
| `udp` | IPv4 UDP DNS (port 53) | `PacketFilter.matches()` protocol check | Admitted | **PASS** |
| `udp` | IPv4 TCP ACK (port 80) | `PacketFilter.matches()` protocol check | Excluded | **PASS** |
| `arp` | ARP Reply | `PacketFilter.matches()` protocol check | Admitted | **PASS** |
| `arp` | IPv4 UDP DNS (port 53) | `PacketFilter.matches()` protocol check | Excluded | **PASS** |
| `port 53` | UDP DNS (port 53) | Port check on layers and endpoints | Admitted | **PASS** |
| `port 53` | TCP HTTPS (port 443) | Port check on layers and endpoints | Excluded | **PASS** |
| `src port 51234` | UDP (src 51234, dst 53) | Evaluates source port attribute | Admitted | **PASS** |
| `src port 51234` | UDP (src 1024, dst 53) | Evaluates source port attribute | Excluded | **PASS** |
| `dst port 443` | TCP (src 49152, dst 443) | Evaluates destination port attribute | Admitted | **PASS** |
| `tcp and dst port 443` | TCP (src 49152, dst 443) | Protocol AND destination port match | Admitted | **PASS** |
| `tcp and dst port 443` | UDP (src 49152, dst 443) | Protocol mismatch fails | Excluded | **PASS** |
| `""` or `None` | Any in-scope packet | Evaluates empty filter policy | Admitted | **PASS** |
| `icmp and port 80` | N/A | `PacketFilter.compile()` validation | `FilterSyntaxError` | **PASS (Fail Closed)** |
| `arp and dst port 1` | N/A | `PacketFilter.compile()` validation | `FilterSyntaxError` | **PASS (Fail Closed)** |
| `tcp or udp` | N/A | Disjunction unsupported | `FilterSyntaxError` | **PASS (Fail Closed)** |
| `not tcp` | N/A | Negation unsupported | `FilterSyntaxError` | **PASS (Fail Closed)** |
| `port 0` / `port 70000` | N/A | Port range `[1, 65535]` validation | `FilterSyntaxError` | **PASS (Fail Closed)** |
| `tcp; rm -rf /` | N/A | Metacharacter check | `FilterSyntaxError` | **PASS (Fail Closed)** |

---

## 6. Scope Enforcement Analysis

1. **Missing / Empty Scope Rejection:**
   - Evaluated via `test_01_missing_scope_cidrs_rejected` and `test_02_empty_scope_cidrs_rejected`.
   - `validate_request_dict` rejects empty scope lists with `ProtocolError("scope_cidrs cannot be empty; at least one authorized CIDR network is required.")`.
2. **Endpoint Attribution Invariants:**
   - Both `src_ip` and `dst_ip` are extracted during packet dissection.
   - If neither address can be parsed (such as runt frames < 14 bytes or corrupted headers), `src_ip` and `dst_ip` are `None`. The capture loop rejects the frame immediately:
     ```python
     if not src_ip and not dst_ip:
         continue
     ```
   - Only packets with an address verified by `scope_guard.is_authorized()` are appended to `captured_packets`.
3. **No Socket Creation on Rejected Scope:**
   - Verified via `test_10_proof_rejected_scope_does_not_create_worker_or_socket`.
   - When a request specifies an invalid or missing scope, rejection occurs at schema validation before any raw socket is opened or worker thread is registered.

---

## 7. Test Execution & Observed Evidence

All test runs were executed read-only in the project environment using `.venv/bin/pytest`:

### 7.1 Focused Privilege & Remediation Test Suite
```bash
.venv/bin/pytest tests/unit/test_privilege_ipc.py -v
```
- **Exit Code:** `0`
- **Result:** `59 passed in 16.28s`
- **Failures / Errors:** `0 / 0`
- **Coverage of Findings:**
  - `TestF01CaptureSessionOwnershipAndCancellation`: 10/10 passed.
  - `TestF02PeerCredentialExtraction`: 7/7 passed.
  - `TestF03PacketFilterEnforcement`: 10/10 passed.
  - `TestF04MandatoryScopeEnforcement`: 10/10 passed.
  - Integration & Protocol regression suites: 22/22 passed.

### 7.2 Predecessor Wireless Regressions (TASK-014 / TASK-015)
```bash
.venv/bin/pytest tests/unit/test_wifi.py tests/unit/test_wifi_worker.py tests/unit/test_wireless_scanner.py -v
```
- **Exit Code:** `0`
- **Result:** `59 passed in 2.59s`
- **Failures / Errors:** `0 / 0`

### 7.3 Scope & Lab Regressions (TASK-008)
```bash
.venv/bin/pytest tests/unit/test_scope.py tests/unit/test_lab.py -v
```
- **Exit Code:** `0`
- **Result:** `93 passed in 0.14s`
- **Failures / Errors:** `0 / 0`

### 7.4 Full Project Test Suite
```bash
.venv/bin/pytest tests/
```
- **Exit Code:** `0`
- **Result:** `550 passed, 35 subtests passed in 25.06s`
- **Failures / Errors:** `0 / 0`

### 7.5 Code Quality and Formatting (`git diff --check`)
```bash
git diff --check
```
- **Exit Code:** `0` (Zero whitespace errors, zero trailing spaces, zero merge conflicts).

### 7.6 Database State Invariance
```bash
stat /home/emorphi/.config/itsa-network-os/data.sqlite3
```
- **Status:** Unmodified.
  - Access: `2026-10-19 22:12:58.933347804 +0200`
  - Modify: `2026-10-19 22:12:58.605348218 +0200`
  - Change: `2026-10-19 23:10:22.836339878 +0200`

---

## 8. Security Properties Classification

### 8.1 Verified Code Properties
- Kernel peer credential extraction fails closed without EUID fallback (**F-02**).
- Session ownership requires valid kernel peer UID and constant-time capability secret match (**F-01**).
- Cancellation is targeted per-session and idempotent (**F-01**).
- Server accept loop remains non-blocking during captures via threaded connection handling (**F-01**).
- Packet filtering is compiled and enforced server-side before returning packets (**F-03**).
- Filter grammar strictly rejects shell metacharacters, contradictions, and unsupported syntax (**F-03**).
- Missing, empty, or out-of-bounds scope CIDRs fail closed before socket allocation (**F-04**).
- Every admitted packet is confirmed in-scope; unproven frames are discarded (**F-04**).
- Desktop GUI remains unprivileged and displays non-destructive error banners upon denial or scope violations.

### 8.2 Explicitly Unverified / Out-of-Scope Properties
1. **Live Host PolicyKit Dialog:** Real interactive Polkit password prompts (`pkcheck --allow-user-interaction`) require a full graphical desktop seat session with an active Polkit authentication agent. This property is verified using `MockAuthorizer` with simulated authorized, denied, and unavailable outcomes. Live Polkit integration remains deferred to system packaging and integration testing in MILE-05.
2. **Live AF_PACKET Raw Socket Capture:** Opening raw sockets requires real `CAP_NET_RAW` elevation. In accordance with mandatory safety constraints, tests used synthetic packet injection and pure-binary packet dissectors. Live host raw socket binding was not executed.

---

## 9. Vulnerability Assessment & New Defect Check

A code review of all changes was conducted to ensure no new vulnerabilities were introduced:
- **Injection:** Filter parser does not execute subshells or string formatting in system calls.
- **Race Conditions:** `SessionRegistry` and `CaptureSession` operations are guarded by `threading.Lock()` instances.
- **Capability Leaks:** Tokens are 256-bit entropy, not logged, and verified via `hmac.compare_digest`.
- **Memory Exhaustion:** Session count (16), frame sizes (64 KB / 1 MB), and packet count (50) are strictly bounded.

Zero new vulnerabilities were identified.

---

## 10. Final Decision & Acceptance Verdict

**`ACCEPTED — ALL REQUIRED SECURITY GATES PASSED`**

### Summary of Audit Determination:
1. **F-01:** Fully resolved with per-session capability tokens, thread-safe session registry, and non-blocking threaded accept handling.
2. **F-02:** Fully resolved with fail-closed `SO_PEERCRED` validation and complete elimination of EUID fallback.
3. **F-03:** Fully resolved with strict, deterministic server-side `PacketFilter` compilation and in-loop enforcement.
4. **F-04:** Fully resolved with mandatory non-empty scope validation and in-loop endpoint attribution.
5. **Regressions:** Zero regressions across 550 tests.
6. **Safety Invariants:** Host remained completely unmutated; database remained untouched; zero files staged or committed by reviewer.
