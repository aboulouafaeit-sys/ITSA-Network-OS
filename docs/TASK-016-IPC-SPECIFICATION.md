# TASK-016 — Privileged IPC Protocol & Architecture Specification

**Document ID:** DOC-IPC-TASK016-001  
**Project:** ITSA Network OS  
**Platform:** Debian 13 (Trixie) | Linux x86_64 | Python 3.13  
**Milestone:** MILE-05 — Privilege Boundaries & Distribution Packaging  
**Dependencies:** TASK-008 (Authorized Network Scope Enclosure, ADR-010)  
**Predecessors:** TASK-014, TASK-015, TASK-015-FIX-REVIEW  
**Status:** Approved Engineering Specification (Hardened Post-Audit)

---

## 1. System Architecture & Component Separation

ITSA Network OS separates responsibilities across a strict security privilege boundary:

```
+-----------------------------------------------------------------------------------+
|                        Unprivileged Context (UID >= 1000)                         |
|                                                                                   |
|  +-------------------------------------+   +-----------------------------------+  |
|  |     PySide6 Desktop Application     |   |         CLI Entry Points          |  |
|  |   (app_window.py, packet_lab.py)    |   |             (cli.py)              |  |
|  +------------------+------------------+   +-----------------+-----------------+  |
|                     |                                        |                    |
|                     +-------------------+--------------------+                    |
|                                         |                                         |
|                     +-------------------v--------------------+                    |
|                     |       Application Core (app.py)        |                    |
|                     |      ScopeGuard Runtime Validator      |                    |
|                     +-------------------+--------------------+                    |
|                                         |                                         |
|                     +-------------------v--------------------+                    |
|                     |      PrivilegedCaptureClient           |                    |
|                     |   (Unix Socket Client / Session Token) |                    |
|                     +-------------------+--------------------+                    |
+-----------------------------------------|-----------------------------------------+
                                          |
                      Polkit Elevation    |  AF_UNIX Socket / SO_PEERCRED
                      `pkexec` Transport  |  Length-Prefixed JSON Protocol
                                          |
+-----------------------------------------|-----------------------------------------+
|                        Privileged Context (UID 0 / CAP_NET_RAW)                   |
|                                         v                                         |
|                     +----------------------------------------+                    |
|                     |          itsa-priv-helper              |                    |
|                     |    - Fail-Closed SO_PEERCRED Check     |                    |
|                     |    - Threaded Client Connection Pool   |                    |
|                     |    - Capability-Bound Session Registry |                    |
|                     |    - Mandatory ScopeGuard Enclosure    |                    |
|                     |    - Deterministic PacketFilter Engine |                    |
|                     |    - Bounded Raw Socket Packet Engine  |                    |
|                     +----------------------------------------+                    |
+-----------------------------------------------------------------------------------+
```

---

## 2. IPC Transport & Peer Authentication Mechanism

### 2.1 Transport Protocol
The IPC channel utilizes a local **Unix Domain Stream Socket (`AF_UNIX`, `SOCK_STREAM`)** or connected anonymous socketpair spawned via PolicyKit (`pkexec`).

Advantages for Debian 13:
1. **Zero Network Exposure:** Unix sockets are confined to the local Linux VFS / kernel IPC subsystem; they cannot be accessed over external network interfaces or loopback TCP.
2. **Kernel-Enforced Peer Credentials (`SO_PEERCRED`):** The Linux kernel guarantees the authenticity of peer credentials. The helper retrieves the caller's PID, UID, and GID directly from kernel space via `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ...)`.
3. **File Permission Boundaries:** Named sockets reside in `/run/itsa-network-os/` (mode `0700` owned by `root:root`).

### 2.2 Fail-Closed Peer Credential Extraction Algorithm (F-02 Hardening)
Upon accepting a client connection, the server extracts credentials before reading any data or dispatching operations:

```python
SO_PEERCRED = 17  # Standard Linux socket option
creds_size = struct.calcsize("3i")
creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, creds_size)
if not creds or len(creds) != creds_size:
    raise PeerCredentialError("SO_PEERCRED returned invalid byte length")

pid, uid, gid = struct.unpack("3i", creds)
if pid <= 0 or uid < 0 or gid < 0:
    raise PeerCredentialError("Invalid peer PID, UID, or GID")
```

**Security Invariants:**
- If credential retrieval fails (`OSError`, `struct.error`, unsupported socket), the helper **fails closed** immediately and sends `DENIED` with `UNAUTHORIZED`.
- The helper's own EUID, PID, or GID is **never substituted** for peer credentials.
- Missing or invalid credentials are never interpreted as root or authorized.
- Peer identity is validated before PolicyKit authorization or request processing.

---

## 3. Message Framing & Schema Definition

### 3.1 Framing Specification
All IPC frames consist of:
- **Length Prefix (4 bytes):** Unsigned 32-bit integer in big-endian network byte order (`!I`), denoting the length in bytes of the JSON payload.
- **Payload (`N` bytes):** Valid UTF-8 encoded JSON object.

**Buffer Limits:**
- Maximum Request Message Size: `64 KB` (65,536 bytes).
- Maximum Response Message Size: `1 MB` (1,048,576 bytes).
- Any frame exceeding these thresholds is immediately rejected with `MessageTooLargeError`, and the socket is closed to prevent denial-of-service memory exhaustion.

### 3.2 Finite Action Identifiers
The privileged helper exposes only explicit operations. Arbitrary command execution, shell expressions, file path arguments, or unbounded system calls are strictly forbidden:

1. `OP_PING`: Echo health check to verify IPC connectivity and protocol version.
2. `OP_GET_CAPABILITIES`: Report supported operations, Linux kernel capabilities, and version.
3. `OP_START_CAPTURE`: Initiate asynchronous capture session, returning unique `session_id` and capability token `session_token`.
4. `OP_STOP_CAPTURE`: Signal cooperative cancellation to a specific capture session identified by `session_id` and authorized by `session_token`.
5. `OP_GET_CAPTURE_RESULTS`: Query execution status and retrieve collected packets for a session using `session_id` and `session_token`.
6. `OP_CAPTURE_PACKETS`: Synchronous bounded packet capture with server-side session tracking and cooperative cancellation support.

### 3.3 Request Message Schema
```json
{
  "request_id": 101,
  "action": "OP_START_CAPTURE",
  "interface": "eth0",
  "packet_count": 20,
  "timeout_seconds": 3.0,
  "filter_expression": "tcp and dst port 443",
  "scope_cidrs": ["192.168.1.0/24"],
  "session_id": null,
  "session_token": null
}
```

**Field Constraints & Validation Rules:**
- `request_id`: Positive integer `[1, 2^31 - 1]`.
- `action`: String matching one of the valid finite action identifiers.
- `interface`: Validated against `INTERFACE_REGEX` (`^[a-zA-Z0-9_\-\.]{1,16}$`).
- `packet_count`: Integer in range `[1, 50]`. (Defaults to 10).
- `timeout_seconds`: Float in range `[0.1, 10.0]`. (Defaults to 5.0s).
- `filter_expression`: Optional string (max 128 characters) conforming strictly to supported deterministic filter grammar.
- `scope_cidrs`: **Mandatory non-empty list** of valid CIDR strings (max 16 entries). Missing or empty lists fail closed with `ProtocolError` / `SCOPE_VIOLATION`.
- `session_id`: Optional for capture initiation; mandatory for `OP_STOP_CAPTURE` and `OP_GET_CAPTURE_RESULTS` (`^[a-zA-Z0-9_\-]{1,64}$`).
- `session_token`: Optional for capture initiation; mandatory for `OP_STOP_CAPTURE` and `OP_GET_CAPTURE_RESULTS` (length 1 to 128 characters).

### 3.4 Response Message Schema
```json
{
  "request_id": 101,
  "status": "SUCCESS",
  "error_code": null,
  "error_message": null,
  "payload": {
    "session_id": "a1b2c3d4e5f60718",
    "session_token": "secret_capability_token...",
    "interface": "eth0",
    "packet_count": 20,
    "timeout_seconds": 3.0
  }
}
```

**Terminal Status Codes:**
- `SUCCESS`: Operation completed normally within constraints.
- `DENIED`: Polkit authorization denied, peer UID mismatch, or invalid capability token.
- `SCOPE_VIOLATION`: Scope enclosure missing, empty, malformed, or packet destination outside enclosure.
- `INVALID_REQUEST`: Message schema, length, or parameters failed strict validation.
- `TIMEOUT`: Operation reached bounded timeout without error.
- `CANCELLED`: Operation terminated cleanly upon verified user cancellation request.
- `ERROR`: Operational failure (e.g. raw socket creation error).

**Error Codes:**
- `INVALID_SCHEMA`: Framing, size limit, or JSON schema violation.
- `UNAUTHORIZED`: PolicyKit authorization denial or peer UID mismatch.
- `SCOPE_VIOLATION`: Target interface or CIDR violated scope boundaries.
- `INVALID_INTERFACE`: Malformed interface name.
- `INVALID_FILTER`: Unsupported, malformed, or contradictory filter expression.
- `EXECUTION_TIMEOUT`: Operation timed out.
- `CAPTURE_ERROR`: Low-level raw socket capture failure.
- `SYSTEM_ERROR`: Internal daemon error.
- `SESSION_NOT_FOUND`: Specified session identifier does not exist or has expired.
- `INVALID_TOKEN`: Session capability token failed verification.

---

## 4. Capture Session Lifecycle & Ownership Model (F-01 Hardening)

### 4.1 Threat Context and Architectural Invariants
In multi-user or multi-process systems, UID-only ownership is insufficient if multiple processes run under the same UID. Additionally, blocking capture operations must not prevent concurrent cancellation requests from being processed.

### 4.2 Lifecycle Architecture
1. **Threaded Connection Pool:** The server accept loop dispatches client connections into dedicated worker threads (`handle_connection_threaded`), ensuring that an active capture loop on one connection never blocks client requests on another connection.
2. **Per-Session Identifiers & Capability Tokens:**
   - `session_id`: Cryptographically unpredictable hex string (`secrets.token_hex(16)`).
   - `session_token`: High-entropy capability secret (`secrets.token_urlsafe(32)`).
3. **Session Registry (`SessionRegistry`):**
   - Thread-safe registry holding active and recent `CaptureSession` instances.
   - Enforces maximum active session limits (max 16 concurrent sessions).
   - Prunes expired terminal sessions after retention period.
4. **Ownership Verification Rules:**
   - **UID Binding:** Caller peer UID must match `session.owner_uid`.
   - **Capability Binding:** Caller `session_token` must match `session.session_token` using constant-time comparison (`hmac.compare_digest`).
   - Requests lacking valid ownership and matching tokens are rejected with `DENIED` (`UNAUTHORIZED` or `INVALID_TOKEN`).
5. **Dedicated Cancellation Primitives:**
   - Each session maintains its own `cancellation_event: threading.Event`.
   - Cancellation targets only the specified session; no global cancellation state exists.
   - Cancellation is **idempotent**: duplicate or concurrent stop requests succeed deterministically without race conditions.
6. **Token Redaction:**
   - Capability tokens are **never logged** or included in error messages.

---

## 5. Supported Packet Filter Grammar (F-03 Hardening)

### 5.1 Grammar Specification
The application supports a deterministic, safe packet filter engine (`PacketFilter`) that is strictly compiled and evaluated on the trusted server side:

```
Filter       ::= ProtocolExpr [ 'and' PortExpr ] | PortExpr | ε
ProtocolExpr ::= 'tcp' | 'udp' | 'icmp' | 'arp'
PortExpr     ::= [ 'src' | 'dst' ] 'port' <1..65535>
```

### 5.2 Semantics & Validation Invariants
1. **Protocol Matching:**
   - `tcp`: Matches TCP frames (IPv4 EtherType `0x0800`, IP protocol 6). Excludes non-TCP.
   - `udp`: Matches UDP frames (IPv4 EtherType `0x0800`, IP protocol 17). Excludes non-UDP.
   - `icmp`: Matches ICMP frames (IPv4 EtherType `0x0800`, IP protocol 1). Excludes non-ICMP.
   - `arp`: Matches ARP frames (EtherType `0x0806`). Excludes non-ARP.
2. **Port Matching:**
   - `port <N>`: Matches if source port OR destination port equals N.
   - `src port <N>`: Matches if source port equals N.
   - `dst port <N>`: Matches if destination port equals N.
   - Port predicates require TCP or UDP; evaluated against L4 layer fields and address endpoints.
3. **Contradiction Rejection:**
   - `icmp` or `arp` combined with port predicates (e.g. `icmp and port 80`) is rejected with `FilterSyntaxError` (`INVALID_FILTER`).
4. **Disallowed Grammar:**
   - Metacharacters (`;`, `&`, `|`, `$`, `` ` ``, `>`, `<`, `\`, `!`), negation (`not`), disjunction (`or`), and arbitrary tokens are rejected at compile time.
5. **Empty Filter Policy:**
   - Empty string `""` or `None` compiles and matches all in-scope packets.
6. **Execution Safety:**
   - Filters are never evaluated using `eval()`, `exec()`, or subshells.

---

## 6. Mandatory Network Scope Enforcement (F-04 Hardening)

### 6.1 Policy
In accordance with **TASK-008 (ADR-010)**, packet capture requires explicit, authorized scope bounds.

1. **Mandatory Scope Enclosure:** `scope_cidrs` must be provided and must be a non-empty list of valid CIDRs. Requests with missing or empty scopes are rejected before socket opening.
2. **Endpoint Evaluation:** For every frame captured (live or synthetic):
   - Parsed source address (`src_ip`) and destination address (`dst_ip`) are evaluated against `ScopeGuard`.
   - A frame is admitted if at least one proven endpoint is authorized in scope.
3. **Unproven Frames Fail Closed:**
   - Runt frames (< 14 bytes), corrupted headers, or non-IP frames without verified addresses cannot be proven in scope and are silently excluded.
4. **ARP Scope Evaluation:**
   - ARP Sender Protocol Address (`spa`) and Target Protocol Address (`tpa`) are evaluated against scope CIDRs.
5. **IPv6 Scope Policy:**
   - IPv6 frames require an explicit IPv6 network in the authorized scope enclosure; an IPv4-only scope excludes IPv6 frames.
