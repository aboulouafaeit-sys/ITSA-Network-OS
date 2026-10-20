# TASK-016 — Privileged IPC Protocol & Architecture Specification

**Document ID:** DOC-IPC-TASK016-001  
**Project:** ITSA Network OS  
**Platform:** Debian 13 (Trixie) | Linux x86_64 | Python 3.13  
**Milestone:** MILE-05 — Privilege Boundaries & Distribution Packaging  
**Dependencies:** TASK-008 (Authorized Network Scope Enclosure, ADR-010)  
**Predecessors:** TASK-014, TASK-015, TASK-015-FIX-REVIEW  
**Status:** Approved Engineering Specification  

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
|                     |         CaptureHelperClient            |                    |
|                     |      (Unix Socket Client / Polkit)     |                    |
|                     +-------------------+--------------------+                    |
+-----------------------------------------|-----------------------------------------+
                                          |
                      Polkit Elevation    |  AF_UNIX Socket / SCM_CREDENTIALS
                      `pkexec` Transport  |  Length-Prefixed JSON Protocol
                                          |
+-----------------------------------------|-----------------------------------------+
|                        Privileged Context (UID 0 / CAP_NET_RAW)                   |
|                                         v                                         |
|                     +----------------------------------------+                    |
|                     |          itsa-priv-helper              |                    |
|                     |    - SO_PEERCRED Authentication        |                    |
|                     |    - Strict Schema Validation          |                    |
|                     |    - ScopeGuard CIDR Boundary Check    |                    |
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
3. **File Permission Boundaries:** Named sockets reside in `/run/itsa-network-os/` (mode `0700` owned by `root:root` or user runtime `XDG_RUNTIME_DIR/itsa-network-os/` mode `0700`).

### 2.2 Peer Credential Verification Algorithm
Upon receiving a client connection:
```python
# Linux SO_PEERCRED binary structure: pid (int32), uid (uint32), gid (uint32)
SO_PEERCRED = 17  # Standard Linux socket option
creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
pid, uid, gid = struct.unpack("3i", creds)

# Helper validates that caller UID matches the authorized local user session
if not is_authorized_uid(uid):
    sock.close()
    raise UnauthorizedClientError(f"Client UID {uid} denied access")
```

---

## 3. Message Framing & Schema Definition

### 3.1 Framing Specification
All IPC frames consist of:
- **Length Prefix (4 bytes):** Unsigned 32-bit integer in big-endian network byte order (`!I`), denoting the length in bytes of the JSON payload.
- **Payload (`N` bytes):** Valid UTF-8 encoded JSON object.

**Buffer Limits:**
- Maximum Request Message Size: `64 KB` (65,536 bytes).
- Maximum Response Message Size: `1 MB` (1,048,576 bytes).
- Any frame exceeding these thresholds is immediately rejected, and the socket is closed to prevent denial-of-service memory exhaustion.

### 3.2 Finite Action Identifiers
The privileged helper exposes only four finite operations. Arbitrary command execution, shell expressions, file path arguments, or unbounded system calls are strictly forbidden:

1. `OP_PING`: Echo health check to verify IPC connectivity and protocol version.
2. `OP_GET_CAPABILITIES`: Report supported operations, Linux kernel capabilities, and version.
3. `OP_CAPTURE_PACKETS`: Execute bounded raw packet capture on an authorized interface with optional BPF filter and ScopeGuard CIDR enclosure.
4. `OP_STOP_CAPTURE`: Signal cooperative cancellation to an active capture session.

### 3.3 Request Message Schema
```json
{
  "request_id": 101,
  "action": "OP_CAPTURE_PACKETS",
  "interface": "eth0",
  "packet_count": 20,
  "timeout_seconds": 3.0,
  "filter_expression": "ip and (tcp or udp)",
  "scope_cidrs": ["192.168.1.0/24", "10.0.0.0/8"]
}
```

**Field Constraints & Validation Rules:**
- `request_id`: Positive integer `[1, 2^31 - 1]`.
- `action`: String matching one of `["OP_PING", "OP_GET_CAPABILITIES", "OP_CAPTURE_PACKETS", "OP_STOP_CAPTURE"]`.
- `interface`: Validated against `InputValidator.validate_interface_name` (alphanumeric plus `-`, `_`, `.`; max 16 characters).
- `packet_count`: Integer in range `[1, 50]`. (Defaults to 10).
- `timeout_seconds`: Float in range `[0.1, 10.0]`. (Defaults to 5.0s).
- `filter_expression`: Optional string (max 128 characters) restricted to alphanumeric tokens, spaces, and safe BPF operators (`and`, `or`, `not`, `port`, `host`, `src`, `dst`, `tcp`, `udp`, `icmp`, `ip`, `ip6`, `arp`). Reject metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`).
- `scope_cidrs`: List of valid CIDR strings (max 16 entries). Each validated against `ScopeGuard` / `InputValidator.validate_ip_network`.

### 3.4 Response Message Schema
```json
{
  "request_id": 101,
  "status": "SUCCESS",
  "error_code": null,
  "error_message": null,
  "payload": {
    "packets_captured": 2,
    "duration_seconds": 0.42,
    "interface": "eth0",
    "packets": [
      {
        "index": 1,
        "protocol": "TCP",
        "src": "192.168.1.105:49152",
        "dst": "192.168.1.1:443",
        "summary": "[SYN] Seq=0 Len=0",
        "length_bytes": 60,
        "layers": []
      }
    ]
  }
}
```

**Terminal Status Codes:**
- `SUCCESS`: Operation completed normally within constraints.
- `DENIED`: Polkit authorization denied or peer UID unauthorized.
- `SCOPE_VIOLATION`: Target interface or packet destination violated TASK-008 enclosure.
- `INVALID_REQUEST`: Message schema, length, or parameters failed strict validation.
- `TIMEOUT`: Operation reached bounded timeout without error.
- `CANCELLED`: Operation terminated cleanly upon user cancellation request.
- `ERROR`: Operational failure (e.g. interface down, netlink error).

---

## 4. Lifecycle, Cancellation, and Resource Reaping

1. **Preflight Scope Enforcement:** The helper evaluates `interface` and `scope_cidrs` against `ScopeGuard` before calling `socket(AF_PACKET, ...)`.
2. **Non-Blocking / Polled Capture Loop:** Raw packet reception uses non-blocking sockets with `select.select()` or `poll()` with a maximum tick interval of 50 ms.
3. **Monotonic Timeout:** A monotonic deadline `time.monotonic() + timeout_seconds` bounds the execution.
4. **Cooperative Cancellation:** An asynchronous cancellation flag (`threading.Event`) halts the capture loop within 50 ms when `OP_STOP_CAPTURE` is received.
5. **Deterministic Cleanup:** Sockets are closed inside `finally:` blocks. Child helper processes (when spawned via `pkexec`) are monitored with timeouts and reaped with `wait()` to prevent zombie processes.

---

## 5. Audit Logging and Credential Redaction

All security events are recorded via structured logging:
- Client connection attempts (PID, UID, timestamp).
- Authorization verification outcomes (granted / denied).
- Scope enforcement decisions (target IP, authorized vs out-of-scope).
- Session start, duration, and packet counts.
- **Redaction Invariant:** Sensitive packet payloads (passwords, TLS key exchanges, private tokens) are never written to audit logs; only protocol headers, packet indices, and summary lengths are logged.

---

## 6. Packaging & Installation Boundaries

- **Helper Executable:** `/usr/libexec/itsa-network-os/itsa-priv-helper` (Permissions: `0755`, Owner: `root:root`).
- **PolicyKit Action Policy:** `/usr/share/polkit-1/actions/org.itsa.networkos.capture.policy` (Permissions: `0644`, Owner: `root:root`).
- **Runtime Socket Directory:** `/run/itsa-network-os/` (Permissions: `0700`, Owner: `root:root`).
- **Development Invariant:** Host system directories are NEVER modified during tests or development. Packaging artifacts are staged in `packaging/polkit/` and tested via isolated mock backends.
