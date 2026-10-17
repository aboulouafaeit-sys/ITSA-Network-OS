# Debian Live Image Build Guide — ITSA Network OS

## 1. Overview
The ITSA Network OS Live Image is an autonomous, bootable Debian 13 (Trixie) operating system tailored for network engineering and cybersecurity diagnostics.
It runs entirely in RAM, offering an ephemeral, tamper-proof environment that leaves zero footprint on host hard drives.

```
+-------------------------------------------------------------------------------+
|                       Boot Phase (Syslinux / GRUB)                            |
+-------------------------------------------------------------------------------+
                                       |
+-------------------------------------------------------------------------------+
|                   Debian 13 (Trixie) Kernel & Initramfs                       |
|           live-boot loads compressed SquashFS root filesystem into RAM        |
+-------------------------------------------------------------------------------+
                                       |
+-------------------------------------------------------------------------------+
|               XFCE4 Lightweight Desktop Session (User: user)                 |
|                   Automatic login to unprivileged account                     |
+-------------------------------------------------------------------------------+
                                       |
+-------------------------------------------------------------------------------+
|                    Pre-Installed ITSA Network OS Platform                     |
|         Desktop shortcut, Python 3 venv, PySide6 GUI, and CLI toolchain       |
+-------------------------------------------------------------------------------+
```

---

## 2. Prerequisites
Building the ISO requires:
- A Linux environment with `live-build` (Debian 12/13 recommended), OR
- Docker / Podman on any host OS.
- Minimum 10 GB of free storage space.
- A reliable Internet connection to fetch official Debian Trixie packages.

---

## 3. Build Methods

### Method A: Isolated Docker Build (Recommended)
This method executes the entire build inside an isolated container without requiring root access on the host:

```bash
cd itsa-network-os
docker compose -f docker/compose.yaml up --build
```
Upon completion, the resulting `.iso` file and its SHA256 checksum will be located in `build-output/`.

### Method B: Native Debian 13 Build Server
If building natively on a Debian 13 system:

```bash
# 1. Install toolchain
sudo apt-get update && sudo apt-get install -y \
    live-build debootstrap squashfs-tools xorriso

# 2. Run the build script
sudo ./scripts/build_live_iso.sh
```

---

## 4. Testing the Live Image

### Using QEMU (Recommended for Safe Testing)
```bash
qemu-system-x86_64 -m 4G -enable-kvm -cdrom build-output/itsa-network-os-*.iso
```

### Using VirtualBox
1. Create a new virtual machine: Type **Linux**, Version **Debian (64-bit)**.
2. Allocate at least **4096 MB RAM** and **2 CPU cores**.
3. Attach the generated `.iso` to the virtual optical drive.
4. Boot the VM.

---

## 5. Security & Safety Invariants
- **Non-Destructive**: The live system mounts host drives in read-only mode by default.
- **RAM-Only Operations**: Any changes made during the live session exist purely in volatile memory and vanish upon reboot.
- **Verifiable**: Every generated ISO is accompanied by a cryptographic SHA-256 hash.
