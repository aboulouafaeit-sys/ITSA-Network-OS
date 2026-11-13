# ITSA Network OS — Global Brand Identity & Visual Design System

> **Document ID:** DOC-BRAND-001  
> **Status:** Active Baseline (Phase H Acceptance)  
> **Version:** 1.0.0  
> **Last Updated:** 2026-11-13  
> **Author:** Mohamed Aboulouafae & ITSA Network OS Core Maintainers  

---

## 1. Brand Mission & Visual Values

ITSA Network OS is an enterprise-grade, defensive network engineering, diagnostics, and cybersecurity platform. Its visual identity must convey:

- **Network Engineering Expertise:** Structural order, topological clarity, and protocol rigor.
- **Cybersecurity & Trust:** Non-destructive operation, verifiable boundaries, and uncompromised integrity.
- **Technical Precision:** Crisp geometry, mathematical alignment, and optical balance.
- **Reliability & Stability:** Predictability, long-term resilience, and least-privilege guarantees.
- **Modern Innovation:** Next-generation glassmorphic ergonomics, low visual cognitive load, and dark-mode elegance.

---

## 2. Official Logo Design: The Resilient Lattice

The official logo for ITSA Network OS centers on **The Resilient Lattice Core** — an original isometric hexagonal structure symbolizing multi-node network connectivity, cryptographic boundaries, and deterministic routing.

```text
               (256, 56) [Top Node]
                  /\
                 /  \
  (83, 156)     /    \     (429, 156)
  [Upper-Left] /______\    [Upper-Right]
      |       /\      /\       |
      |      /  \    /  \      |
      |     /____\  /____\     |
      |    [Left] \[Right]     |
      |    Security\Switch     |
      |            /\          |
  (83, 356)       /  \     (429, 356)
  [Lower-Left]   /____\    [Lower-Right]
                 \    /
                  \  /
                   \/
               (256, 456) [Bottom Node]
```

### 2.1 Symbolic Anatomy
1. **Outer Hexagonal Boundary (6 Node Terminals):** Represents the 6 fundamental layers of monitored infrastructure (Physical, Data-Link, Network, Transport, TLS/Crypto, and Administrative Policy).
2. **Top Ingress Telemetry Facet (`#00D2FF` to `#00A3FF`):** Symbolizes high-velocity packet flow, bandwidth monitoring, and RF signal telemetry.
3. **Right Switching Engine Facet (`#1F6FEB` to `#0969DA`):** Represents robust OSPF routing, shortest-path calculation, and deterministic state convergence.
4. **Left Security & Verification Facet (`#2EA043` to `#1A7F37`):** Embodies defensive privilege isolation (Polkit, ScopeGuard), non-root execution, and vulnerability auditing.
5. **Central Isometric Kernel Diamond (`#58A6FF` / `#0D1117`):** The isolated, non-destructive core engine coordinating diagnostic workers without host disruption.

### 2.2 Master Geometry & Clearspace Rules
- **Master Artboard:** 512 × 512 px vector grid (`viewBox="0 0 512 512"`).
- **Safe Area / Clearspace ($X$):** Minimum clearspace around the symbol and wordmark is defined as $X = 0.25 \times \text{Symbol Height}$. No text, borders, or foreign visual elements may intrude into this boundary.
- **Minimum Display Sizes:**
  - **Favicon & Taskbar:** 16 × 16 px (high-contrast symbol silhouette).
  - **Desktop Application Icon:** 32 × 32 px (squircle container).
  - **Horizontal Wordmark:** 180 × 45 px.
  - **Stacked Wordmark:** 120 × 140 px.

---

## 3. Official Logo Asset Matrix

All assets are located in the repository under [`assets/branding/`](../assets/branding/):

| Variant | Filename | Primary Context of Use |
|---|---|---|
| **Master Symbol (Dark)** | `assets/branding/svg/itsa-symbol-dark.svg` | Default brand mark on dark surfaces & GUI header |
| **Master Symbol (Light)** | `assets/branding/svg/itsa-symbol-light.svg` | Brand mark on white/light paper & documentation |
| **Monochrome White** | `assets/branding/svg/itsa-symbol-mono-white.svg` | Single-color laser etching, dark print, terminal art |
| **Monochrome Black** | `assets/branding/svg/itsa-symbol-mono-black.svg` | Formal legal documents, black-and-white printing |
| **Horizontal Logo (Dark)** | `assets/branding/svg/itsa-logo-horizontal-dark.svg` | Website navigation, README headers, presentation slides |
| **Horizontal Logo (Light)** | `assets/branding/svg/itsa-logo-horizontal-light.svg` | White background documentation, PDF exports |
| **Stacked Logo (Dark)** | `assets/branding/svg/itsa-logo-stacked-dark.svg` | Splash screens, installer welcome screen, merchandise |
| **Stacked Logo (Light)** | `assets/branding/svg/itsa-logo-stacked-light.svg` | Light theme installer screens, printed manuals |
| **Desktop App Icon** | `assets/branding/svg/itsa-app-icon.svg` | Desktop application launcher, Linux `.desktop` entries |
| **Multi-Res App Icon** | `assets/branding/ico/itsa-app-icon.ico` | Windows launcher, Debian package binary icon |
| **Favicon Matrix** | `assets/branding/ico/favicon.ico` (16, 32) | Web browser tabs, developer portals, docs site |

---

## 4. Color Palette Specifications

The ITSA Network OS palette utilizes mathematically balanced contrast ratios satisfying WCAG AAA standards for text readability and telemetry visibility on dark backgrounds.

### 4.1 Primary Brand Colors

```text
+-----------------------+-----------------------+-----------------------+
| ITSA Electric Cyan    | ITSA Cobalt Core      | ITSA Emerald Pulse    |
| #00D2FF               | #1F6FEB               | #2EA043               |
| RGB(0, 210, 255)      | RGB(31, 111, 235)     | RGB(46, 160, 67)      |
| CMYK(100, 18, 0, 0)   | CMYK(87, 53, 0, 8)    | CMYK(71, 0, 58, 37)   |
| Ingress / Telemetry   | Core Routing / State  | Security / Verified   |
+-----------------------+-----------------------+-----------------------+
```

### 4.2 Dark Mode Surfaces (Primary Runtime Environment)

| Token Name | HEX Code | RGB | Purpose / Usage |
|---|---|---|---|
| `surface-canvas` | `#0D1117` | `13, 17, 23` | Application base background, terminal root |
| `surface-subtle` | `#161B22` | `22, 27, 34` | Cards, sidebar, modal dialogs, headers |
| `surface-overlay` | `#21262D` | `33, 38, 45` | Hover states, active list selections, tooltips |
| `border-default` | `#30363D` | `48, 54, 61` | Structural lines, card strokes, table grids |
| `border-focus` | `#58A6FF` | `88, 166, 255` | Focused inputs, active tabs, accent borders |
| `text-primary` | `#F0F6FC` | `240, 246, 252` | Window titles, primary readings, table data |
| `text-secondary` | `#8B949E` | `139, 148, 158` | Subtitles, port descriptions, inactive labels |

### 4.3 Diagnostic & Telemetry Semantic Palette

| Semantic Token | HEX Code | RGB | Meaning / Usage |
|---|---|---|---|
| `status-success` | `#3FB950` | `63, 185, 80` | Interface UP, healthy link, valid certificate, safe posture |
| `status-warning` | `#D29922` | `210, 153, 34` | Wi-Fi channel congestion, expiring cert, weak cipher |
| `status-danger` | `#F85149` | `248, 81, 73` | Interface DOWN, link failure, open root risk, packet loss |
| `status-info` | `#58A6FF` | `88, 166, 255` | Informational query, route hops, CIDR calculations |
| `status-neutral` | `#8B949E` | `139, 148, 158` | Offline cache, mock mode indicator, unprobed host |

---

## 5. Typography Hierarchy

The typography system is engineered for maximum legibility of complex technical data, IP addresses, hexadecimal dumps, and high-frequency telemetry.

### 5.1 Font Families
- **Interface & Display Sans:** `Segoe UI`, `Inter`, `Roboto`, `Cantarell`, `-apple-system`, `sans-serif`
- **Telemetry & Monospace Code:** `Fira Code`, `JetBrains Mono`, `Consolas`, `DejaVu Sans Mono`, `monospace`

### 5.2 Type Scale

| Level | Size | Weight | Line Height | Usage |
|---|---|---|---|---|
| **Display (H1)** | 24px / 1.75rem | Bold (700) | 32px | Main dashboard banners, major dialog titles |
| **Section (H2)** | 18px / 1.25rem | Semi-Bold (600) | 26px | Tab headers, canvas inspector titles |
| **Card Header (H3)**| 14px / 1.0rem | Medium (500) | 20px | Subnet summary labels, vendor card headers |
| **Body Standard** | 13px / 0.92rem | Regular (400) | 18px | General UI prose, settings options, table text |
| **Caption / Badge** | 11px / 0.78rem | Semi-Bold (600) | 14px | Health status badges, scope indicators, pill tags |
| **Code / Telemetry**| 12px / 0.85rem | Regular (400) | 16px | Hex inspector, packet decode, routing tables |

---

## 6. Spacing & Layout Grid (4px / 8px Metric)

All UI elements adhere to an 8-point base grid with a 4-point sub-grid:
- **`space-1` (4px):** Micro-spacing between icon and badge label.
- **`space-2` (8px):** Gaps between table cells, inline buttons, header widgets.
- **`space-3` (12px):** Sidebar item vertical padding, form input inner padding.
- **`space-4` (16px):** Standard card padding, layout margins.
- **`space-6` (24px):** Major layout section gaps, modal dialog padding.
- **`space-8` (32px):** Canvas margins, empty state containers.

---

## 7. Prohibited Logo Modifications

To protect the integrity and global recognizability of ITSA Network OS, the following modifications are strictly prohibited:

```text
  [❌ DO NOT] Stretch, compress, or alter logo aspect ratio.
  [❌ DO NOT] Recolor logo using unapproved gradients, neon yellows, or red fills.
  [❌ DO NOT] Rotate the symbol from its regular 90° vertical hex orientation.
  [❌ DO NOT] Add decorative drop shadows, generic neon glows, or 3D extrusions.
  [❌ DO NOT] Place the dark logo on low-contrast dark gray or patterned backgrounds.
  [❌ DO NOT] Surround the logo with shield shapes, padlocks, or generic stock art.
  [❌ DO NOT] Re-type the wordmark in decorative or non-approved fonts.
  [❌ DO NOT] Crop the perimeter telemetry nodes or disconnect the facet paths.
```

---

## 8. Application & System Branding Implementations

The brand identity has been systematically applied across the operating platform:

1. **Desktop Shell Header:** Integrated official vector symbol (`itsa-symbol-32.png`) alongside typography and live health badge.
2. **Window System Icon:** High-resolution multi-size icon (`itsa-app-icon-64.png`) assigned to `MainWindow.setWindowIcon()`.
3. **Official About Dialog (`F1` / Header Button):** Branded modal dialog displaying the official vector mark, semantic versioning, architecture invariants, and MIT licensing.
4. **Desktop Entry & Application Menu:** `debian-live` launcher configured with `Icon=itsa-network-os` and assets distributed to `usr/share/icons/hicolor/`.
5. **Debian Live Build Integration:** Multi-resolution icons (SVG, 48x48, 256x256) embedded in the chroot overlay ready for ISO generation.
6. **Documentation & GitHub Repository:** Official SVG logo banners, verified capability matrix, and technical screenshots embedded in `README.md`.
