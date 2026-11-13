#!/usr/bin/env python3
"""Generate official vector SVGs and raster PNG/ICO brand assets for ITSA Network OS."""

import os
import sys
import subprocess
from pathlib import Path

# Ensure PySide6 is available
os.environ["QT_QPA_PLATFORM"] = "offscreen"
try:
    from PySide6.QtCore import QByteArray, QSize
    from PySide6.QtGui import QGuiApplication, QImage, QPainter
    from PySide6.QtSvg import QSvgRenderer
except ImportError:
    print("Error: PySide6 required to render brand assets.")
    sys.exit(1)

ROOT_DIR = Path(__file__).resolve().parent.parent
BRAND_DIR = ROOT_DIR / "assets" / "branding"
SVG_DIR = BRAND_DIR / "svg"
PNG_DIR = BRAND_DIR / "png"
ICO_DIR = BRAND_DIR / "ico"
APP_ASSETS_DIR = ROOT_DIR / "src" / "itsa_network_os" / "ui" / "desktop" / "assets"

for d in [SVG_DIR, PNG_DIR, ICO_DIR, APP_ASSETS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# SVG GENERATORS
# ---------------------------------------------------------------------------

def create_symbol_svg(variant="dark"):
    """
    Generate master vector SVG for the ITSA Resilient Lattice Symbol.
    variant: 'dark', 'light', 'mono-white', 'mono-black'
    """
    if variant == "mono-white":
        top_color = "#FFFFFF"
        right_color = "#E0E0E0"
        left_color = "#C0C0C0"
        center_color = "#FFFFFF"
        node_fill = "#FFFFFF"
        node_inner = "#000000"
        ring_color = "#A0A0A0"
        accent_color = "#FFFFFF"
    elif variant == "mono-black":
        top_color = "#111111"
        right_color = "#333333"
        left_color = "#555555"
        center_color = "#111111"
        node_fill = "#111111"
        node_inner = "#FFFFFF"
        ring_color = "#777777"
        accent_color = "#111111"
    elif variant == "light":
        top_color = "#0091FF"      # Deep Cyan / Blue
        right_color = "#0052CC"    # Solid Cobalt
        left_color = "#1A7F37"     # Dark Emerald
        center_color = "#0D1117"   # Deep Charcoal
        node_fill = "#0969DA"
        node_inner = "#FFFFFF"
        ring_color = "#8C959F"
        accent_color = "#0091FF"
    else:  # default 'dark'
        top_color = "#00D2FF"      # Electric Cyan
        right_color = "#1F6FEB"    # Cobalt Blue
        left_color = "#2EA043"     # Emerald Green
        center_color = "#58A6FF"   # Sky Blue
        node_fill = "#58A6FF"
        node_inner = "#0D1117"
        ring_color = "#30363D"
        accent_color = "#00D2FF"

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <!-- Gradients for depth and optical precision -->
    <linearGradient id="topFacetGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{top_color}" stop-opacity="1"/>
      <stop offset="100%" stop-color="{right_color}" stop-opacity="0.85"/>
    </linearGradient>
    <linearGradient id="rightFacetGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="{right_color}" stop-opacity="1"/>
      <stop offset="100%" stop-color="{center_color}" stop-opacity="0.9"/>
    </linearGradient>
    <linearGradient id="leftFacetGrad" x1="100%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="{left_color}" stop-opacity="1"/>
      <stop offset="100%" stop-color="{top_color}" stop-opacity="0.75"/>
    </linearGradient>
  </defs>

  <!-- Outer Telemetry Transit Ring / Boundary Geometry -->
  <g id="telemetry-bus" stroke="{ring_color}" stroke-width="4" fill="none" opacity="0.6">
    <path d="M 256 56 L 429 156 L 429 356 L 256 456 L 83 356 L 83 156 Z" stroke-dasharray="14 10"/>
  </g>

  <!-- Hexagonal Faceted Lattice Core -->
  <g id="lattice-facets">
    <!-- Top Ingress Telemetry Facet -->
    <path d="M 256 86 L 405 172 L 268 250 L 120 166 Z" 
          fill="url(#topFacetGrad)" />

    <!-- Right Switching Engine Facet -->
    <path d="M 405 190 L 405 342 L 268 422 L 268 268 Z" 
          fill="url(#rightFacetGrad)" />

    <!-- Left Security & Verification Facet -->
    <path d="M 120 184 L 244 256 L 244 422 L 120 342 Z" 
          fill="url(#leftFacetGrad)" />
  </g>

  <!-- Central Dynamic Kernel Core (Isometric Diamond) -->
  <g id="kernel-core">
    <polygon points="256,220 288,238 288,274 256,292 224,274 224,238" 
             fill="{accent_color}" opacity="0.95"/>
    <polygon points="256,232 276,244 276,268 256,280 236,268 236,244" 
             fill="{node_inner}"/>
  </g>

  <!-- Precision Peripheral Node Terminals -->
  <g id="peripheral-nodes">
    <!-- Top Node -->
    <circle cx="256" cy="56" r="14" fill="{node_fill}"/>
    <circle cx="256" cy="56" r="6" fill="{node_inner}"/>

    <!-- Upper Right Node -->
    <circle cx="429" cy="156" r="14" fill="{node_fill}"/>
    <circle cx="429" cy="156" r="6" fill="{node_inner}"/>

    <!-- Lower Right Node -->
    <circle cx="429" cy="356" r="14" fill="{node_fill}"/>
    <circle cx="429" cy="356" r="6" fill="{node_inner}"/>

    <!-- Bottom Node -->
    <circle cx="256" cy="456" r="14" fill="{node_fill}"/>
    <circle cx="256" cy="456" r="6" fill="{node_inner}"/>

    <!-- Lower Left Node -->
    <circle cx="83" cy="356" r="14" fill="{node_fill}"/>
    <circle cx="83" cy="356" r="6" fill="{node_inner}"/>

    <!-- Upper Left Node -->
    <circle cx="83" cy="156" r="14" fill="{node_fill}"/>
    <circle cx="83" cy="156" r="6" fill="{node_inner}"/>
  </g>
</svg>'''
    return svg


def create_horizontal_logo_svg(variant="dark"):
    """
    Generate horizontal logo (Symbol on left, Wordmark on right).
    ViewBox: 0 0 1200 360
    """
    is_dark = (variant == "dark")
    text_primary = "#FFFFFF" if is_dark else "#0D1117"
    text_secondary = "#8B949E" if is_dark else "#57606A"
    accent = "#00D2FF" if is_dark else "#0969DA"
    tagline_color = "#3FB950" if is_dark else "#1A7F37"

    symbol_svg_raw = create_symbol_svg(variant)
    # Strip opening svg and closing svg tags to embed as nested svg
    inner_symbol = symbol_svg_raw[symbol_svg_raw.find("<defs>"):symbol_svg_raw.rfind("</svg>")]

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 360" width="1200" height="360">
  <g transform="translate(30, 20) scale(0.625)">
    {inner_symbol}
  </g>

  <!-- Brand Wordmark: ITSA -->
  <g transform="translate(390, 190)">
    <text font-family="Segoe UI, Inter, Roboto, -apple-system, sans-serif" 
          font-size="142" 
          font-weight="900" 
          letter-spacing="0.04em" 
          fill="{text_primary}">ITSA</text>
  </g>

  <!-- Tagline: NETWORK OS -->
  <g transform="translate(395, 260)">
    <text font-family="Segoe UI, Inter, Roboto, -apple-system, sans-serif" 
          font-size="36" 
          font-weight="700" 
          letter-spacing="0.32em" 
          fill="{accent}">NETWORK OS</text>
  </g>

  <!-- Subtitle / Architecture indicator -->
  <g transform="translate(396, 305)">
    <text font-family="Segoe UI, Inter, Roboto, monospace" 
          font-size="16" 
          font-weight="600" 
          letter-spacing="0.14em" 
          fill="{text_secondary}">DIAGNOSTIC &amp; SECURITY PLATFORM</text>
  </g>

  <!-- Subtle optical boundary rule -->
  <line x1="395" y1="216" x2="1140" y2="216" stroke="{text_secondary}" stroke-width="1.5" opacity="0.25"/>
</svg>'''
    return svg


def create_stacked_logo_svg(variant="dark"):
    """
    Generate stacked / centered logo (Symbol on top, Wordmark below).
    ViewBox: 0 0 600 700
    """
    is_dark = (variant == "dark")
    text_primary = "#FFFFFF" if is_dark else "#0D1117"
    text_secondary = "#8B949E" if is_dark else "#57606A"
    accent = "#00D2FF" if is_dark else "#0969DA"

    symbol_svg_raw = create_symbol_svg(variant)
    inner_symbol = symbol_svg_raw[symbol_svg_raw.find("<defs>"):symbol_svg_raw.rfind("</svg>")]

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 700" width="600" height="700">
  <!-- Centered Symbol -->
  <g transform="translate(100, 30) scale(0.78)">
    {inner_symbol}
  </g>

  <!-- Centered Wordmark: ITSA -->
  <g transform="translate(300, 520)">
    <text font-family="Segoe UI, Inter, Roboto, -apple-system, sans-serif" 
          font-size="110" 
          font-weight="900" 
          letter-spacing="0.06em" 
          text-anchor="middle"
          fill="{text_primary}">ITSA</text>
  </g>

  <!-- Tagline: NETWORK OS -->
  <g transform="translate(300, 580)">
    <text font-family="Segoe UI, Inter, Roboto, -apple-system, sans-serif" 
          font-size="28" 
          font-weight="700" 
          letter-spacing="0.36em" 
          text-anchor="middle"
          fill="{accent}">NETWORK OS</text>
  </g>

  <!-- Subtitle -->
  <g transform="translate(300, 620)">
    <text font-family="Segoe UI, Inter, Roboto, monospace" 
          font-size="14" 
          font-weight="600" 
          letter-spacing="0.18em" 
          text-anchor="middle"
          fill="{text_secondary}">DIAGNOSTIC &amp; SECURITY PLATFORM</text>
  </g>
</svg>'''
    return svg


def create_app_icon_svg():
    """
    Generate modern squircle container application icon (512x512).
    """
    inner_symbol = create_symbol_svg("dark")
    inner_body = inner_symbol[inner_symbol.find("<defs>"):inner_symbol.rfind("</svg>")]

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <!-- Background squircle gradient -->
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#161B22"/>
      <stop offset="100%" stop-color="#0D1117"/>
    </linearGradient>
    <linearGradient id="borderGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#58A6FF" stop-opacity="0.8"/>
      <stop offset="100%" stop-color="#1F6FEB" stop-opacity="0.3"/>
    </linearGradient>
    <filter id="softGlow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="8" result="blur"/>
      <feComposite in="SourceGraphic" in2="blur" operator="over"/>
    </filter>
  </defs>

  <!-- Modern Squircle Base Frame -->
  <rect x="20" y="20" width="472" height="472" rx="108" ry="108" 
        fill="url(#bgGrad)" stroke="url(#borderGrad)" stroke-width="4"/>

  <!-- Embedded Scaled Symbol -->
  <g transform="translate(56, 56) scale(0.78125)">
    {inner_body}
  </g>
</svg>'''
    return svg


def create_favicon_svg():
    """High-contrast 64x64 favicon optimized for small tabs."""
    inner_symbol = create_symbol_svg("dark")
    inner_body = inner_symbol[inner_symbol.find("<defs>"):inner_symbol.rfind("</svg>")]

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect width="64" height="64" rx="14" ry="14" fill="#0D1117"/>
  <g transform="scale(0.125)">
    {inner_body}
  </g>
</svg>'''
    return svg


# ---------------------------------------------------------------------------
# RENDERER UTILITIES (SVG -> PNG via PySide6)
# ---------------------------------------------------------------------------

def render_svg_to_png(svg_str, output_path, width, height):
    """Render an SVG string to transparent PNG at target dimensions."""
    renderer = QSvgRenderer(QByteArray(svg_str.encode("utf-8")))
    if not renderer.isValid():
        raise RuntimeError(f"Invalid SVG for {output_path}")

    image = QImage(width, height, QImage.Format.Format_ARGB32)
    image.fill(0)  # Transparent

    painter = QPainter(image)
    renderer.render(painter)
    painter.end()

    image.save(str(output_path), "PNG")
    print(f"Generated PNG: {output_path.name} ({width}x{height})")


def main():
    app = QGuiApplication([])

    print("=" * 60)
    print("Generating ITSA Network OS Official Brand Assets (Phase H)")
    print("=" * 60)

    # 1. Master SVGs
    svg_manifest = {
        "itsa-symbol.svg": create_symbol_svg("dark"),
        "itsa-symbol-dark.svg": create_symbol_svg("dark"),
        "itsa-symbol-light.svg": create_symbol_svg("light"),
        "itsa-symbol-mono-white.svg": create_symbol_svg("mono-white"),
        "itsa-symbol-mono-black.svg": create_symbol_svg("mono-black"),
        "itsa-logo-horizontal-dark.svg": create_horizontal_logo_svg("dark"),
        "itsa-logo-horizontal-light.svg": create_horizontal_logo_svg("light"),
        "itsa-logo-stacked-dark.svg": create_stacked_logo_svg("dark"),
        "itsa-logo-stacked-light.svg": create_stacked_logo_svg("light"),
        "itsa-app-icon.svg": create_app_icon_svg(),
        "favicon.svg": create_favicon_svg(),
    }

    for filename, content in svg_manifest.items():
        svg_path = SVG_DIR / filename
        svg_path.write_text(content, encoding="utf-8")
        print(f"Wrote SVG master: {svg_path.name}")

    # 2. Raster PNG Exports
    symbol_dark_svg = svg_manifest["itsa-symbol.svg"]
    for size in [512, 256, 128, 64, 48, 32, 16]:
        render_svg_to_png(symbol_dark_svg, PNG_DIR / f"itsa-symbol-{size}.png", size, size)

    app_icon_svg = svg_manifest["itsa-app-icon.svg"]
    for size in [512, 256, 128, 64, 48, 32, 16]:
        render_svg_to_png(app_icon_svg, PNG_DIR / f"itsa-app-icon-{size}.png", size, size)

    # Horizontal logos
    render_svg_to_png(svg_manifest["itsa-logo-horizontal-dark.svg"], PNG_DIR / "itsa-logo-horizontal-dark.png", 1200, 360)
    render_svg_to_png(svg_manifest["itsa-logo-horizontal-light.svg"], PNG_DIR / "itsa-logo-horizontal-light.png", 1200, 360)

    # Stacked logos
    render_svg_to_png(svg_manifest["itsa-logo-stacked-dark.svg"], PNG_DIR / "itsa-logo-stacked-dark.png", 600, 700)
    render_svg_to_png(svg_manifest["itsa-logo-stacked-light.svg"], PNG_DIR / "itsa-logo-stacked-light.png", 600, 700)

    # Favicons
    render_svg_to_png(svg_manifest["favicon.svg"], PNG_DIR / "favicon-32x32.png", 32, 32)
    render_svg_to_png(svg_manifest["favicon.svg"], PNG_DIR / "favicon-16x16.png", 16, 16)

    # 3. Multi-resolution ICO Generation via convert
    app_ico_path = ICO_DIR / "itsa-app-icon.ico"
    subprocess.run([
        "convert",
        str(PNG_DIR / "itsa-app-icon-256.png"),
        str(PNG_DIR / "itsa-app-icon-128.png"),
        str(PNG_DIR / "itsa-app-icon-64.png"),
        str(PNG_DIR / "itsa-app-icon-48.png"),
        str(PNG_DIR / "itsa-app-icon-32.png"),
        str(PNG_DIR / "itsa-app-icon-16.png"),
        str(app_ico_path)
    ], check=True)
    print(f"Generated Multi-res ICO: {app_ico_path.name}")

    fav_ico_path = ICO_DIR / "favicon.ico"
    subprocess.run([
        "convert",
        str(PNG_DIR / "favicon-32x32.png"),
        str(PNG_DIR / "favicon-16x16.png"),
        str(fav_ico_path)
    ], check=True)
    print(f"Generated Favicon ICO: {fav_ico_path.name}")

    # 4. Copy essentials to application assets directory
    for src_file in [
        SVG_DIR / "itsa-symbol.svg",
        SVG_DIR / "itsa-app-icon.svg",
        PNG_DIR / "itsa-app-icon-256.png",
        PNG_DIR / "itsa-app-icon-64.png",
        PNG_DIR / "itsa-symbol-64.png",
        PNG_DIR / "itsa-symbol-32.png",
        ICO_DIR / "itsa-app-icon.ico"
    ]:
        dest = APP_ASSETS_DIR / src_file.name
        dest.write_bytes(src_file.read_bytes())
        print(f"Installed App Asset: {dest.name}")

    print("=" * 60)
    print("All Brand Identity Assets Generated Successfully!")
    print("=" * 60)

if __name__ == "__main__":
    main()
