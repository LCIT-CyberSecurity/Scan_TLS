"""Per-template branding of the HTML report, applied *after* the engine generated it (the engine is untouched).

Supported: organisation name on the cover, accent colour (the report's brand tokens), logo (PNG/JPEG/SVG data URI).
The report language and its sections are those of the engine.
"""
from __future__ import annotations

import base64
import html
import re
from pathlib import Path

MAX_LOGO_BYTES = 150_000
COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_MAGIC = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff"}


class BrandingError(ValueError):
    pass


def validate(branding: dict) -> dict:
    out: dict = {}
    name = (branding.get("organization_name") or "").strip()
    if len(name) > 120:
        raise BrandingError("organization_name is limited to 120 characters")
    if name:
        out["organization_name"] = name
    color = (branding.get("accent_color") or "").strip()
    if color:
        if not COLOR_RE.match(color):
            raise BrandingError("accent_color must look like #1a2b3c")
        out["accent_color"] = color.lower()
    logo = (branding.get("logo") or "").strip()
    if logo:
        match = re.match(r"^data:(image/(?:png|jpeg|svg\+xml));base64,([A-Za-z0-9+/=]+)$", logo)
        if not match:
            raise BrandingError("logo must be a PNG, JPEG or SVG data URI (base64)")
        raw = base64.b64decode(match.group(2), validate=True)
        if len(raw) > MAX_LOGO_BYTES:
            raise BrandingError(f"logo is limited to {MAX_LOGO_BYTES // 1000} KB")
        mime = match.group(1)
        if mime in _MAGIC and not raw.startswith(_MAGIC[mime]):
            raise BrandingError("the logo content does not match its declared type")
        if mime == "image/svg+xml" and b"<svg" not in raw[:2000].lower():
            raise BrandingError("the logo is not an SVG document")
        out["logo"] = logo
    return out


def apply_to_html(path: Path, branding: dict | None) -> bool:
    """Rewrite the generated report in place. Returns True when something was applied."""
    if not branding or not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    original = text
    css = ""
    if branding.get("accent_color"):
        c = branding["accent_color"]
        css += f":root{{--brand-600:{c};--brand-700:{c};--brand-500:{c};}}"
    if branding.get("logo"):
        css += ".brand-logo{height:36px;width:auto;max-width:160px;object-fit:contain;display:block}"
        logo = f'<img class="brand-logo" alt="" src="{html.escape(branding["logo"], quote=True)}">'
        text = re.sub(r'<div class="brand-mark(?: large)?" aria-hidden="true">TS</div>', logo, text)
    if css:
        text = text.replace("</head>", f"<style>{css}</style></head>", 1)
    if branding.get("organization_name"):
        org = html.escape(branding["organization_name"])
        text = text.replace("<div><dt>Produced by</dt>", f"<div><dt>Organisation</dt><dd>{org}</dd></div><div><dt>Produced by</dt>", 1)
    if text != original:
        path.write_text(text, encoding="utf-8")
        return True
    return False
