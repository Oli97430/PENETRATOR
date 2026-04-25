"""Color palette + font helpers for the PENETRATOR GUI.

We do not depend on customtkinter's built-in themes: values are hex codes used
directly by widgets so the look is consistent across platforms.
"""
from __future__ import annotations

# --- Palette ----------------------------------------------------------------
BG_DEEP     = "#0b0f14"   # window background
BG_BASE     = "#11161d"   # main content
BG_SURFACE  = "#172029"   # cards, frames
BG_RAISED   = "#1e2833"   # hovered / active surfaces
BORDER      = "#253241"

TEXT        = "#e6edf3"
TEXT_DIM    = "#8b949e"
TEXT_MUTED  = "#6e7681"

ACCENT      = "#ff3860"   # primary red/crimson - PENETRATOR brand
ACCENT_HOV  = "#ff5a7d"
ACCENT_DIM  = "#5c1a2a"

CYAN        = "#22d3ee"
CYAN_HOV    = "#67e8f9"
GREEN       = "#10b981"
YELLOW      = "#facc15"
RED         = "#ef4444"
BLUE        = "#3b82f6"
PURPLE      = "#a855f7"

# Category colours (used for icons + accents)
CATEGORY_COLORS = {
    "info_gathering":      "#3b82f6",
    "wordlist":            "#a855f7",
    "sql_injection":       "#f59e0b",
    "web_attacks":         "#ef4444",
    "password_tools":      "#ec4899",
    "steganography":       "#14b8a6",
    "xss_tools":           "#f97316",
    "reverse_engineering": "#8b5cf6",
    "forensic":            "#06b6d4",
    "payload":             "#dc2626",
    "osint":               "#10b981",
    "settings":            "#64748b",
    "about":               "#64748b",
}

# --- Fonts ------------------------------------------------------------------
FONT_TITLE      = ("Segoe UI", 22, "bold")
FONT_H1         = ("Segoe UI", 18, "bold")
FONT_H2         = ("Segoe UI", 14, "bold")
FONT_BODY       = ("Segoe UI", 12)
FONT_BODY_BOLD  = ("Segoe UI", 12, "bold")
FONT_SMALL      = ("Segoe UI", 10)
FONT_MONO       = ("Consolas", 11)
FONT_MONO_BOLD  = ("Consolas", 11, "bold")

# Geometry helpers
RADIUS_SM = 6
RADIUS_MD = 10
RADIUS_LG = 14
