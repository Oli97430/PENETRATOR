# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for PENETRATOR — slimmed.

Build with:
    pyinstaller --noconfirm PENETRATOR.spec
"""
from PyInstaller.utils.hooks import collect_all

datas = [("locales", "locales"), ("assets", "assets")]
binaries: list = []
hiddenimports = [
    "PIL.Image", "PIL.ExifTags",
    "dns.resolver", "dns.rdatatype", "dns.exception",
    "phonenumbers", "phonenumbers.carrier", "phonenumbers.geocoder",
    "phonenumbers.timezone",
    "whois",
]

for pkg in ("customtkinter", "CTkMessagebox", "tkinterdnd2"):
    try:
        d, b, h = collect_all(pkg)
        datas += d; binaries += b; hiddenimports += h
    except Exception:
        # Optional package — skip if unavailable
        pass

EXCLUDES = [
    # Heavy scientific / plotting stack — not used
    "matplotlib", "numpy", "scipy", "pandas", "sympy",
    # Test / dev tooling
    "pytest", "_pytest", "pluggy", "py", "iniconfig",
    "tornado", "notebook", "jupyter", "IPython",
    "sphinx", "alabaster", "babel",
    # Unused stdlib test subpackages
    "tkinter.test", "test", "unittest.test", "lib2to3",
    # Optional crypto we don't ship
    "cryptography",
    # PyInstaller's own dev deps
    "PyInstaller", "pyinstaller_hooks_contrib",
]

a = Analysis(
    ["penetrator.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=2,  # strip docstrings + asserts
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="PENETRATOR",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=["assets\\logo.ico"],
)
