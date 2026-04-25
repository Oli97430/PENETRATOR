"""Forensic utilities: EXIF, hex view, hashes, magic identifier, diff."""
from __future__ import annotations

import hashlib
from pathlib import Path

from rich.console import Console
from rich.table import Table

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import (
    ask_input,
    pause,
    print_error,
    print_info,
    print_success,
    print_warning,
)

console = Console()

MAGIC_SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"\x89PNG\r\n\x1a\n",         0,  "PNG image"),
    (b"\xFF\xD8\xFF",              0,  "JPEG image"),
    (b"GIF87a",                    0,  "GIF image (87a)"),
    (b"GIF89a",                    0,  "GIF image (89a)"),
    (b"BM",                        0,  "BMP image"),
    (b"%PDF",                      0,  "PDF document"),
    (b"PK\x03\x04",                0,  "ZIP / OOXML / JAR"),
    (b"Rar!\x1a\x07\x00",          0,  "RAR v1.5+"),
    (b"Rar!\x1a\x07\x01\x00",      0,  "RAR v5+"),
    (b"\x1f\x8b\x08",              0,  "GZIP"),
    (b"7z\xBC\xAF\x27\x1C",        0,  "7-Zip"),
    (b"MZ",                        0,  "Windows PE executable"),
    (b"\x7FELF",                   0,  "Linux ELF executable"),
    (b"\xCA\xFE\xBA\xBE",          0,  "Java class / Mach-O FAT"),
    (b"\xFE\xED\xFA\xCE",          0,  "Mach-O (32-bit)"),
    (b"\xFE\xED\xFA\xCF",          0,  "Mach-O (64-bit)"),
    (b"SQLite format 3\x00",       0,  "SQLite database"),
    (b"ID3",                       0,  "MP3 (ID3)"),
    (b"OggS",                      0,  "OGG"),
    (b"RIFF",                      0,  "RIFF (WAV/AVI)"),
    (b"fLaC",                      0,  "FLAC audio"),
    (b"\x00\x00\x00\x18ftypmp4",   0,  "MP4"),
    (b"\x00\x00\x00\x20ftypisom",  0,  "MP4 (ISO)"),
]


def _require_file(prompt_key: str) -> Path | None:
    path = Path(ask_input(t(prompt_key)))
    if not path.is_file():
        print_error(t("ui.required"))
        pause()
        return None
    return path


def exif_reader() -> None:
    try:
        from PIL import Image, ExifTags  # type: ignore
    except ImportError:
        print_error("Pillow not installed. Run: pip install Pillow")
        pause()
        return
    path = _require_file("ui.input_file")
    if not path:
        return
    try:
        image = Image.open(path)
        raw = image._getexif()
    except Exception as exc:
        print_error(str(exc))
        pause()
        return
    if not raw:
        print_warning(t("modules.forensic.no_exif"))
        pause()
        return
    table = Table(title=f"EXIF: {path.name}", border_style="green")
    table.add_column("Tag", style="cyan")
    table.add_column("Value", style="white", overflow="fold")
    for tag_id, value in raw.items():
        name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if isinstance(value, bytes):
            value = value[:200]
        table.add_row(name, str(value))
    console.print(table)
    pause()


def hex_viewer() -> None:
    path = _require_file("ui.input_file")
    if not path:
        return
    length_s = ask_input("Bytes to display", default="512")
    try:
        length = max(1, min(65536, int(length_s)))
    except ValueError:
        length = 512
    with path.open("rb") as fh:
        chunk = fh.read(length)
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row).ljust(16 * 3)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        console.print(f"[cyan]{i:08x}[/]  {hex_part}  [white]{ascii_part}[/]")
    pause()


def file_hashes() -> None:
    path = _require_file("ui.input_file")
    if not path:
        return
    hashers = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256", "sha512")}
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            for h in hashers.values():
                h.update(chunk)
    size = path.stat().st_size
    table = Table(border_style="green")
    table.add_column("Algorithm", style="cyan")
    table.add_column("Digest", style="white")
    for name, h in hashers.items():
        table.add_row(name.upper(), h.hexdigest())
    console.print(table)
    print_info(f"Size: {size} bytes")
    pause()


def file_magic() -> None:
    path = _require_file("ui.input_file")
    if not path:
        return
    header = path.read_bytes()[:32]
    for signature, offset, name in MAGIC_SIGNATURES:
        if header[offset:offset + len(signature)] == signature:
            print_success(t("modules.forensic.identified_as", type=name))
            pause()
            return
    print_warning(t("modules.forensic.not_identified"))
    print_info("First 32 bytes: " + " ".join(f"{b:02x}" for b in header))
    pause()


def compare_files() -> None:
    left = _require_file("ui.input_file")
    if not left:
        return
    right = _require_file("ui.input_file")
    if not right:
        return
    data_a = left.read_bytes()
    data_b = right.read_bytes()
    if data_a == data_b:
        print_success(t("modules.forensic.files_identical"))
        pause()
        return
    diff_offset: int | None = None
    for i in range(min(len(data_a), len(data_b))):
        if data_a[i] != data_b[i]:
            diff_offset = i
            break
    if diff_offset is None:
        diff_offset = min(len(data_a), len(data_b))
    print_warning(t("modules.forensic.files_differ", offset=f"0x{diff_offset:x}"))
    print_info(f"Size A: {len(data_a)}  Size B: {len(data_b)}")
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.forensic.title", parent=parent)
    menu.add(MenuItem("modules.forensic.exif_reader", exif_reader,
                      "modules.forensic.exif_reader_desc"))
    menu.add(MenuItem("modules.forensic.hex_viewer", hex_viewer,
                      "modules.forensic.hex_viewer_desc"))
    menu.add(MenuItem("modules.forensic.file_hashes", file_hashes,
                      "modules.forensic.file_hashes_desc"))
    menu.add(MenuItem("modules.forensic.file_magic", file_magic,
                      "modules.forensic.file_magic_desc"))
    menu.add(MenuItem("modules.forensic.compare_files", compare_files,
                      "modules.forensic.compare_files_desc"))
    return menu
