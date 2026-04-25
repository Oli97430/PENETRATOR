"""Reverse engineering utilities: strings, PE info, hex dump, file hash."""
from __future__ import annotations

import hashlib
import struct
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


def _require_file(prompt_key: str) -> Path | None:
    path = Path(ask_input(t(prompt_key)))
    if not path.is_file():
        print_error(t("ui.required"))
        pause()
        return None
    return path


def strings_extractor() -> None:
    path = _require_file("ui.input_file")
    if not path:
        return
    min_len_s = ask_input(t("modules.reverse.min_str_length"), default="4")
    try:
        min_len = max(1, int(min_len_s))
    except ValueError:
        min_len = 4

    data = path.read_bytes()
    results: list[tuple[int, str]] = []

    # ASCII strings
    current = bytearray()
    start = 0
    for i, byte in enumerate(data):
        if 32 <= byte < 127:
            if not current:
                start = i
            current.append(byte)
        else:
            if len(current) >= min_len:
                results.append((start, current.decode("ascii", errors="ignore")))
            current = bytearray()
    if len(current) >= min_len:
        results.append((start, current.decode("ascii", errors="ignore")))

    # UTF-16 LE strings (every other byte is null for ASCII)
    current = bytearray()
    start = 0
    i = 0
    while i < len(data) - 1:
        if 32 <= data[i] < 127 and data[i + 1] == 0:
            if not current:
                start = i
            current.append(data[i])
            i += 2
        else:
            if len(current) >= min_len:
                results.append((start, current.decode("ascii", errors="ignore") + " [UTF-16]"))
            current = bytearray()
            i += 1
    if len(current) >= min_len:
        results.append((start, current.decode("ascii", errors="ignore") + " [UTF-16]"))

    print_info(t("modules.reverse.found_strings", count=len(results)))
    for offset, text in results[:500]:
        console.print(f"[cyan]0x{offset:08x}[/]  {text}")
    if len(results) > 500:
        console.print(f"[dim]... {len(results) - 500} more[/]")
    pause()


def pe_info() -> None:
    path = _require_file("ui.input_file")
    if not path:
        return
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        print_error("Not a PE file (missing MZ header).")
        pause()
        return
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        print_error("Invalid PE signature.")
        pause()
        return

    # COFF header
    machine, num_sections, timestamp, _, _, opt_hdr_size, characteristics = \
        struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    machines = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}

    table = Table(title=f"PE: {path.name}", border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Size", str(len(data)))
    table.add_row("Machine", machines.get(machine, f"0x{machine:x}"))
    table.add_row("Sections", str(num_sections))
    table.add_row("Timestamp", f"{timestamp}")
    table.add_row("Characteristics", f"0x{characteristics:x}")
    console.print(table)

    sec_offset = pe_offset + 24 + opt_hdr_size
    sec_table = Table(title="Sections", border_style="cyan")
    sec_table.add_column("Name", style="cyan")
    sec_table.add_column("VirtSize", justify="right")
    sec_table.add_column("VirtAddr", justify="right")
    sec_table.add_column("RawSize", justify="right")
    sec_table.add_column("RawPtr", justify="right")
    for i in range(num_sections):
        off = sec_offset + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        sec_table.add_row(name, f"0x{vsize:x}", f"0x{vaddr:x}",
                          f"0x{rsize:x}", f"0x{rptr:x}")
    console.print(sec_table)
    pause()


def hex_dump_tool() -> None:
    path = _require_file("ui.input_file")
    if not path:
        return
    offset_s = ask_input("Start offset (hex or dec)", default="0")
    length_s = ask_input("Length (bytes)", default="256")
    try:
        offset = int(offset_s, 16) if offset_s.lower().startswith("0x") else int(offset_s)
        length = max(1, min(65536, int(length_s)))
    except ValueError:
        print_error(t("ui.invalid_choice"))
        pause()
        return

    with path.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read(length)

    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row).ljust(16 * 3)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        console.print(f"[cyan]{offset + i:08x}[/]  {hex_part}  [white]{ascii_part}[/]")
    pause()


def hash_file_tool() -> None:
    path = _require_file("ui.input_file")
    if not path:
        return
    algos = ("md5", "sha1", "sha256", "sha512")
    hashers = {name: hashlib.new(name) for name in algos}
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    size = path.stat().st_size
    table = Table(border_style="green")
    table.add_column("Algorithm", style="cyan")
    table.add_column("Digest", style="white")
    for name, hasher in hashers.items():
        table.add_row(name.upper(), hasher.hexdigest())
    console.print(table)
    print_info(t("modules.reverse.file_size", size=size))
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.reverse.title", parent=parent)
    menu.add(MenuItem("modules.reverse.strings", strings_extractor,
                      "modules.reverse.strings_desc"))
    menu.add(MenuItem("modules.reverse.pe_info", pe_info,
                      "modules.reverse.pe_info_desc"))
    menu.add(MenuItem("modules.reverse.hex_dump", hex_dump_tool,
                      "modules.reverse.hex_dump_desc"))
    menu.add(MenuItem("modules.reverse.hash_file", hash_file_tool,
                      "modules.reverse.hash_file_desc"))
    return menu
