"""Steganography tools: image LSB + whitespace."""
from __future__ import annotations

from pathlib import Path

from rich.console import Console

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

DELIMITER = "<<<PEN_END>>>"


# ---------------------------------------------------------------------------
# Image LSB
# ---------------------------------------------------------------------------
def _require_pillow():
    try:
        from PIL import Image  # type: ignore
        return Image
    except ImportError:
        print_error("Pillow not installed. Run: pip install Pillow")
        pause()
        return None


def _text_to_bits(text: str) -> str:
    return "".join(f"{byte:08b}" for byte in text.encode("utf-8"))


def _bits_to_text(bits: str) -> str:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode("utf-8", errors="ignore")


def image_hide() -> None:
    Image = _require_pillow()
    if Image is None:
        return
    cover = Path(ask_input(t("modules.steganography.cover_file")))
    if not cover.is_file():
        print_error(t("ui.required"))
        pause()
        return
    message = ask_input(t("modules.steganography.message"))
    if not message:
        return
    output = Path(ask_input(t("ui.output_file"), default="stego.png"))
    image = Image.open(cover).convert("RGB")
    pixels = list(image.getdata())
    bits = _text_to_bits(message + DELIMITER)
    if len(bits) > len(pixels) * 3:
        print_error("Cover image too small for the message.")
        pause()
        return

    new_pixels: list[tuple[int, int, int]] = []
    bit_idx = 0
    for r, g, b in pixels:
        if bit_idx < len(bits):
            r = (r & ~1) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | int(bits[bit_idx]); bit_idx += 1
        new_pixels.append((r, g, b))
    image.putdata(new_pixels)
    image.save(output, format="PNG")
    print_success(t("ui.saved_to", path=output))
    pause()


def image_extract() -> None:
    Image = _require_pillow()
    if Image is None:
        return
    stego = Path(ask_input(t("modules.steganography.stego_file")))
    if not stego.is_file():
        print_error(t("ui.required"))
        pause()
        return
    image = Image.open(stego).convert("RGB")
    bits: list[str] = []
    for r, g, b in image.getdata():
        bits.append(str(r & 1))
        bits.append(str(g & 1))
        bits.append(str(b & 1))
        if len(bits) % 64 == 0 and len(bits) >= 64:
            text = _bits_to_text("".join(bits))
            if DELIMITER in text:
                message = text.split(DELIMITER, 1)[0]
                print_success(t("modules.steganography.extracted_message"))
                console.print(f"[white]{message}[/]")
                pause()
                return
    text = _bits_to_text("".join(bits))
    if DELIMITER in text:
        message = text.split(DELIMITER, 1)[0]
        print_success(t("modules.steganography.extracted_message"))
        console.print(f"[white]{message}[/]")
    else:
        print_warning(t("ui.no_results"))
    pause()


# ---------------------------------------------------------------------------
# Whitespace stego: encodes each bit as tab (1) or space (0), appended to lines
# ---------------------------------------------------------------------------
def whitespace_hide() -> None:
    cover = Path(ask_input(t("modules.steganography.cover_file")))
    if not cover.is_file():
        print_error(t("ui.required"))
        pause()
        return
    message = ask_input(t("modules.steganography.message"))
    if not message:
        return
    output = Path(ask_input(t("ui.output_file"), default="stego.txt"))
    bits = _text_to_bits(message + DELIMITER)

    lines = cover.read_text(encoding="utf-8", errors="ignore").splitlines()
    if len(bits) > len(lines):
        extra = len(bits) - len(lines)
        lines.extend(["."] * extra)

    stamped: list[str] = []
    for idx, line in enumerate(lines):
        stripped = line.rstrip()
        if idx < len(bits):
            stripped += "\t" if bits[idx] == "1" else " "
        stamped.append(stripped)
    output.write_text("\n".join(stamped) + "\n", encoding="utf-8")
    print_success(t("ui.saved_to", path=output))
    pause()


def whitespace_extract() -> None:
    stego = Path(ask_input(t("modules.steganography.stego_file")))
    if not stego.is_file():
        print_error(t("ui.required"))
        pause()
        return
    bits: list[str] = []
    for line in stego.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.endswith("\t"):
            bits.append("1")
        elif line.endswith(" "):
            bits.append("0")
    text = _bits_to_text("".join(bits))
    if DELIMITER in text:
        message = text.split(DELIMITER, 1)[0]
        print_success(t("modules.steganography.extracted_message"))
        console.print(f"[white]{message}[/]")
    else:
        print_warning(t("ui.no_results"))
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.steganography.title", parent=parent)
    menu.add(MenuItem("modules.steganography.image_hide", image_hide,
                      "modules.steganography.image_hide_desc"))
    menu.add(MenuItem("modules.steganography.image_extract", image_extract,
                      "modules.steganography.image_extract_desc"))
    menu.add(MenuItem("modules.steganography.whitespace_hide", whitespace_hide,
                      "modules.steganography.whitespace_hide_desc"))
    menu.add(MenuItem("modules.steganography.whitespace_extract", whitespace_extract,
                      "modules.steganography.whitespace_extract_desc"))
    return menu
