from gui.engine._core import *

# ---------------------------------------------------------------------------
def _text_to_bits(text: str) -> str:
    """Convert a UTF-8 string to a binary bit string."""
    return "".join(f"{byte:08b}" for byte in text.encode("utf-8"))


def _bits_to_text(bits: str) -> str:
    """Convert a binary bit string back to a UTF-8 string."""
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode("utf-8", errors="ignore")


def image_hide(cover: str, message: str, output: str, log: Logger) -> str | None:
    """Hide a message in a cover image using LSB steganography."""
    try:
        from PIL import Image
    except ImportError:
        log("[-] Pillow not installed. Run: pip install Pillow", "err")
        return None
    src = Path(cover)
    if not src.is_file():
        log(f"[-] Cover not found: {cover}", "err")
        return None
    image = Image.open(src).convert("RGB")
    # Use .load() pixel access (modern API; avoids getdata() deprecation in Pillow 14)
    px = image.load()
    w, h = image.size
    bits = _text_to_bits(message + DELIMITER)
    if len(bits) > w * h * 3:
        log("[-] Cover image too small for the message", "err")
        return None
    bi = 0
    for y in range(h):
        for x in range(w):
            if bi >= len(bits):
                break
            r, g, b = px[x, y]
            if bi < len(bits):
                r = (r & ~1) | int(bits[bi]); bi += 1
            if bi < len(bits):
                g = (g & ~1) | int(bits[bi]); bi += 1
            if bi < len(bits):
                b = (b & ~1) | int(bits[bi]); bi += 1
            px[x, y] = (r, g, b)
        if bi >= len(bits):
            break
    out = Path(output)
    image.save(out, format="PNG")
    log(f"[+] Saved {out}", "ok")
    return str(out)


def image_extract(stego: str, log: Logger) -> str | None:
    """Extract an LSB-hidden message from a stego image."""
    try:
        from PIL import Image
    except ImportError:
        log("[-] Pillow not installed. Run: pip install Pillow", "err")
        return None
    src = Path(stego)
    if not src.is_file():
        log(f"[-] File not found: {stego}", "err")
        return None
    image = Image.open(src).convert("RGB")
    px = image.load()
    w, h = image.size
    bits: list[str] = []
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            bits.append(str(r & 1))
            bits.append(str(g & 1))
            bits.append(str(b & 1))
    text = _bits_to_text("".join(bits))
    if DELIMITER in text:
        msg = text.split(DELIMITER, 1)[0]
        log(f"[+] Extracted: {msg}", "ok")
        return msg
    log("[-] No embedded message found", "warn")
    return None


def ws_hide(cover: str, message: str, output: str, log: Logger) -> str | None:
    """Hide a message in a text file using whitespace steganography."""
    src = Path(cover)
    if not src.is_file():
        log(f"[-] Cover not found: {cover}", "err")
        return None
    bits = _text_to_bits(message + DELIMITER)
    lines = src.read_text(encoding="utf-8", errors="ignore").splitlines()
    if len(bits) > len(lines):
        lines.extend(["."] * (len(bits) - len(lines)))
    stamped = []
    for idx, line in enumerate(lines):
        stripped = line.rstrip()
        if idx < len(bits):
            stripped += "\t" if bits[idx] == "1" else " "
        stamped.append(stripped)
    out = Path(output)
    out.write_text("\n".join(stamped) + "\n", encoding="utf-8")
    log(f"[+] Saved {out}", "ok")
    return str(out)


def ws_extract(stego: str, log: Logger) -> str | None:
    """Extract a whitespace-hidden message from a stego text file."""
    src = Path(stego)
    if not src.is_file():
        log(f"[-] File not found: {stego}", "err")
        return None
    bits: list[str] = []
    for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.endswith("\t"): bits.append("1")
        elif line.endswith(" "): bits.append("0")
    text = _bits_to_text("".join(bits))
    if DELIMITER in text:
        msg = text.split(DELIMITER, 1)[0]
        log(f"[+] Extracted: {msg}", "ok")
        return msg
    log("[-] No embedded message found", "warn")
    return None


# ---------------------------------------------------------------------------
# Reverse engineering + forensic
# ---------------------------------------------------------------------------
def extract_strings(path: str, min_len: int, log: Logger) -> list[tuple[int, str]]:
    """Extract printable ASCII strings of at least min_len from a binary file."""
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return []
    data = p.read_bytes()
    results: list[tuple[int, str]] = []
    current = bytearray(); start = 0
    for i, byte in enumerate(data):
        if 32 <= byte < 127:
            if not current: start = i
            current.append(byte)
        else:
            if len(current) >= min_len:
                results.append((start, current.decode("ascii", errors="ignore")))
            current = bytearray()
    if len(current) >= min_len:
        results.append((start, current.decode("ascii", errors="ignore")))
    log(f"[*] {len(results)} ASCII strings >= {min_len} chars", "cyan")
    return results


def parse_pe(path: str, log: Logger) -> dict:
    """Parse a Windows PE executable header and section table."""
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return {}
    data = p.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        log("[-] Not a PE file (missing MZ header)", "err")
        return {}
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        log("[-] Invalid PE signature", "err")
        return {}
    machine, num_sections, timestamp, _, _, opt_hdr_size, characteristics = \
        struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    machines = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
    out: dict = {
        "size": len(data),
        "machine": machines.get(machine, f"0x{machine:x}"),
        "sections": num_sections,
        "timestamp": timestamp,
        "characteristics": f"0x{characteristics:x}",
        "sec_table": [],
    }
    log(f"[+] Machine: {out['machine']}  sections: {num_sections}", "ok")
    sec_offset = pe_offset + 24 + opt_hdr_size
    for i in range(num_sections):
        off = sec_offset + i * 40
        if off + 40 > len(data): break
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        out["sec_table"].append((name, vsize, vaddr, rsize, rptr))
        log(f"  {name:<10} vsize=0x{vsize:x} vaddr=0x{vaddr:x} raw=0x{rsize:x}@0x{rptr:x}", "info")
    return out


def hex_dump(path: str, offset: int, length: int, log: Logger) -> str:
    """Display a hex + ASCII dump of a file region."""
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return ""
    with p.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read(length)
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row).ljust(16 * 3)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        line = f"{offset + i:08x}  {hex_part}  {ascii_part}"
        lines.append(line)
        log(line, "muted")
    return "\n".join(lines)


def file_hashes(path: str, log: Logger) -> dict[str, str]:
    """Compute MD5, SHA-1, SHA-256, and SHA-512 hashes of a file."""
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return {}
    hashers = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256", "sha512")}
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            for h in hashers.values():
                h.update(chunk)
    out = {name: h.hexdigest() for name, h in hashers.items()}
    log(f"[*] File: {p.name}  size: {p.stat().st_size:,} bytes", "cyan")
    for name, digest in out.items():
        log(f"  {name.upper():<7} {digest}", "info")
    return out


def read_exif(path: str, log: Logger) -> dict:
    """Read EXIF metadata from an image file."""
    try:
        from PIL import Image, ExifTags
    except ImportError:
        log("[-] Pillow not installed. Run: pip install Pillow", "err")
        return {}
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return {}
    try:
        img = Image.open(p)
        raw = img._getexif() or {}
    except Exception as exc:
        log(f"[-] {exc}", "err")
        return {}
    out: dict[str, str] = {}
    for tag_id, value in raw.items():
        name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if isinstance(value, bytes): value = value[:200]
        out[name] = str(value)
        log(f"  {name:<22} {value}", "info")
    if not out:
        log("[!] No EXIF metadata", "warn")
    return out


def identify_magic(path: str, log: Logger) -> str | None:
    """Identify a file type by its magic bytes signature."""
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return None
    header = p.read_bytes()[:32]
    for signature, name in MAGIC_SIGNATURES:
        if header.startswith(signature):
            log(f"[+] {name}", "ok")
            return name
    log("[!] Unknown file signature", "warn")
    log("  First 32 bytes: " + " ".join(f"{b:02x}" for b in header), "muted")
    return None


def compare_files(a: str, b: str, log: Logger) -> dict:
    """Compare two files byte-by-byte and report the first difference offset."""
    pa, pb = Path(a), Path(b)
    if not pa.is_file() or not pb.is_file():
        log("[-] One or both files not found", "err")
        return {}
    da, db = pa.read_bytes(), pb.read_bytes()
    if da == db:
        log("[+] Files are identical", "ok")
        return {"identical": True, "size_a": len(da), "size_b": len(db)}
    off = None
    for i in range(min(len(da), len(db))):
        if da[i] != db[i]:
            off = i; break
    if off is None:
        off = min(len(da), len(db))
    log(f"[!] Differ at offset 0x{off:x}   sizes: {len(da):,} vs {len(db):,}", "warn")
    return {"identical": False, "offset": off, "size_a": len(da), "size_b": len(db)}


# ---------------------------------------------------------------------------
