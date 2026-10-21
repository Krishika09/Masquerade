"""Small, dependency-free helpers shared by the analysis stages."""
import hashlib
import math
import re
from collections import Counter
from datetime import datetime, timezone

PRINTABLE_ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
PRINTABLE_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_strings(data: bytes, limit_bytes: int = 32 * 1024 * 1024):
    """Return (ascii_strings, utf16_strings) of length >= 5 found in the binary."""
    blob = data[:limit_bytes]
    ascii_s = [m.group().decode("ascii", "ignore") for m in PRINTABLE_ASCII_RE.finditer(blob)]
    utf16_s = [m.group().decode("utf-16le", "ignore") for m in PRINTABLE_UTF16_RE.finditer(blob)]
    return ascii_s, utf16_s


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def ts_to_utc(ts: int) -> str:
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return "invalid"


def sniff_magic(data: bytes) -> str:
    """Best-effort identification of common non-PE formats for the invalid-file view."""
    sigs = [
        (b"MZ", "DOS/PE executable (MZ)"),
        (b"%PDF", "PDF document"),
        (b"PK\x03\x04", "ZIP archive / OOXML document"),
        (b"\x89PNG", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF8", "GIF image"),
        (b"\x7fELF", "ELF executable (Linux)"),
        (b"\xcf\xfa\xed\xfe", "Mach-O executable (macOS)"),
        (b"Rar!", "RAR archive"),
        (b"7z\xbc\xaf", "7-Zip archive"),
        (b"\xd0\xcf\x11\xe0", "OLE2 compound document (legacy Office)"),
        (b"{\\rtf", "RTF document"),
    ]
    for sig, name in sigs:
        if data.startswith(sig):
            return name
    if not data:
        return "Empty file"
    sample = data[:4096]
    if all(32 <= b < 127 or b in (9, 10, 13) for b in sample):
        return "Plain text"
    return "Unknown binary data"
