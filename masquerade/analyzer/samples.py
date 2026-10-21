"""Safe built-in samples for demonstrations.

``build_synthetic_test_pe`` assembles a *non-functional* PE32 image in memory
so the real pefile pipeline can be exercised without handling malware. It
contains no code beyond a single ``RET`` instruction; the "suspicious"
properties (RWX section, high-entropy random bytes, an injection-style import
table, entry point in the last section, deceptive filename) exist only in
the headers and data so that every contradiction category has something real
to parse. Nothing in it calls the imported APIs.

The bytes are generated on demand and never written to disk by default, so
endpoint security products have nothing to quarantine.
"""
import os
import random
import struct
import sys

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
IMAGE_BASE = 0x400000

SYNTHETIC_NAME = "invoice_2024.pdf.exe"
SYNTHETIC_IMPORTS = ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
                     "OpenProcess", "LoadLibraryA", "GetProcAddress", "ExitProcess"]


def _align(v, a):
    return (v + a - 1) // a * a


def build_synthetic_test_pe(seed: int = 1337) -> bytes:
    rnd = random.Random(seed)

    # --- section payloads ---------------------------------------------------
    text_raw = b"\xC3" + b"\x00" * (FILE_ALIGN - 1)                    # .text : just RET
    text_vsize = 0x9000                                                # grows 72x in memory

    rdata_rva = SECT_ALIGN + _align(text_vsize, SECT_ALIGN)            # 0xA000
    # Import table layout inside .rdata
    n = len(SYNTHETIC_IMPORTS)
    desc_off = 0
    ilt_off = 0x40
    iat_off = ilt_off + (n + 1) * 4
    names_off = iat_off + (n + 1) * 4
    hint_names, rvas = b"", []
    for api in SYNTHETIC_IMPORTS:
        rvas.append(rdata_rva + names_off + len(hint_names))
        entry = struct.pack("<H", 0) + api.encode() + b"\x00"
        if len(entry) % 2:
            entry += b"\x00"
        hint_names += entry
    dll_off = names_off + len(hint_names)
    dll_name = b"KERNEL32.dll\x00"
    thunks = b"".join(struct.pack("<I", r) for r in rvas) + b"\x00\x00\x00\x00"
    rdata = bytearray(_align(dll_off + len(dll_name), FILE_ALIGN))
    rdata[desc_off:desc_off + 20] = struct.pack("<IIIII", rdata_rva + ilt_off, 0, 0,
                                                rdata_rva + dll_off, rdata_rva + iat_off)
    rdata[ilt_off:ilt_off + len(thunks)] = thunks
    rdata[iat_off:iat_off + len(thunks)] = thunks
    rdata[names_off:names_off + len(hint_names)] = hint_names
    rdata[dll_off:dll_off + len(dll_name)] = dll_name
    rdata = bytes(rdata)

    # .xyz : 12 KB of pseudo-random bytes (entropy ~7.98), stub entry = RET
    xyz_raw = b"\xC3" + bytes(rnd.getrandbits(8) for _ in range(0x3000 - 1))
    xyz_rva = rdata_rva + SECT_ALIGN

    overlay = bytes(rnd.getrandbits(8) for _ in range(0x1800))          # 6 KB random overlay

    sections = [
        (b".text\x00\x00\x00", text_vsize, SECT_ALIGN, text_raw, 0x60000020),     # R-X
        (b".rdata\x00\x00", len(rdata), rdata_rva, rdata, 0x40000040),           # R--
        (b".xyz\x00\x00\x00\x00", len(xyz_raw), xyz_rva, xyz_raw, 0xE0000060),   # RWX
    ]

    headers_size = 0x400
    size_of_image = _align(xyz_rva + len(xyz_raw), SECT_ALIGN)
    entry_point = xyz_rva  # entry point in the last, writable, high-entropy section

    # --- DOS header + stub --------------------------------------------------
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    stub = b"This program cannot be run in DOS mode.\r\r\n$"
    dos[0x40:0x40 + len(stub)] = stub

    # --- COFF + optional header ---------------------------------------------
    timestamp = 2051222400  # 2035-01-01 - deliberately implausible (future)
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), timestamp, 0, 0, 0xE0, 0x0102)
    data_dirs = [(0, 0)] * 16
    data_dirs[1] = (rdata_rva + desc_off, 40)
    data_dirs[12] = (rdata_rva + iat_off, len(thunks))
    opt = struct.pack("<HBB9I6H4I2H6I", 0x10B, 14, 0,
                      len(text_raw) + len(xyz_raw), len(rdata), 0,
                      entry_point, SECT_ALIGN, rdata_rva,
                      IMAGE_BASE, SECT_ALIGN, FILE_ALIGN,
                      6, 0, 0, 0, 6, 0,
                      0, size_of_image, headers_size, 0,
                      2, 0x0000,  # GUI subsystem, no ASLR/DEP flags
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", a, s) for a, s in data_dirs)

    sec_headers, body, ptr = b"", b"", headers_size
    for name, vsize, rva, raw, ch in sections:
        sec_headers += struct.pack("<8s6I2HI", name, vsize, rva, len(raw), ptr, 0, 0, 0, 0, ch)
        body += raw
        ptr += len(raw)

    header = bytes(dos) + b"PE\x00\x00" + coff + opt + sec_headers
    header += b"\x00" * (headers_size - len(header))
    return header + body + overlay


def benign_reference_path() -> str:
    """A real, benign PE that exists on any machine running this app: the
    Python interpreter binary itself. It is only read, never launched."""
    exe = sys.executable
    if os.name == "nt":
        return exe
    return exe  # non-Windows: ELF - will be reported as not-a-PE, which is also a valid demo
