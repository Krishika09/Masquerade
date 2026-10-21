"""DEMO / ILLUSTRATIVE feature record.

This is a hand-written feature record shaped exactly like the extractor's
output, used so that a presentation-ready report can be produced without
handling a real malware sample. It does NOT describe a real file:

* hashes are SHA-256/MD5/SHA-1 of a fixed label string, not of a binary;
* network indicators use reserved documentation ranges (RFC 5737 IPs,
  RFC 2606 ``.example`` domains);
* the record is passed through the *real* contradiction engine, scoring and
  ML stages, so every finding and number on the report is computed, not typed.
"""
import hashlib

from .utils import human_size

DEMO_LABEL = b"MASQUERADE-DEMO-ILLUSTRATIVE-SAMPLE-v1 (not a real file)"


def _sec(idx, name, va, vsize, raw, ptr, ent, ch, flags):
    r, w, x = bool(ch & 0x40000000), bool(ch & 0x80000000), bool(ch & 0x20000000)
    return {
        "index": idx, "name": name, "virtual_address": va, "virtual_address_hex": f"0x{va:08X}",
        "virtual_size": vsize, "raw_size": raw, "raw_pointer": ptr, "entropy": ent,
        "characteristics": f"0x{ch:08X}", "flags": flags,
        "readable": r, "writable": w, "executable": x,
        "perms": ("R" if r else "-") + ("W" if w else "-") + ("X" if x else "-"),
        "is_code": bool(ch & 0x20),
        "vsize_raw_ratio": round(vsize / raw, 2) if raw else None,
        "contains_entry_point": False,
    }


def demo_features() -> dict:
    size = 187_904
    sections = [
        _sec(0, ".text", 0x1000, 0x1A3F0, 0x1A400, 0x400, 7.9412, 0x60000020,
             ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]),
        _sec(1, ".rdata", 0x1C000, 0x2C10, 0x2E00, 0x1A800, 4.1180, 0x40000040,
             ["CNT_INITIALIZED_DATA", "MEM_READ"]),
        _sec(2, ".data", 0x1F000, 0x5A00, 0x600, 0x1D600, 2.0174, 0xC0000040,
             ["CNT_INITIALIZED_DATA", "MEM_READ", "MEM_WRITE"]),
        _sec(3, ".xyz", 0x25000, 0x6000, 0x5E00, 0x1DC00, 7.6233, 0xE0000060,
             ["CNT_CODE", "CNT_INITIALIZED_DATA", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE"]),
        _sec(4, ".rsrc", 0x2B000, 0x1C88, 0x1E00, 0x23A00, 5.0931, 0x40000040,
             ["CNT_INITIALIZED_DATA", "MEM_READ"]),
    ]
    sections[3]["contains_entry_point"] = True

    imports = [
        ("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess",
                          "LoadLibraryA", "GetProcAddress", "ExitProcess"]),
        ("USER32.dll", ["MessageBoxW"]),
    ]
    from .extractor import API_TO_TAG, CONTEXT_ONLY_APIS, CONTEXT_ONLY_TAGS, normalize_api
    suspicious, apis = [], []
    for dll, funcs in imports:
        for fn in funcs:
            apis.append(fn)
            n = normalize_api(fn)
            if n in API_TO_TAG:
                tag = API_TO_TAG[n]
                suspicious.append({"api": fn, "normalized": n, "dll": dll, "tag": tag,
                                   "context_only": tag in CONTEXT_ONLY_TAGS or n in CONTEXT_ONLY_APIS})

    sha256 = hashlib.sha256(DEMO_LABEL).hexdigest()
    return {
        "schema": "masquerade.features/1",
        "valid_pe": True,
        "demo": True,
        "file": {
            "name": "Q3_financial_report.pdf.exe", "size": size, "size_human": human_size(size),
            "extension": ".exe", "inner_extension": ".pdf", "magic": "DOS/PE executable (MZ)",
            "entropy": 7.6127, "md5": hashlib.md5(DEMO_LABEL).hexdigest(),
            "sha1": hashlib.sha1(DEMO_LABEL).hexdigest(), "sha256": sha256,
        },
        "pe": {
            "type": "EXE", "is_dll": False, "magic": "PE32", "bits": 32, "arch": "x86",
            "machine": "Intel 386 (x86)", "subsystem": "Windows GUI",
            "timestamp": 1714521600, "timestamp_utc": "2024-05-01 00:00:00 UTC",
            "entry_point": 0x25A30, "entry_point_hex": "0x00025A30",
            "image_base": 0x400000, "image_base_hex": "0x400000", "base_of_code": 0x1000,
            "size_of_image": 0x2D000, "expected_size_of_image": 0x2D000, "size_of_headers": 0x400,
            "size_of_code": 0x20200, "section_alignment": 0x1000, "file_alignment": 0x200,
            "checksum": 0x0003A1F2, "checksum_calculated": 0x0002E9C4,
            "linker_version": "6.0", "os_version": "4.0", "number_of_sections": 5,
            "characteristics": ["EXECUTABLE_IMAGE", "32BIT_MACHINE", "RELOCS_STRIPPED"],
            "dll_characteristics": [],
            "has_signature": False, "signature_size": 0, "is_dotnet": False,
            "has_relocations": False, "has_tls": False, "tls_callbacks": 0,
            "has_debug": False, "debug_types": [], "pdb_path": None, "has_rich_header": False,
            "imphash": hashlib.md5(DEMO_LABEL + b"imphash").hexdigest(),
            "entry_section": ".xyz", "entry_section_index": 3,
        },
        "sections": sections,
        "entropy": {"overall": 7.6127, "max_section": 7.9412, "max_section_name": ".text",
                    "max_non_resource": 7.9412, "mean_section": 5.3586, "max_executable": 7.9412,
                    "high_entropy_sections": [".text", ".xyz"]},
        "imports": {
            "dll_count": 2, "import_count": 8, "by_ordinal": 0,
            "dlls": [{"name": d, "count": len(f), "delay_load": False, "functions": f} for d, f in imports],
            "normalized_apis": sorted({normalize_api(a) for a in apis}),
            "suspicious": suspicious,
            "suspicious_count": sum(1 for s in suspicious if not s["context_only"]),
        },
        "exports": {"count": 0, "names": [], "dll_name": None},
        "strings": {
            "total": 41, "ascii": 33, "unicode": 8, "density_per_kb": 0.224,
            "meaningful": 12, "meaningful_per_kb": 0.065,
            "suspicious": [
                {"type": "URL", "value": "http://cdn-update.example/api/v2/check"},
                {"type": "IPv4 address", "value": "203.0.113.47"},
                {"type": "Hard-coded user agent", "value": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"},
                {"type": "Staging path", "value": "%APPDATA%\\Microsoft\\svc_host.exe"},
            ],
            "suspicious_count": 4,
            "sample": ["KERNEL32.dll", "USER32.dll", "VirtualAlloc", "WriteProcessMemory",
                       "CreateRemoteThread", "http://cdn-update.example/api/v2/check",
                       "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
                       "%APPDATA%\\Microsoft\\svc_host.exe", "203.0.113.47", "Adobe Systems"],
        },
        "overlay": {"present": False, "offset": None, "size": 0, "ratio": 0.0, "entropy": 0.0,
                    "is_signature": False},
        "version_info": {"CompanyName": "Adobe Systems Incorporated", "FileDescription": "Adobe Reader",
                         "OriginalFilename": "stub32.exe", "FileVersion": "11.0.23.22"},
        "resources": {"count": 3, "types": ["ICON", "GROUP_ICON", "VERSION"]},
        "parser_warnings": ["Suspicious flags set for section 3. Both IMAGE_SCN_MEM_WRITE and "
                            "IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable."],
    }
