"""Stage 02 - Static PE feature extraction.

Everything here operates on the raw bytes of the sample via ``pefile``.
The sample is never written with an executable extension, loaded as a
module, or passed to a subprocess.
"""
import os
import re

import pefile

from .utils import (extract_strings, hashes, human_size, shannon_entropy,
                    sniff_magic, ts_to_utc)

# --------------------------------------------------------------------------
# Knowledge tables
# --------------------------------------------------------------------------

# Imported APIs worth surfacing to an analyst, grouped by the behaviour they
# *can* support. A single API is context, never proof - combinations are
# evaluated by the contradiction engine.
API_TAGS = {
    "Memory / injection": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "CreateRemoteThreadEx", "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
        "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory", "NtCreateThreadEx",
        "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
        "SetThreadContext", "GetThreadContext", "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection", "NtMapViewOfSection", "OpenProcess",
        "SuspendThread", "ResumeThread",
    ],
    "Dynamic resolution": ["LoadLibrary", "LoadLibraryEx", "GetProcAddress",
                           "LdrLoadDll", "LdrGetProcedureAddress", "GetModuleHandle"],
    "Process / execution": ["CreateProcess", "WinExec", "ShellExecute", "ShellExecuteEx",
                            "CreateProcessAsUser", "CreateProcessWithToken"],
    "Network": ["InternetOpen", "InternetOpenUrl", "InternetConnect", "HttpSendRequest",
                "HttpOpenRequest", "InternetReadFile", "URLDownloadToFile",
                "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "socket",
                "connect", "send", "recv", "WSAStartup", "gethostbyname"],
    "Persistence / registry": ["RegSetValueEx", "RegCreateKeyEx", "RegSetValue",
                               "RegCreateKey", "CreateService", "StartService",
                               "OpenSCManager", "ChangeServiceConfig"],
    "Anti-analysis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                      "NtQueryInformationProcess", "OutputDebugString",
                      "NtSetInformationThread", "GetTickCount", "QueryPerformanceCounter"],
    "Input capture": ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
                      "GetKeyboardState", "RegisterRawInputDevices"],
    "Privilege / token": ["AdjustTokenPrivileges", "OpenProcessToken",
                          "LookupPrivilegeValue", "ImpersonateLoggedOnUser",
                          "DuplicateTokenEx"],
    "Crypto": ["CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
               "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey"],
    "File enumeration": ["FindFirstFile", "FindFirstFileEx", "FindNextFile"],
}
API_TO_TAG = {api: tag for tag, apis in API_TAGS.items() for api in apis}

# Low-signal APIs that are only shown for context in the UI.
CONTEXT_ONLY_TAGS = {"Anti-analysis"}
CONTEXT_ONLY_APIS = {"GetTickCount", "QueryPerformanceCounter", "GetModuleHandle",
                     "OutputDebugString"}

STANDARD_SECTIONS = {
    ".text", ".code", ".data", ".rdata", ".idata", ".edata", ".pdata", ".rsrc",
    ".reloc", ".bss", ".tls", ".crt", ".didat", ".gfids", ".00cfg", ".xdata",
    ".CRT", "CODE", "DATA", "BSS", ".textbss", ".orpc", ".sxdata", ".ndata",
    "INIT", "PAGE", ".retplne", ".voltbl", ".fptable", ".gehcont", ".rodata",
    ".buildid", ".eh_fram", ".symtab", "_RDATA", ".wpp_sf", ".mrdata",
    ".msvcjmc", ".detourc", ".detourd", ".shared", ".giats",
}
PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".UPX0": "UPX", ".UPX1": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", "ASPack": "ASPack",
    ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
    ".themida": "Themida", ".winlice": "WinLicense", "MPRESS1": "MPRESS",
    "MPRESS2": "MPRESS", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".vmp2": "VMProtect", ".enigma1": "Enigma", ".enigma2": "Enigma",
    "PEC2": "PECompact", "pec1": "PECompact", ".perplex": "Perplex",
    ".yP": "Y0da", ".packed": "generic packer", ".mpress": "MPRESS",
}

MACHINE_NAMES = {
    0x14C: ("x86", "Intel 386 (x86)"), 0x8664: ("x64", "AMD64 (x86-64)"),
    0x1C0: ("ARM", "ARM"), 0x1C4: ("ARMv7", "ARM Thumb-2"), 0xAA64: ("ARM64", "ARM64"),
    0x200: ("IA64", "Intel Itanium"),
}
SUBSYSTEMS = {
    1: "Native", 2: "Windows GUI", 3: "Windows Console", 5: "OS/2 Console",
    7: "POSIX Console", 9: "Windows CE GUI", 10: "EFI Application",
    11: "EFI Boot Service Driver", 12: "EFI Runtime Driver", 14: "Xbox",
    16: "Windows Boot Application",
}
DEBUG_TYPES = {1: "COFF", 2: "CODEVIEW", 4: "MISC", 9: "BORLAND", 12: "VC_FEATURE",
               13: "POGO", 14: "ILTCG", 16: "REPRO", 20: "EX_DLLCHARACTERISTICS"}

SUSPICIOUS_STRING_PATTERNS = [
    ("URL", re.compile(r"https?://[^\s\"'<>()\x00]{4,200}", re.I)),
    ("Registry run key", re.compile(r"Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?", re.I)),
    ("Registry path", re.compile(r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\s\"']{3,120}")),
    ("Shadow-copy / recovery tampering", re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit(?:\.exe)?\s+/set\s+\{default\}\s+recoveryenabled\s+no|wbadmin\s+delete", re.I)),
    ("Log clearing", re.compile(r"wevtutil(?:\.exe)?\s+cl\b", re.I)),
    ("Script / LOLBin command", re.compile(r"(?:powershell(?:\.exe)?\s+-(?:e|enc|encodedcommand|nop|w\s+hidden)\b|cmd(?:\.exe)?\s+/c\s+\S+|certutil(?:\.exe)?\s+-urlcache|mshta(?:\.exe)?\s+http|regsvr32(?:\.exe)?\s+/s\s+/n|rundll32(?:\.exe)?\s+\S+,\S+|schtasks(?:\.exe)?\s+/create)", re.I)),
    ("Staging path", re.compile(r"%(?:APPDATA|TEMP|TMP|LOCALAPPDATA|PROGRAMDATA)%[^\s\"']{0,80}|\\AppData\\Roaming\\[^\s\"']{1,80}", re.I)),
    ("Ransom / crypto-currency", re.compile(r"your (?:files|documents) (?:have been|are) encrypted|bitcoin|monero|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b.*btc|\.onion\b", re.I)),
    ("Hard-coded user agent", re.compile(r"Mozilla/\d\.\d \([^)]{5,80}\)")),
    ("Long base64 blob", re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}")),
]
IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")

SECTION_FLAGS = [
    (0x00000020, "CNT_CODE"), (0x00000040, "CNT_INITIALIZED_DATA"),
    (0x00000080, "CNT_UNINITIALIZED_DATA"), (0x02000000, "MEM_DISCARDABLE"),
    (0x10000000, "MEM_SHARED"), (0x20000000, "MEM_EXECUTE"),
    (0x40000000, "MEM_READ"), (0x80000000, "MEM_WRITE"),
]


class NotAPEError(Exception):
    """Raised when the sample cannot be parsed as a PE image."""


def normalize_api(name: str) -> str:
    """CreateProcessW -> CreateProcess, LoadLibraryExA -> LoadLibraryEx."""
    return re.sub(r"(?<=[a-z0-9])[AW]$", "", name)


def _section_name(raw: bytes) -> str:
    name = raw.rstrip(b"\x00").decode("latin-1")
    return "".join(c if 32 <= ord(c) < 127 else f"\\x{ord(c):02x}" for c in name) or "<empty>"


def _flag_list(value: int, table) -> list:
    return [name for bit, name in table if value & bit]


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

def basic_file_info(data: bytes, filename: str) -> dict:
    base = os.path.basename(filename or "sample")
    parts = base.split(".")
    ext = ("." + parts[-1].lower()) if len(parts) > 1 else ""
    inner_ext = ("." + parts[-2].lower()) if len(parts) > 2 else ""
    info = {
        "name": base,
        "size": len(data),
        "size_human": human_size(len(data)),
        "extension": ext,
        "inner_extension": inner_ext,
        "magic": sniff_magic(data),
        "entropy": round(shannon_entropy(data), 4),
    }
    info.update(hashes(data))
    return info


def extract_features(data: bytes, filename: str) -> dict:
    """Parse ``data`` statically and return a JSON-serialisable feature record."""
    file_info = basic_file_info(data, filename)
    if not data.startswith(b"MZ"):
        raise NotAPEError("Missing 'MZ' DOS signature - this is not a Windows PE file "
                          f"(detected: {file_info['magic']}).")
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise NotAPEError(f"pefile could not parse the PE structure: {exc}") from exc

    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
    except Exception as exc:  # malformed directories are themselves evidence
        pe.__dict__.setdefault("_masq_dir_error", str(exc))

    features = {
        "schema": "masquerade.features/1",
        "valid_pe": True,
        "file": file_info,
        "pe": _headers(pe, data),
        "sections": _sections(pe),
    }
    features["entropy"] = _entropy_summary(features["sections"], file_info["entropy"])
    features["imports"] = _imports(pe)
    features["exports"] = _exports(pe)
    features["strings"] = _strings(data)
    features["overlay"] = _overlay(pe, data)
    features["version_info"] = _version_info(pe)
    features["resources"] = _resources(pe)
    features["parser_warnings"] = list(pe.get_warnings())[:25]
    if pe.__dict__.get("_masq_dir_error"):
        features["parser_warnings"].append("Data directory parse error: " + pe._masq_dir_error)

    _locate_entry_point(features)
    pe.close()
    return features


# --------------------------------------------------------------------------
# Individual extractors
# --------------------------------------------------------------------------

def _headers(pe, data) -> dict:
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    machine_short, machine_long = MACHINE_NAMES.get(fh.Machine, (f"0x{fh.Machine:x}", "Unknown"))
    is_dll = bool(fh.Characteristics & 0x2000)
    subsystem = SUBSYSTEMS.get(oh.Subsystem, f"Unknown ({oh.Subsystem})")
    if is_dll:
        pe_type = "DLL"
    elif oh.Subsystem == 1:
        pe_type = "Driver / Native"
    else:
        pe_type = "EXE"

    dirs = oh.DATA_DIRECTORY
    def _dir(idx):
        return dirs[idx] if len(dirs) > idx else None
    sec_dir = _dir(4)
    clr_dir = _dir(14)
    reloc_dir = _dir(5)

    debug_types, pdb_path = [], None
    for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        debug_types.append(DEBUG_TYPES.get(entry.struct.Type, str(entry.struct.Type)))
        pdb = getattr(getattr(entry, "entry", None), "PdbFileName", None)
        if pdb:
            pdb_path = pdb.rstrip(b"\x00").decode("utf-8", "ignore")

    tls_callbacks = 0
    has_tls = hasattr(pe, "DIRECTORY_ENTRY_TLS")
    if has_tls:
        try:
            cb_va = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
            if cb_va:
                ptr_size = 8 if oh.Magic == 0x20B else 4
                rva = cb_va - oh.ImageBase
                for i in range(64):
                    raw = pe.get_data(rva + i * ptr_size, ptr_size)
                    if int.from_bytes(raw, "little") == 0:
                        break
                    tls_callbacks += 1
        except Exception:
            pass

    checksum_calc = None
    if len(data) <= 16 * 1024 * 1024:
        try:
            checksum_calc = pe.generate_checksum()
        except Exception:
            checksum_calc = None

    rich = None
    try:
        rich = pe.parse_rich_header()
    except Exception:
        rich = None

    try:
        imphash = pe.get_imphash() or None
    except Exception:
        imphash = None

    sections_end = max((s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
                        for s in pe.sections), default=0)
    align = oh.SectionAlignment or 0x1000
    expected_soi = (sections_end + align - 1) // align * align if sections_end else 0

    return {
        "type": pe_type,
        "is_dll": is_dll,
        "magic": "PE32+" if oh.Magic == 0x20B else "PE32",
        "bits": 64 if oh.Magic == 0x20B else 32,
        "arch": machine_short,
        "machine": machine_long,
        "subsystem": subsystem,
        "timestamp": fh.TimeDateStamp,
        "timestamp_utc": ts_to_utc(fh.TimeDateStamp),
        "entry_point": oh.AddressOfEntryPoint,
        "entry_point_hex": f"0x{oh.AddressOfEntryPoint:08X}",
        "image_base": oh.ImageBase,
        "image_base_hex": f"0x{oh.ImageBase:X}",
        "base_of_code": oh.BaseOfCode,
        "size_of_image": oh.SizeOfImage,
        "expected_size_of_image": expected_soi,
        "size_of_headers": oh.SizeOfHeaders,
        "size_of_code": oh.SizeOfCode,
        "section_alignment": oh.SectionAlignment,
        "file_alignment": oh.FileAlignment,
        "checksum": oh.CheckSum,
        "checksum_calculated": checksum_calc,
        "linker_version": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
        "os_version": f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}",
        "number_of_sections": fh.NumberOfSections,
        "characteristics": _flag_list(fh.Characteristics, [
            (0x0002, "EXECUTABLE_IMAGE"), (0x0020, "LARGE_ADDRESS_AWARE"),
            (0x0100, "32BIT_MACHINE"), (0x0200, "DEBUG_STRIPPED"),
            (0x1000, "SYSTEM"), (0x2000, "DLL"), (0x0001, "RELOCS_STRIPPED")]),
        "dll_characteristics": _flag_list(oh.DllCharacteristics, [
            (0x0020, "HIGH_ENTROPY_VA"), (0x0040, "DYNAMIC_BASE (ASLR)"),
            (0x0080, "FORCE_INTEGRITY"), (0x0100, "NX_COMPAT (DEP)"),
            (0x0400, "NO_SEH"), (0x1000, "APPCONTAINER"), (0x4000, "GUARD_CF"),
            (0x8000, "TERMINAL_SERVER_AWARE")]),
        "has_signature": bool(sec_dir and sec_dir.VirtualAddress and sec_dir.Size),
        "signature_size": sec_dir.Size if sec_dir else 0,
        "is_dotnet": bool(clr_dir and clr_dir.VirtualAddress),
        "has_relocations": bool(reloc_dir and reloc_dir.VirtualAddress),
        "has_tls": has_tls,
        "tls_callbacks": tls_callbacks,
        "has_debug": bool(debug_types),
        "debug_types": debug_types,
        "pdb_path": pdb_path,
        "has_rich_header": bool(rich),
        "imphash": imphash,
    }


def _sections(pe) -> list:
    out = []
    for idx, s in enumerate(pe.sections):
        ch = s.Characteristics
        r, w, x = bool(ch & 0x40000000), bool(ch & 0x80000000), bool(ch & 0x20000000)
        raw = s.get_data()
        out.append({
            "index": idx,
            "name": _section_name(s.Name),
            "virtual_address": s.VirtualAddress,
            "virtual_address_hex": f"0x{s.VirtualAddress:08X}",
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "raw_pointer": s.PointerToRawData,
            "entropy": round(shannon_entropy(raw), 4) if raw else 0.0,
            "characteristics": f"0x{ch:08X}",
            "flags": _flag_list(ch, SECTION_FLAGS),
            "readable": r, "writable": w, "executable": x,
            "perms": ("R" if r else "-") + ("W" if w else "-") + ("X" if x else "-"),
            "is_code": bool(ch & 0x20),
            "vsize_raw_ratio": round(s.Misc_VirtualSize / s.SizeOfRawData, 2) if s.SizeOfRawData else None,
            "contains_entry_point": False,
        })
    return out


def _entropy_summary(sections, overall) -> dict:
    with_data = [s for s in sections if s["raw_size"] > 0]
    top = max(with_data, key=lambda s: s["entropy"], default=None)
    code = [s["entropy"] for s in with_data if s["executable"]]
    non_rsrc = [s["entropy"] for s in with_data if s["name"] != ".rsrc"]
    return {
        "overall": overall,
        "max_section": top["entropy"] if top else 0.0,
        "max_section_name": top["name"] if top else None,
        "max_non_resource": max(non_rsrc, default=0.0),
        "mean_section": round(sum(s["entropy"] for s in with_data) / len(with_data), 4) if with_data else 0.0,
        "max_executable": max(code, default=0.0),
        "high_entropy_sections": [s["name"] for s in with_data if s["entropy"] >= 7.0],
    }


def _imports(pe) -> dict:
    dlls, all_apis, suspicious = [], [], []
    by_ordinal = 0
    seen = set()
    entries = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])
    delay = list(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []) or [])
    for entry, is_delay in [(e, False) for e in entries] + [(e, True) for e in delay]:
        dll = (entry.dll or b"?").decode("latin-1", "ignore")
        funcs = []
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode("latin-1", "ignore")
            else:
                by_ordinal += 1
                name = f"ord#{imp.ordinal}"
            funcs.append(name)
            all_apis.append(name)
            norm = normalize_api(name)
            tag = API_TO_TAG.get(norm) or API_TO_TAG.get(name)
            if tag and norm not in seen:
                seen.add(norm)
                suspicious.append({"api": name, "normalized": norm, "dll": dll, "tag": tag,
                                   "context_only": tag in CONTEXT_ONLY_TAGS or norm in CONTEXT_ONLY_APIS})
        dlls.append({"name": dll, "count": len(funcs), "delay_load": is_delay, "functions": funcs})
    return {
        "dll_count": len(dlls),
        "import_count": len(all_apis),
        "by_ordinal": by_ordinal,
        "dlls": dlls,
        "normalized_apis": sorted({normalize_api(a) for a in all_apis}),
        "suspicious": suspicious,
        "suspicious_count": sum(1 for s in suspicious if not s["context_only"]),
    }


def _exports(pe) -> dict:
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not exp:
        return {"count": 0, "names": [], "dll_name": None}
    names = [(s.name or b"").decode("latin-1", "ignore") or f"ord#{s.ordinal}" for s in exp.symbols]
    dll_name = None
    try:
        dll_name = pe.get_string_at_rva(exp.struct.Name).decode("latin-1", "ignore")
    except Exception:
        pass
    return {"count": len(names), "names": names[:200], "dll_name": dll_name}


def _strings(data) -> dict:
    ascii_s, utf16_s = extract_strings(data)
    combined = ascii_s + utf16_s
    hits, seen = [], set()
    for text in combined:
        for kind, rx in SUSPICIOUS_STRING_PATTERNS:
            for m in rx.finditer(text):
                val = m.group(0)[:200]
                if (kind, val) not in seen:
                    seen.add((kind, val))
                    hits.append({"type": kind, "value": val})
        for m in IPV4_RE.finditer(text):
            ip = m.group(0)
            octs = [int(o) for o in ip.split(".")]
            if octs[0] in (0, 255) or octs[1:] == [0, 0, 0] or all(o < 10 for o in octs):
                continue  # version numbers / masks, not addresses
            if ("IPv4 address", ip) not in seen:
                seen.add(("IPv4 address", ip))
                hits.append({"type": "IPv4 address", "value": ip})
    size_kb = max(len(data) / 1024, 1)
    interesting = [s for s in combined if 6 <= len(s) <= 120][:60]
    meaningful = sum(1 for s in combined if len(s) >= 8)
    return {
        "total": len(combined),
        "meaningful": meaningful,
        "meaningful_per_kb": round(meaningful / size_kb, 3),
        "ascii": len(ascii_s),
        "unicode": len(utf16_s),
        "density_per_kb": round(len(combined) / size_kb, 3),
        "suspicious": hits[:80],
        "suspicious_count": len(hits),
        "sample": interesting,
    }


def _overlay(pe, data) -> dict:
    try:
        start = pe.get_overlay_data_start_offset()
    except Exception:
        start = None
    if start is None or start >= len(data):
        return {"present": False, "offset": None, "size": 0, "ratio": 0.0, "entropy": 0.0,
                "is_signature": False}
    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4] if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 else None
    is_sig = bool(sec_dir and sec_dir.VirtualAddress == start
                  and sec_dir.VirtualAddress + sec_dir.Size >= len(data))
    blob = data[start:]
    return {
        "present": True,
        "offset": start,
        "offset_hex": f"0x{start:X}",
        "size": len(blob),
        "size_human": human_size(len(blob)),
        "ratio": round(len(blob) / len(data), 4),
        "entropy": round(shannon_entropy(blob[: 8 * 1024 * 1024]), 4),
        "is_signature": is_sig,
    }


def _version_info(pe) -> dict:
    out = {}
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        for fi_list in getattr(pe, "FileInfo", []) or []:
            for fi in fi_list:
                if getattr(fi, "Key", b"") == b"StringFileInfo":
                    for st in fi.StringTable:
                        for k, v in st.entries.items():
                            out[k.decode("utf-8", "ignore")] = v.decode("utf-8", "ignore")
    except Exception:
        pass
    keep = ["CompanyName", "FileDescription", "ProductName", "OriginalFilename",
            "InternalName", "FileVersion", "ProductVersion", "LegalCopyright"]
    return {k: out[k] for k in keep if out.get(k)}


def _resources(pe) -> dict:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if not root:
        return {"count": 0, "types": []}
    types = []
    for entry in root.entries:
        if entry.name is not None:
            types.append(str(entry.name))
        else:
            types.append(pefile.RESOURCE_TYPE.get(entry.struct.Id, str(entry.struct.Id)).replace("RT_", ""))
    return {"count": len(types), "types": types}


def _locate_entry_point(features):
    ep = features["pe"]["entry_point"]
    features["pe"]["entry_section"] = None
    features["pe"]["entry_section_index"] = None
    for s in features["sections"]:
        span = max(s["virtual_size"], s["raw_size"])
        if s["virtual_address"] <= ep < s["virtual_address"] + span:
            s["contains_entry_point"] = True
            features["pe"]["entry_section"] = s["name"]
            features["pe"]["entry_section_index"] = s["index"]
            break
