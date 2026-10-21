"""Stage 03 - The PE contradiction engine.

A contradiction is two or more observable properties of a PE file that do
not naturally agree with each other, or with the apparent identity of the
file. Each rule returns zero or more findings; every finding carries the
same record shape so that it can drive the score, the report and later
validation:

    name, category, bucket, severity, score, evidence, explanation, why
"""
import re

SEVERITY_FACTOR = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}

# Evidence buckets and their initial weights (see scoring.py). Weights are a
# starting point to be tuned on a validation set - not claimed optimal.
BUCKETS = {
    "identity":        {"label": "Identity mismatch",              "weight": 10, "category": "Identity"},
    "section":         {"label": "RWX / section anomaly",          "weight": 20, "category": "Section"},
    "high_entropy":    {"label": "High entropy",                   "weight": 15, "category": "Entropy-Content"},
    "entropy_content": {"label": "Entropy-content contradiction",  "weight": 15, "category": "Entropy-Content"},
    "api":             {"label": "API combination",                "weight": 15, "category": "API"},
    "structural":      {"label": "Structural anomaly",             "weight": 10, "category": "Structural"},
}

CATEGORY_CODES = {"Identity": "A", "Section": "B", "Entropy-Content": "C", "API": "D", "Structural": "E"}

DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".mov",
            ".zip", ".rar", ".csv", ".htm", ".html", ".odt", ".wav"}
EXEC_EXTS = {".exe", ".scr", ".com", ".pif", ".cpl", ".dll", ".sys", ".ocx", ".drv", ".efi", ".mui"}
SYSTEM_BINARIES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "explorer.exe",
                   "services.exe", "smss.exe", "spoolsv.exe", "taskhost.exe", "taskhostw.exe",
                   "dllhost.exe", "conhost.exe", "rundll32.exe", "wininit.exe", "lsm.exe"}

DATA_SECTION_NAMES = {".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata", ".bss"}


def _finding(name, bucket, severity, evidence, explanation, why, attack=None):
    weight = BUCKETS[bucket]["weight"]
    return {
        "name": name,
        "category": BUCKETS[bucket]["category"],
        "category_code": CATEGORY_CODES[BUCKETS[bucket]["category"]],
        "bucket": bucket,
        "severity": severity,
        "score": round(weight * SEVERITY_FACTOR[severity], 1),
        "evidence": evidence,
        "explanation": explanation,
        "why": why,
        "attack": attack,
    }


def _apis(features) -> set:
    return set(features["imports"]["normalized_apis"])


def _has_any(apis, *names):
    return [n for n in names if n in apis]


# --------------------------------------------------------------------------
# A. Identity
# --------------------------------------------------------------------------

def identity_rules(f):
    out = []
    fi, pe = f["file"], f["pe"]
    name = fi["name"]
    lower = name.lower()

    if "‮" in name:
        out.append(_finding(
            "Right-to-left override in filename", "identity", "HIGH",
            {"filename": name.encode("unicode_escape").decode(), "codepoint": "U+202E"},
            "The filename contains a Unicode RLO character, which visually reverses the "
            "extension so an executable can appear to be a document.",
            "Explorer renders text after U+202E right-to-left, so 'invoice‮fdp.exe' is "
            "displayed as 'invoiceexe.pdf'. Legitimate software has no reason to do this.",
            "T1036.002 Right-to-Left Override"))

    m = re.search(r"\.([a-z0-9]{2,4})(\s*)\.(exe|scr|com|pif|cpl|dll)$", lower)
    if m and ("." + m.group(1)) in DOC_EXTS:
        out.append(_finding(
            "Deceptive double extension", "identity", "HIGH",
            {"filename": name, "claimed_type": "." + m.group(1), "actual_extension": "." + m.group(3),
             "actual_content": f"{pe['magic']} {pe['type']} ({pe['arch']})",
             "padding_spaces": len(m.group(2))},
            f"The name claims to be a '.{m.group(1)}' file, but the real extension and the "
            f"content are a Windows {pe['type']}.",
            "Windows hides known extensions by default, so 'report.pdf.exe' is shown as "
            "'report.pdf'. The apparent identity and the actual PE structure disagree.",
            "T1036.007 Double File Extension"))
    elif fi["extension"] in DOC_EXTS:
        out.append(_finding(
            "Extension contradicts PE content", "identity", "HIGH",
            {"filename": name, "claimed_type": fi["extension"],
             "actual_content": f"{pe['magic']} {pe['type']} ({pe['arch']})", "magic": "MZ / PE\\0\\0"},
            f"The file is named like a '{fi['extension']}' document but contains a Windows "
            f"{pe['type']} image.",
            "A document or media file never starts with an MZ/PE header. A mismatch between "
            "the extension and the magic bytes is a classic masquerading indicator.",
            "T1036.008 Masquerade File Type"))

    if fi["extension"] == ".dll" and not pe["is_dll"]:
        out.append(_finding(
            "DLL extension on a non-DLL image", "identity", "MEDIUM",
            {"extension": ".dll", "IMAGE_FILE_DLL": False, "pe_type": pe["type"]},
            "The file is named as a DLL but its header says it is a standalone executable.",
            "Loaders and analysts trust the extension; the header characteristic is what the "
            "OS actually uses. Disagreement suggests the file was renamed to blend in."))
    elif fi["extension"] in (".exe", ".scr") and pe["is_dll"]:
        out.append(_finding(
            "EXE extension on a DLL image", "identity", "MEDIUM",
            {"extension": fi["extension"], "IMAGE_FILE_DLL": True},
            "The file is named as an executable but its header marks it as a DLL.",
            "A DLL cannot run on its own; renaming it as .exe is unusual for normal software."))

    if fi["extension"] == ".scr":
        out.append(_finding(
            "Screensaver (.scr) executable", "identity", "LOW",
            {"extension": ".scr", "pe_type": pe["type"]},
            "SCR files are ordinary executables and are frequently abused as email attachments.",
            "The .scr extension executes like .exe when opened but is less often blocked."))

    if lower in SYSTEM_BINARIES and not pe["has_signature"]:  # in-box copies may be catalog-signed
        out.append(_finding(
            "Unsigned file using a Windows system binary name", "identity", "MEDIUM",
            {"filename": name, "authenticode_directory": "absent"},
            f"'{name}' is the name of a core Windows process, but this file carries no "
            "Authenticode signature.",
            "Genuine Windows system binaries are signed by Microsoft. An unsigned copy using the "
            "same name is a common way to hide in process listings.",
            "T1036.005 Match Legitimate Name or Location"))

    vi = f.get("version_info", {})
    orig = (vi.get("OriginalFilename") or "").strip()
    if orig and orig.lower().rsplit(".", 1)[0] != lower.split(".")[0] \
            and orig.lower() not in lower and lower.split(".")[0] not in orig.lower():
        out.append(_finding(
            "Filename differs from embedded OriginalFilename", "identity", "LOW",
            {"filename": name, "OriginalFilename": orig,
             "CompanyName": vi.get("CompanyName", "-")},
            "The version resource says the file was built as a different program.",
            "Renaming alone is not malicious (downloads are renamed often), but combined with "
            "other contradictions it suggests the file is presenting a false identity."))

    company = (vi.get("CompanyName") or "").lower()
    if "microsoft" in company and not pe["has_signature"]:
        out.append(_finding(
            "Claims Microsoft authorship without an embedded signature", "identity", "LOW",
            {"CompanyName": vi.get("CompanyName"), "authenticode_directory": "absent"},
            "The version resource names Microsoft as the publisher, but the file carries no embedded signature.",
            "Version strings are trivially forged. Many in-box Windows files are catalog-signed rather than "
            "embedded-signed, so this is weak on its own - verify with the system catalog (sigcheck -i)."))
    return out


# --------------------------------------------------------------------------
# B. Section
# --------------------------------------------------------------------------

def section_rules(f):
    out = []
    secs = f["sections"]

    wx = [s for s in secs if s["writable"] and s["executable"]]
    if wx:
        rwx = [s for s in wx if s["readable"]]
        out.append(_finding(
            "RWX section" if rwx else "Writable + executable section", "section", "HIGH",
            {"sections": ", ".join(f"{s['name']} ({s['perms']}, {s['characteristics']})" for s in wx),
             "rwx_count": len(rwx), "wx_count": len(wx),
             "entropy": ", ".join(f"{s['name']}={s['entropy']:.2f}" for s in wx)},
            f"{len(wx)} section(s) are mapped both writable and executable: "
            + ", ".join(s["name"] for s in wx) + ".",
            "Modern compilers separate code (R-X) from data (RW-). A section that can be "
            "written and then executed is what a self-unpacking stub or injected shellcode "
            "needs, and it defeats W^X / DEP protections.",
            "T1027.002 Software Packing"))

    for s in secs:
        if s["executable"] and s["raw_size"] == 0 and s["virtual_size"] > 0:
            out.append(_finding(
                "Executable section with no data on disk", "section", "MEDIUM",
                {"section": s["name"], "raw_size": 0, "virtual_size": s["virtual_size"],
                 "perms": s["perms"]},
                f"{s['name']} occupies {s['virtual_size']:,} bytes in memory but 0 bytes in the "
                "file, and is executable.",
                "An empty executable region is reserved space that something must fill at run "
                "time - typically an unpacking stub decompressing the real code into it."))
        elif s["raw_size"] and s["vsize_raw_ratio"] and s["vsize_raw_ratio"] >= 10 \
                and s["virtual_size"] >= 0x4000:
            out.append(_finding(
                "Virtual size far exceeds raw size", "section", "MEDIUM",
                {"section": s["name"], "virtual_size": s["virtual_size"], "raw_size": s["raw_size"],
                 "ratio": f"{s['vsize_raw_ratio']}x"},
                f"{s['name']} grows {s['vsize_raw_ratio']}x when loaded into memory.",
                "Large in-memory growth with little file data indicates content is generated or "
                "decompressed at run time rather than shipped statically."))

    packers = sorted({s["name"] for s in secs if s["name"] in _packer_names()})
    if packers:
        out.append(_finding(
            "Known packer section names", "section", "MEDIUM",
            {"sections": ", ".join(packers),
             "packer": ", ".join(sorted({_packer_names()[p] for p in packers}))},
            "Section names match those written by a known executable packer.",
            "Packing is used by legitimate software too, but it hides the real code from static "
            "analysis, so the file needs unpacking before its intent can be judged.",
            "T1027.002 Software Packing"))

    from .extractor import STANDARD_SECTIONS
    odd = [s["name"] for s in secs if s["name"] not in STANDARD_SECTIONS and s["name"] not in _packer_names()]
    if odd:
        out.append(_finding(
            "Non-standard section names", "section", "LOW",
            {"sections": ", ".join(odd), "count": len(odd)},
            "Section names do not match those produced by common compilers/linkers.",
            "Custom names are allowed by the format, but compilers emit a predictable set "
            "(.text, .rdata, .data...). Unusual names often come from packers or crypters."))

    mislabeled = [s for s in secs if s["name"] in DATA_SECTION_NAMES and s["executable"]]
    if mislabeled:
        out.append(_finding(
            "Data section marked executable", "section", "MEDIUM",
            {"sections": ", ".join(f"{s['name']} ({s['perms']})" for s in mislabeled)},
            "A section whose name says 'data' or 'resources' is executable.",
            "The section name and its permissions disagree: compilers never mark .data/.rsrc as "
            "code. Malware sometimes hides code in sections that analysts skip."))

    text_noexec = [s for s in secs if s["name"] in (".text", "CODE") and not s["executable"]]
    if text_noexec:
        out.append(_finding(
            "Code section is not executable", "section", "LOW",
            {"sections": ", ".join(f"{s['name']} ({s['perms']})" for s in text_noexec)},
            "The section named as code is not executable, so the real code must live elsewhere.",
            "This disagreement between name and permission indicates the layout was rewritten."))

    names = [s["name"] for s in secs]
    dups = sorted({n for n in names if names.count(n) > 1})
    if dups:
        out.append(_finding(
            "Duplicate section names", "section", "LOW",
            {"duplicates": ", ".join(dups)},
            "More than one section shares the same name.",
            "Linkers merge same-named sections; duplicates are a sign of manual tampering."))
    return out


def _packer_names():
    from .extractor import PACKER_SECTIONS
    return PACKER_SECTIONS


# --------------------------------------------------------------------------
# C. Entropy-Content
# --------------------------------------------------------------------------

def entropy_rules(f):
    out = []
    ent, imp, strs, pe = f["entropy"], f["imports"], f["strings"], f["pe"]
    secs = [s for s in f["sections"] if s["raw_size"] >= 512]

    hot = [s for s in secs if s["name"] != ".rsrc" and s["entropy"] >= 7.0]
    if hot:
        top = max(hot, key=lambda s: s["entropy"])
        exec_hot = [s for s in hot if s["executable"]]
        sev = "HIGH" if top["entropy"] >= 7.5 or exec_hot else "MEDIUM"
        out.append(_finding(
            "High-entropy section", "high_entropy", sev,
            {"sections": ", ".join(f"{s['name']}={s['entropy']:.2f}" for s in hot),
             "max_entropy": round(top["entropy"], 2), "threshold": 7.0,
             "executable_high_entropy": len(exec_hot)},
            f"{top['name']} has entropy {top['entropy']:.2f} bits/byte (maximum is 8.0).",
            "Compiled x86 code typically sits around 5.5-6.8 bits/byte. Values above ~7.0 mean "
            "the bytes are close to random, i.e. compressed or encrypted. Entropy alone is not "
            "proof - installers and media are also high-entropy - so it is weighed with the "
            "content checks below."))
    else:
        rs = [s for s in secs if s["name"] == ".rsrc" and s["entropy"] >= 7.5]
        if rs and rs[0]["raw_size"] > 0.5 * f["file"]["size"]:
            out.append(_finding(
                "Resource section dominated by high-entropy data", "high_entropy", "LOW",
                {"section": ".rsrc", "entropy": rs[0]["entropy"], "raw_size": rs[0]["raw_size"],
                 "share_of_file": f"{rs[0]['raw_size'] / f['file']['size']:.0%}"},
                "Most of the file is a high-entropy resource blob.",
                "Embedded encrypted payloads are often stored as resources; compressed images can "
                "also cause this, so it is weighted low."))

    maxe = ent["max_non_resource"]
    if maxe >= 7.0 and not pe["is_dotnet"]:
        sparse_imports = imp["import_count"] <= 20
        few_strings = strs.get("meaningful", strs["total"]) < 40 or strs.get("meaningful_per_kb", 9) < 1.0
        if sparse_imports or few_strings:
            sev = "HIGH" if (sparse_imports and few_strings) else "MEDIUM"
            out.append(_finding(
                "Possible packing / obfuscation", "entropy_content", sev,
                {"max_entropy": round(maxe, 2), "imports": imp["import_count"],
                 "dlls": imp["dll_count"], "strings": strs.get("meaningful", strs["total"]),
                 "strings_per_kb": strs.get("meaningful_per_kb", strs["density_per_kb"])},
                "High section entropy combined with "
                + (" and ".join(x for x, c in [("sparse imports", sparse_imports),
                                                ("very few readable strings", few_strings)] if c))
                + " may indicate packing or obfuscation.",
                "A normal program with this much content would import dozens of APIs and contain "
                "many readable strings. When entropy is high but imports and strings are scarce, "
                "the real content is hidden from static view and recovered only at run time.",
                "T1027 Obfuscated Files or Information"))

    resource_only = pe["is_dll"] and pe["entry_point"] == 0
    if imp["import_count"] == 0 and not pe["is_dotnet"] and not resource_only:
        out.append(_finding(
            "No import table", "entropy_content", "MEDIUM",
            {"imports": 0, "dlls": 0, "pe_type": pe["type"]},
            "The image imports no functions at all.",
            "Any useful Windows program must call the OS. With no imports it must locate APIs "
            "manually at run time (e.g. PEB walking), a technique used by shellcode loaders."))

    ov = f["overlay"]
    if ov["present"] and not ov["is_signature"] and ov["size"] >= 4096 and ov["entropy"] >= 7.2:
        out.append(_finding(
            "High-entropy overlay", "entropy_content", "LOW" if pe["has_signature"] else "MEDIUM",
            {"overlay_offset": ov.get("offset_hex"), "overlay_size": ov["size"],
             "overlay_entropy": ov["entropy"], "share_of_file": f"{ov['ratio']:.0%}"},
            "Data appended after the last section is compressed or encrypted.",
            "The loader never maps the overlay, so code that reads it is carrying a hidden "
            "payload. Installers do this legitimately, which is why it is not rated high."))
    return out


# --------------------------------------------------------------------------
# D. API combinations
# --------------------------------------------------------------------------

def api_rules(f):
    out = []
    apis = _apis(f)
    imp = f["imports"]

    alloc = _has_any(apis, "VirtualAllocEx", "VirtualAlloc", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory")
    write = _has_any(apis, "WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory")
    execs = _has_any(apis, "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
                     "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread")
    openp = _has_any(apis, "OpenProcess")
    stages = sum(bool(x) for x in (alloc, write, execs))
    if stages == 3:
        out.append(_finding(
            "Process-injection-like API combination", "api", "HIGH",
            {"allocate": ", ".join(alloc), "write": ", ".join(write), "execute": ", ".join(execs),
             "open_target": ", ".join(openp) or "-"},
            "The import table contains every step of classic remote process injection: "
            "allocate memory, write into it, and start a thread there.",
            "Each API alone is common. Together - " + " + ".join([alloc[0], write[0], execs[0]])
            + (" + OpenProcess" if openp else "")
            + " - they form the allocate/write/execute chain used to run code inside another "
            "process. Investigate; debuggers and some security tools use it legitimately.",
            "T1055 Process Injection"))
    elif stages == 2 and (write or execs):
        out.append(_finding(
            "Partial process-injection API chain", "api", "MEDIUM",
            {"allocate": ", ".join(alloc) or "-", "write": ", ".join(write) or "-",
             "execute": ", ".join(execs) or "-", "open_target": ", ".join(openp) or "-"},
            "Two of the three allocate/write/execute injection steps are imported.",
            "The missing step can be resolved dynamically, so a partial chain is still worth "
            "checking in a disassembler.", "T1055 Process Injection"))

    hollow = _has_any(apis, "NtUnmapViewOfSection", "ZwUnmapViewOfSection")
    if hollow and _has_any(apis, "CreateProcess") and _has_any(apis, "SetThreadContext", "ResumeThread"):
        out.append(_finding(
            "Process-hollowing API combination", "api", "HIGH",
            {"apis": ", ".join(hollow + _has_any(apis, "CreateProcess", "SetThreadContext",
                                                  "ResumeThread", "WriteProcessMemory"))},
            "Imports match the process-hollowing pattern: create a process, unmap its image, "
            "write a new one, redirect its thread.",
            "Unmapping another process's image has almost no legitimate use in ordinary "
            "applications.", "T1055.012 Process Hollowing"))

    dyn = _has_any(apis, "LoadLibrary", "LoadLibraryEx", "LdrLoadDll")
    gpa = _has_any(apis, "GetProcAddress", "LdrGetProcedureAddress")
    protect = _has_any(apis, "VirtualProtect", "VirtualProtectEx")
    if dyn and gpa and imp["import_count"] <= 25 and not f["pe"]["is_dotnet"]:
        sev = "MEDIUM" if (alloc or protect) else "LOW"
        out.append(_finding(
            "Minimal imports with dynamic API resolution", "api", sev,
            {"resolvers": ", ".join(dyn + gpa), "total_imports": imp["import_count"],
             "memory_apis": ", ".join(alloc + protect) or "-"},
            f"Only {imp['import_count']} APIs are imported, including the pair needed to resolve "
            "any other API at run time.",
            "LoadLibrary + GetProcAddress let a program hide which APIs it really uses. With a "
            "small import table" + (" and memory-permission APIs" if (alloc or protect) else "")
            + ", the visible imports are likely a loader, not the real functionality.",
            "T1106 Native API"))

    # VirtualAlloc + VirtualProtect in a large import table is deliberately not
    # reported: JITs and memory allocators use it constantly.

    hooks = _has_any(apis, "SetWindowsHookEx")
    keys = _has_any(apis, "GetAsyncKeyState", "GetKeyState", "GetKeyboardState")
    if hooks and keys:
        out.append(_finding(
            "Keyboard hook + key-state polling", "api", "MEDIUM",
            {"apis": ", ".join(hooks + keys)},
            "The file can install a global hook and read keyboard state.",
            "This pairing is the core of most user-mode keyloggers.", "T1056.001 Keylogging"))

    netdl = _has_any(apis, "URLDownloadToFile", "InternetOpenUrl", "WinHttpSendRequest", "HttpSendRequest")
    run = _has_any(apis, "WinExec", "ShellExecute", "ShellExecuteEx", "CreateProcess")
    if netdl and run and imp["import_count"] <= 120:
        out.append(_finding(
            "Download-and-execute API combination", "api", "MEDIUM",
            {"download": ", ".join(netdl), "execute": ", ".join(run)},
            "The file can fetch content over HTTP and launch a process.",
            "A compact binary that downloads and then executes is the shape of a dropper / "
            "first-stage loader.", "T1105 Ingress Tool Transfer"))

    crypt = _has_any(apis, "CryptEncrypt", "BCryptEncrypt", "CryptGenKey", "BCryptGenerateSymmetricKey")
    enum = _has_any(apis, "FindFirstFile", "FindFirstFileEx", "FindNextFile")
    ransom_str = [s for s in f["strings"]["suspicious"]
                  if s["type"] in ("Ransom / crypto-currency", "Shadow-copy / recovery tampering")]
    if crypt and enum and ransom_str:
        out.append(_finding(
            "Encryption + file enumeration + ransom indicators", "api", "HIGH",
            {"crypto": ", ".join(crypt), "enumeration": ", ".join(enum),
             "strings": "; ".join(s["value"][:60] for s in ransom_str[:3])},
            "Bulk file encryption capability co-occurs with ransom or recovery-tampering strings.",
            "Encryption APIs and directory walking are normal separately; together with these "
            "strings they match ransomware behaviour.", "T1486 Data Encrypted for Impact"))

    reg = _has_any(apis, "RegSetValueEx", "RegSetValue")
    runkey = [s for s in f["strings"]["suspicious"] if s["type"] == "Registry run key"]
    if reg and runkey:
        out.append(_finding(
            "Registry Run-key persistence", "api", "MEDIUM",
            {"api": ", ".join(reg), "string": runkey[0]["value"]},
            "The file writes registry values and references an autorun key.",
            "Writing to ...\\CurrentVersion\\Run makes a program start at every logon.",
            "T1547.001 Registry Run Keys"))

    evasion = [s for s in f["strings"]["suspicious"]
               if s["type"] in ("Shadow-copy / recovery tampering", "Log clearing")]
    if evasion and not (crypt and enum and ransom_str):
        out.append(_finding(
            "Recovery-tampering commands embedded", "api", "MEDIUM",
            {"strings": "; ".join(s["value"] for s in evasion[:3])},
            "Command lines that delete shadow copies, disable recovery or clear logs are embedded.",
            "Ordinary applications do not destroy backups or event logs.", "T1490 Inhibit System Recovery"))

    anti = _has_any(apis, "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                    "NtSetInformationThread")
    if len(anti) >= 2 and imp["import_count"] <= 60:
        out.append(_finding(
            "Multiple anti-debugging APIs", "api", "LOW",
            {"apis": ", ".join(anti)},
            "Several debugger-detection APIs are imported by a small binary.",
            "One check is common in runtime libraries; several in a small program suggest the "
            "author expects to be analysed.", "T1622 Debugger Evasion"))
    return out


# --------------------------------------------------------------------------
# E. Structural
# --------------------------------------------------------------------------

def structural_rules(f):
    out = []
    pe, secs = f["pe"], f["sections"]
    ep = pe["entry_point"]
    ep_sec = next((s for s in secs if s["contains_entry_point"]), None)

    if ep == 0 and not pe["is_dll"]:
        out.append(_finding(
            "Executable with zero entry point", "structural", "MEDIUM",
            {"AddressOfEntryPoint": "0x00000000", "pe_type": pe["type"]},
            "An EXE whose entry point is 0 starts executing at the DOS header.",
            "Only DLLs may legitimately omit an entry point."))
    elif ep and ep_sec is None:
        out.append(_finding(
            "Entry point outside all sections", "structural", "HIGH",
            {"AddressOfEntryPoint": pe["entry_point_hex"],
             "section_ranges": ", ".join(f"{s['name']}@{s['virtual_address_hex']}" for s in secs)},
            "The entry point does not fall inside any declared section.",
            "The header points execution at memory no section describes - a deliberate "
            "malformation used to confuse analysis tools."))
    elif ep_sec is not None:
        if not ep_sec["executable"]:
            out.append(_finding(
                "Entry point in non-executable section", "structural", "HIGH",
                {"AddressOfEntryPoint": pe["entry_point_hex"], "section": ep_sec["name"],
                 "perms": ep_sec["perms"]},
                f"Execution starts in {ep_sec['name']}, which is not marked executable.",
                "The header and section table disagree about where code lives."))
        last = ep_sec["index"] == len(secs) - 1 and len(secs) > 1
        normal = ep_sec["name"] in (".text", "CODE", ".code", ".textbss", "INIT", "PAGE")
        if not normal:
            sev = "MEDIUM" if (last or ep_sec["writable"]) else "LOW"
            out.append(_finding(
                "Unusual entry-point section", "structural", sev,
                {"AddressOfEntryPoint": pe["entry_point_hex"], "section": ep_sec["name"],
                 "section_index": f"{ep_sec['index'] + 1} of {len(secs)}",
                 "perms": ep_sec["perms"], "entropy": ep_sec["entropy"]},
                f"Execution begins in '{ep_sec['name']}'"
                + (", the last section" if last else "") + " instead of the main code section.",
                "Compilers place the entry point in .text. An entry point in the last or a "
                "writable section is typical of a packer/crypter stub that was appended to the "
                "original program."))

    ts = pe["timestamp"]
    repro = "REPRO" in pe.get("debug_types", [])
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).timestamp()
    if not repro and ts and (ts > now + 86400 or ts < 631152000):
        out.append(_finding(
            "Implausible compile timestamp", "structural", "LOW",
            {"TimeDateStamp": ts, "utc": pe["timestamp_utc"],
             "reason": "in the future" if ts > now else "before 1990"},
            "The header compile time is " + ("in the future." if ts > now else "before 1990."),
            "Timestamps are often forged to defeat timeline analysis. Reproducible builds use "
            "hashes here, but those declare a REPRO debug entry, which this file does not."))

    if pe["expected_size_of_image"] and pe["size_of_image"] != pe["expected_size_of_image"] \
            and abs(pe["size_of_image"] - pe["expected_size_of_image"]) > pe["section_alignment"]:
        out.append(_finding(
            "SizeOfImage disagrees with section layout", "structural", "LOW",
            {"SizeOfImage": hex(pe["size_of_image"]),
             "computed_from_sections": hex(pe["expected_size_of_image"])},
            "The declared in-memory size does not match the extent of the sections.",
            "Hand-edited or packer-rebuilt headers often leave inconsistent sizes."))

    overlap, beyond = [], []
    fsize = f["file"]["size"]
    ordered = sorted([s for s in secs if s["raw_size"]], key=lambda s: s["raw_pointer"])
    for a, b in zip(ordered, ordered[1:]):
        if a["raw_pointer"] + a["raw_size"] > b["raw_pointer"]:
            overlap.append(f"{a['name']}/{b['name']}")
    for s in secs:
        if s["raw_size"] and s["raw_pointer"] + s["raw_size"] > fsize + 0x200:
            beyond.append(s["name"])
    if overlap or beyond:
        out.append(_finding(
            "Abnormal section layout on disk", "structural", "MEDIUM",
            {"overlapping": ", ".join(overlap) or "-", "extends_past_eof": ", ".join(beyond) or "-"},
            "Section raw data overlaps or points beyond the end of the file.",
            "Linkers lay sections out sequentially. Overlaps are crafted to confuse parsers."))

    n = pe["number_of_sections"]
    if n <= 1 or n > 12:
        out.append(_finding(
            "Unusual number of sections", "structural", "LOW",
            {"NumberOfSections": n, "typical_range": "3 - 8"},
            f"The image has {n} section(s).",
            "Typical compilers produce 3-8 sections; one or very many suggests a packer or a "
            "hand-built image."))

    cs, calc = pe["checksum"], pe.get("checksum_calculated")
    if cs and calc is not None and cs != calc:
        out.append(_finding(
            "Header checksum mismatch", "structural", "LOW",
            {"declared": hex(cs), "calculated": hex(calc)},
            "The PE checksum is set but does not match the file contents.",
            "A non-zero checksum is written by the linker; a mismatch means the file was "
            "modified after linking (patched, infected or appended to)."))

    if pe["tls_callbacks"]:
        out.append(_finding(
            "TLS callbacks present", "structural", "LOW",
            {"tls_callbacks": pe["tls_callbacks"]},
            "Code is registered to run before the official entry point.",
            "TLS callbacks are used by some runtimes, but also to run anti-debug checks before a "
            "debugger breaks at the entry point.", "T1622 Debugger Evasion"))

    if len(f.get("parser_warnings", [])) >= 3:
        out.append(_finding(
            "Malformed header fields", "structural", "LOW",
            {"pefile_warnings": len(f["parser_warnings"]),
             "first": f["parser_warnings"][0][:120]},
            "The PE parser reported several structural irregularities.",
            "Compiler output parses cleanly; repeated warnings indicate hand-crafted or damaged "
            "structures."))
    return out


RULESETS = [
    ("A", "Identity", identity_rules),
    ("B", "Section", section_rules),
    ("C", "Entropy-Content", entropy_rules),
    ("D", "API", api_rules),
    ("E", "Structural", structural_rules),
]

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def detect(features) -> list:
    findings = []
    for _code, _name, fn in RULESETS:
        findings.extend(fn(features))
    findings.sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], -x["score"]))
    for i, fnd in enumerate(findings, 1):
        fnd["id"] = f"F{i:02d}"
    return findings


def context_notes(features) -> list:
    """Observations that inform the analyst but are deliberately NOT scored."""
    notes = []
    pe = features["pe"]
    if pe["has_signature"]:
        notes.append("Authenticode signature directory present ("
                     f"{pe['signature_size']:,} bytes). Presence only - the signature was not verified.")
    if pe["is_dotnet"]:
        notes.append(".NET assembly: native import/entropy heuristics are relaxed because managed "
                     "code imports only mscoree.dll.")
    if "DYNAMIC_BASE (ASLR)" not in pe["dll_characteristics"]:
        notes.append("ASLR (DYNAMIC_BASE) is not enabled - common for older or hand-built binaries.")
    if "NX_COMPAT (DEP)" not in pe["dll_characteristics"]:
        notes.append("DEP (NX_COMPAT) is not declared.")
    if pe.get("pdb_path"):
        notes.append(f"Debug PDB path: {pe['pdb_path']}")
    ctx = [s["api"] for s in features["imports"]["suspicious"] if s["context_only"]]
    if ctx:
        notes.append("Low-signal APIs (context only): " + ", ".join(ctx[:8]))
    return notes
