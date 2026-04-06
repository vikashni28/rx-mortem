"""
ml/feature_extractor.py  —  RX-MORTEM v2
Binary feature extraction shared by train.py and ml_predictor.py.
Returns a 5-element list matching FEATURE_COLUMNS order:
  [file_size, entropy, num_sections, imports_count, suspicious_strings_count]
"""

import math, os, re, struct, sys
from collections import Counter

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config.settings import FEATURE_COLUMNS, MIN_STRING_LENGTH

_SUSPICIOUS = [
    "VirtualAlloc","VirtualAllocEx","WriteProcessMemory","ReadProcessMemory",
    "CreateRemoteThread","NtCreateThreadEx","OpenProcess","TerminateProcess",
    "cmd.exe","powershell","WinExec","ShellExecute","CreateProcess",
    "InternetOpenUrl","URLDownloadToFile","WinHttpOpen","HttpSendRequest",
    "socket","connect","bind","recv","send","gethostbyname",
    "RegSetValue","RegCreateKey","CurrentVersion\\Run",
    "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtSetInformationThread",
    "CryptEncrypt","CryptGenKey","vssadmin","bcdedit","wbadmin",
    "lsass","mimikatz","sekurlsa",
    "GetAsyncKeyState","SetWindowsHookEx","WH_KEYBOARD",
    "LoadLibrary","GetProcAddress","MapViewOfFile",
    "ptrace","LD_PRELOAD","/proc/self/mem","/etc/shadow",
    "payload","shellcode","inject","meterpreter","reverse_tcp",
    "UPX!","bitcoin",".onion",
]


def _entropy(data: bytes) -> float:
    if not data: return 0.0
    c = Counter(data); t = len(data)
    return round(-sum((v/t)*math.log2(v/t) for v in c.values()), 6)


def _strings(data: bytes) -> list:
    pat = re.compile(rb"[\x20-\x7e]{" + str(MIN_STRING_LENGTH).encode() + rb",}")
    return [s.decode("ascii", errors="ignore") for s in pat.findall(data)]


def _count_suspicious(strings: list) -> int:
    joined = "\n".join(strings).lower()
    return sum(1 for ind in _SUSPICIOUS if ind.lower() in joined)


def _count_sections(data: bytes) -> int:
    if data[:2] == b"MZ":
        try:
            import pefile
            pe = pefile.PE(data=data); n = len(pe.sections); pe.close(); return n
        except Exception: pass
        try:
            off = struct.unpack_from("<I", data, 0x3C)[0]
            if off + 6 < len(data):
                return struct.unpack_from("<H", data, off + 6)[0]
        except Exception: pass
    if data[:4] == b"\x7fELF":
        try:
            import io
            from elftools.elf.elffile import ELFFile
            return ELFFile(io.BytesIO(data)).num_sections()
        except Exception: pass
        try:
            if len(data) >= 64: return struct.unpack_from("<H", data, 60)[0]
        except Exception: pass
    return 1


def _count_imports(data: bytes) -> int:
    if data[:2] == b"MZ":
        try:
            import pefile
            pe = pefile.PE(data=data)
            n = sum(len(e.imports) for e in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]))
            pe.close(); return n
        except Exception: pass
    if data[:4] == b"\x7fELF":
        try:
            import io
            from elftools.elf.elffile import ELFFile
            from elftools.elf.sections import SymbolTableSection
            elf = ELFFile(io.BytesIO(data)); n = 0
            for sec in elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    n += sum(1 for sym in sec.iter_symbols()
                             if sym["st_shndx"]=="SHN_UNDEF" and sym.name)
            return n
        except Exception: pass
    known = [b"CreateFile",b"ReadFile",b"WriteFile",b"GetProcAddress",
             b"LoadLibrary",b"VirtualAlloc",b"socket",b"connect",
             b"malloc",b"free",b"printf",b"fopen",b"strcmp"]
    return sum(1 for api in known if api in data)


def extract_features_from_file(filepath: str) -> list:
    with open(filepath, "rb") as fh: data = fh.read()
    strings = _strings(data)
    return [
        float(len(data)),
        float(_entropy(data)),
        float(_count_sections(data)),
        float(_count_imports(data)),
        float(_count_suspicious(strings)),
    ]


def extract_features_from_static(static: dict) -> list:
    return [
        float(static.get("file_size", 0)),
        float(static.get("entropy", 0.0)),
        float(static.get("sections_count", len(static.get("sections", [])))),
        float(static.get("imports_count",  len(static.get("imports",  [])))),
        float(len(static.get("suspicious_strings", []))),
    ]
