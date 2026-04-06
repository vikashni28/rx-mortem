import math
import os
import re
import struct
from collections import Counter


SUSPICIOUS_STRINGS = [
    "cmd.exe", "powershell", "CreateRemoteThread", "VirtualAlloc",
    "WriteProcessMemory", "WinExec", "ShellExecute", "URLDownloadToFile",
    "InternetOpenUrl", "socket", "connect", "bind", "recv", "send",
    "RegSetValue", "RegCreateKey", "OpenProcess", "TerminateProcess",
    "IsDebuggerPresent", "NtSetInformationThread", "ZwQueryInformationProcess",
    "GetAsyncKeyState", "SetWindowsHookEx", "keylog", "ransomware",
    "encrypt", "decrypt", "base64", "http://", "https://", "ftp://",
    "bcdedit", "vssadmin", "wbadmin", "taskkill", "netsh", "schtasks",
    "mimikatz", "payload", "shellcode", "inject", "bypass", "obfuscat",
    "meterpreter", "reverse_tcp", "bind_tcp", "autorun", "startup",
    "\\AppData\\Roaming", "\\Temp\\", "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER",
    "DeleteFile", "MoveFileEx", "FindFirstFile", "GetTempPath",
    "CreateMutex", "OpenMutex", "MapViewOfFile", "CreateFileMapping",
    "GetProcAddress", "LoadLibrary", "NtUnmapViewOfSection",
    "RtlDecompressBuffer", "SetFileAttributes", "GetCommandLine",
]


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 6)


def extract_strings(data: bytes, min_len: int = 4) -> list:
    pattern = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    return [s.decode("ascii", errors="ignore") for s in pattern.findall(data)]


def find_suspicious_strings(strings: list) -> list:
    found = []
    lower_strings = [s.lower() for s in strings]
    for sus in SUSPICIOUS_STRINGS:
        sus_lower = sus.lower()
        for s in lower_strings:
            if sus_lower in s and sus not in found:
                found.append(sus)
                break
    return found


def is_pe(data: bytes) -> bool:
    if len(data) < 2:
        return False
    return data[:2] == b'MZ'


def is_elf(data: bytes) -> bool:
    if len(data) < 4:
        return False
    return data[:4] == b'\x7fELF'


def analyze_pe(data: bytes, filepath: str) -> dict:
    result = {
        "format": "PE",
        "sections": [],
        "imports": [],
        "exports": [],
        "characteristics": [],
        "machine": "unknown",
        "timestamp": None,
        "is_dll": False,
        "is_64bit": False,
    }

    try:
        import pefile
        pe = pefile.PE(data=data)

        machine_map = {
            0x14c: "x86",
            0x8664: "x86_64",
            0xaa64: "ARM64",
            0x1c0: "ARM",
        }
        result["machine"] = machine_map.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:04x}")
        result["timestamp"] = pe.FILE_HEADER.TimeDateStamp
        result["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        result["is_64bit"] = pe.OPTIONAL_HEADER.Magic == 0x20b if hasattr(pe, 'OPTIONAL_HEADER') else False

        char_flags = {
            0x0001: "RELOCS_STRIPPED",
            0x0002: "EXECUTABLE_IMAGE",
            0x0020: "LARGE_ADDRESS_AWARE",
            0x2000: "DLL",
        }
        for flag, name in char_flags.items():
            if pe.FILE_HEADER.Characteristics & flag:
                result["characteristics"].append(name)

        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").strip("\x00")
            sec_data = section.get_data()
            sec_entropy = calculate_entropy(sec_data)
            result["sections"].append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "size": section.SizeOfRawData,
                "entropy": sec_entropy,
                "characteristics": hex(section.Characteristics),
            })

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                for imp in entry.imports:
                    if imp.name:
                        result["imports"].append(f"{dll_name}::{imp.name.decode('utf-8', errors='ignore')}")

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result["exports"].append(exp.name.decode("utf-8", errors="ignore"))

        pe.close()

    except ImportError:
        result["parse_error"] = "pefile not installed, using raw analysis"
        result.update(_raw_pe_analysis(data))
    except Exception as e:
        result["parse_error"] = str(e)
        result.update(_raw_pe_analysis(data))

    return result


def _raw_pe_analysis(data: bytes) -> dict:
    result = {"sections": [], "imports": [], "exports": []}
    try:
        if len(data) < 64:
            return result
        pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
        if pe_offset + 24 > len(data):
            return result
        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        result["machine"] = f"0x{machine:04x}"
        result["num_sections_raw"] = num_sections
    except Exception:
        pass
    return result


def analyze_elf(data: bytes, filepath: str) -> dict:
    result = {
        "format": "ELF",
        "sections": [],
        "imports": [],
        "exports": [],
        "machine": "unknown",
        "elf_class": "unknown",
        "endianness": "unknown",
        "os_abi": "unknown",
        "entry_point": None,
    }

    try:
        from elftools.elf.elffile import ELFFile
        import io

        stream = io.BytesIO(data)
        elf = ELFFile(stream)

        elf_class_map = {1: "32-bit", 2: "64-bit"}
        endian_map = {1: "little", 2: "big"}
        machine_map = {
            0x3e: "x86_64",
            0x03: "x86",
            0x28: "ARM",
            0xb7: "AArch64",
            0x08: "MIPS",
        }

        result["elf_class"] = elf_class_map.get(elf.elfclass // 32 if elf.elfclass in (32, 64) else 0, str(elf.elfclass))
        result["endianness"] = "little" if elf.little_endian else "big"
        result["machine"] = machine_map.get(elf['e_machine'] if isinstance(elf['e_machine'], int) else 0, str(elf['e_machine']))
        result["entry_point"] = hex(elf['e_entry'])
        result["elf_class"] = f"{elf.elfclass}-bit"

        for section in elf.iter_sections():
            sec_name = section.name
            sec_data = section.data()
            sec_entropy = calculate_entropy(sec_data)
            result["sections"].append({
                "name": sec_name,
                "type": section['sh_type'],
                "size": section['sh_size'],
                "entropy": sec_entropy,
                "address": hex(section['sh_addr']),
            })

        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.sections import SymbolTableSection

        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    if sym.name and sym['st_info']['bind'] == 'STB_GLOBAL':
                        if sym['st_shndx'] == 'SHN_UNDEF':
                            result["imports"].append(sym.name)
                        else:
                            result["exports"].append(sym.name)

    except ImportError:
        result["parse_error"] = "pyelftools not installed, using raw analysis"
        result.update(_raw_elf_analysis(data))
    except Exception as e:
        result["parse_error"] = str(e)
        result.update(_raw_elf_analysis(data))

    return result


def _raw_elf_analysis(data: bytes) -> dict:
    result = {"sections": [], "imports": [], "exports": []}
    try:
        if len(data) < 16:
            return result
        elf_class = data[4]
        endian = data[5]
        result["elf_class"] = "64-bit" if elf_class == 2 else "32-bit"
        result["endianness"] = "little" if endian == 1 else "big"
    except Exception:
        pass
    return result


def analyze_file(filepath: str) -> dict:
    result = {
        "filepath": filepath,
        "file_size": 0,
        "entropy": 0.0,
        "format": "unknown",
        "sections": [],
        "imports": [],
        "exports": [],
        "strings_count": 0,
        "suspicious_strings": [],
        "all_strings_sample": [],
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()

        result["file_size"] = len(data)
        result["entropy"] = calculate_entropy(data)

        all_strings = extract_strings(data)
        result["strings_count"] = len(all_strings)
        result["all_strings_sample"] = all_strings[:50]
        result["suspicious_strings"] = find_suspicious_strings(all_strings)

        if is_pe(data):
            pe_info = analyze_pe(data, filepath)
            result.update(pe_info)
        elif is_elf(data):
            elf_info = analyze_elf(data, filepath)
            result.update(elf_info)
        else:
            result["format"] = "unknown/raw"

        result["imports_count"] = len(result.get("imports", []))
        result["exports_count"] = len(result.get("exports", []))
        result["sections_count"] = len(result.get("sections", []))

    except Exception as e:
        result["error"] = str(e)

    return result
