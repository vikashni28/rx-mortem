import os
from typing import List, Dict

YARA_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "yara_rules",
    "malware_rules.yar"
)


def scan_with_yara(filepath: str) -> List[Dict]:
    matches = []

    try:
        import yara
        if not os.path.exists(YARA_RULES_PATH):
            return [{"error": f"YARA rules file not found: {YARA_RULES_PATH}"}]

        rules = yara.compile(filepath=YARA_RULES_PATH)
        raw_matches = rules.match(filepath)

        for match in raw_matches:
            match_info = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta) if match.meta else {},
                "strings": [],
            }
            for string_match in match.strings:
                string_info = {
                    "identifier": string_match.identifier if hasattr(string_match, 'identifier') else str(string_match),
                    "instances": [],
                }
                if hasattr(string_match, 'instances'):
                    for instance in string_match.instances[:3]:
                        string_info["instances"].append({
                            "offset": instance.offset,
                            "matched_data": instance.matched_data[:64].hex() if instance.matched_data else ""
                        })
                match_info["strings"].append(string_info)

            matches.append(match_info)

    except ImportError:
        matches = _fallback_pattern_scan(filepath)
    except Exception as e:
        matches = [{"error": f"YARA scan failed: {str(e)}"}]

    return matches


def _fallback_pattern_scan(filepath: str) -> List[Dict]:
    """
    Fallback signature-based scanner when yara-python is not installed.
    Uses raw byte pattern matching against known malware indicators.
    """
    matches = []

    BYTE_SIGNATURES = {
        "Metasploit_Shellcode_x86": [
            b"\xfc\xe8\x82\x00\x00\x00",
            b"\x89\xe5\x81\xec",
        ],
        "UPX_Packer": [
            b"UPX!",
            b"UPX0",
            b"UPX1",
        ],
        "MSFPAYLOAD_Generic": [
            b"MSFPAYLOAD",
            b"meterpreter",
            b"Meterpreter",
        ],
        "Suspicious_Registry_Access": [
            b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ],
        "Ransomware_Indicator": [
            b"YOUR FILES HAVE BEEN ENCRYPTED",
            b"your files have been encrypted",
            b"PAY RANSOM",
            b"bitcoin",
            b"BTC wallet",
            b".onion",
        ],
        "Keylogger_API": [
            b"GetAsyncKeyState",
            b"SetWindowsHookEx",
            b"WH_KEYBOARD_LL",
        ],
        "Process_Injection": [
            b"VirtualAllocEx",
            b"WriteProcessMemory",
            b"CreateRemoteThread",
            b"NtCreateThreadEx",
        ],
        "AntiDebug_Technique": [
            b"IsDebuggerPresent",
            b"CheckRemoteDebuggerPresent",
            b"NtQueryInformationProcess",
            b"ZwSetInformationThread",
        ],
        "Network_Beacon": [
            b"InternetOpenUrl",
            b"URLDownloadToFile",
            b"WinHttpOpen",
            b"HttpSendRequest",
        ],
        "ELF_Suspicious": [
            b"/proc/self/maps",
            b"ptrace",
            b"LD_PRELOAD",
            b"/dev/mem",
        ],
        "Credential_Theft": [
            b"lsass.exe",
            b"SAM\\SAM\\Domains\\Account\\Users",
            b"sekurlsa",
            b"wce.exe",
        ],
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()

        for rule_name, patterns in BYTE_SIGNATURES.items():
            matched_patterns = []
            for pattern in patterns:
                if pattern in data:
                    offset = data.find(pattern)
                    matched_patterns.append({
                        "identifier": f"${pattern[:8].hex()}",
                        "instances": [{"offset": offset, "matched_data": pattern.hex()}]
                    })

            if matched_patterns:
                matches.append({
                    "rule": rule_name,
                    "namespace": "fallback",
                    "tags": ["fallback_scan"],
                    "meta": {"description": f"Fallback pattern match for {rule_name}"},
                    "strings": matched_patterns,
                })

    except Exception as e:
        matches.append({"error": f"Fallback scan failed: {str(e)}"})

    return matches
