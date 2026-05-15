# evasion_tester.py — Evasion Testing Module
#
# Simulates a basic signature-based detection engine and tests
# whether original and obfuscated payloads are detected or bypass it.
#
# Uses encoder.py and obfuscator.py for payload transformation.
#
# Usage:
#   python evasion_tester.py

import datetime
from encoder import base64_encode, xor_encode, rot13_encode, multi_layer_encode
from obfuscator import apply_all

# ─── SIMULATED SIGNATURE DATABASE ────────────────────────────────────────────
#
# Represents a simplified AV/IDS signature engine.
# Real engines use thousands of patterns; this simulates the concept.

SIGNATURES = [
    "cmd.exe",
    "powershell",
    "whoami",
    "net user",
    "mimikatz",
    "meterpreter",
    "shellcode",
    "malware",
    "exploit",
    "reverse_shell",
    "calc.exe",
    "/c whoami",
    "invoke-expression",
    "downloadstring",
]

LOG_FILE = "evasion_results.log"

# ─── DETECTION ENGINE ─────────────────────────────────────────────────────────

def detect(payload: str) -> tuple:
    """
    Scan a payload string against the signature database.

    Returns:
        (bool, str | None) — (detected, matched_signature)
    """
    payload_lower = payload.lower()
    for sig in SIGNATURES:
        if sig.lower() in payload_lower:
            return True, sig
    return False, None


# ─── TEST RUNNER ──────────────────────────────────────────────────────────────

def run_tests(payload: str, xor_key: int = 42) -> list:
    """
    Run detection against the original payload and all
    encoded/obfuscated variants. Returns a list of result dicts.
    """
    results = []

    # ── Build all variants ──────────────────────────────────────────────────

    variants = {
        "Original (plaintext)":         payload,
        "Base64 Encoded":               base64_encode(payload),
        "XOR Encoded (hex)":            xor_encode(payload, xor_key),
        "ROT13 Encoded":                rot13_encode(payload),
        "Multi-Layer (ROT13+XOR+B64)":  multi_layer_encode(payload, xor_key)["after_base64"],
    }

    obfuscated = apply_all(payload)
    for k, v in obfuscated.items():
        if k != "original":
            variants[f"Obfuscated [{k}]"] = v

    # ── Test each variant ───────────────────────────────────────────────────

    for technique, transformed in variants.items():
        detected, matched_sig = detect(transformed)
        results.append({
            "technique":   technique,
            "payload":     transformed[:80] + "..." if len(transformed) > 80 else transformed,
            "detected":    detected,
            "matched_sig": matched_sig if detected else "—",
            "status":      "DETECTED" if detected else "BYPASSED",
        })

    return results


def log_results(payload: str, results: list, xor_key: int):
    """Write test results to log file."""
    ts    = datetime.datetime.now().isoformat()
    lines = []
    lines.append(f"\n{'='*65}")
    lines.append(f"  EVASION TEST RUN — {ts}")
    lines.append(f"  Original Payload : {payload}")
    lines.append(f"  XOR Key          : {xor_key}")
    lines.append(f"{'='*65}")

    detected_count = sum(1 for r in results if r["detected"])
    bypassed_count = len(results) - detected_count

    lines.append(f"  Total Variants   : {len(results)}")
    lines.append(f"  Detected         : {detected_count}")
    lines.append(f"  Bypassed         : {bypassed_count}")
    lines.append(f"{'-'*65}")

    for r in results:
        status_label = f"[{r['status']}]"
        lines.append(
            f"  {status_label:<12} {r['technique']:<40} "
            f"Sig: {r['matched_sig']}"
        )

    lines.append(f"{'='*65}")

    output = "\n".join(lines)
    print(output)

    with open(LOG_FILE, "a") as f:
        f.write(output + "\n")

    print(f"\n[+] Results saved to: {LOG_FILE}")
    return output


def print_results_table(results: list):
    """Print a clean formatted table of results to console."""
    print(f"\n  {'TECHNIQUE':<42} {'STATUS':<12} {'MATCHED SIGNATURE'}")
    print(f"  {'-'*42} {'-'*12} {'-'*20}")
    for r in results:
        print(f"  {r['technique']:<42} {r['status']:<12} {r['matched_sig']}")


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Test payloads — safe strings that represent common attacker commands
    # These are used only for educational evasion testing in a lab environment
    test_payloads = [
        "cmd.exe /c whoami",
        "powershell -ep bypass downloadstring",
        "mimikatz sekurlsa::logonpasswords",
    ]

    XOR_KEY = 42

    print("=" * 65)
    print("  EVASION TESTER — Signature Detection Simulation")
    print("=" * 65)

    for payload in test_payloads:
        print(f"\n[*] Testing payload: {payload}")
        results = run_tests(payload, XOR_KEY)
        print_results_table(results)
        log_results(payload, results, XOR_KEY)
        print()
