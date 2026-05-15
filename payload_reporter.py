# reporter.py — Report Generator
#
# Reads the evasion_results.log produced by evasion_tester.py
# and generates a structured, consolidated final report.
#
# Usage:
#   python reporter.py

import datetime
import os
from encoder import base64_encode, xor_encode, rot13_encode, multi_layer_encode
from obfuscator import apply_all
from evasion_tester import run_tests, SIGNATURES

LOG_FILE    = "evasion_results.log"
REPORT_FILE = "payload_encoder_report.txt"

# ─── FUNCTIONS ────────────────────────────────────────────────────────────────

def parse_log():
    """
    Parse evasion_results.log and extract summary statistics.
    Returns: { total, detected, bypassed, runs: [list of run blocks] }
    """
    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file '{LOG_FILE}' not found. Run evasion_tester.py first.")
        return None

    with open(LOG_FILE, "r") as f:
        content = f.read()

    runs = [block.strip() for block in content.split("=" * 65) if "EVASION TEST RUN" in block]

    total_detected = content.count("[DETECTED]")
    total_bypassed = content.count("[BYPASSED]")

    return {
        "total_runs":    len(runs),
        "total_detected": total_detected,
        "total_bypassed": total_bypassed,
        "runs":          runs,
    }


def generate_comparison_table(payload: str, xor_key: int = 42) -> list:
    """
    Generate a live comparison table of original vs all encoded/obfuscated
    variants with their detection status.
    """
    return run_tests(payload, xor_key)


def generate_report():
    """Build and save the final consolidated report."""
    now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parsed = parse_log()

    lines = []
    lines.append("=" * 70)
    lines.append("    CUSTOM PAYLOAD ENCODER & OBFUSCATION FRAMEWORK")
    lines.append("    FINAL ANALYSIS REPORT")
    lines.append("=" * 70)
    lines.append(f"  Report Generated  : {now}")
    lines.append(f"  Log File          : {LOG_FILE}")
    if parsed:
        lines.append(f"  Total Test Runs   : {parsed['total_runs']}")
        lines.append(f"  Total DETECTED    : {parsed['total_detected']}")
        lines.append(f"  Total BYPASSED    : {parsed['total_bypassed']}")
        bypass_rate = 0
        total = parsed['total_detected'] + parsed['total_bypassed']
        if total > 0:
            bypass_rate = round((parsed['total_bypassed'] / total) * 100, 1)
        lines.append(f"  Overall Bypass Rate: {bypass_rate}%")
    lines.append("=" * 70)

    # ── Signature database summary ──────────────────────────────────────────
    lines.append("\n[SIMULATED SIGNATURE DATABASE]")
    lines.append("-" * 50)
    lines.append(f"  Total Signatures  : {len(SIGNATURES)}")
    lines.append("  Sample signatures : " + ", ".join(SIGNATURES[:5]) + " ...")

    # ── Encoding technique effectiveness ────────────────────────────────────
    lines.append("\n[ENCODING TECHNIQUE EFFECTIVENESS]")
    lines.append("-" * 50)

    sample_payload = "cmd.exe /c whoami"
    results = generate_comparison_table(sample_payload)

    lines.append(f"  Test Payload: '{sample_payload}'\n")
    lines.append(f"  {'TECHNIQUE':<42} {'STATUS':<12} {'MATCHED SIG'}")
    lines.append(f"  {'-'*42} {'-'*12} {'-'*20}")
    for r in results:
        lines.append(f"  {r['technique']:<42} {r['status']:<12} {r['matched_sig']}")

    # ── Obfuscation analysis ─────────────────────────────────────────────────
    lines.append("\n[OBFUSCATION ANALYSIS NOTES]")
    lines.append("-" * 50)
    analysis = [
        ("Base64 Encoding",
         "Completely hides the original string. BYPASSED because the signature engine "
         "scans the encoded output, not the decoded content."),
        ("XOR Encoding",
         "Converts payload to hex bytes. Very effective — no readable strings remain."),
        ("ROT13",
         "Simple substitution. Effective against exact-match signatures but "
         "vulnerable to ROT13-aware scanners."),
        ("Multi-Layer (ROT13+XOR+B64)",
         "Strongest evasion. Multiple transformations make pattern matching nearly impossible."),
        ("Random Case",
         "Bypasses case-sensitive signatures. Fails against case-insensitive scanners."),
        ("Escape Sequences",
         "Converts to \\xNN hex notation. Highly effective against plain-text scanners."),
        ("Junk Character Insertion",
         "Breaks exact-match patterns by inserting noise characters between real content."),
        ("Reverse String",
         "Simple reversal defeats naive forward-scanning signature engines."),
    ]
    for technique, note in analysis:
        lines.append(f"\n  {technique}:")
        lines.append(f"    {note}")

    # ── Full log history ─────────────────────────────────────────────────────
    if parsed and parsed["runs"]:
        lines.append("\n\n[FULL TEST LOG HISTORY]")
        lines.append("-" * 50)
        for run in parsed["runs"]:
            lines.append(run)
            lines.append("")

    lines.append("\n" + "=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)

    report_text = "\n".join(lines)

    print(report_text)
    with open(REPORT_FILE, "w") as f:
        f.write(report_text)

    print(f"\n[+] Report saved to: {REPORT_FILE}")


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    generate_report()
