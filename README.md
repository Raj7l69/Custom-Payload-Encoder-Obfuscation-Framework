# Custom Payload Encoder & Obfuscation Framework

A Python-based educational toolkit that demonstrates how payloads are encoded and obfuscated to study evasion of signature-based detection systems.

Built strictly for **educational and lab purposes** as part of a cybersecurity project. All testing is done against a simulated local detection engine — no real malware is created or deployed.

---

## What It Does

- **Encodes** payloads using Base64, XOR, and ROT13
- **Obfuscates** strings using multiple techniques (case randomization, junk insertion, escape sequences, etc.)
- **Simulates** a basic signature-based detection engine and tests whether each variant gets detected or bypasses it
- **Generates** a consolidated analysis report with bypass rates and technique effectiveness notes

---

## Project Structure

```
payload-encoder-framework/
│
├── encoder.py          # Base64, XOR, ROT13 encoding & decoding
├── obfuscator.py       # String obfuscation techniques
├── evasion_tester.py   # Simulated detection engine + evasion testing
├── reporter.py         # Final report generation
│
├── evasion_results.log         # Created by evasion_tester.py (auto-generated)
└── payload_encoder_report.txt  # Final report created by reporter.py (auto-generated)
```

---

## Requirements

- **Python:** 3.8 or above
- **OS:** Windows / Linux / macOS
- **Dependencies:** None — uses only Python standard library (`base64`, `codecs`, `random`, `datetime`)

---

## How to Use

### Step 1 — Run the Encoder (standalone demo)

```bash
python encoder.py
```

Demonstrates Base64, XOR, ROT13, and multi-layer encoding on a test payload.

---

### Step 2 — Run the Obfuscator (standalone demo)

```bash
python obfuscator.py
```

Applies all obfuscation techniques to a test payload and prints each variant.

---

### Step 3 — Run Evasion Tests

```bash
python evasion_tester.py
```

Tests multiple payloads against the simulated signature engine. Results are printed to console and saved to `evasion_results.log`.

---

### Step 4 — Generate the Final Report

```bash
python reporter.py
```

Reads `evasion_results.log` and generates a full analysis report in `payload_encoder_report.txt`.

---

## Encoding Techniques

| Technique | Method | Evasion Effectiveness |
|---|---|---|
| Base64 | Standard Base64 encoding | High — hides all readable strings |
| XOR | Single-byte XOR + hex output | High — no recognizable patterns |
| ROT13 | Caesar cipher (shift 13) | Medium — bypasses exact-match only |
| Multi-Layer | ROT13 → XOR → Base64 | Very High — multiple transformations |

---

## Obfuscation Techniques

| Technique | Description |
|---|---|
| Random Case | Randomly alternates character case — `whoami` → `wHoAmI` |
| Junk Chars | Inserts null/junk characters between real chars |
| Reverse String | Reverses the payload string |
| Char Substitution | Replaces chars with Unicode lookalikes |
| Escape Sequences | Converts chars to `\xNN` hex notation |
| Split & Concat | Splits string into concatenated chunks — `"who"+"ami"` |
| Double Encoding | Applies percent-encoding twice |

---

## Sample Output

**Evasion test results:**
```
  TECHNIQUE                                  STATUS       MATCHED SIGNATURE
  ------------------------------------------ ------------ --------------------
  Original (plaintext)                       DETECTED     cmd.exe
  Base64 Encoded                             BYPASSED     —
  XOR Encoded (hex)                          BYPASSED     —
  ROT13 Encoded                              BYPASSED     —
  Multi-Layer (ROT13+XOR+B64)                BYPASSED     —
  Obfuscated [random_case]                   DETECTED     cmd.exe
  Obfuscated [escape_sequence]               BYPASSED     —
```

---

## MITRE ATT&CK Coverage

| Technique | ID |
|---|---|
| Obfuscated Files or Information | T1027 |
| Command and Scripting Interpreter | T1059 |
| Deobfuscate/Decode Files or Information | T1140 |

---

## Ethical Disclaimer

This framework is built **strictly for educational purposes**.

- No real malware is created, deployed, or executed
- All detection testing is done against a **locally simulated** signature engine
- The payloads used are harmless test strings — no actual system commands are run
- Only use this in **controlled lab environments** that you own or have explicit permission to test on

---

## Future Enhancements

- YARA rule-based detection simulation
- PE/ELF string extraction and obfuscation
- HTML/PDF report export
- CLI interface using `argparse`
- Layer-by-layer bypass visualization
