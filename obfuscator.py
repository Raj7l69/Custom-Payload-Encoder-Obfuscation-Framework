# obfuscator.py — String Obfuscation Module
#
# Implements multiple string obfuscation techniques to transform
# payloads and make signature-based detection harder.
#
# Imported by evasion_tester.py and can also be run standalone.
#
# Usage (standalone):
#   python obfuscator.py

import random
import string

# ─── OBFUSCATION FUNCTIONS ────────────────────────────────────────────────────

def random_case(payload: str) -> str:
    """
    Randomly alternate the case of each character.
    Example: "whoami" -> "WhOaMi"

    This breaks simple case-sensitive signature matches.
    """
    return "".join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in payload
    )


def insert_junk_chars(payload: str, junk_char: str = "%00", interval: int = 3) -> str:
    """
    Insert a junk/null character after every N characters.
    Example: "calc" -> "cal%00c%00"

    Breaks fixed-width signature patterns.
    """
    result = ""
    for i, c in enumerate(payload):
        result += c
        if (i + 1) % interval == 0 and i != len(payload) - 1:
            result += junk_char
    return result


def reverse_string(payload: str) -> str:
    """
    Reverse the payload string.
    Example: "malware.exe" -> "exe.erawlam"

    Simple but effective against naive keyword scanners.
    """
    return payload[::-1]


def char_substitution(payload: str) -> str:
    """
    Substitute characters with visually similar Unicode lookalikes.
    Example: "a" -> "а" (Cyrillic a), "e" -> "е" (Cyrillic e)

    Breaks exact-match detection while preserving visual appearance.
    """
    substitutions = {
        'a': '\u0430',  # Cyrillic small letter a
        'e': '\u0435',  # Cyrillic small letter ie
        'o': '\u043e',  # Cyrillic small letter o
        'p': '\u0440',  # Cyrillic small letter er
        'c': '\u0441',  # Cyrillic small letter es
        'x': '\u0445',  # Cyrillic small letter ha
    }
    return "".join(substitutions.get(c, c) for c in payload)


def escape_sequence(payload: str) -> str:
    """
    Convert each character to its escape sequence representation.
    Example: "cmd" -> "\\x63\\x6d\\x64"

    Makes the payload unreadable as plain text to scanners.
    """
    return "".join(f"\\x{ord(c):02x}" for c in payload)


def split_concat(payload: str, chunk_size: int = 3) -> str:
    """
    Split the payload into chunks and represent it as a
    string concatenation expression.
    Example: "whoami" -> '"who"+"ami"'

    Defeats scanners that look for complete strings.
    """
    chunks = [
        f'"{payload[i:i+chunk_size]}"'
        for i in range(0, len(payload), chunk_size)
    ]
    return "+".join(chunks)


def double_encode(payload: str) -> str:
    """
    Apply URL-style percent encoding twice.
    Example: "a" -> "%2561" (%25 is the encoded form of %)

    Confuses parsers that only decode once.
    """
    single = "".join(f"%{ord(c):02x}" for c in payload)
    double = single.replace("%", "%25")
    return double


def apply_all(payload: str) -> dict:
    """
    Apply all obfuscation techniques to the payload.
    Returns a dict of { technique_name: obfuscated_output }.
    """
    return {
        "original":           payload,
        "random_case":        random_case(payload),
        "junk_chars":         insert_junk_chars(payload),
        "reversed":           reverse_string(payload),
        "char_substitution":  char_substitution(payload),
        "escape_sequence":    escape_sequence(payload),
        "split_concat":       split_concat(payload),
        "double_encoded":     double_encode(payload),
    }


# ─── STANDALONE DEMO ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_payload = "cmd.exe /c whoami"

    print("=" * 60)
    print("  STRING OBFUSCATOR — DEMO")
    print("=" * 60)
    print(f"\n  Original: {test_payload}\n")

    results = apply_all(test_payload)
    for technique, output in results.items():
        if technique == "original":
            continue
        print(f"  [{technique}]")
        print(f"    {output}\n")

    print("=" * 60)
