# encoder.py — Payload Encoding Module
#
# Supports Base64, XOR, and ROT13 encoding and decoding.
# Imported by evasion_tester.py and can also be run standalone.
#
# Usage (standalone):
#   python encoder.py

import base64
import codecs

# ─── ENCODING FUNCTIONS ───────────────────────────────────────────────────────

def base64_encode(payload: str) -> str:
    """Encode a string payload using Base64."""
    encoded = base64.b64encode(payload.encode()).decode()
    return encoded


def base64_decode(encoded: str) -> str:
    """Decode a Base64 encoded string back to plaintext."""
    decoded = base64.b64decode(encoded.encode()).decode()
    return decoded


def xor_encode(payload: str, key: int) -> str:
    """
    XOR encode a string payload with a single-byte integer key.
    Returns a hex string representation of the encoded bytes.

    Example:
        xor_encode("calc.exe", 42)  ->  "494b4b4e126b676b"
    """
    encoded_bytes = bytes([ord(c) ^ key for c in payload])
    return encoded_bytes.hex()


def xor_decode(hex_payload: str, key: int) -> str:
    """
    Decode an XOR-encoded hex string back to plaintext using the same key.
    """
    raw_bytes = bytes.fromhex(hex_payload)
    decoded = "".join([chr(b ^ key) for b in raw_bytes])
    return decoded


def rot13_encode(payload: str) -> str:
    """
    Apply ROT13 substitution cipher to a string.
    ROT13 is its own inverse — encoding and decoding use the same function.
    """
    return codecs.encode(payload, "rot_13")


def rot13_decode(payload: str) -> str:
    """Decode a ROT13-encoded string (same as encoding)."""
    return codecs.encode(payload, "rot_13")


def multi_layer_encode(payload: str, xor_key: int) -> dict:
    """
    Apply multiple encoding layers in sequence:
      1. ROT13
      2. XOR
      3. Base64 on the XOR hex output

    Returns a dict with each layer's output for comparison.
    """
    layer1 = rot13_encode(payload)
    layer2 = xor_encode(layer1, xor_key)
    layer3 = base64_encode(layer2)

    return {
        "original":      payload,
        "after_rot13":   layer1,
        "after_xor":     layer2,
        "after_base64":  layer3,
    }


# ─── STANDALONE DEMO ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_payload = "cmd.exe /c whoami"
    xor_key      = 42

    print("=" * 60)
    print("  PAYLOAD ENCODER — DEMO")
    print("=" * 60)
    print(f"\n  Original Payload : {test_payload}")
    print(f"  XOR Key          : {xor_key}\n")

    b64 = base64_encode(test_payload)
    print(f"  [Base64 Encoded] : {b64}")
    print(f"  [Base64 Decoded] : {base64_decode(b64)}\n")

    xor = xor_encode(test_payload, xor_key)
    print(f"  [XOR Encoded]    : {xor}")
    print(f"  [XOR Decoded]    : {xor_decode(xor, xor_key)}\n")

    r13 = rot13_encode(test_payload)
    print(f"  [ROT13 Encoded]  : {r13}")
    print(f"  [ROT13 Decoded]  : {rot13_decode(r13)}\n")

    layers = multi_layer_encode(test_payload, xor_key)
    print("  [Multi-Layer Encoding]")
    for step, value in layers.items():
        print(f"    {step:<18}: {value}")

    print("\n" + "=" * 60)
