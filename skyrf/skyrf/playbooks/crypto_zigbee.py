"""Criptografía Zigbee (AES-CCM) compartida por los playbooks.

Zigbee PRO usa AES-128 en modo CCM* con:
- nonce de 13 bytes = source address (8B LE) || frame counter (4B LE) || security control (1B)
- MIC de 4 bytes (M=32 bits)
- AAD = auxiliary security header (security control .. fin del aux header)

Referencias: IEEE 802.15.4-2020 (CCM*), Zigbee PRO 2023 (sección de seguridad
NWK/APS), y la metodología pública de zbdsniff/KillerBee y del análisis de
Securelist (dic-2025) sobre inyección Zigbee.
"""

from __future__ import annotations

from Crypto.Cipher import AES

# Trust Center Link Key por defecto del estándar Zigbee ("ZigBeeAlliance09")
DEFAULT_TC_LINK_KEY = bytes.fromhex("5A6967426565416C6C69616E63653039")


def build_nonce(src_addr: int, frame_counter: int, security_control: int) -> bytes:
    """nonce = src addr (8B LE) || frame counter (4B LE) || security control (1B)."""
    return (src_addr.to_bytes(8, "little")
            + frame_counter.to_bytes(4, "little")
            + bytes([security_control]))


def ccm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes,
                mic_len: int = 4) -> bytes:
    """AES-CCM encrypt → ciphertext || MIC."""
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=mic_len)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct + tag


def ccm_decrypt(key: bytes, nonce: bytes, ciphertext_and_mic: bytes, aad: bytes,
                mic_len: int = 4) -> bytes | None:
    """AES-CCM decrypt. Devuelve None si el MIC no verifica (llave/nonce mal)."""
    ct, tag = ciphertext_and_mic[:-mic_len], ciphertext_and_mic[-mic_len:]
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=mic_len)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        return None
