"""Construcción y parseo manual de frames 802.15.4 / Zigbee NWK / APS.

Decisión deliberada: bytes crudos con struct en vez de depender de la
serialización interna de Scapy — es determinista, testeable y es exactamente
lo que viaja por el aire (y lo que acepta un radio TX por serie).

Layout 802.15.4 (data frame, short+short addressing, PAN compression):
  FCF(2 LE) | seq(1) | dst PAN(2) | dst addr(2) | src addr(2)

Layout NWK header (sin ext src):
  FC(2 LE) | dst(2) | src(2) | radius(1) | seq(1)

NWK aux security header (security level 5, network key, extended nonce):
  SC(1)=0x2D | frame counter(4 LE) | src largo(8 LE) | key seq(1)
"""

from __future__ import annotations

import struct

# --- constantes de seguridad ---
SEC_CTRL_NWK = 0x2D   # level 5 (ENC-MIC-32) | key_type=1 (network) | ext nonce
SEC_CTRL_TC = 0x25    # level 5 | key_type=2 (key-transport/TC link) | ext nonce

# --- FCF 802.15.4 ---
FCF_DATA = 0x8841  # data | security off | ack off | PAN compression | short addrs


def mac_header(dst_pan: int, dst: int, src: int, seq: int) -> bytes:
    fcf = struct.pack("<H", FCF_DATA)
    return fcf + bytes([seq & 0xFF]) + struct.pack("<HHH", dst_pan, dst, src)


def parse_mac(frame: bytes) -> dict:
    """Parsea el header MAC mínimo. Lanza ValueError si no es data short/short."""
    if len(frame) < 9:
        raise ValueError("frame demasiado corto")
    fcf, seq = struct.unpack_from("<HB", frame, 0)
    frame_type = fcf & 0x7
    if frame_type != 0x1:  # data
        raise ValueError("no es data frame")
    dst_mode = (fcf >> 10) & 0x3
    src_mode = (fcf >> 14) & 0x3
    pan_compress = (fcf >> 6) & 0x1
    if dst_mode != 0x2 or src_mode != 0x2 or not pan_compress:
        raise ValueError("addressing no soportado (se espera short/short + pan compression)")
    dst_pan, dst, src = struct.unpack_from("<HHH", frame, 3)
    return {"dst_pan": dst_pan, "dst": dst, "src": src, "seq": seq, "nwk_off": 9}


def nwk_header(dst: int, src: int, seq: int, *, security: bool, radius: int = 30) -> bytes:
    # FC: frametype=0(data) | proto v2 (bits2-5) | discover=1 (bits6-7) | security bit9
    fc = 0x0008 | (1 << 6) | ((1 if security else 0) << 9)
    return struct.pack("<H", fc) + struct.pack("<HHBB", dst, src, radius, seq & 0xFF)


def nwk_aux_header(frame_counter: int, src_long: int, sec_ctrl: int = SEC_CTRL_NWK,
                   key_seq: int = 0) -> bytes:
    return (bytes([sec_ctrl]) + struct.pack("<I", frame_counter)
            + struct.pack("<Q", src_long) + bytes([key_seq]))


def parse_nwk_security(frame: bytes, nwk_off: int) -> dict:
    """Parsea NWK header + aux security header. Devuelve offsets y campos."""
    fc = struct.unpack_from("<H", frame, nwk_off)[0]
    security = bool((fc >> 9) & 1)
    hdr = struct.unpack_from("<HHBB", frame, nwk_off + 2)
    off = nwk_off + 8  # sin ext src/dst
    out = {"security": security, "dst": hdr[0], "src": hdr[1], "off": off}
    if security:
        sc = frame[off]
        fc4, src_long, key_seq = struct.unpack_from("<IQB", frame, off + 1)
        out.update({"sc": sc, "frame_counter": fc4, "src_long": src_long,
                    "key_seq": key_seq, "payload_off": off + 14})
    else:
        out["payload_off"] = off
    return out


def aps_header(dst_ep: int, cluster: int, profile: int, src_ep: int, counter: int,
               command: bool = False) -> bytes:
    """APS data frame (FC=0x00) o APS command (FC=0x02 → solo FC + counter)."""
    if command:
        return bytes([0x02, counter & 0xFF])
    return (bytes([0x00, dst_ep]) + struct.pack("<HH", cluster, profile)
            + bytes([src_ep, counter & 0xFF]))
