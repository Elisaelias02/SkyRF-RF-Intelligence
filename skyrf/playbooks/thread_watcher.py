#!/usr/bin/env python3
"""SkyRF — thread_watcher.py
Watcher de seguridad Thread pasivo (802.15.4 + 6LoWPAN) para el CatSniffer.

Se alimenta de los mismos frames 802.15.4 crudos que el flujo Zigbee
(`catnip sniff thread -c <canal> -r lab.hex` / `--proto zigbee` en el bridge)
y detecta en tiempo real:

  * Tráfico MLE (UDP 19788)      — comando, si va en claro (suite 0xFF).
  * Ventana de comisionado       — CoAP/DTLS en UDP 5684: un joiner está
                                   recibiendo la network key cifrada con KEK
                                   derivada del PSKd → momento exacto del ataque.
  * MLE sensible sin seguridad   — comandos MLE que no son Discovery/Announce
                                   viajando sin seguridad a nivel MLE.
  * Data frames sin seguridad MAC en una red que sí la usa (mezcla = mala
                                   configuración o inyección).

Soporta 6LoWPAN IPHC (RFC 6282) con NHC-UDP en las 4 formas de compresión
de puertos. No reensambla FRAG1/FRAGN: los datagramas fragmentados se
contabilizan y se analiza el primer fragmento.

Kill chain Thread (pasivo, hardware RX):
  1. Este watcher detecta la ventana de comisionado (DTLS/5684).
  2. El handshake DTLS usa TLS_PSK con el PSKd del dispositivo (la
     "commissioning credential" de 6 dígitos/letras de la etiqueta).
  3. PSKd débil → fuerza bruta offline del handshake → KEK → network key.
  4. Con la network key: descifrar todo el tráfico Thread en Wireshark
     (Preferences › Protocols › IEEE 802.15.4 › Decryption keys).

by Cinn4mor0ll
"""

import struct
import time
from dataclasses import dataclass, field

UDP_PORT_MLE = 19788            # 0x4C4C — Mesh Link Establishment
UDP_PORT_COAPS = 5684           # comisionamiento Thread: CoAP sobre DTLS

MLE_COMMANDS = {
    0: "Link Request", 1: "Link Accept", 2: "Link Accept and Request",
    3: "Link Reject", 4: "Advertisement", 5: "Update", 6: "Update Request",
    7: "Data Request", 8: "Data Response", 9: "Parent Request",
    10: "Parent Response", 11: "Child ID Request", 12: "Child ID Response",
    15: "Discovery Request", 16: "Discovery Response", 17: "Announce",
    18: "Child Update Request", 19: "Child Update Response",
}
# Comandos que legítimamente van sin seguridad MLE (fase de descubrimiento)
MLE_UNSECURED_OK = {15, 16, 17}

LOWPAN_IPV6 = 0x41              # dispatch: IPv6 sin comprimir
LOWPAN_IPHC = 0x60              # 011xxxxx
LOWPAN_IPHC_MASK = 0xE0
LOWPAN_FRAG1 = 0xC0             # 110xxxxx
LOWPAN_FRAGN = 0xE0             # 11100xxx


def _mac_parse(frame: bytes):
    """Parseo tolerante del header 802.15.4. Devuelve dict o None."""
    if len(frame) < 5:
        return None
    fcf = struct.unpack_from("<H", frame, 0)[0]
    if (fcf & 0x7) != 0x1:                      # solo data frames
        return None
    security = bool(fcf & 0x08)
    pan_compress = bool(fcf & 0x40)
    seq_suppress = bool(fcf & 0x100)
    dst_mode = (fcf >> 10) & 0x3
    src_mode = (fcf >> 14) & 0x3
    off = 3 if not seq_suppress else 2
    if len(frame) < off:
        return None
    seq = frame[2] if not seq_suppress else None
    dst_pan = dst = src = None
    try:
        if dst_mode == 0x2:
            dst_pan, dst = struct.unpack_from("<HH", frame, off)
            off += 4
        elif dst_mode == 0x3:
            dst_pan, dst = struct.unpack_from("<HQ", frame, off)
            off += 10
        if src_mode != 0:
            if not pan_compress:
                off += 2                          # src PAN
            if src_mode == 0x2:
                src = struct.unpack_from("<H", frame, off)[0]
                off += 2
            elif src_mode == 0x3:
                src = struct.unpack_from("<Q", frame, off)[0]
                off += 8
    except struct.error:
        return None
    # aux security header MAC (si lo hay): SC(1) + FC(4) [+ key id]
    aux = None
    if security and off < len(frame):
        sc = frame[off]
        key_mode = (sc >> 3) & 0x3
        aux_len = 5 + (0 if key_mode == 0 else {1: 1, 2: 5, 3: 9}[key_mode])
        aux = {"sec_level": sc & 0x7, "len": aux_len}
        off += aux_len
    if off > len(frame):
        return None
    return {"dst_pan": dst_pan, "dst": dst, "src": src, "seq": seq,
            "mac_security": security, "aux": aux, "payload": frame[off:]}


def _skip_iphc_addresses(pl: bytes, off: int, b1: int) -> int:
    """Salta src/dst del IPHC según SAC/SAM/M/DAC/DAM. Devuelve nuevo offset."""
    cid, sac, sam, m, dac, dam = ((b1 >> 7) & 1, (b1 >> 6) & 1,
                                  (b1 >> 4) & 3, (b1 >> 3) & 1,
                                  (b1 >> 2) & 1, b1 & 3)
    if cid:
        off += 1
    def size(stateless, mode):
        # modos: 00=128b inline, 01=64b, 10=16b, 11=elidido (0b)
        # con contexto (SAC/DAC=1): 00=elidido(0), 01=64b, 10=16b, 11=0b
        return (16, 8, 2, 0)[mode] if stateless == 0 else (0, 8, 2, 0)[mode]
    off += size(sac, sam)
    if m:                                            # multicast dst
        off += (16, 6, 4, 1)[dam] if dac == 0 else (0, 6, 1, 0)[dam]
    else:
        off += size(dac, dam)
    return min(off, len(pl))


def _parse_udp_ports(pl: bytes, off: int, nh_compressed: bool):
    """Extrae (sport, dport, payload_off) de un header UDP posiblemente
    comprimido con NHC. Devuelve None si no cuadra."""
    if not nh_compressed:
        if off >= len(pl) or pl[off] != 17:          # next header = UDP
            return None
        if off + 9 > len(pl):
            return None
        sport, dport = struct.unpack_from(">HH", pl, off + 1)
        return sport, dport, off + 9                 # +NH+4B hdr+2B cksum
    if off >= len(pl):
        return None
    nhc = pl[off]
    if (nhc & 0xF8) != 0xF0:                         # no es NHC-UDP
        return None
    p_mode = nhc & 0x3
    c_elided = bool(nhc & 0x4)
    off += 1
    try:
        if p_mode == 0:
            sport, dport = struct.unpack_from(">HH", pl, off)
            off += 4
        elif p_mode == 1:
            sport = struct.unpack_from(">H", pl, off)[0]
            dport = 0xF000 + pl[off + 2]
            off += 3
        elif p_mode == 2:
            sport = 0xF000 + pl[off]
            dport = struct.unpack_from(">H", pl, off + 1)[0]
            off += 3
        else:
            b = pl[off]
            sport = 0xF0B0 + (b >> 4)
            dport = 0xF0B0 + (b & 0x0F)
            off += 1
        off += 0 if c_elided else 2                  # checksum
    except (struct.error, IndexError):
        return None
    return sport, dport, off


def parse_6lowpan_udp(payload: bytes):
    """payload MAC → (sport, dport, udp_payload) o None."""
    if not payload:
        return None
    d = payload[0]
    if d == LOWPAN_IPV6:                             # IPv6 sin comprimir
        if len(payload) < 41 or (payload[1] >> 4) != 6:
            return None
        if payload[7] != 17:                         # next header
            return None
        sport, dport = struct.unpack_from(">HH", payload, 41)
        return sport, dport, payload[49:]
    if (d & LOWPAN_IPHC_MASK) != LOWPAN_IPHC:
        return None                                  # FRAG1/FRAGN/mesh: fuera
    if len(payload) < 3:
        return None
    b0, b1 = payload[0], payload[1]
    tf = (b0 >> 3) & 3
    nh_compressed = bool(b0 & 0x04)
    off = 2 + (4, 3, 1, 0)[tf]                       # traffic class/flow label
    off = _skip_iphc_addresses(payload, off, b1)
    if off >= len(payload):
        return None
    got = _parse_udp_ports(payload, off, nh_compressed)
    if not got:
        return None
    sport, dport, poff = got
    return sport, dport, payload[poff:]


@dataclass
class ThreadWatcher:
    """feed(frame_8021544, rssi=None, ts=None) -> list[dict] de alertas
    {level, title, detail, proto:'thread'} para el bridge/dashboard."""

    on_alert: object = None
    stats: dict = field(default_factory=lambda: {
        "frames": 0, "lowpan": 0, "mle": 0, "coaps": 0, "other_udp": 0})
    _seen_mac_sec: set = field(default_factory=set)  # PAN ids que usan seguridad MAC
    _commissioning_alerts: int = 0

    def _alert(self, level, title, detail):
        a = {"level": level, "title": title, "detail": detail, "proto": "thread"}
        if callable(self.on_alert):
            self.on_alert(a)
        return a

    def feed(self, frame: bytes, rssi=None, ts=None):
        alerts = []
        self.stats["frames"] += 1
        mac = _mac_parse(frame)
        if mac is None:
            return alerts
        pan = mac["dst_pan"]
        if pan is not None:
            self._seen_mac_sec.add((pan, mac["mac_security"]))
            # mezcla de seguridad MAC en el mismo PAN
            if (pan, True) in self._seen_mac_sec and (pan, False) in self._seen_mac_sec:
                self._seen_mac_sec.discard((pan, False))
                alerts.append(self._alert(
                    "warn", "MEZCLA DE SEGURIDAD MAC",
                    f"PAN 0x{pan:04X}: hay data frames con y sin seguridad MAC — "
                    "mala configuración o posible inyección"))

        got = parse_6lowpan_udp(mac["payload"])
        if not got:
            return alerts
        self.stats["lowpan"] += 1
        sport, dport, udp_payload = got
        src = mac["src"]
        src_s = f"0x{src:04X}" if isinstance(src, int) and src < 0x10000 else \
                (f"{src:016X}" if isinstance(src, int) else "?")

        if sport == UDP_PORT_COAPS or dport == UDP_PORT_COAPS:
            self.stats["coaps"] += 1
            if self._commissioning_alerts < 3:       # no spamear
                self._commissioning_alerts += 1
                alerts.append(self._alert(
                    "critical", "VENTANA DE COMISIONADO ABIERTA",
                    f"DTLS/CoAP en UDP 5684 desde {src_s} — un joiner está "
                    "recibiendo la network key cifrada con KEK(PSKd). Si el PSKd "
                    "es débil (etiqueta del dispositivo), el handshake capturado "
                    "es crackeable offline y la network key cae con él"))
        elif sport == UDP_PORT_MLE or dport == UDP_PORT_MLE:
            self.stats["mle"] += 1
            alerts += self._mle(udp_payload, mac, src_s)
        else:
            self.stats["other_udp"] += 1
        return alerts

    def _mle(self, mle: bytes, mac: dict, src_s: str):
        alerts = []
        if len(mle) < 2:
            return alerts
        suite = mle[0]
        if suite == 0xFF:                            # sin seguridad MLE: comando en claro
            cmd = mle[1]
            name = MLE_COMMANDS.get(cmd, f"cmd 0x{cmd:02X}")
            if cmd in MLE_UNSECURED_OK:
                alerts.append(self._alert(
                    "info", f"MLE {name}",
                    f"{src_s} — descubrimiento Thread normal (sin seguridad MLE "
                    "por diseño)"))
            else:
                alerts.append(self._alert(
                    "critical", "MLE SENSIBLE EN CLARO",
                    f"{src_s} envió MLE {name} SIN seguridad MLE (suite 0xFF) — "
                    "este comando debería ir cifrado; la red acepta mensajes de "
                    "control sin autenticar"))
        elif suite == 0x00 and not mac["mac_security"]:
            alerts.append(self._alert(
                "warn", "MLE CON SEGURIDAD DEGRADADA",
                f"{src_s}: suite 0x00 (delega en 802.15.4) pero el frame MAC "
                "no lleva aux security header — confidencialidad nula"))
        return alerts


# ----------------------------------------------------------------------------
# CLI forense sobre un raw log de catnip (una trama hex por línea)
# ----------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(
        prog="skyrf.playbooks.thread_watcher",
        description="Watcher Thread pasivo sobre un raw log 802.15.4 de catnip")
    ap.add_argument("raw", help="archivo con una trama 802.15.4 en hex por línea")
    args = ap.parse_args(argv)

    w = ThreadWatcher()

    def show(a):
        icon = {"critical": "[★ CRIT]", "warn": "[! WARN]", "info": "[i]"}[a["level"]]
        print(f"{icon} {a['title']}\n        {a['detail']}")

    w.on_alert = show
    n = 0
    with open(args.raw, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                frame = bytes.fromhex(line)
            except ValueError:
                continue
            n += 1
            w.feed(frame)
    s = w.stats
    print(f"\n[*] {n} tramas · {s['lowpan']} 6LoWPAN/UDP · {s['mle']} MLE · "
          f"{s['coaps']} CoAPS(comisionado) · {s['other_udp']} otros UDP")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
