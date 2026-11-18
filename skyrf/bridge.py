"""SkyRF Bridge — puente CatSniffer → dashboard (WebSocket local).

El dashboard web se conecta a ws://localhost:8765 y recibe paquetes y
alertas en tiempo real. El bridge:

1. Sigue la captura que catnip/Wireshark escribe a disco (--raw / pcapng).
2. Parsea cada frame 802.15.4 (MAC/NWK) y lo reenvía como evento JSON.
3. Corre el transport-key-watcher en línea: si cae una network key,
   emite alerta crítica + evento `key_captured`.

Uso:
    # catnip con volcado hex en paralelo (terminal 1):
    catnip sniff zigbee --channel 15 -ff -ws --raw lab.hex
    # bridge (terminal 2):
    python -m skyrf.bridge --raw-follow lab.hex --channel 15

    # o siguiendo un pcapng de Wireshark:
    python -m skyrf.bridge --pcap-follow captura.pcapng --channel 15

Notas honestas:
- El volcado --raw de catnip se asume como frames 802.15.4 en hex, uno por
  línea (formato documentado por Electronic Cats para herramientas externas).
  Si tu versión escribe binario, usa --pcap-follow (Wireshark guarda pcapng).
- RSSI real solo llega si la fuente lo incluye (pcap con radio metadata);
  sin él el dashboard muestra "—".
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import struct
import sys
import time

import websockets

from skyrf import __version__
from skyrf.playbooks.frames import parse_mac
from skyrf.playbooks.transport_key_watcher import TransportKeyWatcher

HOST, PORT = "127.0.0.1", 8765

CLIENTS: set = set()
LOOP: asyncio.AbstractEventLoop | None = None


def broadcast(msg: dict) -> None:
    if LOOP is None or not CLIENTS:
        return
    data = json.dumps(msg)
    LOOP.call_soon_threadsafe(lambda: asyncio.ensure_future(_send_all(data)))


async def _send_all(data: str) -> None:
    dead = []
    for ws in CLIENTS:
        try:
            await ws.send(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        CLIENTS.discard(ws)


async def handler(ws) -> None:
    CLIENTS.add(ws)
    await ws.send(json.dumps({
        "type": "hello", "tool": "skyrf-bridge", "version": __version__,
    }))
    try:
        async for _ in ws:  # el dashboard no envía comandos (Fase 3)
            pass
    finally:
        CLIENTS.discard(ws)


# ----------------------------- fuentes de captura ----------------------------

BLE_ADV_AA = bytes.fromhex("8e89bed6")  # access address de advertising (al aire, LSB first)

# PDU type (nibble bajo del primer byte del header) → tipo de frame para la UI
_BLE_PDU_FRAME_TYPE = {
    0x00: "beacon",   # ADV_IND
    0x01: "data",     # ADV_DIRECT_IND
    0x02: "beacon",   # ADV_NONCONN_IND
    0x03: "beacon",   # ADV_SCAN_IND
    0x04: "command",  # SCAN_REQ
    0x05: "data",     # SCAN_RSP
    0x06: "command",  # CONNECT_IND / AUX_CONNECT_REQ
}


def parse_ble_adv(frame: bytes) -> dict | None:
    """Parsea un PDU de advertising BLE (canales 37-39).

    Tolera volcados con o sin el access address (0x8E89BED6) al inicio.
    Devuelve {len, src, frameType} o None si no es un ADV PDU reconocible.
    """
    b = bytes(frame)
    i = b.find(BLE_ADV_AA)
    if 0 <= i <= 1:
        b = b[i + 4:]                      # volcado con AA: el PDU empieza después
    if len(b) < 8:
        return None
    pdu_len = b[1] & 0x3F                  # header byte 1: length (6 bits)
    payload = b[2:2 + pdu_len]
    if len(payload) < 6:
        return None
    adva = payload[:6]                     # AdvA: BD_ADDR little-endian al aire
    src = ":".join(f"{x:02X}" for x in reversed(adva))
    return {
        "len": 2 + pdu_len,
        "src": src,
        "frameType": _BLE_PDU_FRAME_TYPE.get(b[0] & 0x0F, "data"),
    }


def _emit_packet(frame: bytes, channel: int, rssi: int | None, watcher,
                 proto: str = "zigbee") -> None:
    if proto == "ble":
        adv = parse_ble_adv(frame)
        if adv is None:
            return                         # no-ADV (data channels) o basura: fuera
        src, dst, frame_type, plen = adv["src"], "", adv["frameType"], adv["len"]
    else:
        try:
            mac = parse_mac(frame)
        except ValueError:
            src, dst = "", ""
        else:
            src, dst = f"0x{mac['src']:04X}", f"0x{mac['dst']:04X}"
        frame_type, plen = "data", len(frame)
    broadcast({
        "type": "packet", "t": time.time(), "len": plen,
        "channel": channel, "rssi": rssi, "src": src, "dst": dst,
        "frameType": frame_type,
    })
    if watcher is not None:                # el watcher es Zigbee-only
        watcher.feed(frame)


def follow_hex_file(path: str, channel: int, watcher,
                    proto: str = "zigbee") -> None:
    """Sigue un archivo hex creciente (tail -f). Un frame por línea."""
    pos = 0
    buf = ""
    while True:
        try:
            with open(path, "r") as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()
        except FileNotFoundError:
            time.sleep(0.5); continue
        if chunk:
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    _emit_packet(bytes.fromhex(line), channel, None, watcher,
                                 proto=proto)
                except ValueError:
                    pass  # línea incompleta o no-hex: se ignora
        else:
            time.sleep(0.1)


def follow_pcap_file(path: str, channel: int, watcher,
                     proto: str = "zigbee") -> None:
    """Sigue un pcap/pcapng creciente (captura de Wireshark/catnip).

    Estrategia: re-lectura completa por polling, emitiendo solo los paquetes
    nuevos (índice > emitidos). Robusta ante escrituras parciales.
    """
    from scapy.all import PcapReader  # import diferido

    emitted = 0
    while True:
        try:
            with PcapReader(path) as reader:
                packets = list(reader)
        except FileNotFoundError:
            time.sleep(0.5); continue
        except Exception:
            time.sleep(0.3); continue  # archivo a medio escribir

        for pkt in packets[emitted:]:
            emitted += 1
            _emit_packet(bytes(pkt), channel, None, watcher, proto=proto)
        time.sleep(0.3)


def main() -> int:
    global LOOP
    ap = argparse.ArgumentParser(prog="skyrf bridge",
                                 description="Puente CatSniffer → dashboard SkyRF")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--raw-follow", metavar="ARCHIVO",
                     help="sigue un volcado hex de catnip (--raw)")
    src.add_argument("--pcap-follow", metavar="ARCHIVO",
                     help="sigue un pcap/pcapng de Wireshark/catnip")
    ap.add_argument("--proto", choices=["zigbee", "ble"], default="zigbee",
                    help="protocolo del volcado (zigbee cubre 802.15.4: "
                         "Zigbee y Thread; ble = advertising 37-39)")
    ap.add_argument("--channel", type=int, default=None,
                    help="canal de captura (Zigbee/Thread 11-26; BLE: 37 por "
                         "defecto, etiqueta de los canales de advertising)")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()
    if args.channel is None:
        args.channel = 37 if args.proto == "ble" else 15

    def on_key(net) -> None:
        broadcast({
            "type": "alert", "level": "critical",
            "title": "TRANSPORT KEY CAPTURADO",
            "detail": f"Network key extraída con TC link key por defecto · {net.summary()}",
        })
        broadcast({
            "type": "key_captured",
            "panId": f"0x{net.pan_id:04X}", "tcAddr": f"0x{net.src_tc:016X}",
            "networkKey": net.network_key.hex(),
        })
        print(f"\n  ⚡ NETWORK KEY: {net.network_key.hex()}  ({net.summary()})\n")

    watcher = TransportKeyWatcher(on_key_captured=on_key) \
        if args.proto == "zigbee" else None
    watcher_line = ("transport-key-watcher: ACTIVO (TC link key por defecto)"
                    if watcher else
                    "transport-key-watcher: N/A (BLE no usa Transport Key)")

    print(f"""
  SkyRF bridge v{__version__} — ws://{args.host}:{args.port}
  Fuente: {args.raw_follow or args.pcap_follow}  ({args.proto}, canal {args.channel})
  {watcher_line}
  Abre el dashboard y pulsa CAPTURAR. Ctrl+C para salir.
""")

    async def serve():
        global LOOP
        LOOP = asyncio.get_running_loop()
        async with websockets.serve(handler, args.host, args.port):
            await asyncio.Future()  # para siempre

    import threading
    target = (follow_hex_file if args.raw_follow else follow_pcap_file)
    path = args.raw_follow or args.pcap_follow
    t = threading.Thread(target=target,
                         args=(path, args.channel, watcher, args.proto),
                         daemon=True)
    t.start()

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
