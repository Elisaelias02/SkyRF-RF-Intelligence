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

def _emit_packet(frame: bytes, channel: int, rssi: int | None, watcher) -> None:
    try:
        mac = parse_mac(frame)
    except ValueError:
        src, dst = "", ""
    else:
        src, dst = f"0x{mac['src']:04X}", f"0x{mac['dst']:04X}"
    broadcast({
        "type": "packet", "t": time.time(), "len": len(frame),
        "channel": channel, "rssi": rssi, "src": src, "dst": dst,
        "frameType": "data",
    })
    watcher.feed(frame)


def follow_hex_file(path: str, channel: int, watcher) -> None:
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
                    _emit_packet(bytes.fromhex(line), channel, None, watcher)
                except ValueError:
                    pass  # línea incompleta o no-hex: se ignora
        else:
            time.sleep(0.1)


def follow_pcap_file(path: str, channel: int, watcher) -> None:
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
            _emit_packet(bytes(pkt), channel, None, watcher)
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
    ap.add_argument("--channel", type=int, required=True,
                    help="canal de captura (Zigbee 11-26)")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()

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

    watcher = TransportKeyWatcher(on_key_captured=on_key)

    print(f"""
  SkyRF bridge v{__version__} — ws://{args.host}:{args.port}
  Fuente: {args.raw_follow or args.pcap_follow}  (canal {args.channel})
  transport-key-watcher: ACTIVO (TC link key por defecto)
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
    t = threading.Thread(target=target, args=(path, args.channel, watcher),
                         daemon=True)
    t.start()

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
