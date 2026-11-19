"""SkyRF Bridge — puente CatSniffer → dashboard (WebSocket local).

El dashboard web se conecta a ws://localhost:8765 y recibe paquetes y
alertas en tiempo real. El bridge:

1. Sigue la captura que catnip/Wireshark escribe a disco (--raw / pcapng).
2. Parsea cada frame y lo reenvía como evento JSON al dashboard.
3. Corre los watchers de seguridad en línea según el protocolo:
   - zigbee  → transport-key-watcher (network keys) + thread-watcher
               (MLE / ventana de comisionado Thread; mismo PHY 802.15.4)
   - lora/fsk → lorawan-auditor (FCnt reset, DevNonce reutilizado, floods)
   - ble     → visibilidad de advertising; el crackeo de pairing es offline
               (skyrf.playbooks.ble_legacy sobre el pcap de Sniffle)

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
import re
import struct
import sys
import time

import websockets

from skyrf import __version__
from skyrf.playbooks.frames import parse_mac
from skyrf.playbooks.transport_key_watcher import TransportKeyWatcher
from skyrf.playbooks.thread_watcher import ThreadWatcher
from skyrf.playbooks.lorawan_auditor import LoRaWANAuditor

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


# Estado de la fuente actual (lo fija main()); se anuncia en el hello para que
# el dashboard sepa qué captura está viva y qué protocolo se está sniffando.
CURRENT_SOURCE: str | None = None
CURRENT_PROTO: str = "zigbee"
PLAYBOOK_RUNNING = False


async def handler(ws) -> None:
    CLIENTS.add(ws)
    await ws.send(json.dumps({
        "type": "hello", "tool": "skyrf-bridge", "version": __version__,
        "source": CURRENT_SOURCE, "proto": CURRENT_PROTO,
        "attack": attack_status(),
    }))
    try:
        async for raw in ws:
            try:
                await handle_command(ws, raw)
            except Exception as e:
                await ws.send(json.dumps({
                    "type": "playbook_done", "id": None, "playbook": None,
                    "ok": False, "code": -1, "error": str(e),
                }))
    finally:
        CLIENTS.discard(ws)


# ------------------------- ejecución de playbooks ---------------------------
# El dashboard manda {"type":"run_playbook","id":...,"playbook":...,"pcap":...}
# y el bridge ejecuta el módulo correspondiente streameando su salida línea a
# línea. Lista blanca cerrada: solo estos dos módulos, sin shell de por medio.

PLAYBOOKS = {
    "ble_legacy": "skyrf.playbooks.ble_legacy",
    "selftest": "skyrf.playbooks.selftest",
}


async def handle_command(ws, raw: str) -> None:
    global PLAYBOOK_RUNNING
    try:
        msg = json.loads(raw)
    except ValueError:
        return
    mtype = msg.get("type")
    req_id = msg.get("id")
    if mtype == "victim_mode":
        await victim_mode(ws, req_id, bool(msg.get("start")))
        return
    if mtype == "capture_control":
        await capture_control(ws, req_id, msg)
        return
    if mtype != "run_playbook":
        return

    name = str(msg.get("playbook") or "")
    if name not in PLAYBOOKS:
        await ws.send(json.dumps({
            "type": "playbook_done", "id": req_id, "playbook": name,
            "ok": False, "code": -1, "error": f"playbook desconocido: {name}",
        }))
        return
    if PLAYBOOK_RUNNING:
        await ws.send(json.dumps({
            "type": "playbook_out", "id": req_id,
            "line": "[!] Ya hay un playbook en ejecución — espera a que termine.",
        }))
        await ws.send(json.dumps({
            "type": "playbook_done", "id": req_id, "playbook": name,
            "ok": False, "code": -1,
        }))
        return

    argv = [sys.executable, "-m", PLAYBOOKS[name]]
    if name == "ble_legacy":
        target = msg.get("pcap") or CURRENT_SOURCE
        if (not target or not isinstance(target, str)
                or not target.endswith((".pcap", ".pcapng"))
                or not os.path.isfile(target)):
            await ws.send(json.dumps({
                "type": "playbook_out", "id": req_id,
                "line": f"[✗] Captura no válida o inexistente: {target}",
            }))
            await ws.send(json.dumps({
                "type": "playbook_done", "id": req_id, "playbook": name,
                "ok": False, "code": -1,
            }))
            return
        out = target.rsplit(".", 1)[0] + "_descifrado.pcapng"
        argv += [target, "-o", out]

    PLAYBOOK_RUNNING = True
    await ws.send(json.dumps({
        "type": "playbook_started", "id": req_id, "playbook": name,
        "cmd": "python " + " ".join(argv[1:]),
    }))
    print(f"  » playbook {name} lanzado desde el dashboard")
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        assert proc.stdout is not None
        async for chunk in proc.stdout:
            for line in chunk.decode(errors="replace").splitlines():
                print(f"  │ {line}")
                await ws.send(json.dumps({
                    "type": "playbook_out", "id": req_id, "line": line,
                }))
        rc = await proc.wait()
    finally:
        PLAYBOOK_RUNNING = False
    await ws.send(json.dumps({
        "type": "playbook_done", "id": req_id, "playbook": name,
        "ok": rc == 0, "code": rc,
    }))
    print(f"  » playbook {name} terminó (rc={rc})")


# --------------------------- orquestación de ataque --------------------------
# El dashboard también puede gobernar la cadena completa del PoC BLE Legacy:
#   1. victim_mode  → prepara la Kali como víctima (Legacy Pairing forzado)
#   2. capture_control → arranca/para tshark+Sniffle escribiendo el pcap
#   3. run_playbook ble_legacy → crackea el pairing sobre ese pcap
#
# Blindaje: sin shell intermedio para tshark (argv fijo, parámetros validados
# con regex); los scripts de víctima son fijos y usan `sudo -n`, así que si no
# existe la regla NOPASSWD (ver README §4) fallan limpio, sin prompt colgado.

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_SERPORT_RE = re.compile(r"^/dev/ttyACM\d+$")
_OUTFILE_RE = re.compile(r"^/[A-Za-z0-9_\-/\.]+\.pcapng$")

CAPTURE_PROC: asyncio.subprocess.Process | None = None
CAPTURE_OUT: str | None = None
VICTIM_ACTIVE = False
VICTIM_ADDR: str | None = None

# Scripts fijos (sin parámetros del usuario -> nada que inyectar).
# ON:  apaga el adaptador, desactiva Secure Connections (fuerza Legacy
#      Pairing), lo enciende y lo deja emparejable/descubierto con un agente
#      capaz de mostrar passkey.
# OFF: deshace todo y devuelve el adaptador a Secure Connections.
VICTIM_ON_SCRIPT = (
    "sudo -n btmgmt power off && sudo -n btmgmt sc off && sudo -n btmgmt power on"
    " && printf 'power on\\npairable on\\ndiscoverable on\\n"
    "agent KeyboardOnly\\nadvertise on\\nquit\\n' | bluetoothctl"
)
VICTIM_OFF_SCRIPT = (
    "printf 'advertise off\\nquit\\n' | bluetoothctl;"
    " sudo -n btmgmt power off && sudo -n btmgmt sc on && sudo -n btmgmt power on"
)


def attack_status() -> dict:
    return {
        "type": "attack_status",
        "capture": CAPTURE_PROC is not None and CAPTURE_PROC.returncode is None,
        "captureOut": CAPTURE_OUT,
        "victim": VICTIM_ACTIVE,
        "victimAddr": VICTIM_ADDR,
    }


async def _stream_lines(ws, req_id, proc, tag: str) -> int:
    """Reenvía stdout de un proceso al dashboard como eventos attack_out."""
    assert proc.stdout is not None
    async for chunk in proc.stdout:
        for line in chunk.decode(errors="replace").splitlines():
            print(f"  │[{tag}] {line}")
            await ws.send(json.dumps(
                {"type": "attack_out", "id": req_id, "tag": tag, "line": line}))
    return await proc.wait()


async def _run_script(ws, req_id, script: str, tag: str) -> int:
    proc = await asyncio.create_subprocess_exec(
        "bash", "-c", script,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    return await _stream_lines(ws, req_id, proc, tag)


async def _broadcast_status() -> None:
    data = json.dumps(attack_status())
    await _send_all(data)


async def victim_mode(ws, req_id, start: bool) -> None:
    """Activa/desactiva la Kali como víctima BLE emparejable en modo Legacy."""
    global VICTIM_ACTIVE, VICTIM_ADDR
    tag = "victim"
    await ws.send(json.dumps({
        "type": "attack_out", "id": req_id, "tag": tag,
        "line": ("[»] Activando modo víctima: Secure Connections OFF, "
                 "Kali emparejable y visible…" if start else
                 "[»] Desactivando modo víctima: restaurando Secure Connections…"),
    }))
    try:
        rc = await _run_script(
            ws, req_id, VICTIM_ON_SCRIPT if start else VICTIM_OFF_SCRIPT, tag)
    except FileNotFoundError as e:
        await ws.send(json.dumps({
            "type": "attack_out", "id": req_id, "tag": tag,
            "line": f"[✗] Falta una herramienta del sistema: {e}",
        }))
        await ws.send(json.dumps({
            "type": "attack_done", "id": req_id, "action": "victim_mode",
            "ok": False, "code": -1,
        }))
        return

    ok = rc == 0
    if ok and start:
        addr = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "bash", "-c", "hcitool dev | awk 'NR>1{print $2; exit}'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL)
            assert proc.stdout is not None
            out, _ = await proc.communicate()
            cand = out.decode(errors="replace").strip()
            if _MAC_RE.match(cand):
                addr = cand.upper()
        except Exception:
            pass
        VICTIM_ACTIVE = True
        VICTIM_ADDR = addr
        await ws.send(json.dumps({
            "type": "attack_out", "id": req_id, "tag": tag,
            "line": (f"[★] Kali en modo víctima — BD_ADDR {addr}. Empareja el "
                     "teléfono contra esta dirección." if addr else
                     "[★] Kali en modo víctima (no pude leer el BD_ADDR, "
                     "míralo con `hcitool dev`)."),
        }))
    elif ok:
        VICTIM_ACTIVE = False
        VICTIM_ADDR = None
        await ws.send(json.dumps({
            "type": "attack_out", "id": req_id, "tag": tag,
            "line": "[✓] Modo víctima desactivado, adaptador restaurado.",
        }))
    else:
        await ws.send(json.dumps({
            "type": "attack_out", "id": req_id, "tag": tag,
            "line": ("[✗] Falló (¿regla sudoers NOPASSWD para btmgmt/"
                     "bluetoothctl/hcitool instalada? ver README §4)."),
        }))
    await ws.send(json.dumps({
        "type": "attack_done", "id": req_id, "action": "victim_mode",
        "ok": ok, "code": rc,
    }))
    await _broadcast_status()


async def capture_control(ws, req_id, msg: dict) -> None:
    """Arranca o detiene tshark+Sniffle escribiendo el pcap del ataque."""
    global CAPTURE_PROC, CAPTURE_OUT
    tag = "capture"
    action = str(msg.get("action") or "")

    if action == "stop":
        if CAPTURE_PROC is None or CAPTURE_PROC.returncode is not None:
            await ws.send(json.dumps({
                "type": "attack_out", "id": req_id, "tag": tag,
                "line": "[i] No hay captura en curso.",
            }))
            await ws.send(json.dumps({
                "type": "attack_done", "id": req_id,
                "action": "capture_stop", "ok": False, "code": -1,
            }))
            return
        CAPTURE_PROC.terminate()
        try:
            await asyncio.wait_for(CAPTURE_PROC.wait(), timeout=5)
        except asyncio.TimeoutError:
            CAPTURE_PROC.kill()
            await CAPTURE_PROC.wait()
        await ws.send(json.dumps({
            "type": "attack_out", "id": req_id, "tag": tag,
            "line": f"[✓] Captura detenida — pcap listo en {CAPTURE_OUT}. "
                    "Ya puedes lanzar BLE LEGACY CRACK.",
        }))
        CAPTURE_PROC = None
        await ws.send(json.dumps({
            "type": "attack_done", "id": req_id,
            "action": "capture_stop", "ok": True, "code": 0,
        }))
        await _broadcast_status()
        return

    if action != "start":
        return

    if CAPTURE_PROC is not None and CAPTURE_PROC.returncode is None:
        await ws.send(json.dumps({
            "type": "attack_out", "id": req_id, "tag": tag,
            "line": "[!] Ya hay una captura en curso — deténla primero.",
        }))
        await ws.send(json.dumps({
            "type": "attack_done", "id": req_id,
            "action": "capture_start", "ok": False, "code": -1,
        }))
        return

    serport = str(msg.get("serport") or "/dev/ttyACM0")
    mac = str(msg.get("mac") or "").strip().upper()
    out = str(msg.get("outfile") or "").strip() or (
        CURRENT_SOURCE if CURRENT_SOURCE and CURRENT_SOURCE.endswith(".pcapng")
        else "/tmp/skyrf_ataque.pcapng")

    if not _SERPORT_RE.match(serport):
        await ws.send(json.dumps({
            "type": "attack_out", "id": req_id, "tag": tag,
            "line": f"[✗] Puerto serie inválido: {serport}",
        }))
        await ws.send(json.dumps({
            "type": "attack_done", "id": req_id,
            "action": "capture_start", "ok": False, "code": -1,
        }))
        return
    if mac and not _MAC_RE.match(mac):
        await ws.send(json.dumps({
            "type": "attack_out", "id": req_id, "tag": tag,
            "line": f"[✗] MAC inválida: {mac}",
        }))
        await ws.send(json.dumps({
            "type": "attack_done", "id": req_id,
            "action": "capture_start", "ok": False, "code": -1,
        }))
        return
    if (not _OUTFILE_RE.match(out)
            or not (out.startswith("/home/") or out.startswith("/tmp/"))):
        await ws.send(json.dumps({
            "type": "attack_out", "id": req_id, "tag": tag,
            "line": f"[✗] Ruta de salida inválida (debe ser /home/... o /tmp/... .pcapng): {out}",
        }))
        await ws.send(json.dumps({
            "type": "attack_done", "id": req_id,
            "action": "capture_start", "ok": False, "code": -1,
        }))
        return

    argv = ["tshark", "-i", "sniffle",
            "-o", f"extcap.sniffle.serport:{serport}"]
    if mac:
        argv += ["-o", f"extcap.sniffle.mac:{mac}"]
    argv += ["-w", out]

    await ws.send(json.dumps({
        "type": "attack_out", "id": req_id, "tag": tag,
        "line": "[»] Arrancando captura: " + " ".join(argv),
    }))
    try:
        CAPTURE_PROC = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
    except FileNotFoundError:
        CAPTURE_PROC = None
        await ws.send(json.dumps({
            "type": "attack_out", "id": req_id, "tag": tag,
            "line": "[✗] tshark no está instalado o no está en el PATH.",
        }))
        await ws.send(json.dumps({
            "type": "attack_done", "id": req_id,
            "action": "capture_start", "ok": False, "code": -1,
        }))
        return

    CAPTURE_OUT = out
    asyncio.ensure_future(_capture_watchdog(CAPTURE_PROC))
    await ws.send(json.dumps({
        "type": "attack_done", "id": req_id,
        "action": "capture_start", "ok": True, "code": 0,
    }))
    await _broadcast_status()


async def _capture_watchdog(proc) -> None:
    """Espera a que tshark muera solo (error, puerto ocupado, etc.) y avisa."""
    global CAPTURE_PROC
    assert proc.stdout is not None
    async for chunk in proc.stdout:
        for line in chunk.decode(errors="replace").splitlines():
            print(f"  │[capture] {line}")
            broadcast({"type": "attack_out", "id": None,
                       "tag": "capture", "line": line})
    rc = await proc.wait()
    if CAPTURE_PROC is proc:
        CAPTURE_PROC = None
        broadcast({"type": "attack_out", "id": None, "tag": "capture",
                   "line": f"[i] tshark terminó por su cuenta (rc={rc})."})
        data = json.dumps(attack_status())
        await _send_all(data)


# ----------------------------- fuentes de captura ----------------------------

# Access address de advertising (0x8E89BED6) tal como aparece en el pcap de
# Sniffle: uint32 little-endian -> bytes d6 be 89 8e (ojo: no el valor "de spec").
BLE_ADV_AA = bytes.fromhex("d6be898e")

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

    Tolera tres formatos de volcado:
    - PDU pelón (header + payload)
    - con access address (0x8E89BED6) al inicio
    - pcap DLT_BLUETOOTH_LE_LL_WITH_PHDR (pseudo-header de 10B antes del AA)

    Devuelve {len, src, frameType} o None si no es un ADV PDU reconocible.
    """
    b = bytes(frame)
    # Localización determinista del AA: el PHDR también lleva el AA de
    # referencia (offset 4), así que NO se puede buscar la secuencia a ciegas.
    if len(b) >= 14 + 8 and b[10:14] == BLE_ADV_AA:
        b = b[14:]                         # pcap DLT 256: PHDR(10B) + AA + PDU + CRC
    elif len(b) >= 4 + 8 and b[:4] == BLE_ADV_AA:
        b = b[4:]                          # DLT 251 / volcado crudo: AA + PDU
    else:
        return None                        # data channel u otro AA: fuera
    if len(b) < 8:
        return None
    pdu_len = b[1] & 0x3F                  # header byte 1: length (6 bits)
    payload = b[2:2 + pdu_len]
    if len(payload) < 6 or pdu_len > 37:   # ADV payload máx BLE 4.x = 37 B
        return None
    adva = payload[:6]                     # AdvA: BD_ADDR little-endian al aire
    src = ":".join(f"{x:02X}" for x in reversed(adva))
    return {
        "len": 2 + pdu_len,
        "src": src,
        "frameType": _BLE_PDU_FRAME_TYPE.get(b[0] & 0x0F, "data"),
    }


def parse_lora_frame(payload: bytes) -> dict | None:
    """Best-effort LoRaWAN: MHDR(1B) + DevAddr(4B, little-endian al aire).

    Identifica al nodo por su DevAddr; frames no-LoRaWAN dan una etiqueta
    de todos modos (la metadata es lo que alimenta al clasificador).
    """
    if len(payload) < 5:
        return None
    return {"src": "0x" + payload[1:5][::-1].hex().upper(), "len": len(payload)}


def _emit_packet(frame: bytes, channel: int, rssi: int | None, consumers,
                 proto: str = "zigbee") -> None:
    if proto == "ble":
        adv = parse_ble_adv(frame)
        if adv is None:
            return                         # no-ADV (data channels) o basura: fuera
        src, dst, frame_type, plen = adv["src"], "", adv["frameType"], adv["len"]
        # RSSI real: vive en el PHDR del pcap (byte 1, con signo) si no vino ya
        if rssi is None and len(frame) >= 14 and frame[10:14] == BLE_ADV_AA:
            rssi = struct.unpack_from("<b", frame, 1)[0]
    elif proto in ("lora", "fsk"):
        node = parse_lora_frame(frame)
        if node is None:
            return
        src, dst, frame_type, plen = node["src"], "", "data", node["len"]
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
        "frameType": frame_type, "proto": proto,
    })
    for consume in consumers:              # watchers de seguridad del protocolo
        try:
            consume(frame, rssi)
        except Exception:
            pass                           # un frame raro no puede tumbar el bridge


# catnip v3.3+ escribe lora/fsk raw como:  RX: <hex> | RSSI: <rssi> | SNR: <snr>
_RX_LINE = re.compile(
    r"^RX:\s*([0-9a-fA-F]+)\s*(?:\|\s*RSSI:\s*(-?\d+))?"
)


def follow_hex_file(path: str, channel: int, consumers,
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
                m = _RX_LINE.match(line)   # formato lora/fsk de catnip v3.3+
                try:
                    if m:
                        rssi = int(m.group(2)) if m.group(2) else None
                        _emit_packet(bytes.fromhex(m.group(1)), channel, rssi,
                                     consumers, proto=proto)
                    else:
                        _emit_packet(bytes.fromhex(line), channel, None,
                                     consumers, proto=proto)
                except ValueError:
                    pass  # línea incompleta o no-hex: se ignora
        else:
            time.sleep(0.1)


def follow_pcap_file(path: str, channel: int, consumers,
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
            _emit_packet(bytes(pkt), channel, None, consumers, proto=proto)
        time.sleep(0.3)


def main() -> int:
    global LOOP, CURRENT_SOURCE, CURRENT_PROTO
    ap = argparse.ArgumentParser(prog="skyrf bridge",
                                 description="Puente CatSniffer → dashboard SkyRF")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--raw-follow", metavar="ARCHIVO",
                     help="sigue un volcado hex de catnip (--raw)")
    src.add_argument("--pcap-follow", metavar="ARCHIVO",
                     help="sigue un pcap/pcapng de Wireshark/catnip")
    ap.add_argument("--proto", choices=["zigbee", "ble", "lora", "fsk"],
                    default="zigbee",
                    help="protocolo del volcado (zigbee cubre 802.15.4: "
                         "Zigbee y Thread; ble = advertising 37-39, vía pcap "
                         "de Sniffle; lora/fsk = raw hex de catnip)")
    ap.add_argument("--channel", type=int, default=None,
                    help="canal de captura (Zigbee/Thread 11-26; BLE: 37 por "
                         "defecto, etiqueta de los canales de advertising; "
                         "lora/fsk: 0 = sub-GHz, sin columna en el waterfall)")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()
    if args.channel is None:
        args.channel = {"zigbee": 15, "ble": 37}.get(args.proto, 0)

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

    def on_watch_alert(a: dict) -> None:
        broadcast({"type": "alert", "level": a["level"],
                   "title": a["title"], "detail": a["detail"]})
        icon = {"critical": "⚡", "warn": "⚠", "info": "·"}.get(a["level"], "·")
        print(f"  {icon} [{a['proto']}] {a['title']}: {a['detail']}")

    # watchers por protocolo — cada uno expone feed(frame, rssi=None, ...)
    consumers = []
    watcher_lines = []
    if args.proto == "zigbee":
        tkw = TransportKeyWatcher(on_key_captured=on_key)
        consumers.append(lambda f, rssi=None: tkw.feed(f))
        watcher_lines.append("transport-key-watcher: ACTIVO (TC link key por defecto)")
        tw = ThreadWatcher(on_alert=on_watch_alert)
        consumers.append(lambda f, rssi=None: tw.feed(f, rssi=rssi))
        watcher_lines.append("thread-watcher: ACTIVO (MLE/19788 · comisionado/5684)")
    elif args.proto in ("lora", "fsk"):
        lw = LoRaWANAuditor(on_alert=on_watch_alert)
        consumers.append(lambda f, rssi=None: lw.feed(f, rssi=rssi))
        watcher_lines.append("lorawan-auditor: ACTIVO (FCnt reset · DevNonce · floods)")
    else:
        watcher_lines.append("watchers: N/A en BLE — pairing se crackea offline "
                             "(skyrf.playbooks.ble_legacy <pcap>)")

    print(f"""
  SkyRF bridge v{__version__} — ws://{args.host}:{args.port}
  Fuente: {args.raw_follow or args.pcap_follow}  ({args.proto}, canal {args.channel})
  {chr(10).join(watcher_lines)}
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
    CURRENT_SOURCE, CURRENT_PROTO = path, args.proto
    t = threading.Thread(target=target,
                         args=(path, args.channel, consumers, args.proto),
                         daemon=True)
    t.start()

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
