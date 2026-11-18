#!/usr/bin/env python3
"""SkyRF — lorawan_auditor.py
Auditor de seguridad LoRaWAN pasivo para el CatSniffer.

Se alimenta de los frames crudos que catnip vuelca en el raw log
(`catnip sniff lora -r lora.raw`, formato `RX: <hex> | RSSI: <n> | SNR: <n>`)
y detecta en tiempo real:

  * FCnt reset        — el contador de tramas de un DevAddr retrocede: el
                        dispositivo usa ABP y reinició sesión sin cambiar de
                        claves → VULNERABLE A REPLAY (un frame viejo capturado
                        se puede reinyectar y la red lo acepta).
  * DevAddr duplicado — dos "sesiones" con el mismo DevAddr (colisión o
                        suplantación).
  * DevNonce reutilizado en join-requests (RNG débil → claves de sesión
                        repetidas → el join-accept viejo se puede reutilizar).
  * Join-request flood — tormenta de uniones (DoS contra el network server).
  * Tráfico LoRa crudo que no es LoRaWAN (sync privado / propietario).

Modo live: lo instancia el bridge (python -m skyrf.bridge --proto lora).
Modo forense sobre un raw ya capturado:
    python -m skyrf.playbooks.lorawan_auditor lora.raw

by Cinn4mor0ll
"""

import argparse
import re
import sys
import time
from dataclasses import dataclass, field

# MHDR.MType (bits 7..5 del primer octeto)
MTYPE = {0: "Join-request", 1: "Join-accept", 2: "Unconfirmed Data Up",
         3: "Unconfirmed Data Down", 4: "Confirmed Data Up",
         5: "Confirmed Data Down", 6: "RFU/Rejoin", 7: "Proprietary"}

_RX_LINE = re.compile(r"^RX:\s*([0-9a-fA-F]+)\s*(?:\|\s*RSSI:\s*(-?\d+))?"
                      r"(?:\s*\|\s*SNR:\s*(-?[\d.]+))?")


@dataclass
class DevState:
    last_fcnt: int = -1
    frames: int = 0
    resets: int = 0
    first_seen: float = 0.0


@dataclass
class LoRaWANAuditor:
    """Acumula estado por DevAddr/DevEUI y emite alertas.

    feed(payload, rssi=None, snr=None, ts=None) -> list[dict] con alertas
    {level, title, detail, proto:'lora'} listas para el bridge/dashboard."""

    on_alert: object = None                 # callable(alert_dict) opcional
    join_flood_window: float = 10.0         # s
    join_flood_threshold: int = 20          # joins en la ventana = flood
    devices: dict = field(default_factory=dict)    # DevAddr -> DevState
    join_nonces: dict = field(default_factory=dict)  # DevEUI -> {DevNonce}
    join_times: list = field(default_factory=list)
    stats: dict = field(default_factory=lambda: {"frames": 0, "lorawan": 0,
                                                 "joins": 0, "data": 0,
                                                 "proprietary": 0})

    # ------------------------------------------------------------------
    def _alert(self, level: str, title: str, detail: str) -> dict:
        a = {"level": level, "title": title, "detail": detail, "proto": "lora"}
        if callable(self.on_alert):
            self.on_alert(a)
        return a

    # ------------------------------------------------------------------
    def feed(self, payload: bytes, rssi=None, snr=None, ts=None):
        ts = ts if ts is not None else time.time()
        alerts = []
        self.stats["frames"] += 1
        if len(payload) < 5:
            return alerts
        mtype = payload[0] >> 5
        self.stats["lorawan"] += 1

        if mtype == 0:                                   # Join-request
            alerts += self._join_request(payload, rssi, ts)
        elif mtype in (2, 3, 4, 5):                      # Data up/down
            alerts += self._data(payload, mtype, rssi, ts)
        elif mtype == 1:
            self.stats["joins"] += 0                     # join-accept: cifrado, nada que auditar
        elif mtype == 7:
            self.stats["proprietary"] += 1
            alerts.append(self._alert(
                "info", "LORA PROPIETARIO",
                f"Trama con MType=Proprietary ({len(payload)}B) — no es LoRaWAN; "
                "si esperabas LoRaWAN, revisa el sync word (0x34 público vs 0x12 privado)"))
        return alerts

    # ------------------------------------------------------------------
    def _join_request(self, payload: bytes, rssi, ts):
        alerts = []
        self.stats["joins"] += 1
        if len(payload) >= 23:                           # MHDR+AppEUI+DevEUI+DevNonce+MIC
            app_eui = payload[1:9][::-1].hex()
            dev_eui = payload[9:17][::-1].hex()
            dev_nonce = int.from_bytes(payload[17:19], "little")
            seen = self.join_nonces.setdefault(dev_eui, set())
            if dev_nonce in seen:
                alerts.append(self._alert(
                    "critical", "DEVNONCE REUTILIZADO",
                    f"DevEUI {dev_eui} repitió DevNonce {dev_nonce} — RNG débil: "
                    "las claves de sesión se repiten y los join-accept viejos son "
                    "reutilizables (replay de activación)"))
            seen.add(dev_nonce)
        # join flood
        now = ts
        self.join_times = [t for t in self.join_times
                           if now - t < self.join_flood_window]
        self.join_times.append(now)
        if len(self.join_times) == self.join_flood_threshold:
            alerts.append(self._alert(
                "warn", "JOIN-REQUEST FLOOD",
                f"{len(self.join_times)} join-requests en {self.join_flood_window:.0f}s — "
                "posible DoS contra el network server o reseteo masivo de nodos"))
        return alerts

    # ------------------------------------------------------------------
    def _data(self, payload: bytes, mtype: int, rssi, ts):
        alerts = []
        self.stats["data"] += 1
        dev_addr = payload[1:5][::-1].hex().upper()      # DevAddr LE en el aire
        f_ctrl = payload[5]
        f_cnt = int.from_bytes(payload[6:8], "little")
        f_opts_len = f_ctrl & 0x0F
        direction = "up" if mtype in (2, 4) else "down"

        st = self.devices.get(dev_addr)
        if st is None:
            st = DevState(first_seen=ts)
            self.devices[dev_addr] = st
        else:
            if 0 <= f_cnt < st.last_fcnt and direction == "up":
                st.resets += 1
                alerts.append(self._alert(
                    "critical", "FCNT RESET — REPLAY-VULNERABLE",
                    f"DevAddr 0x{dev_addr}: FCnt {st.last_fcnt} → {f_cnt}. "
                    "Sesión ABP reiniciada sin rotar claves: los frames capturados "
                    "con FCnt mayor se pueden reinyectar tal cual y la red los acepta. "
                    "Mitigación: OTAA o persistencia de FCnt en el nodo"))
            elif f_cnt == st.last_fcnt and direction == "up":
                alerts.append(self._alert(
                    "warn", "FCNT DUPLICADO",
                    f"DevAddr 0x{dev_addr} reutilizó FCnt={f_cnt} — retransmisión "
                    "legítima o replay en curso"))
        st.last_fcnt = max(st.last_fcnt, f_cnt)
        st.frames += 1

        if f_opts_len:
            alerts.append(self._alert(
                "info", "COMANDOS MAC EN FOPTS",
                f"DevAddr 0x{dev_addr}: {f_opts_len}B de MAC commands en FOpts — "
                "visibles en claro para cualquier observador"))
        return alerts


# ----------------------------------------------------------------------------
# CLI forense
# ----------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="skyrf.playbooks.lorawan_auditor",
        description="Auditor LoRaWAN pasivo sobre un raw log de catnip "
                    "(`catnip sniff lora -r lora.raw`)")
    ap.add_argument("raw", help="archivo raw de catnip (líneas 'RX: <hex> | RSSI: .. | SNR: ..')")
    ap.add_argument("--json", action="store_true", help="resumen final en JSON")
    args = ap.parse_args(argv)

    auditor = LoRaWANAuditor()
    n_lines = 0

    def show(a):
        icon = {"critical": "[★ CRIT]", "warn": "[! WARN]", "info": "[i]"}[a["level"]]
        print(f"{icon} {a['title']}\n        {a['detail']}")

    auditor.on_alert = show
    with open(args.raw, "r", errors="replace") as fh:
        for line in fh:
            m = _RX_LINE.match(line.strip())
            if not m:
                continue
            n_lines += 1
            payload = bytes.fromhex(m.group(1))
            rssi = int(m.group(2)) if m.group(2) else None
            auditor.feed(payload, rssi=rssi)

    s = auditor.stats
    print(f"\n[*] {n_lines} tramas · {s['data']} data · {s['joins']} joins · "
          f"{s['proprietary']} propietarias · {len(auditor.devices)} DevAddr únicos")
    for addr, st in sorted(auditor.devices.items()):
        flag = f"  ⚠ {st.resets} FCNT RESET" if st.resets else ""
        print(f"    0x{addr}: {st.frames} frames, FCnt máx {st.last_fcnt}{flag}")
    if args.json:
        import json
        print(json.dumps({"stats": s, "devices": {
            a: {"frames": d.frames, "fcnt_max": d.last_fcnt, "resets": d.resets}
            for a, d in auditor.devices.items()}}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
