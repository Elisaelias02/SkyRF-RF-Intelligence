"""SkyRF playbook: ble_audit — auditoría pasiva de privacidad BLE.

Lee un pcap/pcapng del CatSniffer (Sniffle, DLT 256), agrega por AdvA y
genera un REPORTE DE AUDITORÍA en Markdown: resumen ejecutivo, hallazgos,
inventario de dispositivos con nivel de exposición, metodología y
recomendaciones. 100% pasivo: en ningún momento se conecta a nada.

    python -m skyrf.playbooks.ble_audit captura.pcapng -o reporte.md

by Cinn4mor0ll
"""

import argparse
import struct
import sys
import time
from dataclasses import dataclass, field

from skyrf.playbooks.ble_legacy import read_capture

BLE_ADV_AA = bytes.fromhex("d6be898e")

# Company IDs (Bluetooth SIG) — los más vistos en la vida real
_COMPANY = {
    0x004C: "Apple", 0x0006: "Microsoft", 0x00E0: "Google",
    0x0075: "Samsung", 0x012D: "Sony", 0x000D: "Texas Instruments",
    0x0059: "Nordic Semi", 0x000A: "CSR", 0x000F: "Broadcom",
    0x0002: "Intel", 0x0087: "Garmin",
}

_APPLE_CONTINUITY = {
    0x02: "iBeacon", 0x05: "AirDrop", 0x07: "AirPods", 0x09: "AirPlay",
    0x0C: "Handoff", 0x10: "Nearby (iPhone/Mac)", 0x12: "Find My (¿AirTag?)",
}

_SERVICES = {
    0xFEED: "Tile (rastreador)", 0xFE2C: "Google Fast Pair",
    0xFE95: "Xiaomi Mi", 0xFEAA: "Eddystone beacon",
    0xFD6F: "Exposure Notification", 0x180D: "Sensor cardíaco",
    0x1812: "HID (teclado/mouse)", 0xFE9F: "Google (Cast/Nest)",
    0xFEB2: "Microsoft Swift Pair",
}

_TRACKY = {0xFEED, 0xFE2C, 0xFEB2}


def _parse_ad(data: bytes) -> dict:
    out = {"name": None, "company": None, "company_id": None,
           "apple_type": None, "services": [], "txpower": None}
    i = 0
    while i + 2 <= len(data):
        ln = data[i]
        if ln == 0 or i + 1 + ln > len(data):
            break
        t, val = data[i + 1], data[i + 2: i + 1 + ln]
        if t in (0x08, 0x09) and val:
            name = val.decode("utf-8", errors="replace").strip("\x00").strip()
            if name:
                out["name"] = name
        elif t == 0xFF and len(val) >= 2:
            cid = val[0] | (val[1] << 8)
            out["company_id"] = cid
            out["company"] = _COMPANY.get(cid, f"0x{cid:04X}")
            if cid == 0x004C and len(val) >= 3:
                out["apple_type"] = val[2]
        elif t in (0x02, 0x03):
            out["services"] += [val[j] | (val[j + 1] << 8)
                                for j in range(0, len(val) - 1, 2)]
        elif t == 0x0A and val:
            out["txpower"] = int.from_bytes(val[:1], "big", signed=True)
        i += 1 + ln
    return out


def _identity(ad: dict) -> str | None:
    if ad["name"]:
        return ad["name"]
    if ad["company_id"] == 0x004C and ad["apple_type"] is not None:
        return "Apple · " + _APPLE_CONTINUITY.get(
            ad["apple_type"], f"Continuity 0x{ad['apple_type']:02X}")
    for u in ad["services"]:
        if u in _SERVICES:
            return _SERVICES[u]
    return ad["company"]


@dataclass
class Dev:
    addr: str
    addr_type: str = "pública"
    name: str | None = None
    company: str | None = None
    apple_type: int | None = None
    services: set = field(default_factory=set)
    txpower: int | None = None
    rssi: list = field(default_factory=list)
    pkts: int = 0
    first: float = 0.0
    last: float = 0.0
    channels: set = field(default_factory=set)

    def identity(self) -> str:
        ad = {"name": self.name, "company": self.company,
              "company_id": 0x004C if self.company == "Apple" else None,
              "apple_type": self.apple_type, "services": list(self.services)}
        return _identity(ad) or "—"

    def exposure(self) -> tuple[str, list[str]]:
        pts, why = 0, []
        if self.name:
            pts += 2
            why.append(f'nombre en claro: "{self.name}"')
        if self.addr_type == "pública":
            pts += 2
            why.append("MAC pública (fija, trackeable a largo plazo)")
        if self.apple_type == 0x12:
            pts += 3
            why.append("Find My: posible AirTag / rastreador Apple")
        tr = [u for u in self.services if u in _TRACKY]
        if tr:
            pts += 1
            why.append(f"servicio rastreable: {_SERVICES[tr[0]]}")
        level = "alto" if pts >= 3 else "medio" if pts >= 2 else "bajo"
        return level, why

    def rssi_avg(self) -> float | None:
        return sum(self.rssi) / len(self.rssi) if self.rssi else None

    def distance(self) -> float | None:
        """Log-distance calibrado a -59 dBm @1 m (convención iBeacon, n=2.5)."""
        ra = self.rssi_avg()
        if ra is None:
            return None
        return max(0.3, min(60.0, 10 ** ((-59.0 - ra) / 25.0)))


def _parse_frame(frame: bytes):
    """Devuelve (adva, addr_type, ad_dict, rssi, channel) o None."""
    b = bytes(frame)
    rssi = None
    if len(b) >= 14 + 8 and b[10:14] == BLE_ADV_AA:
        rssi = struct.unpack_from("<b", b, 1)[0]
        b = b[14:]
    elif len(b) >= 4 + 8 and b[:4] == BLE_ADV_AA:
        b = b[4:]
    else:
        return None
    if len(b) < 8:
        return None
    pdu_len = b[1] & 0x3F
    payload = b[2:2 + pdu_len]
    if len(payload) < 6 or pdu_len > 37:
        return None
    pdu_type = b[0] & 0x0F
    if pdu_type not in (0x00, 0x02, 0x04, 0x06):
        return None
    adva = ":".join(f"{x:02X}" for x in reversed(payload[:6]))
    addr_type = "aleatoria" if (b[0] & 0x40) else "pública"
    ad = _parse_ad(payload[6:]) if len(payload) > 6 else _parse_ad(b"")
    return adva, addr_type, ad, rssi


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="skyrf.playbooks.ble_audit",
        description="Auditoría pasiva de privacidad BLE → reporte Markdown")
    ap.add_argument("pcap", help="captura pcap/pcapng del Sniffle")
    ap.add_argument("-o", "--out", help="salida .md (default: <pcap>_auditoria.md)")
    args = ap.parse_args(argv)

    out_path = args.out or args.pcap.rsplit(".", 1)[0] + "_auditoria.md"

    print("  SkyRF · auditoría pasiva de privacidad BLE · by Cinn4mor0ll")
    print()
    try:
        pkts = read_capture(args.pcap)
    except (ValueError, OSError) as e:
        print(f" [✗] {e}")
        return 2
    print(f" [*] {len(pkts)} paquetes leídos de {args.pcap}")

    devs: dict[str, Dev] = {}
    for p in pkts:
        r = _parse_frame(p.data)
        if r is None:
            continue
        adva, addr_type, ad, rssi = r
        d = devs.get(adva)
        if d is None:
            d = Dev(addr=adva, first=p.ts)
            devs[adva] = d
        d.pkts += 1
        d.last = p.ts
        d.addr_type = addr_type
        if ad["name"]:
            d.name = ad["name"]
        if ad["company"]:
            d.company = ad["company"]
        if ad["apple_type"] is not None:
            d.apple_type = ad["apple_type"]
        d.services.update(ad["services"])
        if ad["txpower"] is not None:
            d.txpower = ad["txpower"]
        if rssi is not None:
            d.rssi.append(rssi)

    print(f" [*] {len(devs)} dispositivos únicos por AdvA")

    # ---------- métricas agregadas ----------
    levels = {"alto": [], "medio": [], "bajo": []}
    named, public, findmy, tracky = [], [], [], []
    for d in devs.values():
        lv, _why = d.exposure()
        levels[lv].append(d)
        if d.name:
            named.append(d)
        if d.addr_type == "pública":
            public.append(d)
        if d.apple_type == 0x12:
            findmy.append(d)
        if any(u in _TRACKY for u in d.services):
            tracky.append(d)

    dur = 0.0
    ts_all = [p.ts for p in pkts if p.ts]
    if ts_all:
        dur = max(ts_all) - min(ts_all)

    for lv in ("alto", "medio", "bajo"):
        print(f"     exposición {lv:5s}: {len(levels[lv])}")
    print()

    # ---------- reporte ----------
    L: list[str] = []
    L.append("# Auditoría de privacidad BLE — SkyRF")
    L.append("")
    L.append(f"**Fecha:** {time.strftime('%Y-%m-%d %H:%M')}  ")
    L.append(f"**Fuente:** `{args.pcap}` ({len(pkts)} paquetes, "
             f"{dur:.0f} s de captura)  ")
    L.append("**Alcance:** escucha 100% pasiva (canales de advertising 37–39); "
             "en ningún momento se estableció conexión con ningún dispositivo.  ")
    L.append("**by Cinn4mor0ll**")
    L.append("")
    L.append("## 1. Resumen ejecutivo")
    L.append("")
    L.append(f"- **{len(devs)} dispositivos únicos** detectados emitiendo por Bluetooth LE.")
    L.append(f"- Exposición **alta: {len(levels['alto'])}** · media: {len(levels['medio'])}"
             f" · baja: {len(levels['bajo'])}.")
    L.append(f"- **{len(named)}** anuncian su **nombre en claro** "
             f" y **{len(public)}** usan **MAC pública** (fija y correlacionable a largo plazo).")
    if findmy:
        L.append(f"- ⚠ **{len(findmy)}** emiten mensajes **Find My** de Apple: posibles "
                 "AirTag u objetos de la red de rastreo — verificar que no haya ninguno ajeno siguiéndonos.")
    if tracky:
        L.append(f"- **{len(tracky)}** anuncian servicios de rastreo por diseño (Tile / Fast Pair / Swift Pair).")
    L.append("")
    L.append("## 2. Hallazgos destacados")
    L.append("")
    for d in sorted(levels["alto"], key=lambda x: x.pkts, reverse=True)[:8]:
        _lv, why = d.exposure()
        L.append(f"- **{d.identity()}** (`{d.addr}`): " + "; ".join(why) + ".")
    if not levels["alto"]:
        L.append("- Ningún dispositivo con exposición alta en esta captura.")
    L.append("")
    L.append("## 3. Inventario de dispositivos")
    L.append("")
    L.append("| Dispositivo | MAC | Tipo MAC | Exposición | RSSI prom. | Distancia aprox. | Paquetes |")
    L.append("|---|---|---|---|---|---|---|")
    for d in sorted(devs.values(), key=lambda x: -x.pkts):
        lv, _ = d.exposure()
        ra = d.rssi_avg()
        dist = d.distance()
        L.append(f"| {d.identity()} | `{d.addr}` | {d.addr_type} | {lv.upper()} "
                 f"| {f'{ra:.0f} dBm' if ra is not None else '—'} "
                 f"| {f'≈{dist:.1f} m' if dist else '—'} | {d.pkts} |")
    L.append("")
    L.append("## 4. Metodología")
    L.append("")
    L.append("- **Captura:** CatSniffer V3 (CC1352) con firmware Sniffle en modo promiscuo; "
             "pcap DLT 256 (BLE LL + PHDR) vía `tshark -i sniffle`.")
    L.append("- **Identificación:** decodificación de AD structures (nombre 0x08/0x09, "
             "manufacturer 0xFF con company IDs del Bluetooth SIG, Apple Continuity, "
             "service UUIDs 0x02/0x03).")
    L.append("- **Tipo de dirección:** bit TxAdd del PDU header — pública = fija de fábrica "
             "(correlacionable entre lugares y días); aleatoria = rota periódicamente.")
    L.append("- **Distancia:** modelo log-distance `10^((−59 − RSSI)/25)`, calibrado a "
             "-59 dBm a 1 metro (convención iBeacon), n=2.5 (interior con obstáculos); "
             "precisión orientativa.")
    L.append("- **Nivel de exposición:** nombre en claro (+2), MAC pública (+2), "
             "Find My (+3), servicio rastreable (+1) → alto ≥3, medio ≥2.")
    L.append("")
    L.append("## 5. Recomendaciones")
    L.append("")
    L.append("1. Apagar el Bluetooth cuando no se use: es un balizado continuo de presencia.")
    L.append("2. Renombrar dispositivos con nombres no identificativos (evitar nombre real, "
             "modelo de coche, casa, etc.).")
    L.append("3. Preferir dispositivos que usen direcciones aleatorias rotativas y "
             "Secure Connections (LE Legacy Pairing es crackeable offline).")
    L.append("4. Auditar periódicamente si aparecen rastreadores (Find My/Tile) desconocidos "
             "moviéndose con nosotros.")
    L.append("5. Mantener firmware al día: los stacks BLE viejos acumulan CVEs de pairing.")
    L.append("")
    L.append("---")
    L.append("*Reporte generado por SkyRF · playbook ble_audit · by Cinn4mor0ll*")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print(f" [★] Reporte de auditoría escrito en: {out_path}")
    print(f"     {len(devs)} dispositivos · {len(levels['alto'])} de exposición ALTA · "
          f"{len(findmy)} Find My · {len(public)} MAC públicas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
