"""Fuente PCAP: lee capturas reales de catnip / Kismet (PCAP-NG) con Scapy.

Los PCAP del CatSniffer llevan el encapsulado propietario (DLT 147 +
dissector catsniffer_rpi). Para la Fase 1 basta con extraer la metadata de
la capa 802.15.4 que Scapy ya entiende; la clasificación no toca payloads.
"""

from __future__ import annotations

from skyrf.capture.synthetic_source import Packet


def read_pcap(path: str) -> list[Packet]:
    """Lee un PCAP/PCAP-NG y devuelve Packets con metadata 802.15.4.

    TODO(fase-2): mapear frame types reales (beacon/data/ack/command) desde
    Dot15d4FCS; hoy se reporta todo como 'data' salvo beacon/ack evidentes.
    """
    from scapy.all import PcapReader  # import diferido: scapy es pesado
    from scapy.layers.dot15d4 import Dot15d4Beacon, Dot15d4Ack, Dot15d4Cmd

    packets: list[Packet] = []
    with PcapReader(path) as reader:
        for pkt in reader:
            dot15 = pkt.getlayer("Dot15d4FCS") or pkt.getlayer("Dot15d4")
            if dot15 is None:
                continue
            frame_type = "data"
            if Dot15d4Beacon in pkt:
                frame_type = "beacon"
            elif Dot15d4Ack in pkt:
                frame_type = "ack"
            elif Dot15d4Cmd in pkt:
                frame_type = "command"
            packets.append(Packet(
                timestamp=float(pkt.time),
                length=len(bytes(pkt)),
                protocol_hint="unknown",   # el clasificador lo decide
                frame_type=frame_type,
                src=str(getattr(dot15, "src_addr", "")),
                dst=str(getattr(dot15, "dest_addr", "")),
            ))
    return packets
