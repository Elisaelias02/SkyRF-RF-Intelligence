"""Extracción de features por ventana de tiempo.

Diseño deliberado: TODO se calcula de metadata (longitudes, tiempos, tipos de
frame, canales). Nada del payload. Si el clasificador funciona con esto sobre
tráfico cifrado real, RQ1 queda respondida.
"""

from __future__ import annotations

import math
from collections import Counter

from skyrf.capture.synthetic_source import Packet

FEATURE_NAMES = [
    "n_packets",
    "len_mean", "len_std", "len_min", "len_max",
    "iat_mean", "iat_std", "iat_min", "iat_max",
    "burst_ratio",        # fracción de paquetes con IAT < 10 ms (ráfagas)
    "beacon_ratio",
    "command_ratio",
    "channel_entropy",    # qué tan disperso está en canales
    "duty_cycle",         # airtime aproximado / duración de la ventana
]


def _entropy(counts: list[int]) -> float:
    total = sum(counts)
    if total == 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def extract_window(packets: list[Packet], window_s: float) -> list[float]:
    """Extrae el vector de features de una ventana de paquetes."""
    if len(packets) < 2:
        return [0.0] * len(FEATURE_NAMES)

    lens = [p.length for p in packets]
    iats = [b.timestamp - a.timestamp for a, b in zip(packets, packets[1:])]
    types = Counter(p.frame_type for p in packets)
    channels = Counter(p.channel for p in packets)

    n = len(packets)
    len_mean = sum(lens) / n
    len_std = math.sqrt(sum((x - len_mean) ** 2 for x in lens) / n)
    iat_mean = sum(iats) / len(iats)
    iat_std = math.sqrt(sum((x - iat_mean) ** 2 for x in iats) / len(iats))

    # airtime aproximado: ~len bytes * 32 us/byte (802.15.4 @250kbps) como proxy
    airtime = sum(lens) * 32e-6
    duty = min(airtime / max(window_s, 1e-6), 1.0)

    return [
        float(n),
        len_mean, len_std, float(min(lens)), float(max(lens)),
        iat_mean, iat_std, min(iats), max(iats),
        sum(1 for i in iats if i < 0.010) / len(iats),
        types.get("beacon", 0) / n,
        types.get("command", 0) / n,
        _entropy(list(channels.values())),
        duty,
    ]


def split_windows(stream: list[Packet], window_s: float = 5.0,
                  hop_s: float | None = None) -> list[list[Packet]]:
    """Divide un stream en ventanas deslizantes."""
    if not stream:
        return []
    hop_s = hop_s or window_s / 2
    t0, t_end = stream[0].timestamp, stream[-1].timestamp
    windows, start = [], t0
    while start + window_s <= t_end:
        w = [p for p in stream if start <= p.timestamp < start + window_s]
        if len(w) >= 2:
            windows.append(w)
        start += hop_s
    return windows
