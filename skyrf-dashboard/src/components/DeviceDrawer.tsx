import { useEffect } from 'react';
import type { Device } from '@/lib/rf/engine';
import { PROTOCOLS, extractWindow, type Protocol } from '@/lib/rf/core';

const PROTO_COLOR: Record<Protocol, string> = {
  zigbee: '#00e5ff', ble: '#7dd3fc', thread: '#e879f9', lora: '#34d399',
};

// Log-distance calibrado a -59 dBm @1 m (convención iBeacon, n=2.5)
function estDistance(rssi: number): string {
  const d = Math.min(60, Math.max(0.3, Math.pow(10, (-59 - rssi) / 25)));
  return d < 10 ? `≈${d.toFixed(1)} m` : `≈${Math.round(d)} m`;
}

interface Props {
  device: Device | null;
  onClose: () => void;
}

export function DeviceDrawer({ device, onClose }: Props) {
  useEffect(() => {
    if (!device) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    globalThis.addEventListener('keydown', onKey);
    return () => globalThis.removeEventListener('keydown', onKey);
  }, [device, onClose]);

  if (!device) return null;

  const win = device.pkts.slice(-12);
  const winS = win.length >= 2 ? Math.max(win[win.length - 1].t - win[0].t, 1) : 5;
  const feats = win.length >= 4 ? extractWindow(
    win.map(p => ({
      t: p.t, len: p.len, proto: device.proto ?? ('zigbee' as Protocol),
      channel: p.channel,
      src: device.id, frameType: p.frameType as 'data' | 'beacon' | 'ack' | 'command',
    })), winS) : null;

  // Si el bridge etiquetó el protocolo (él sabe qué está sniffando), es la
  // verdad: ese protocolo al 100%. Si no, barras del clasificador por metadata.
  const probs: Record<Protocol, number> | null = device.proto
    ? { zigbee: 0, ble: 0, thread: 0, lora: 0, [device.proto]: 1 }
    : device.cls?.probs ?? null;

  const FEATURE_LABELS: Array<{ key: string; fmt: (v: number) => string }> = [
    { key: 'paquetes (ventana)', fmt: v => String(Math.round(v)) },
    { key: 'len media', fmt: v => `${v.toFixed(1)} B` },
    { key: 'IAT media', fmt: v => `${(v * 1000).toFixed(1)} ms` },
    { key: 'burst ratio', fmt: v => `${(v * 100).toFixed(0)}%` },
    { key: 'duty cycle', fmt: v => `${(v * 100).toFixed(2)}%` },
  ];
  const featVals = feats ? [feats[0], feats[1], feats[5], feats[9], feats[13]] : null;

  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label={`Detalle de ${device.id}`}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-[2px]" onClick={onClose} />
      <aside className="absolute right-0 top-0 bottom-0 w-full max-w-sm bg-card border-l border-border flex flex-col">
        <div className="panel-header h-12">
          <div className="min-w-0">
            <div className="text-[13px] font-semibold truncate">
              {device.dev ? <span className="text-[#00e5ff]">{device.dev}</span> : `Nodo ${device.id}`}
            </div>
            <div className="text-[10px] text-muted-foreground">
              {device.dev ? `${device.id} · ` : ''}canal {device.channel}{device.addrType ? ` · MAC ${device.addrType}` : ''} · RF
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Cerrar detalle"
            className="flex items-center justify-center w-8 h-8 rounded border border-border text-muted-foreground
              hover:text-foreground hover:border-primary/50 transition-colors duration-150 cursor-pointer
              focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
          >
            ✕
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4 space-y-5">
          {device.proto === 'ble' && (
            <section>
              <h3 className="label-caps mb-2">Auditoría de exposición</h3>
              <div className="rounded-md border border-border/60 bg-secondary/30 p-3 space-y-2">
                <div className="flex items-center gap-2">
                  <span className={`inline-block px-2 py-0.5 rounded border text-[10px] font-semibold tracking-[0.12em] uppercase ${
                    device.exposure === 'alto' ? 'text-[#f87171] border-[#f87171]/40 bg-[#f87171]/10'
                    : device.exposure === 'medio' ? 'text-[#fbbf24] border-[#fbbf24]/40 bg-[#fbbf24]/10'
                    : 'text-[#34d399] border-[#34d399]/40 bg-[#34d399]/10'
                  }`}>
                    {device.exposure ?? 'bajo'}
                  </span>
                  {device.addrType && (
                    <span className="text-[10px] text-muted-foreground">
                      MAC {device.addrType}{device.addrType === 'pública' ? ' · trackeable' : ' · rota periódicamente'}
                    </span>
                  )}
                  {device.rssi !== null && (
                    <span className="text-[10px] text-[#00e5ff]/80 ml-auto tabular-nums">
                      {estDistance(device.rssi)} · {Math.round(device.rssi)} dBm
                    </span>
                  )}
                </div>
                {device.expWhy && device.expWhy.length > 0 ? (
                  <ul className="space-y-1">
                    {device.expWhy.map((w, i) => (
                      <li key={i} className="text-[11px] text-foreground/85 leading-snug">· {w}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-[10px] text-muted-foreground leading-snug">
                    Sin datos identificativos en sus anuncios — buena higiene de privacidad.
                  </p>
                )}
              </div>
            </section>
          )}

          <section>
            <h3 className="label-caps mb-2">Clasificación por protocolo</h3>
            <div className="space-y-1.5">
              {PROTOCOLS.map(p => {
                const v = probs?.[p] ?? 0;
                return (
                  <div key={p} className="flex items-center gap-2">
                    <span className="w-14 text-[10px] tracking-[0.12em] uppercase text-muted-foreground">{p}</span>
                    <div className="flex-1 h-3 rounded-sm bg-secondary overflow-hidden">
                      <div
                        className="h-full rounded-sm transition-[width] duration-200"
                        style={{ width: `${v * 100}%`, background: PROTO_COLOR[p] }}
                      />
                    </div>
                    <span className="w-11 text-right text-[11px] tabular-nums">
                      {(v * 100).toFixed(0)}%
                    </span>
                  </div>
                );
              })}
            </div>
            <p className="text-[10px] text-muted-foreground mt-2 leading-snug">
              {device.proto
                ? `Protocolo confirmado por el bridge — la captura activa es ${device.proto.toUpperCase()}.`
                : 'Clasificación por metadata de capa MAC — sin descifrar payloads.'}
            </p>
          </section>

          <section>
            <h3 className="label-caps mb-2">Features de la ventana</h3>
            <div className="grid grid-cols-2 gap-px bg-border rounded overflow-hidden">
              {FEATURE_LABELS.map((f, i) => (
                <div key={f.key} className="bg-secondary/40 px-3 py-2">
                  <div className="text-[9px] tracking-[0.15em] uppercase text-muted-foreground">{f.key}</div>
                  <div className="text-[13px] font-semibold tabular-nums mt-0.5">
                    {featVals ? f.fmt(featVals[i]) : '—'}
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section>
            <h3 className="label-caps mb-2">Radio</h3>
            <div className="space-y-1 text-[12px]">
              <div className="flex justify-between"><span className="text-muted-foreground">RSSI</span><span className="tabular-nums">{device.rssi !== null ? `${Math.round(device.rssi)} dBm` : '—'}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">Canal</span><span className="tabular-nums">{device.channel}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">Paquetes en buffer</span><span className="tabular-nums">{device.pkts.length}</span></div>
            </div>
          </section>
        </div>
      </aside>
    </div>
  );
}
