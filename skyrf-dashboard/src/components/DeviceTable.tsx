import type { Device } from '@/lib/rf/engine';
import type { Protocol } from '@/lib/rf/core';

const PROTO_STYLE: Record<Protocol, string> = {
  zigbee: 'text-[#00e5ff] border-[#00e5ff]/40 bg-[#00e5ff]/10',
  ble: 'text-[#7dd3fc] border-[#7dd3fc]/40 bg-[#7dd3fc]/10',
  thread: 'text-[#e879f9] border-[#e879f9]/40 bg-[#e879f9]/10',
  lora: 'text-[#34d399] border-[#34d399]/40 bg-[#34d399]/10',
};

function Sparkline({ data }: { data: number[] }) {
  if (data.length < 2) return <div className="w-20 h-5" />;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) =>
    `${(i / (data.length - 1)) * 80},${20 - (v / max) * 18}`).join(' ');
  return (
    <svg width="80" height="20" aria-hidden="true">
      <polyline points={pts} fill="none" stroke="#00e5ff" strokeWidth="1" opacity="0.85" />
    </svg>
  );
}

function fmtAgo(t: number, now: number) {
  const d = Math.max(0, now - t);
  return d < 1 ? 'ahora' : `${Math.floor(d)}s`;
}

interface Props {
  devices: Device[];
  elapsed: number;
  filter: Protocol | 'all';
  onSelect: (d: Device) => void;
}

export function DeviceTable({ devices, elapsed, filter, onSelect }: Props) {
  const rows = devices.filter(d =>
    filter === 'all' || (d.cls?.label ?? null) === filter);

  return (
    <div className="panel overflow-hidden flex flex-col min-h-0">
      <div className="panel-header">
        <span className="label-caps">Dispositivos detectados</span>
        <span className="text-[10px] text-muted-foreground tracking-wider">
          {rows.length} NODOS · CLASIFICACIÓN POR METADATA
        </span>
      </div>
      <div className="overflow-auto">
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left border-b border-border">
              {['', 'Dirección', 'Nodo', 'Protocolo', 'Conf.', 'RSSI', 'Canal', 'Pkts/s', 'Visto'].map(h => (
                <th key={h} className="label-caps font-medium px-3 py-2 whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map(d => {
              const conf = d.cls ? Math.round(d.cls.confidence * 100) : null;
              const proto = d.cls?.label;
              const pps = d.ppsHistory[d.ppsHistory.length - 1] ?? 0;
              return (
                <tr
                  key={d.id}
                  onClick={() => onSelect(d)}
                  onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(d); } }}
                  tabIndex={0}
                  className="border-b border-border/50 cursor-pointer transition-colors duration-150
                    hover:bg-secondary/60 focus-visible:outline-none focus-visible:bg-secondary/80"
                >
                  <td className="px-3 py-2">
                    <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#34d399]" />
                  </td>
                  <td className="px-3 py-2 font-medium tabular-nums whitespace-nowrap">{d.id}</td>
                  <td className="px-3 py-2 whitespace-nowrap text-muted-foreground">Nodo 802.15.4</td>
                  <td className="px-3 py-2">
                    {proto ? (
                      <span className={`inline-block px-1.5 py-0.5 rounded border text-[10px] font-semibold tracking-[0.12em] uppercase ${PROTO_STYLE[proto]}`}>
                        {proto}
                      </span>
                    ) : (
                      <span className="inline-block px-1.5 py-0.5 rounded border border-border text-[10px] tracking-[0.12em] text-muted-foreground">
                        …
                      </span>
                    )}
                  </td>
                  <td className={`px-3 py-2 tabular-nums ${conf !== null && conf < 70 ? 'text-[#fbbf24]' : 'text-foreground'}`}>
                    {conf !== null ? `${conf}%` : '—'}
                  </td>
                  <td className="px-3 py-2 tabular-nums text-muted-foreground whitespace-nowrap">
                    {d.rssi !== null ? `${Math.round(d.rssi)} dBm` : '—'}
                  </td>
                  <td className="px-3 py-2 tabular-nums">{d.channel || '—'}</td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <span className="tabular-nums w-6 text-right">{pps}</span>
                      <Sparkline data={d.ppsHistory} />
                    </div>
                  </td>
                  <td className="px-3 py-2 text-muted-foreground tabular-nums">{fmtAgo(d.lastSeen, elapsed)}</td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={9} className="px-3 py-10 text-center text-muted-foreground">
                  Esperando tráfico del CatSniffer — inicia la captura con el bridge conectado
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
