import type { Snapshot } from '@/lib/rf/engine';

function Stat({ label, value, accent = false, sub }: {
  label: string; value: string; accent?: boolean; sub?: string;
}) {
  return (
    <div className="flex flex-col justify-center px-4 py-2 border-r border-border last:border-r-0 min-w-0">
      <span className="label-caps">{label}</span>
      <div className="flex items-baseline gap-2">
        <span className={`text-xl font-semibold tabular-nums ${accent ? 'text-primary' : 'text-foreground'}`}>
          {value}
        </span>
        {sub && <span className="text-[10px] text-muted-foreground tracking-wider">{sub}</span>}
      </div>
    </div>
  );
}

export function StatsBar({ snap }: { snap: Snapshot }) {
  const mm = String(Math.floor(snap.elapsed / 60)).padStart(2, '0');
  const ss = String(Math.floor(snap.elapsed % 60)).padStart(2, '0');
  const crits = snap.alerts.filter(a => a.level === 'critical').length;

  return (
    <div className="panel grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 divide-x-0 overflow-hidden">
      <Stat label="Paquetes/s" value={String(snap.pps)} accent />
      <Stat label="Dispositivos" value={String(snap.devices.length)} />
      <Stat label="Redes PAN" value={String(snap.networksFound)} />
      <Stat
        label="Alertas"
        value={String(snap.alerts.length)}
        sub={crits > 0 ? `${crits} CRÍTICAS` : undefined}
      />
      <Stat
        label="Network key"
        value={snap.keyCaptured ? 'EXTRAÍDA' : '—'}
        accent={!!snap.keyCaptured}
      />
      <Stat label="Uptime" value={`${mm}:${ss}`} />
    </div>
  );
}
