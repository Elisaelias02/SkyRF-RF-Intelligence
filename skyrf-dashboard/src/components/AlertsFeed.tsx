import type { Alert } from '@/lib/rf/engine';
import { ShieldAlert, TriangleAlert, Info } from 'lucide-react';

const LEVEL = {
  info: { icon: Info, color: 'text-[#7dd3fc]', bar: 'bg-[#7dd3fc]' },
  warn: { icon: TriangleAlert, color: 'text-[#fbbf24]', bar: 'bg-[#fbbf24]' },
  critical: { icon: ShieldAlert, color: 'text-[#f87171]', bar: 'bg-[#f87171]' },
} as const;

function fmt(t: number) {
  const mm = String(Math.floor(t / 60)).padStart(2, '0');
  const ss = String(Math.floor(t % 60)).padStart(2, '0');
  return `${mm}:${ss}`;
}

export function AlertsFeed({ alerts }: { alerts: Alert[] }) {
  return (
    <div className="panel overflow-hidden flex flex-col min-h-0 h-full">
      <div className="panel-header">
        <span className="label-caps">Eventos de seguridad</span>
        <span className="text-[10px] text-muted-foreground tracking-wider tabular-nums">
          {alerts.length}
        </span>
      </div>
      <div className="overflow-auto flex-1 p-2 space-y-1.5">
        {alerts.length === 0 && (
          <div className="border border-dashed border-border rounded p-6 text-center text-muted-foreground text-[11px] tracking-wider">
            Sin eventos — inicia la captura
          </div>
        )}
        {alerts.map(a => {
          const L = LEVEL[a.level];
          const Icon = L.icon;
          return (
            <div key={a.id} className="alert-in relative flex gap-2.5 pl-3 pr-2 py-2 rounded bg-secondary/40 overflow-hidden">
              <span className={`absolute left-0 top-0 bottom-0 w-[3px] ${L.bar}`} />
              <Icon size={14} className={`${L.color} mt-0.5 shrink-0`} />
              <div className="min-w-0">
                <div className="flex items-baseline gap-2">
                  <span className={`text-[10px] font-semibold tracking-[0.14em] ${L.color}`}>
                    {a.title}
                  </span>
                  <span className="text-[10px] text-muted-foreground tabular-nums shrink-0">
                    {fmt(a.t)}
                  </span>
                </div>
                <p className="text-[11px] text-muted-foreground leading-snug mt-0.5 break-words">
                  {a.detail}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
