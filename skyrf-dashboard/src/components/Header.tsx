import { Play, Pause, RotateCcw, Cable } from 'lucide-react';
import type { Protocol } from '@/lib/rf/core';
import type { WsStatus } from '@/lib/rf/engine';
import { SniffingCat } from '@/components/SniffingCat';

interface Props {
  running: boolean;
  wsStatus: WsStatus;
  filter: Protocol | 'all';
  onFilter: (f: Protocol | 'all') => void;
  onToggle: () => void;
  onReset: () => void;
  onBridgeInfo: () => void;
}

const FILTERS: Array<{ id: Protocol | 'all'; label: string }> = [
  { id: 'all', label: 'TODOS' },
  { id: 'zigbee', label: 'ZIGBEE' },
  { id: 'ble', label: 'BLE' },
  { id: 'thread', label: 'THREAD' },
  { id: 'lora', label: 'LORA' },
];

const WS_CHIP: Record<WsStatus, { label: string; dot: string; text: string }> = {
  offline: { label: 'BRIDGE OFFLINE', dot: 'bg-muted-foreground', text: 'text-muted-foreground' },
  connecting: { label: 'CONECTANDO…', dot: 'bg-[#fbbf24] pulse-dot', text: 'text-[#fbbf24]' },
  live: { label: 'CATSNIFFER LIVE', dot: 'bg-primary pulse-dot', text: 'text-primary' },
};

function RadarLogo() {
  return (
    <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true">
      {/* orejas de gata Sky */}
      <path d="M9 7 L12 2 L14 8 Z" fill="#00e5ff" opacity="0.9" />
      <path d="M23 7 L20 2 L18 8 Z" fill="#00e5ff" opacity="0.9" />
      {/* anillos de radar */}
      <circle cx="16" cy="17" r="12" fill="none" stroke="#1a2540" strokeWidth="1" />
      <circle cx="16" cy="17" r="8" fill="none" stroke="#1a2540" strokeWidth="1" />
      <circle cx="16" cy="17" r="4" fill="none" stroke="#1a2540" strokeWidth="1" />
      {/* barrido */}
      <g className="radar-sweep">
        <path d="M16 17 L16 5 A12 12 0 0 1 24.5 10.5 Z" fill="#00e5ff" opacity="0.35" />
        <line x1="16" y1="17" x2="16" y2="5" stroke="#00e5ff" strokeWidth="1.2" />
      </g>
      {/* blips */}
      <circle cx="21" cy="14" r="1.3" fill="#00e5ff" />
      <circle cx="12" cy="22" r="1" fill="#00e5ff" opacity="0.6" />
    </svg>
  );
}

export function Header({ running, wsStatus, filter, onFilter, onToggle, onReset, onBridgeInfo }: Props) {
  const chip = WS_CHIP[wsStatus];
  return (
    <header className="flex items-center gap-4 h-14 px-4 border-b border-border bg-card/60 backdrop-blur-sm sticky top-0 z-40">
      <div className="flex items-center gap-3 min-w-0">
        <RadarLogo />
        <div className="leading-none">
          <div className="font-display font-bold text-lg tracking-tight text-foreground">
            Sky<span className="text-primary">RF</span>
          </div>
          <div className="label-caps mt-0.5">RF intelligence</div>
        </div>
        {/* Sky olfatea el espectro mientras la captura corre */}
        <SniffingCat active={running} />
      </div>

      <button
        onClick={onBridgeInfo}
        className={`flex items-center gap-1.5 px-2.5 h-7 rounded border border-border bg-secondary/50 cursor-pointer
          hover:border-primary/50 transition-colors duration-150
          focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary`}
        title="Estado del bridge al CatSniffer"
      >
        <span className={`w-1.5 h-1.5 rounded-full ${chip.dot}`} />
        <span className={`text-[11px] tracking-[0.15em] font-medium ${chip.text}`}>
          {chip.label}
        </span>
      </button>

      <div className="hidden md:flex items-center gap-1 ml-2">
        {FILTERS.map(f => (
          <button
            key={f.id}
            onClick={() => onFilter(f.id)}
            className={`h-7 px-2.5 rounded text-[10px] tracking-[0.15em] font-medium border transition-colors duration-150 cursor-pointer
              focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary
              ${filter === f.id
                ? 'border-primary/60 bg-primary/10 text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'}`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-2 ml-auto">
        <button
          onClick={onBridgeInfo}
          className="hidden sm:flex items-center gap-2 h-8 px-3 rounded border border-border text-[11px] tracking-wider text-muted-foreground
            hover:text-foreground hover:border-primary/50 transition-colors duration-150 cursor-pointer
            focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
        >
          <Cable size={13} className="text-primary" />
          BRIDGE
        </button>

        <button
          onClick={onReset}
          title="Reiniciar captura"
          className="flex items-center justify-center w-8 h-8 rounded border border-border text-muted-foreground
            hover:text-foreground hover:border-primary/50 transition-colors duration-150 cursor-pointer
            focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
        >
          <RotateCcw size={14} />
        </button>

        <button
          onClick={onToggle}
          className={`flex items-center gap-2 h-8 px-4 rounded text-[11px] font-semibold tracking-[0.15em] transition-colors duration-150 cursor-pointer
            focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary
            ${running
              ? 'border border-warn/60 text-[#fbbf24] hover:bg-warn/10'
              : 'bg-primary text-primary-foreground hover:bg-primary/90'}`}
        >
          {running ? <Pause size={13} /> : <Play size={13} />}
          {running ? 'PAUSAR' : 'CAPTURAR'}
        </button>
      </div>
    </header>
  );
}
