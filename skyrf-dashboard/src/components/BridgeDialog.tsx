import { useEffect, useState } from 'react';
import { X, Copy, Check, Terminal, Zap } from 'lucide-react';
import type { WsStatus } from '@/lib/rf/engine';

const SNIFF_CMD = 'catnip sniff zigbee --channel 15 -ff --raw lab.hex';
const BRIDGE_CMD = 'python -m skyrf.bridge --raw-follow lab.hex --channel 15';

const PLAYBOOKS = [
  { name: 'transport-key-watcher', desc: 'Captura la network key del Transport Key (TC link key por defecto)' },
  { name: 'zcl-injector', desc: 'Inyección ZCL OnOff spoofeando al coordinador' },
  { name: 'persistence', desc: 'Mgmt_Permit_Joining permanente vía ZDO 0x0036' },
];

export function BridgeDialog({ open, wsStatus, onClose }: {
  open: boolean;
  wsStatus: WsStatus;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    globalThis.addEventListener('keydown', onKey);
    return () => globalThis.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const copy = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(id);
      setTimeout(() => setCopied(null), 1500);
    } catch { /* portapapeles no disponible */ }
  };

  const statusLine =
    wsStatus === 'live' ? { text: 'BRIDGE CONECTADO · STREAM ACTIVO', cls: 'text-primary', dot: 'bg-primary pulse-dot' }
    : wsStatus === 'connecting' ? { text: 'CONECTANDO A ws://localhost:8765…', cls: 'text-[#fbbf24]', dot: 'bg-[#fbbf24] pulse-dot' }
    : { text: 'SIN BRIDGE · LANZA LOS COMANDOS DE ABAJO', cls: 'text-muted-foreground', dot: 'bg-muted-foreground' };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Bridge al CatSniffer">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-[2px]" onClick={onClose} />
      <div className="relative panel w-full max-w-md p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="font-display font-semibold text-base">Bridge · CatSniffer V3</h2>
            <p className="text-[11px] text-muted-foreground mt-1">SkyRF se alimenta del sniffer en vivo</p>
          </div>
          <button
            onClick={onClose}
            aria-label="Cerrar"
            className="flex items-center justify-center w-8 h-8 rounded border border-border text-muted-foreground
              hover:text-foreground hover:border-primary/50 transition-colors duration-150 cursor-pointer
              focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
          >
            <X size={14} />
          </button>
        </div>

        <div className="mt-4 border border-border rounded p-3">
          <div className="flex items-center gap-2">
            <span className={`w-1.5 h-1.5 rounded-full ${statusLine.dot}`} />
            <span className={`text-[11px] font-semibold tracking-[0.12em] ${statusLine.cls}`}>
              {statusLine.text}
            </span>
          </div>
        </div>

        <div className="mt-3 space-y-2">
          <div className="border border-border rounded p-3">
            <div className="flex items-center gap-2 mb-1.5">
              <Terminal size={12} className="text-primary" />
              <span className="text-[11px] font-semibold tracking-[0.12em]">1 · CAPTURA (catnip)</span>
            </div>
            <CmdLine id="sniff" cmd={SNIFF_CMD} copied={copied} onCopy={copy} />
          </div>

          <div className="border border-border rounded p-3">
            <div className="flex items-center gap-2 mb-1.5">
              <Terminal size={12} className="text-primary" />
              <span className="text-[11px] font-semibold tracking-[0.12em]">2 · BRIDGE (skyrf)</span>
            </div>
            <CmdLine id="bridge" cmd={BRIDGE_CMD} copied={copied} onCopy={copy} />
            <p className="text-[10.5px] text-muted-foreground mt-2 leading-snug">
              También acepta <code className="text-foreground">--pcap-follow captura.pcapng</code> si
              prefieres leer el pipe de Wireshark.
            </p>
          </div>

          <div className="border border-primary/30 bg-primary/5 rounded p-3">
            <div className="flex items-center gap-2 mb-1.5">
              <Zap size={12} className="text-primary" />
              <span className="text-[11px] font-semibold tracking-[0.12em] text-primary">PLAYBOOKS DE ATAQUE</span>
            </div>
            <ul className="space-y-1.5">
              {PLAYBOOKS.map(p => (
                <li key={p.name} className="text-[11px] leading-snug">
                  <code className="text-primary/90">{p.name}</code>
                  <span className="text-muted-foreground"> — {p.desc}</span>
                </li>
              ))}
            </ul>
            <p className="text-[10.5px] text-muted-foreground mt-2 leading-snug">
              El watcher corre dentro del bridge: al capturar la network key, el dashboard celebra contigo.
            </p>
          </div>
        </div>

        <p className="text-[10px] text-muted-foreground mt-4 tracking-wide">
          SkyRF · by Cinn4mor0ll
        </p>
      </div>
    </div>
  );
}

function CmdLine({ id, cmd, copied, onCopy }: {
  id: string;
  cmd: string;
  copied: string | null;
  onCopy: (id: string, text: string) => void;
}) {
  return (
    <div className="flex items-center gap-2 bg-background rounded border border-border px-2.5 py-1.5">
      <code className="flex-1 text-[10.5px] text-primary/90 truncate">{cmd}</code>
      <button
        onClick={() => onCopy(id, cmd)}
        aria-label="Copiar comando"
        className="text-muted-foreground hover:text-primary transition-colors duration-150 cursor-pointer
          focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary rounded"
      >
        {copied === id ? <Check size={13} className="text-[#34d399]" /> : <Copy size={13} />}
      </button>
    </div>
  );
}
