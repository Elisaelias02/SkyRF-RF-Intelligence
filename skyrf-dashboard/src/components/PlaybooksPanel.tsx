import { useEffect, useRef } from 'react';
import { engine, type Snapshot } from '@/lib/rf/engine';
import { Cat, Play, Radar, ShieldCheck, SquareTerminal, Trash2, Zap } from 'lucide-react';

/**
 * PlaybooksPanel — ejecución de playbooks de ataque DESDE el dashboard.
 * El bridge (ws) recibe la orden, lanza el módulo Python correspondiente y
 * streamea su salida aquí línea a línea. Éxito → Sky da el puñito.
 */

interface PlaybookCard {
  id: 'ble_legacy' | 'selftest' | null;   // null = watcher automático
  name: string;
  desc: string;
  auto?: string;                          // nota para watchers en línea
}

const CARDS: PlaybookCard[] = [
  {
    id: 'ble_legacy',
    name: 'BLE LEGACY CRACK',
    desc: 'Fuerza bruta del TK de LE Legacy Pairing sobre la captura viva y descifrado AES-CCM de la conexión.',
  },
  {
    id: 'selftest',
    name: 'SELFTEST 8/8',
    desc: 'Verifica la cripto (c1/s1, crack round-trip) y los 4 watchers contra vectores oficiales.',
  },
  {
    id: null,
    name: 'TRANSPORT KEY WATCHER',
    desc: 'Extrae la network key Zigbee al unirse un dispositivo.',
    auto: 'AUTO · --proto zigbee',
  },
  {
    id: null,
    name: 'THREAD WATCHER',
    desc: 'MLE sensible en claro y ventanas de comisionado abiertas.',
    auto: 'AUTO · --proto zigbee',
  },
  {
    id: null,
    name: 'LORAWAN AUDITOR',
    desc: 'FCnt reset (replay), DevNonce reutilizado y floods de join.',
    auto: 'AUTO · --proto lora',
  },
];

export function PlaybooksPanel({ snap }: { snap: Snapshot }) {
  const logRef = useRef<HTMLDivElement>(null);
  const { running, log, lastOk } = snap.playbook;
  const live = snap.wsStatus === 'live';
  const fileName = snap.bridgeSource?.split('/').pop() ?? null;

  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [log.length]);

  return (
    <section className="panel overflow-hidden">
      <div className="panel-header">
        <span className="label-caps flex items-center gap-2">
          <Zap className="w-3.5 h-3.5 text-[#00e5ff]" />
          Playbooks de ataque
        </span>
        <span className="text-[10px] text-muted-foreground tracking-wider">
          {live
            ? `FUENTE: ${fileName ?? snap.bridgeSource} · ${(snap.bridgeProto ?? '').toUpperCase()}`
            : 'BRIDGE OFFLINE — los playbooks se ejecutan con el bridge vivo'}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-2 p-3">
        {CARDS.map(c => (
          <div
            key={c.name}
            className="rounded-md border border-border/70 bg-secondary/20 p-3 flex flex-col gap-2 min-h-[120px]"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] font-semibold tracking-[0.12em] text-foreground">
                {c.name}
              </span>
              {c.auto ? (
                <span className="text-[9px] px-1.5 py-0.5 rounded border border-[#34d399]/40 text-[#34d399] tracking-[0.12em] whitespace-nowrap">
                  {c.auto}
                </span>
              ) : (
                <Cat className="w-3.5 h-3.5 text-[#00e5ff]/70" />
              )}
            </div>
            <p className="text-[10px] leading-relaxed text-muted-foreground flex-1">
              {c.desc}
            </p>
            {c.id && (
              <button
                type="button"
                disabled={!live || running !== null}
                onClick={() => engine.runPlaybook(c.id as 'ble_legacy' | 'selftest')}
                className="inline-flex items-center justify-center gap-1.5 rounded border border-[#00e5ff]/50
                  bg-[#00e5ff]/10 px-2 py-1.5 text-[10px] font-semibold tracking-[0.15em] text-[#00e5ff]
                  transition-colors hover:bg-[#00e5ff]/20 disabled:opacity-35 disabled:cursor-not-allowed"
              >
                <Play className="w-3 h-3" />
                {running === c.id ? 'EJECUTANDO…' : 'EJECUTAR'}
              </button>
            )}
          </div>
        ))}
      </div>

      <div className="px-3 pb-3">
        <div className="rounded-md border border-border/70 bg-black/50 overflow-hidden">
          <div className="flex items-center justify-between px-3 py-1.5 border-b border-border/50">
            <span className="label-caps flex items-center gap-2">
              <SquareTerminal className="w-3.5 h-3.5 text-[#00e5ff]" />
              Consola del playbook
              {lastOk === true && <ShieldCheck className="w-3.5 h-3.5 text-[#34d399]" />}
            </span>
            <button
              type="button"
              onClick={() => engine.clearPlaybookLog()}
              className="inline-flex items-center gap-1 text-[9px] tracking-[0.15em] text-muted-foreground
                hover:text-foreground transition-colors"
            >
              <Trash2 className="w-3 h-3" />
              LIMPIAR
            </button>
          </div>
          <div
            ref={logRef}
            className="h-44 overflow-y-auto px-3 py-2 font-mono text-[11px] leading-relaxed text-cyan-100/85"
          >
            {log.length === 0 ? (
              <div className="text-muted-foreground/60 flex items-center gap-2 pt-1">
                <Radar className="w-3.5 h-3.5" />
                {live
                  ? 'Lista. Pulsa EJECUTAR en un playbook — la salida aparece aquí en vivo.'
                  : 'Conecta el bridge (botón CAPTURAR) para habilitar los playbooks.'}
              </div>
            ) : (
              log.map((line, i) => (
                <div key={`${i}-${line.length}`} className="whitespace-pre-wrap break-all">
                  {line}
                </div>
              ))
            )}
            {running && (
              <div className="text-[#00e5ff] animate-pulse">▊</div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
