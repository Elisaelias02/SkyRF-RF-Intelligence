import { useState } from 'react';
import { engine, type Snapshot } from '@/lib/rf/engine';
import { Crosshair, Play, Radio, Square } from 'lucide-react';

/**
 * AttackPanel → panel de CAPTURA Sniffle (la Kali ya no actúa como víctima
 * desde la UI: el foco es la auditoría pasiva). El pcap resultante alimenta
 * los playbooks: BLE AUDIT (reporte de privacidad) y BLE LEGACY CRACK.
 */

export function AttackPanel({ snap }: { snap: Snapshot }) {
  const live = snap.wsStatus === 'live';
  const [mac, setMac] = useState('');
  const [serport, setSerport] = useState('/dev/ttyACM0');

  return (
    <section className="panel overflow-hidden">
      <div className="panel-header">
        <span className="label-caps flex items-center gap-2">
          <Radio className="w-3.5 h-3.5 text-[#00e5ff]" />
          Captura Sniffle — auditoría pasiva
        </span>
        <span className="text-[10px] text-muted-foreground tracking-wider">
          {live
            ? 'SIN CONEXIONES · SOLO ESCUCHA · CANALES 37-39'
            : 'BRIDGE OFFLINE — conecta CAPTURAR para habilitar la captura'}
        </span>
      </div>

      <div className="p-3 flex flex-col gap-2.5">
        <div className="flex flex-col sm:flex-row gap-2">
          <input
            value={mac}
            onChange={e => setMac(e.target.value.toUpperCase())}
            placeholder="MAC OBJETIVO · VACÍO = AUDITORÍA DE TODOS"
            disabled={!live || snap.attack.capture}
            className="flex-1 min-w-0 rounded border border-border/70 bg-black/40 px-2.5 py-1.5
              font-mono text-[11px] tracking-wider text-cyan-100 placeholder:text-muted-foreground/50
              focus:outline-none focus:border-[#00e5ff]/60 disabled:opacity-40"
          />
          <input
            value={serport}
            onChange={e => setSerport(e.target.value)}
            disabled={!live || snap.attack.capture}
            className="sm:w-36 rounded border border-border/70 bg-black/40 px-2.5 py-1.5
              font-mono text-[11px] tracking-wider text-cyan-100
              focus:outline-none focus:border-[#00e5ff]/60 disabled:opacity-40"
          />
          {snap.attack.capture ? (
            <button
              type="button"
              onClick={() => engine.captureStop()}
              className="inline-flex items-center justify-center gap-1.5 rounded border
                border-[#f0abfc]/50 bg-[#f0abfc]/10 px-4 py-1.5 text-[11px] font-semibold
                tracking-[0.15em] text-[#f0abfc] transition-colors hover:bg-[#f0abfc]/20"
            >
              <Square className="w-3.5 h-3.5" />
              DETENER CAPTURA
            </button>
          ) : (
            <button
              type="button"
              disabled={!live}
              onClick={() => engine.captureStart(mac.trim(), serport)}
              className="inline-flex items-center justify-center gap-1.5 rounded border
                border-[#00e5ff]/50 bg-[#00e5ff]/10 px-4 py-1.5 text-[11px] font-semibold
                tracking-[0.15em] text-[#00e5ff] transition-colors hover:bg-[#00e5ff]/20
                disabled:opacity-35 disabled:cursor-not-allowed"
            >
              <Play className="w-3.5 h-3.5" />
              INICIAR CAPTURA
            </button>
          )}
        </div>

        <div className="flex items-center justify-between gap-2 flex-wrap">
          <p className="text-[10px] leading-relaxed text-muted-foreground/80">
            <span className="text-[#00e5ff]/80">Vacío</span> = auditoría de todo
            lo que emite cerca (nombres, fabricantes, rastreadores, exposición).
            Con <span className="text-[#00e5ff]/80">MAC</span> = sigue la conexión
            de ese objetivo por los canales de datos.
          </p>
          <span
            className={`text-[9px] tracking-[0.12em] px-1.5 py-0.5 rounded border w-fit ${
              snap.attack.capture
                ? 'border-[#34d399]/40 text-[#34d399]'
                : 'border-border/60 text-muted-foreground'
            }`}
          >
            {snap.attack.capture
              ? `CAPTURANDO → ${snap.attack.captureOut?.split('/').pop() ?? 'pcap'}`
              : 'DETENIDA'}
          </span>
        </div>

        <p className="text-[9px] leading-relaxed text-muted-foreground/60 border-t border-border/40 pt-2">
          Con la captura detenida, abajo: <Crosshair className="inline w-3 h-3 -mt-0.5" />
          {' '}<span className="text-foreground/80">BLE AUDIT REPORT</span> genera el
          informe de privacidad y <span className="text-foreground/80">BLE LEGACY CRACK</span>
          {' '}intenta el ataque de pairing sobre el mismo pcap.
        </p>
      </div>
    </section>
  );
}
