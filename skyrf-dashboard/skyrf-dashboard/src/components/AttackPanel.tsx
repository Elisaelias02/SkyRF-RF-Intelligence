import { useState } from 'react';
import { engine, type Snapshot } from '@/lib/rf/engine';
import {
  Bluetooth, Crosshair, KeyRound, Play, Square, Target,
} from 'lucide-react';

/**
 * AttackPanel — secuencia guiada del PoC BLE Legacy en 3 pasos, todo desde
 * la web. El bridge gobierna el Bluetooth de la Kali y el tshark+Sniffle;
 * cada paso streamea su salida a la consola de playbooks (abajo).
 *
 *   1. MODO VÍCTIMA  → Kali emparejable con Secure Connections desactivado
 *   2. CAPTURA       → tshark+Sniffle siguiendo la MAC de la víctima
 *   3. CRACK         → playbook ble_legacy sobre el pcap capturado
 */

function StepShell({
  n, title, icon, state, stateOk, children,
}: {
  n: string;
  title: string;
  icon: React.ReactNode;
  state: string;
  stateOk: boolean | null;   // null = neutro
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-md border border-border/70 bg-secondary/20 p-3 flex flex-col gap-2 min-h-[150px]">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold tracking-[0.12em] text-foreground flex items-center gap-1.5">
          <span className="text-[#00e5ff]">{n}</span> {title}
        </span>
        {icon}
      </div>
      <span
        className={`text-[9px] tracking-[0.12em] px-1.5 py-0.5 rounded border w-fit ${
          stateOk === null
            ? 'border-border/60 text-muted-foreground'
            : stateOk
              ? 'border-[#34d399]/40 text-[#34d399]'
              : 'border-[#f0abfc]/40 text-[#f0abfc]'
        }`}
      >
        {state}
      </span>
      <div className="flex-1 flex flex-col gap-2 justify-end">{children}</div>
    </div>
  );
}

export function AttackPanel({ snap }: { snap: Snapshot }) {
  const live = snap.wsStatus === 'live';
  const busy = snap.playbook.running !== null;
  const [mac, setMac] = useState('');
  const [serport, setSerport] = useState('/dev/ttyACM0');

  const victimMac = snap.attack.victimAddr ?? '';
  const effectiveMac = mac.trim() || victimMac;

  return (
    <section className="panel overflow-hidden">
      <div className="panel-header">
        <span className="label-caps flex items-center gap-2">
          <Crosshair className="w-3.5 h-3.5 text-[#00e5ff]" />
          Modo ataque — BLE Legacy end-to-end
        </span>
        <span className="text-[10px] text-muted-foreground tracking-wider">
          {live
            ? 'KALI COMO VÍCTIMA · PAIRING POR PIN · CRACK EN VIVO'
            : 'BRIDGE OFFLINE — conecta CAPTURAR para habilitar el modo ataque'}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 p-3">
        {/* ------------------------- PASO 1 · VÍCTIMA ------------------------ */}
        <StepShell
          n="01"
          title="MODO VÍCTIMA"
          icon={<Bluetooth className="w-3.5 h-3.5 text-[#00e5ff]/70" />}
          state={snap.attack.victim
            ? `ACTIVO · ${snap.attack.victimAddr ?? 'BD_ADDR ?'}`
            : 'INACTIVO'}
          stateOk={snap.attack.victim ? true : null}
        >
          <p className="text-[10px] leading-relaxed text-muted-foreground">
            La Kali se vuelve emparejable con Secure Connections apagado: el
            teléfono cae a Legacy Pairing y su PIN queda crackeable.
          </p>
          <button
            type="button"
            disabled={!live}
            onClick={() => engine.victimMode(!snap.attack.victim)}
            className={`inline-flex items-center justify-center gap-1.5 rounded border px-2 py-1.5
              text-[10px] font-semibold tracking-[0.15em] transition-colors
              disabled:opacity-35 disabled:cursor-not-allowed ${
              snap.attack.victim
                ? 'border-[#f0abfc]/50 bg-[#f0abfc]/10 text-[#f0abfc] hover:bg-[#f0abfc]/20'
                : 'border-[#00e5ff]/50 bg-[#00e5ff]/10 text-[#00e5ff] hover:bg-[#00e5ff]/20'
            }`}
          >
            <Target className="w-3 h-3" />
            {snap.attack.victim ? 'DESACTIVAR VÍCTIMA' : 'ACTIVAR VÍCTIMA'}
          </button>
        </StepShell>

        {/* ------------------------- PASO 2 · CAPTURA ------------------------ */}
        <StepShell
          n="02"
          title="CAPTURA SNIFFLE"
          icon={<Crosshair className="w-3.5 h-3.5 text-[#00e5ff]/70" />}
          state={snap.attack.capture
            ? `CAPTURANDO → ${snap.attack.captureOut?.split('/').pop() ?? 'pcap'}`
            : 'DETENIDA'}
          stateOk={snap.attack.capture ? true : null}
        >
          <div className="flex gap-1.5">
            <input
              value={mac}
              onChange={e => setMac(e.target.value.toUpperCase())}
              placeholder={victimMac || 'MAC VÍCTIMA'}
              disabled={!live || snap.attack.capture}
              className="flex-1 min-w-0 rounded border border-border/70 bg-black/40 px-2 py-1
                font-mono text-[10px] tracking-wider text-cyan-100 placeholder:text-muted-foreground/50
                focus:outline-none focus:border-[#00e5ff]/60 disabled:opacity-40"
            />
            <input
              value={serport}
              onChange={e => setSerport(e.target.value)}
              disabled={!live || snap.attack.capture}
              className="w-28 rounded border border-border/70 bg-black/40 px-2 py-1
                font-mono text-[10px] tracking-wider text-cyan-100
                focus:outline-none focus:border-[#00e5ff]/60 disabled:opacity-40"
            />
          </div>
          {snap.attack.capture ? (
            <button
              type="button"
              onClick={() => engine.captureStop()}
              className="inline-flex items-center justify-center gap-1.5 rounded border
                border-[#f0abfc]/50 bg-[#f0abfc]/10 px-2 py-1.5 text-[10px] font-semibold
                tracking-[0.15em] text-[#f0abfc] transition-colors hover:bg-[#f0abfc]/20"
            >
              <Square className="w-3 h-3" />
              DETENER CAPTURA
            </button>
          ) : (
            <button
              type="button"
              disabled={!live || !effectiveMac}
              onClick={() => engine.captureStart(effectiveMac, serport)}
              className="inline-flex items-center justify-center gap-1.5 rounded border
                border-[#00e5ff]/50 bg-[#00e5ff]/10 px-2 py-1.5 text-[10px] font-semibold
                tracking-[0.15em] text-[#00e5ff] transition-colors hover:bg-[#00e5ff]/20
                disabled:opacity-35 disabled:cursor-not-allowed"
            >
              <Play className="w-3 h-3" />
              INICIAR CAPTURA
            </button>
          )}
        </StepShell>

        {/* -------------------------- PASO 3 · CRACK ------------------------- */}
        <StepShell
          n="03"
          title="CRACK DEL PAIRING"
          icon={<KeyRound className="w-3.5 h-3.5 text-[#00e5ff]/70" />}
          state={snap.playbook.lastName === 'ble_legacy'
            ? snap.playbook.lastOk === true
              ? 'TK RECUPERADO'
              : snap.playbook.lastOk === false
                ? 'SIN ÉXITO — REVISA LA CONSOLA'
                : 'LISTO PARA LANZAR'
            : 'ESPERANDO CAPTURA'}
          stateOk={snap.playbook.lastName === 'ble_legacy'
            ? snap.playbook.lastOk
            : null}
        >
          <p className="text-[10px] leading-relaxed text-muted-foreground">
            Con la captura detenida y el emparejamiento hecho, lanza el crack:
            fuerza bruta del TK y descifrado AES-CCM de toda la conexión.
          </p>
          <button
            type="button"
            disabled={!live || busy || snap.attack.capture}
            onClick={() => engine.runPlaybook(
              'ble_legacy', snap.attack.captureOut ?? undefined)}
            className="inline-flex items-center justify-center gap-1.5 rounded border
              border-[#00e5ff]/50 bg-[#00e5ff]/10 px-2 py-1.5 text-[10px] font-semibold
              tracking-[0.15em] text-[#00e5ff] transition-colors hover:bg-[#00e5ff]/20
              disabled:opacity-35 disabled:cursor-not-allowed"
          >
            <KeyRound className="w-3 h-3" />
            {snap.playbook.running === 'ble_legacy' ? 'CRACKEANDO…' : 'LANZAR CRACK'}
          </button>
        </StepShell>
      </div>
    </section>
  );
}
