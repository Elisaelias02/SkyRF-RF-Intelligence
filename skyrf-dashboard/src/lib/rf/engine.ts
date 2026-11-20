/**
 * SkyRF — motor del dashboard: consume el stream REAL del CatSniffer vía el
 * bridge local (skyrf.bridge, WebSocket en localhost:8765), clasifica por
 * dispositivo y mantiene espectro/alertas.
 *
 * No hay datos simulados: sin bridge no hay tráfico.
 */

import {
  CentroidClassifier, extractWindow,
  type Protocol, type Classification,
} from './core';

export interface Device {
  id: string;               // src addr en el aire (short addr hex)
  rssi: number | null;
  channel: number;
  pkts: Array<{ t: number; len: number; channel: number; frameType: string }>;
  ppsHistory: number[];
  firstSeen: number;
  lastSeen: number;
  proto?: Protocol;         // verdad del bridge (él sabe qué está sniffando)
  cls?: Classification;
  dev?: string | null;      // identidad BLE: nombre / Apple Continuity / servicio
  addrType?: string | null; // 'pública' | 'aleatoria' (BLE)
  exposure?: string | null; // 'alto' | 'medio' | 'bajo' (score del bridge)
  expWhy?: string[] | null; // razones del nivel de exposición
}

export interface Alert {
  id: number;
  t: number;
  level: 'info' | 'warn' | 'critical';
  title: string;
  detail: string;
}

export type WsStatus = 'offline' | 'connecting' | 'live';

export interface KeyCapture {
  panId: string;
  tcAddr: string;
  networkKey: string;
}

export interface PlaybookState {
  running: string | null;   // nombre del playbook en ejecución
  log: string[];
  lastName: string | null;
  lastOk: boolean | null;
}

export interface AttackState {
  capture: boolean;          // tshark+Sniffle corriendo bajo el bridge
  captureOut: string | null; // pcap que se está escribiendo
  victim: boolean;           // Kali en modo víctima (Legacy forzado)
  victimAddr: string | null; // BD_ADDR de la Kali víctima
}

export interface Snapshot {
  wsStatus: WsStatus;
  capturing: boolean;
  elapsed: number;
  pps: number;
  devices: Device[];
  alerts: Alert[];
  spectrum: number[];
  spectrumLabels: string[];
  networksFound: number;
  keyCaptured: KeyCapture | null;
  successTick: number;      // se incrementa en cada captura exitosa (overlay)
  successLabel: string;     // qué se celebra en el overlay
  bridgeSource: string | null;
  bridgeProto: string | null;
  playbook: PlaybookState;
  attack: AttackState;
}

const SPECTRUM_LABELS = [
  ...Array.from({ length: 16 }, (_, i) => String(11 + i)),
  '37', '38', '39',
];

const WS_URL = `ws://${location.hostname}:8765`;

export class Engine {
  private classifier = new CentroidClassifier();
  private devices = new Map<string, Device>();
  private alerts: Alert[] = [];
  private spectrum: number[] = SPECTRUM_LABELS.map(() => 0);
  private ws: WebSocket | null = null;
  private wsStatus: WsStatus = 'offline';
  private capturing = false;
  private startedAt = 0;
  private pktCounter = 0;
  private pps = 0;
  private alertId = 0;
  private keyCaptured: Snapshot['keyCaptured'] = null;
  private successTick = 0;
  private successLabel = 'NETWORK KEY CAPTURADA';
  private pans = new Set<string>();
  private bridgeSource: string | null = null;
  private bridgeProto: string | null = null;
  private playbook: PlaybookState = {
    running: null, log: [], lastName: null, lastOk: null,
  };
  private attack: AttackState = {
    capture: false, captureOut: null, victim: false, victimAddr: null,
  };

  constructor() {
    this.classifier.train();
    setInterval(() => this.tick(), 250);
  }

  /* ------------------------------ conexión WS ----------------------------- */

  private connect() {
    if (this.ws && this.ws.readyState <= WebSocket.OPEN) return;
    this.wsStatus = 'connecting';
    const ws = new WebSocket(WS_URL);
    this.ws = ws;

    ws.onopen = () => {
      this.wsStatus = 'live';
      this.pushAlert('info', 'BRIDGE CONECTADO',
        `Stream del CatSniffer activo · ${WS_URL}`);
    };
    ws.onmessage = (ev) => this.onMessage(ev.data);
    ws.onclose = () => {
      this.wsStatus = 'offline';
      this.ws = null;
      if (this.capturing) {
        this.pushAlert('warn', 'BRIDGE DESCONECTADO',
          'Reintentando… verifica que skyrf bridge esté corriendo');
      }
      setTimeout(() => this.capturing && this.connect(), 2000);
    };
    ws.onerror = () => ws.close();
  }

  private onMessage(raw: string) {
    let msg: Record<string, unknown>;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'hello') {
      this.bridgeSource = typeof msg.source === 'string' ? msg.source : null;
      this.bridgeProto = typeof msg.proto === 'string' ? msg.proto : null;
      if (msg.attack && typeof msg.attack === 'object') {
        this.applyAttackStatus(msg.attack as Record<string, unknown>);
      }
      return;
    }
    if (msg.type === 'attack_status') {
      this.applyAttackStatus(msg);
      return;
    }
    if (msg.type === 'attack_out') {
      const tag = String(msg.tag ?? 'attack');
      const line = String(msg.line ?? '').split('\r').pop() ?? '';
      this.pushPlaybookLine(`│[${tag}] ${line}`);
      return;
    }
    if (msg.type === 'attack_done') {
      const ok = msg.ok === true;
      const action = String(msg.action ?? '');
      if (action.startsWith('capture')) {
        this.pushPlaybookLine(ok
          ? '└─ [★] captura bajo control del bridge'
          : `└─ [✗] captura: operación fallida (rc=${String(msg.code)})`);
      } else if (action === 'victim_mode') {
        this.pushPlaybookLine(ok
          ? '└─ [★] modo víctima listo'
          : `└─ [✗] modo víctima falló (rc=${String(msg.code)})`);
      }
      return;
    }
    if (msg.type === 'playbook_started') {
      this.playbook.running = String(msg.playbook ?? '');
      this.playbook.lastName = this.playbook.running;
      this.playbook.lastOk = null;
      this.pushPlaybookLine(`┌─ EJECUTANDO: ${String(msg.cmd ?? msg.playbook ?? '')}`);
      return;
    }
    if (msg.type === 'playbook_out') {
      // el progreso del cracker usa \r; nos quedamos con el último segmento
      this.pushPlaybookLine(String(msg.line ?? '').split('\r').pop() ?? '');
      return;
    }
    if (msg.type === 'playbook_done') {
      const ok = msg.ok === true;
      const name = String(msg.playbook ?? this.playbook.lastName ?? '');
      this.playbook.running = null;
      this.playbook.lastOk = ok;
      this.playbook.lastName = name || null;
      this.pushPlaybookLine(ok
        ? '└─ [★] PLAYBOOK COMPLETADO CON ÉXITO'
        : `└─ [✗] playbook terminó sin éxito (rc=${String(msg.code)})`);
      if (ok) {
        this.successLabel = name === 'ble_legacy'
          ? 'PAIRING CRACKEADO'
          : 'SELFTEST SUPERADO';
        this.successTick++;
      }
      return;
    }
    if (msg.type === 'alert') {
      this.pushAlert(
        msg.level as Alert['level'], String(msg.title), String(msg.detail));
      return;
    }
    if (msg.type === 'key_captured') {
      this.keyCaptured = {
        panId: String(msg.panId), tcAddr: String(msg.tcAddr),
        networkKey: String(msg.networkKey),
      };
      this.successLabel = 'NETWORK KEY CAPTURADA';
      this.successTick++;
      return;
    }
    if (msg.type !== 'packet' || !this.capturing) return;

    const src = String(msg.src || 'desconocido');
    const now = (performance.now() - this.startedAt) / 1000;
    const channel = Number(msg.channel ?? 0);
    const len = Number(msg.len ?? 0);
    const proto = typeof msg.proto === 'string'
      ? msg.proto as Protocol : undefined;

    let d = this.devices.get(src);
    if (!d) {
      d = {
        id: src, rssi: null, channel, pkts: [], ppsHistory: [],
        firstSeen: now, lastSeen: now, proto,
      };
      this.devices.set(src, d);
      if (src !== 'desconocido') {
        const tag = typeof msg.dev === 'string' && msg.dev ? ` · ${msg.dev}` : '';
        this.pushAlert('info', 'DISPOSITIVO NUEVO', `${src}${tag} · canal ${channel}`);
      }
    }
    if (proto) d.proto = proto;
    if (typeof msg.dev === 'string' && msg.dev) d.dev = msg.dev;
    if (typeof msg.addrType === 'string' && msg.addrType) d.addrType = msg.addrType;
    if (typeof msg.exposure === 'string' && msg.exposure) d.exposure = msg.exposure;
    if (Array.isArray(msg.expWhy) && msg.expWhy.length) d.expWhy = msg.expWhy;
    d.channel = channel;
    d.lastSeen = now;
    d.rssi = typeof msg.rssi === 'number' ? msg.rssi : null;
    d.pkts.push({ t: now, len, channel, frameType: String(msg.frameType ?? 'data') });
    this.pktCounter++;

    const col = SPECTRUM_LABELS.indexOf(String(channel));
    if (col >= 0) this.spectrum[col] = Math.min(1, this.spectrum[col] + 0.12);
  }

  /* -------------------------------- bucle -------------------------------- */

  private tick() {
    this.spectrum = this.spectrum.map(v =>
      Math.max(v * 0.96, 0.03 + Math.random() * 0.05));
    if (!this.capturing) return;

    const now = (performance.now() - this.startedAt) / 1000;
    for (const d of this.devices.values()) {
      d.pkts = d.pkts.filter(p => p.t >= now - 70);
      // ventana adaptativa (igual que el clasificador Python)
      let win = d.pkts.filter(p => p.t >= now - 5);
      let winS = 5;
      if (win.length < 6 && d.pkts.length >= 6) {
        win = d.pkts.slice(-12);
        winS = Math.max(win[win.length - 1].t - win[0].t, 1);
      }
      if (win.length >= 4 && Math.floor(now * 2) % 2 === 0) {
        d.cls = this.classifier.classify(
          extractWindow(
            win.map(p => ({
              t: p.t, len: p.len,
              proto: d.proto ?? ('zigbee' as Protocol),
              channel: p.channel, src: d.id,
              frameType: p.frameType as 'data' | 'beacon' | 'ack' | 'command',
            })),
            winS,
          ),
        );
      }
      const recent = d.pkts.filter(p => p.t >= now - 5).length / 5;
      d.ppsHistory.push(Math.round(recent));
      if (d.ppsHistory.length > 40) d.ppsHistory.shift();
    }
    this.pps = this.pktCounter * 4; // tick de 250 ms
    this.pktCounter = 0;
  }

  /* ------------------------------ API pública ----------------------------- */

  start() {
    this.capturing = true;
    if (!this.startedAt) this.startedAt = performance.now();
    this.connect();
  }

  pause() {
    this.capturing = false;
    this.pushAlert('info', 'CAPTURA EN PAUSA', 'El stream sigue abierto; el análisis se congela');
  }

  reset() {
    this.devices.clear();
    this.alerts = []; this.alertId = 0;
    this.spectrum = SPECTRUM_LABELS.map(() => 0);
    this.keyCaptured = null; this.pans.clear();
    this.pps = 0; this.pktCounter = 0;
    this.startedAt = performance.now();
  }

  private pushAlert(level: Alert['level'], title: string, detail: string) {
    const now = this.startedAt ? (performance.now() - this.startedAt) / 1000 : 0;
    this.alerts.unshift({ id: ++this.alertId, t: now, level, title, detail });
    if (this.alerts.length > 60) this.alerts.pop();
  }

  /* ----------------------------- playbooks -------------------------------- */

  private pushPlaybookLine(line: string) {
    this.playbook.log.push(line);
    if (this.playbook.log.length > 400) this.playbook.log.shift();
  }

  runPlaybook(name: 'ble_legacy' | 'ble_audit' | 'selftest', pcap?: string) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.pushPlaybookLine('[✗] Bridge offline — no puedo lanzar el playbook');
      return;
    }
    if (this.playbook.running) return;
    this.playbook.log = [];
    this.playbook.lastOk = null;
    this.ws.send(JSON.stringify({
      type: 'run_playbook', id: String(Date.now()), playbook: name,
      ...(pcap ? { pcap } : {}),
    }));
  }

  clearPlaybookLog() {
    this.playbook.log = [];
    this.playbook.lastOk = null;
    this.playbook.lastName = null;
  }

  /* ------------------------- orquestación de ataque ------------------------ */

  private applyAttackStatus(msg: Record<string, unknown>) {
    this.attack = {
      capture: msg.capture === true,
      captureOut: typeof msg.captureOut === 'string' ? msg.captureOut : null,
      victim: msg.victim === true,
      victimAddr: typeof msg.victimAddr === 'string' ? msg.victimAddr : null,
    };
  }

  private sendAttack(msg: Record<string, unknown>) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.pushPlaybookLine('[✗] Bridge offline — no puedo ejecutar la acción');
      return false;
    }
    this.ws.send(JSON.stringify({ id: String(Date.now()), ...msg }));
    return true;
  }

  victimMode(start: boolean) {
    this.sendAttack({ type: 'victim_mode', start });
  }

  captureStart(mac: string, serport: string) {
    this.sendAttack({
      type: 'capture_control', action: 'start',
      mac: mac.trim(), serport: serport.trim() || '/dev/ttyACM0',
    });
  }

  captureStop() {
    this.sendAttack({ type: 'capture_control', action: 'stop' });
  }

  getSnapshot(): Snapshot {
    return {
      wsStatus: this.wsStatus,
      capturing: this.capturing,
      elapsed: this.startedAt ? (performance.now() - this.startedAt) / 1000 : 0,
      pps: this.pps,
      devices: [...this.devices.values()],
      alerts: [...this.alerts],
      spectrum: [...this.spectrum],
      spectrumLabels: [...SPECTRUM_LABELS],
      networksFound: this.pans.size || (this.keyCaptured ? 1 : 0),
      keyCaptured: this.keyCaptured,
      successTick: this.successTick,
      successLabel: this.successLabel,
      bridgeSource: this.bridgeSource,
      bridgeProto: this.bridgeProto,
      playbook: {
        running: this.playbook.running,
        log: [...this.playbook.log],
        lastName: this.playbook.lastName,
        lastOk: this.playbook.lastOk,
      },
      attack: { ...this.attack },
    };
  }
}

export const engine = new Engine();
