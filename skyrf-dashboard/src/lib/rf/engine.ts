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
  cls?: Classification;
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
  private pans = new Set<string>();

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
      this.successTick++;
      return;
    }
    if (msg.type !== 'packet' || !this.capturing) return;

    const src = String(msg.src || 'desconocido');
    const now = (performance.now() - this.startedAt) / 1000;
    const channel = Number(msg.channel ?? 0);
    const len = Number(msg.len ?? 0);

    let d = this.devices.get(src);
    if (!d) {
      d = {
        id: src, rssi: null, channel, pkts: [], ppsHistory: [],
        firstSeen: now, lastSeen: now,
      };
      this.devices.set(src, d);
      if (src !== 'desconocido') {
        this.pushAlert('info', 'DISPOSITIVO NUEVO', `${src} · canal ${channel}`);
      }
    }
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
              t: p.t, len: p.len, proto: 'zigbee' as Protocol,
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
    };
  }
}

export const engine = new Engine();
