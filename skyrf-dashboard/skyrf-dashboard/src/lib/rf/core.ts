/**
 * SkyRF — núcleo RF: simulación de tráfico, extracción de features y
 * clasificador. Espejo en TS del pipeline Python (skyrf.*).
 *
 * Firmas ancladas a los estándares:
 * - IEEE 802.15.4-2020 (Zigbee/Thread): 250 kbps → 32 µs/byte; PSDU ≤127 B; ch 11-26
 * - BLE Core Spec: adv ch 37/38/39, intervalo típico ~100 ms; connection events densos
 * - Thread: 802.15.4 + CoAP request/response (paquetes medianos, conversacional)
 * - LoRaWAN: airtime largo por SF, duty cycle ~1%, tráfico esporádico
 */

export type Protocol = 'zigbee' | 'ble' | 'thread' | 'lora';
export type FrameType = 'data' | 'beacon' | 'ack' | 'command';

export interface Packet {
  t: number;          // segundos relativos
  len: number;        // bytes
  proto: Protocol;
  channel: number;
  src: string;
  frameType: FrameType;
}

export const PROTOCOLS: Protocol[] = ['zigbee', 'ble', 'thread', 'lora'];

/** RNG determinista (mulberry32) */
export function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(r: () => number, arr: T[]): T {
  return arr[Math.floor(r() * arr.length)];
}
function randint(r: () => number, lo: number, hi: number) {
  return lo + Math.floor(r() * (hi - lo + 1));
}
function expovariate(r: () => number, lambda: number) {
  return -Math.log(1 - r()) / lambda;
}
function gauss(r: () => number, mu: number, sigma: number) {
  const u = Math.max(r(), 1e-9), v = r();
  return mu + sigma * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

type Gen = (t0: number, dur: number, r: () => number, src: string) => Packet[];

const genZigbee: Gen = (t0, dur, r, src) => {
  const out: Packet[] = []; let t = t0;
  const chans = [15, 20, 25];
  while (t < t0 + dur) {
    if (r() < 0.08) { // burst de comando ZCL
      const n = randint(r, 3, 7);
      for (let i = 0; i < n; i++) {
        out.push({ t, len: randint(r, 30, 90), proto: 'zigbee', channel: pick(r, chans), src, frameType: 'command' });
        t += 0.002 + r() * 0.008;
      }
    } else {
      out.push({ t, len: randint(r, 25, 70), proto: 'zigbee', channel: pick(r, chans), src, frameType: 'data' });
      t += expovariate(r, 1 / 0.25);
    }
  }
  return out;
};

const genBle: Gen = (t0, dur, r, src) => {
  const out: Packet[] = []; let t = t0;
  const chans = [37, 38, 39];
  while (t < t0 + dur) {
    if (r() < 0.15) { // connection event
      const n = randint(r, 4, 10); let b = t;
      for (let i = 0; i < n; i++) {
        out.push({ t: b, len: randint(r, 10, 40), proto: 'ble', channel: pick(r, chans), src, frameType: 'data' });
        b += 0.0005 + r() * 0.0015;
      }
      t += 0.03 + r() * 0.02;
    } else {
      out.push({ t, len: randint(r, 12, 31), proto: 'ble', channel: pick(r, chans), src, frameType: 'beacon' });
      t += Math.max(gauss(r, 0.1, 0.005), 0.02);
    }
  }
  return out;
};

const genThread: Gen = (t0, dur, r, src) => {
  const out: Packet[] = []; let t = t0;
  const chans = Array.from({ length: 16 }, (_, i) => 11 + i);
  while (t < t0 + dur) {
    if (r() < 0.3) { // CoAP req/resp
      out.push({ t, len: randint(r, 60, 120), proto: 'thread', channel: pick(r, chans), src, frameType: 'command' });
      t += 0.005 + r() * 0.015;
      out.push({ t, len: randint(r, 60, 120), proto: 'thread', channel: pick(r, chans), src, frameType: 'data' });
    } else {
      out.push({ t, len: randint(r, 40, 110), proto: 'thread', channel: pick(r, chans), src, frameType: 'data' });
    }
    t += expovariate(r, 1 / 0.4);
  }
  return out;
};

const genLora: Gen = (t0, dur, r, src) => {
  const out: Packet[] = []; let t = t0;
  while (t < t0 + dur) {
    out.push({ t, len: randint(r, 51, 222), proto: 'lora', channel: randint(r, 0, 7), src, frameType: 'data' });
    t += expovariate(r, 1 / 3) + 0.05 + r() * 0.35; // airtime SF alto
  }
  return out;
};

const GENS: Record<Protocol, Gen> = { zigbee: genZigbee, ble: genBle, thread: genThread, lora: genLora };

export function generate(proto: Protocol, dur: number, seed: number, src = 'syn'): Packet[] {
  return GENS[proto](0, dur, rng(seed), src);
}

/* ------------------------------- features ------------------------------ */

export const FEATURE_NAMES = [
  'n_packets', 'len_mean', 'len_std', 'len_min', 'len_max',
  'iat_mean', 'iat_std', 'iat_min', 'iat_max',
  'burst_ratio', 'beacon_ratio', 'command_ratio', 'channel_entropy', 'duty_cycle',
] as const;

function entropy(counts: number[]): number {
  const total = counts.reduce((a, b) => a + b, 0);
  if (!total) return 0;
  let h = 0;
  for (const c of counts) if (c) { const p = c / total; h -= p * Math.log2(p); }
  return h;
}

export function extractWindow(pkts: Packet[], windowS: number): number[] {
  if (pkts.length < 2) return FEATURE_NAMES.map(() => 0);
  const n = pkts.length;
  const lens = pkts.map(p => p.len);
  const iats: number[] = [];
  for (let i = 1; i < n; i++) iats.push(pkts[i].t - pkts[i - 1].t);
  const mean = (a: number[]) => a.reduce((x, y) => x + y, 0) / a.length;
  const std = (a: number[], m: number) => Math.sqrt(a.reduce((x, y) => x + (y - m) ** 2, 0) / a.length);
  const lm = mean(lens), im = mean(iats);
  const chanCounts = new Map<number, number>();
  let beacons = 0, commands = 0;
  for (const p of pkts) {
    chanCounts.set(p.channel, (chanCounts.get(p.channel) ?? 0) + 1);
    if (p.frameType === 'beacon') beacons++;
    if (p.frameType === 'command') commands++;
  }
  const airtime = lens.reduce((a, b) => a + b, 0) * 32e-6; // 802.15.4 proxy
  return [
    n, lm, std(lens, lm), Math.min(...lens), Math.max(...lens),
    im, std(iats, im), Math.min(...iats), Math.max(...iats),
    iats.filter(i => i < 0.01).length / iats.length,
    beacons / n, commands / n,
    entropy([...chanCounts.values()]),
    Math.min(airtime / Math.max(windowS, 1e-6), 1),
  ];
}

export function splitWindows(stream: Packet[], windowS: number, hopS = windowS / 2): Packet[][] {
  if (!stream.length) return [];
  const t0 = stream[0].t, tEnd = stream[stream.length - 1].t;
  const out: Packet[][] = [];
  for (let s = t0; s + windowS <= tEnd; s += hopS) {
    const w = stream.filter(p => p.t >= s && p.t < s + windowS);
    if (w.length >= 2) out.push(w);
  }
  return out;
}

/* ------------------------- clasificador centroides ---------------------- */

export interface Classification {
  label: Protocol;
  confidence: number;
  probs: Record<Protocol, number>;
}

export class CentroidClassifier {
  private centroids = new Map<Protocol, number[]>();
  private scales = new Map<Protocol, number>();
  private fMean: number[] = [];
  private fStd: number[] = [];

  /** Entrena generando tráfico sintético (mismas firmas documentadas). */
  train(samplesPerProto = 24, seed = 1337): void {
    const r = rng(seed);
    const allFeats: number[][] = [];
    const perProto = new Map<Protocol, number[][]>();
    for (const proto of PROTOCOLS) {
      const feats: number[][] = [];
      for (let i = 0; i < samplesPerProto; i++) {
        const stream = generate(proto, 60, Math.floor(r() * 2 ** 31));
        for (const w of splitWindows(stream, 5)) feats.push(extractWindow(w, 5));
      }
      perProto.set(proto, feats);
      allFeats.push(...feats);
    }

    // normalización z-score GLOBAL por feature (crítico: sin esto, features
    // con magnitudes pequeñas como iat_min dominan la distancia)
    const dim = allFeats[0].length;
    this.fMean = new Array(dim).fill(0);
    this.fStd = new Array(dim).fill(0);
    for (const f of allFeats) for (let d = 0; d < dim; d++) this.fMean[d] += f[d] / allFeats.length;
    for (const f of allFeats) for (let d = 0; d < dim; d++) this.fStd[d] += (f[d] - this.fMean[d]) ** 2 / allFeats.length;
    this.fStd = this.fStd.map(s => Math.sqrt(s) || 1);

    for (const proto of PROTOCOLS) {
      const feats = perProto.get(proto)!;
      const c = new Array(dim).fill(0);
      for (const f of feats) {
        const z = this.norm(f);
        for (let d = 0; d < dim; d++) c[d] += z[d] / feats.length;
      }
      let acc = 0;
      for (const f of feats) acc += this.dist(this.norm(f), c);
      this.centroids.set(proto, c);
      this.scales.set(proto, acc / feats.length || 1);
    }
  }

  private norm(f: number[]): number[] {
    return f.map((v, i) => (v - this.fMean[i]) / this.fStd[i]);
  }

  private dist(a: number[], b: number[]): number {
    let s = 0;
    for (let i = 0; i < a.length; i++) { const d = a[i] - b[i]; s += d * d; }
    return Math.sqrt(s);
  }

  classify(features: number[]): Classification {
    const z = this.norm(features);
    const scores = new Map<Protocol, number>();
    for (const proto of PROTOCOLS) {
      const c = this.centroids.get(proto)!;
      const d = this.dist(z, c) / (this.scales.get(proto) || 1);
      scores.set(proto, Math.exp(-d * d)); // gaussian kernel
    }
    const total = [...scores.values()].reduce((a, b) => a + b, 0) || 1;
    const probs = Object.fromEntries(
      PROTOCOLS.map(p => [p, (scores.get(p) ?? 0) / total]),
    ) as Record<Protocol, number>;
    const label = PROTOCOLS.reduce((a, b) => (probs[a] >= probs[b] ? a : b));
    return { label, confidence: probs[label], probs };
  }
}
