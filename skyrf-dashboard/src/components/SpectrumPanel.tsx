import { useEffect, useRef } from 'react';

interface Props {
  spectrum: number[];
  labels: string[];
  running: boolean;
}

/** Colormap: oscuro → cyan → magenta (picos) */
function colorFor(v: number): string {
  if (v < 0.08) return 'rgba(5,8,16,0)';
  if (v < 0.3) return `rgba(0,90,110,${0.25 + v})`;
  if (v < 0.65) return `rgba(0,229,255,${0.35 + v * 0.5})`;
  if (v < 0.9) return `rgba(127,243,255,${0.7 + v * 0.3})`;
  return '#ff4fd8';
}

export function SpectrumPanel({ spectrum, labels, running }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const historyRef = useRef<number[][]>([]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const render = () => {
      const { width, height } = canvas;
      const top = 22;                 // franja de etiquetas
      const h = height - top;
      const cols = labels.length;
      const cw = width / cols;

      // agregar fila actual al historial
      historyRef.current.push([...spectrum]);
      if (historyRef.current.length > h) historyRef.current.shift();

      // fondo
      ctx.fillStyle = '#070b14';
      ctx.fillRect(0, 0, width, height);

      // waterfall (las filas nuevas arriba, scroll hacia abajo)
      const rows = historyRef.current;
      for (let r = 0; r < rows.length; r++) {
        const row = rows[rows.length - 1 - r];
        for (let c = 0; c < cols; c++) {
          const v = row[c] ?? 0;
          if (v < 0.08) continue;
          ctx.fillStyle = colorFor(v);
          ctx.fillRect(c * cw + 1, top + r, cw - 2, 1.5);
        }
      }

      // línea de barras actual (intensidad presente)
      for (let c = 0; c < cols; c++) {
        const v = spectrum[c] ?? 0;
        ctx.fillStyle = colorFor(Math.max(v, 0.1));
        ctx.fillRect(c * cw + 1, top, cw - 2, 2);
      }

      // etiquetas y rejilla
      ctx.font = '9px "JetBrains Mono", monospace';
      ctx.textAlign = 'center';
      for (let c = 0; c < cols; c++) {
        const x = c * cw + cw / 2;
        const active = (spectrum[c] ?? 0) > 0.12;
        ctx.fillStyle = active ? '#00e5ff' : '#5b6b85';
        ctx.fillText(labels[c], x, 13);
        ctx.strokeStyle = 'rgba(26,37,64,0.5)';
        ctx.beginPath();
        ctx.moveTo(c * cw, top);
        ctx.lineTo(c * cw, height);
        ctx.stroke();
      }

      // separador BLE
      const bleStart = (cols - 3) * cw;
      ctx.fillStyle = '#7dd3fc';
      ctx.font = '8px "JetBrains Mono", monospace';
      ctx.fillText('BLE ADV', bleStart + 1.5 * cw, height - 4);
      ctx.fillStyle = '#00e5ff';
      ctx.fillText('2.4 GHz · multi-protocolo', (cols - 3) * cw / 2, height - 4);
    };

    render();
    if (!running) return;
    const id = setInterval(render, 100);
    return () => clearInterval(id);
  }, [spectrum, labels, running]);

  // redimensionar con devicePixelRatio
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const parent = canvas.parentElement!;
    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      canvas.width = parent.clientWidth * dpr;
      canvas.height = 190 * dpr;
      canvas.style.width = `${parent.clientWidth}px`;
      canvas.style.height = '190px';
      canvas.getContext('2d')?.scale(dpr, dpr);
      historyRef.current = [];
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(parent);
    return () => ro.disconnect();
  }, []);

  return (
    <div className="panel overflow-hidden">
      <div className="panel-header">
        <span className="label-caps">Espectro de canales · waterfall</span>
        <span className="text-[10px] text-muted-foreground tracking-wider">
          CANALES 11–26 · BLE 37/38/39
        </span>
      </div>
      <div className="w-full">
        <canvas ref={canvasRef} className="block w-full" aria-label="Waterfall de actividad por canal" />
      </div>
    </div>
  );
}
