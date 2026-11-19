import { useEffect, useState } from "react";
import type { KeyCapture } from "@/lib/rf/engine";

/**
 * SuccessKitty — overlay de celebración cuando el ataque tiene éxito:
 * Sky te da el puñito (fist bump). Dos patas convergen al centro, estrella
 * de impacto, y se muestra la network key capturada. Cierre automático a
 * los ~5 s, con Esc o click.
 */
export function SuccessKitty({
  tick,
  keyCapture,
  label,
}: {
  tick: number;
  keyCapture: KeyCapture | null;
  label?: string;
}) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (tick <= 0) return;
    setVisible(true);
    const t = setTimeout(() => setVisible(false), 5200);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setVisible(false);
    globalThis.addEventListener("keydown", onKey);
    return () => {
      clearTimeout(t);
      globalThis.removeEventListener("keydown", onKey);
    };
  }, [tick]);

  if (!visible) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm cursor-pointer"
      onClick={() => setVisible(false)}
      role="presentation"
    >
      <div className="relative flex flex-col items-center gap-5 px-8" onClick={(e) => e.stopPropagation()}>
        {/* fist bump de patitas — huella de gato: almohadilla + 4 dedos */}
        <svg viewBox="0 0 200 120" className="w-56 h-auto" aria-hidden>
          {/* pata izquierda (Sky) — el wrapper lleva el translate/rotate para
              que la animación CSS (que pisa el atributo transform) no lo rompa */}
          <g transform="translate(48,62) rotate(62)">
            <g className="paw-left">
              {/* almohadilla principal */}
              <path
                d="M0 0 C -13 0 -19 9 -19 18 C -19 28 -10 32 0 32 C 10 32 19 28 19 18 C 19 9 13 0 0 0 Z"
                fill="#0c1220" stroke="#00e5ff" strokeWidth="3" strokeLinejoin="round"
              />
              {/* dedos (toe beans) */}
              <circle cx="-15" cy="-8" r="5.5" fill="#0c1220" stroke="#00e5ff" strokeWidth="2.5" />
              <circle cx="-5.5" cy="-14" r="5.5" fill="#0c1220" stroke="#00e5ff" strokeWidth="2.5" />
              <circle cx="5.5" cy="-14" r="5.5" fill="#0c1220" stroke="#00e5ff" strokeWidth="2.5" />
              <circle cx="15" cy="-8" r="5.5" fill="#0c1220" stroke="#00e5ff" strokeWidth="2.5" />
            </g>
          </g>
          {/* pata derecha (tú) */}
          <g transform="translate(152,62) rotate(-62)">
            <g className="paw-right">
              <path
                d="M0 0 C -13 0 -19 9 -19 18 C -19 28 -10 32 0 32 C 10 32 19 28 19 18 C 19 9 13 0 0 0 Z"
                fill="#0c1220" stroke="#7dffe9" strokeWidth="3" strokeLinejoin="round"
              />
              <circle cx="-15" cy="-8" r="5.5" fill="#0c1220" stroke="#7dffe9" strokeWidth="2.5" />
              <circle cx="-5.5" cy="-14" r="5.5" fill="#0c1220" stroke="#7dffe9" strokeWidth="2.5" />
              <circle cx="5.5" cy="-14" r="5.5" fill="#0c1220" stroke="#7dffe9" strokeWidth="2.5" />
              <circle cx="15" cy="-8" r="5.5" fill="#0c1220" stroke="#7dffe9" strokeWidth="2.5" />
            </g>
          </g>
          {/* estrella de impacto — el translate va en el wrapper: el CSS
              transform de la animación NO debe pisarlo */}
          <g transform="translate(100,70)">
            <g className="impact-star">
              <path d="M0 -16 L4 -5 L16 -4 L6 3 L10 15 L0 8 L-10 15 L-6 3 L-16 -4 L-4 -5 Z"
                fill="#00e5ff" opacity="0.95" />
            </g>
            <g className="impact-ring">
              <circle r="26" fill="none" stroke="#00e5ff" strokeWidth="2" />
            </g>
          </g>
        </svg>

        <div className="text-center">
          <div className="font-display text-2xl font-bold tracking-wide text-[#00e5ff] drop-shadow-[0_0_12px_rgba(0,229,255,.6)]">
            ¡BUENA ESA, SKY!
          </div>
          <div className="mt-1 font-mono text-sm text-cyan-200/80">
            {label ?? 'NETWORK KEY CAPTURADA'}
          </div>
        </div>

        {keyCapture && (
          <div className="rounded-md border border-cyan-500/30 bg-[#0c1220]/90 px-5 py-3 font-mono text-xs text-cyan-100/90 space-y-1">
            <div><span className="text-cyan-400/60">PAN ID&nbsp;&nbsp;:</span> {keyCapture.panId}</div>
            <div><span className="text-cyan-400/60">TC ADDR :</span> {keyCapture.tcAddr}</div>
            <div className="break-all"><span className="text-cyan-400/60">NET KEY :</span> {keyCapture.networkKey}</div>
          </div>
        )}

        <div className="font-mono text-[10px] uppercase tracking-[0.25em] text-cyan-500/50">
          click o Esc para cerrar
        </div>
      </div>
    </div>
  );
}
