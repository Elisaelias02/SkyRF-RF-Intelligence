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
}: {
  tick: number;
  keyCapture: KeyCapture | null;
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
        {/* fist bump */}
        <svg viewBox="0 0 200 120" className="w-56 h-auto" aria-hidden>
          {/* pata izquierda (Sky) */}
          <g className="paw-left">
            <path
              d="M10 78 Q10 58 34 58 L52 58 Q66 58 66 70 Q66 82 52 82 L34 82 Q10 82 10 78 Z"
              fill="#0c1220" stroke="#00e5ff" strokeWidth="3" strokeLinejoin="round"
            />
            {/* nudillos */}
            <path d="M22 58 Q24 50 30 58 M34 58 Q36 50 42 58 M46 58 Q48 50 54 58"
              fill="none" stroke="#00e5ff" strokeWidth="2.5" strokeLinecap="round" />
            {/* almohadilla */}
            <circle cx="20" cy="70" r="4" fill="none" stroke="#00e5ff" strokeWidth="2" />
          </g>
          {/* pata derecha (tú) */}
          <g className="paw-right">
            <path
              d="M190 78 Q190 58 166 58 L148 58 Q134 58 134 70 Q134 82 148 82 L166 82 Q190 82 190 78 Z"
              fill="#0c1220" stroke="#7dffe9" strokeWidth="3" strokeLinejoin="round"
            />
            <path d="M178 58 Q176 50 170 58 M166 58 Q164 50 158 58 M154 58 Q152 50 146 58"
              fill="none" stroke="#7dffe9" strokeWidth="2.5" strokeLinecap="round" />
            <circle cx="180" cy="70" r="4" fill="none" stroke="#7dffe9" strokeWidth="2" />
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
            ¡BUEN ESE, SKY!
          </div>
          <div className="mt-1 font-mono text-sm text-cyan-200/80">
            NETWORK KEY CAPTURADA
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
