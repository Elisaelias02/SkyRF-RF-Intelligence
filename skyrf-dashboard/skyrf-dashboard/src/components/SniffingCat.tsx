/** Sky — la gatita que olfatea el espectro mientras la captura está activa. */
export function SniffingCat({ active }: { active: boolean }) {
  return (
    <svg
      width="44" height="44" viewBox="0 0 64 64"
      aria-hidden="true"
      className={active ? 'skycat sniffing' : 'skycat'}
    >
      {/* orejas */}
      <path d="M14 22 L18 6 L28 16 Z" fill="none" stroke="#00e5ff" strokeWidth="2" strokeLinejoin="round" />
      <path d="M50 22 L46 6 L36 16 Z" fill="none" stroke="#00e5ff" strokeWidth="2" strokeLinejoin="round" />
      {/* cabeza */}
      <path d="M12 30 Q12 48 32 48 Q52 48 52 30 Q52 18 32 18 Q12 18 12 30 Z"
        fill="none" stroke="#00e5ff" strokeWidth="2" />
      {/* ojos */}
      <g className="cat-eye">
        <ellipse cx="24" cy="31" rx="2.6" ry="3.4" fill="#00e5ff" />
      </g>
      <g className="cat-eye" style={{ animationDelay: '0.08s' }}>
        <ellipse cx="40" cy="31" rx="2.6" ry="3.4" fill="#00e5ff" />
      </g>
      {/* nariz + boca */}
      <g className="cat-nose">
        <path d="M29.5 37 L34.5 37 L32 40 Z" fill="#00e5ff" />
      </g>
      <path d="M32 40 Q32 43 28.5 43.5 M32 40 Q32 43 35.5 43.5"
        fill="none" stroke="#00e5ff" strokeWidth="1.4" strokeLinecap="round" />
      {/* bigotes */}
      <g className="cat-whiskers-l">
        <path d="M6 34 Q14 35 21 36" stroke="#00e5ff" strokeWidth="1.2" fill="none" strokeLinecap="round" opacity="0.8" />
        <path d="M6 39 Q14 38.5 21 38.5" stroke="#00e5ff" strokeWidth="1.2" fill="none" strokeLinecap="round" opacity="0.6" />
      </g>
      <g className="cat-whiskers-r">
        <path d="M58 34 Q50 35 43 36" stroke="#00e5ff" strokeWidth="1.2" fill="none" strokeLinecap="round" opacity="0.8" />
        <path d="M58 39 Q50 38.5 43 38.5" stroke="#00e5ff" strokeWidth="1.2" fill="none" strokeLinecap="round" opacity="0.6" />
      </g>
      {/* ondas de olfateo — solo cuando sniffing */}
      <g className="sniff-waves">
        <path className="sniff-wave" d="M30 52 Q32 55 34 52" stroke="#00e5ff" strokeWidth="1.3" fill="none" strokeLinecap="round" />
        <path className="sniff-wave" d="M29 56 Q32 60 35 56" stroke="#00e5ff" strokeWidth="1.3" fill="none" strokeLinecap="round" style={{ animationDelay: '0.35s' }} />
        <path className="sniff-wave" d="M28 60 Q32 65 36 60" stroke="#00e5ff" strokeWidth="1.3" fill="none" strokeLinecap="round" style={{ animationDelay: '0.7s' }} />
      </g>
    </svg>
  );
}
