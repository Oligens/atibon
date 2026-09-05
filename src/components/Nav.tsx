import { useNow } from "../hooks";

const LINKS = [
  { href: "#architecture", label: "Architecture" },
  { href: "#console", label: "Console" },
  { href: "#code", label: "Code source" },
  { href: "#deploiement", label: "Déploiement" },
];

/** Marque COJ : hexagone + monogramme. */
function CojMark({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" aria-hidden>
      <path
        d="M20 2.5 35 11v18L20 37.5 5 29V11L20 2.5Z"
        stroke="#2bff9e"
        strokeWidth="1.6"
        fill="rgba(43,255,158,0.06)"
      />
      <path d="M20 8.5 29.5 14v12L20 31.5 10.5 26V14L20 8.5Z" stroke="#1a8f5f" strokeWidth="1" fill="none" />
      <text x="20" y="24.5" textAnchor="middle" fontFamily="Chakra Petch, sans-serif" fontWeight="700" fontSize="10.5" fill="#2bff9e">
        COJ
      </text>
    </svg>
  );
}

export default function Nav() {
  const now = useNow(1000);
  const utc = new Date(now).toISOString().slice(11, 19);

  return (
    <header className="fixed inset-x-0 top-0 z-40 border-b border-[#14261d] bg-[#04080a]/85 backdrop-blur-sm">
      <div className="mx-auto flex h-14 max-w-7xl items-center gap-6 px-5">
        <a href="#top" className="flex items-center gap-3">
          <CojMark />
          <div className="leading-none">
            <div className="font-display text-[15px] font-bold tracking-[0.22em] text-[#eafff3]">
              COJ-MATRIX <span className="text-[#2bff9e]">FIREWALL</span>
            </div>
            <div className="mt-1 font-mono text-[10px] tracking-[0.3em] text-[#6f8a7b]">PoC v0.1.0 · RUST · NALGEBRA</div>
          </div>
        </a>

        <nav className="ml-auto hidden items-center gap-1 md:flex">
          {LINKS.map((l) => (
            <a
              key={l.href}
              href={l.href}
              className="px-3 py-2 font-mono text-[11px] uppercase tracking-[0.18em] text-[#8fae9d] transition-colors duration-200 hover:bg-[#0d1a14] hover:text-[#2bff9e]"
            >
              {l.label}
            </a>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-4 md:ml-6">
          <div className="hidden items-center gap-2 sm:flex">
            <span className="led h-2 w-2 rounded-full bg-[#2bff9e] text-[#2bff9e]" />
            <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#7dffb9]">Système armé</span>
          </div>
          <span className="font-mono text-[11px] tabular-nums tracking-wider text-[#6f8a7b]">{utc} UTC</span>
        </div>
      </div>
    </header>
  );
}
