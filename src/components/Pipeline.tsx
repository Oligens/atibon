import { useReducedMotion, useReveal } from "../hooks";

const FORMULAS = [
  { fx: "V′ = M · V", caption: "Transformation à l'entrée — le trafic devient illisible au sniffing" },
  { fx: "det(M) ≠ 0 · scellé", caption: "Verrou structurel — toute altération de M fait diverger le déterminant" },
  { fx: "V = M⁻¹ · V′", caption: "Restitution à la sortie — seul le pare-feu détient l'inverse" },
];

const STATS = [
  { k: "N = 12", v: "dimension fixe du vecteur d'état" },
  { k: "0xC04AC0DE", v: "seed scellée de la matrice-clé" },
  { k: "FNV-1a", v: "empreinte d'intégrité 16 bits du payload" },
  { k: "≤ 10⁻⁹", v: "dérive relative tolérée sur det(M)" },
];

const GATEWAYS = [
  {
    id: "01",
    name: "Passerelle d'Ingress",
    zone: "Zone de captage & normalisation",
    accent: "#2bff9e",
    bullets: [
      "Point d'entrée unique du trafic — interception des paquets bruts.",
      "Suppression des en-têtes corrompus, normalisation IPv4/IPv6.",
      "Projection de chaque paquet sur le vecteur d'état V ∈ ℝ¹².",
    ],
  },
  {
    id: "02",
    name: "Passerelle Matrice",
    zone: "Zone de transformation algorithmique",
    accent: "#ffb347",
    bullets: [
      "Cœur névralgique : conversion des flux en matrices d'état.",
      "Multiplication par la matrice-clé M — neutralisation des charges polymorphes.",
      "Contrôle permanent du déterminant : divergence = blocage immédiat.",
    ],
  },
  {
    id: "03",
    name: "Passerelle d'Egress",
    zone: "Zone de restitution & micro-segmentation",
    accent: "#45e0ff",
    bullets: [
      "Application de M⁻¹ et restitution du paquet d'origine à l'identique.",
      "Vérification FNV-1a bout-en-bout du payload.",
      "Réencapsulation en VLANs dynamiques isolés, chiffrement de bout en bout.",
    ],
  },
];

function PipelineDiagram() {
  const reduced = useReducedMotion();
  const box = (x: number, y: number, w: number, h: number, accent: string) => (
    <g>
      <rect x={x} y={y} width={w} height={h} fill="rgba(10,20,16,0.92)" stroke={accent} strokeWidth="1.2" />
      <rect x={x} y={y} width={w} height={h} fill="none" stroke="#1c3527" strokeWidth="4" opacity="0.35" />
      <path d={`M ${x} ${y + 14} v -14 h 14`} stroke={accent} strokeWidth="2" fill="none" />
      <path d={`M ${x + w - 14} ${y + h} h 14 v -14`} stroke={accent} strokeWidth="2" fill="none" />
    </g>
  );

  return (
    <svg viewBox="0 0 720 880" className="w-full" role="img" aria-label="Schéma du pipeline à triple passerelle">
      <defs>
        <radialGradient id="glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="rgba(43,255,158,0.14)" />
          <stop offset="100%" stopColor="rgba(43,255,158,0)" />
        </radialGradient>
      </defs>
      <circle cx="360" cy="440" r="330" fill="url(#glow)" />

      {/* connecteurs */}
      <path d="M 300 200 C 300 260, 300 290, 300 350" stroke="#1c3527" strokeWidth="2" fill="none" className={reduced ? "" : "dash-flow"} strokeDasharray="6 8" />
      <path d="M 300 570 C 300 630, 300 610, 300 670" stroke="#1c3527" strokeWidth="2" fill="none" className={reduced ? "" : "dash-flow"} strokeDasharray="6 8" />
      <path d="M 470 670 C 470 610, 470 260, 470 200" stroke="rgba(69,224,255,0.25)" strokeWidth="1.4" fill="none" strokeDasharray="3 9" className={reduced ? "" : "dash-flow"} />

      {/* paquets descendants (flux transformé V') */}
      {!reduced && (
        <g>
          {[0, 1.4, 2.8].map((b) => (
            <circle key={`d${b}`} r="4.5" fill="#2bff9e" opacity="0.95">
              <animateMotion dur="4.2s" begin={`${b}s`} repeatCount="indefinite" path="M 300 160 C 300 300, 300 560, 300 720" />
            </circle>
          ))}
          {[0.7, 3.1].map((b) => (
            <circle key={`u${b}`} r="3" fill="#45e0ff" opacity="0.8">
              <animateMotion dur="5.6s" begin={`${b}s`} repeatCount="indefinite" path="M 470 720 C 470 500, 470 320, 470 160" />
            </circle>
          ))}
        </g>
      )}
      {reduced && (
        <g>
          <circle cx="300" cy="275" r="4.5" fill="#2bff9e" />
          <circle cx="300" cy="620" r="4.5" fill="#2bff9e" />
          <circle cx="470" cy="430" r="3" fill="#45e0ff" />
        </g>
      )}

      {/* ── Passerelle Ingress ── */}
      {box(80, 30, 560, 170, "#2bff9e")}
      <text x="110" y="72" fontFamily="Chakra Petch, sans-serif" fontWeight="700" fontSize="19" fill="#eafff3">PASSERELLE INGRESS</text>
      <text x="110" y="94" fontFamily="IBM Plex Mono, monospace" fontSize="11" fill="#6f8a7b">ZONE DE CAPTAGE & NORMALISATION</text>
      <text x="110" y="126" fontFamily="IBM Plex Mono, monospace" fontSize="12" fill="#8fae9d">› paquets bruts → vecteurs V ∈ ℝ¹²</text>
      <text x="110" y="148" fontFamily="IBM Plex Mono, monospace" fontSize="12" fill="#8fae9d">› en-têtes corrompus purgés · IPv4/IPv6</text>
      <text x="110" y="170" fontFamily="IBM Plex Mono, monospace" fontSize="12" fill="#8fae9d">› checksum FNV-1a apposé sur le payload</text>
      <text x="616" y="72" textAnchor="end" fontFamily="IBM Plex Mono, monospace" fontSize="11" fill="#2bff9e">[ 01 ]</text>

      {/* ── Passerelle Matrice ── */}
      {box(80, 350, 560, 220, "#ffb347")}
      <text x="110" y="392" fontFamily="Chakra Petch, sans-serif" fontWeight="700" fontSize="19" fill="#eafff3">PASSERELLE MATRICE</text>
      <text x="110" y="414" fontFamily="IBM Plex Mono, monospace" fontSize="11" fill="#6f8a7b">ZONE DE TRANSFORMATION ALGORITHMIQUE</text>
      <text x="110" y="448" fontFamily="IBM Plex Mono, monospace" fontSize="13" fill="#ffb347">V′ = M · V      — neutralise sniffing & charges polymorphes</text>
      <text x="110" y="472" fontFamily="IBM Plex Mono, monospace" fontSize="13" fill="#ffb347">det(M) scellé   — divergence → blocage + leurre</text>
      <text x="110" y="496" fontFamily="IBM Plex Mono, monospace" fontSize="13" fill="#ffb347">checksum ≠ attendu → quarantaine 24 h</text>
      <text x="110" y="532" fontFamily="IBM Plex Mono, monospace" fontSize="11" fill="#6f8a7b">bouclier anti-inspection actif : TracerPid · intégrité binaire · LD_PRELOAD</text>
      <text x="616" y="392" textAnchor="end" fontFamily="IBM Plex Mono, monospace" fontSize="11" fill="#ffb347">[ 02 ]</text>

      {/* ── Passerelle Egress ── */}
      {box(80, 670, 560, 170, "#45e0ff")}
      <text x="110" y="712" fontFamily="Chakra Petch, sans-serif" fontWeight="700" fontSize="19" fill="#eafff3">PASSERELLE EGRESS</text>
      <text x="110" y="734" fontFamily="IBM Plex Mono, monospace" fontSize="11" fill="#6f8a7b">ZONE DE RESTITUTION & MICRO-SEGMENTATION</text>
      <text x="110" y="766" fontFamily="IBM Plex Mono, monospace" fontSize="12" fill="#8fae9d">› V = M⁻¹ · V′ — restitution bit-à-bit</text>
      <text x="110" y="788" fontFamily="IBM Plex Mono, monospace" fontSize="12" fill="#8fae9d">› intégrité FNV-1a vérifiée de bout en bout</text>
      <text x="110" y="810" fontFamily="IBM Plex Mono, monospace" fontSize="12" fill="#8fae9d">› VLANs dynamiques · chiffrement E2E</text>
      <text x="616" y="712" textAnchor="end" fontFamily="IBM Plex Mono, monospace" fontSize="11" fill="#45e0ff">[ 03 ]</text>
    </svg>
  );
}

export default function Pipeline() {
  const reveal = useReveal();
  const gw0 = useReveal();
  const gw1 = useReveal();
  const gw2 = useReveal();
  const gwReveals = [gw0, gw1, gw2];

  return (
    <section id="architecture" className="relative mx-auto max-w-7xl px-5 pt-28">
      <div className="grid gap-14 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
        {/* colonne texte — sticky */}
        <div className="lg:sticky lg:top-24 lg:self-start">
          <div ref={reveal.ref} className={`reveal ${reveal.inView ? "is-in" : ""}`}>
            <p className="font-mono text-[11px] uppercase tracking-[0.34em] text-[#2bff9e]">01 · Architecture globale</p>
            <h2 className="font-display mt-4 text-4xl font-bold leading-[1.05] text-[#eafff3] sm:text-5xl">
              Trois passerelles,
              <br />
              un noyau <span className="text-[#ffb347]">matriciel</span>.
            </h2>
            <p className="mt-6 max-w-xl text-[15px] leading-relaxed text-[#8fae9d]">
              Chaque flux est capté, projeté dans un espace vectoriel de dimension fixe, multiplié par une matrice
              inversible <span className="font-mono text-[#eafff3]">M ∈ GL(12, ℝ)</span> dont seul le pare-feu détient
              l'inverse — puis restitué à l'identique après double contrôle : déterminant scellé et empreinte FNV-1a.
            </p>

            <div className="mt-10 space-y-1 border-l-2 border-[#1c3527]">
              {FORMULAS.map((f, i) => (
                <div
                  key={f.fx}
                  className="group border-b border-[#101f17] py-4 pl-6 transition-colors duration-300 hover:border-[#2bff9e]/40 hover:bg-[#0a1410]"
                >
                  <div className="font-mono text-xl font-semibold text-[#eafff3] transition-colors duration-300 group-hover:text-[#2bff9e] sm:text-2xl">
                    <span className="mr-3 text-[#3d5a4a]">{String(i + 1).padStart(2, "0")}</span>
                    {f.fx}
                  </div>
                  <p className="mt-1.5 pl-9 text-[13px] text-[#6f8a7b]">{f.caption}</p>
                </div>
              ))}
            </div>

            <dl className="mt-10 grid grid-cols-2 gap-x-6 gap-y-6">
              {STATS.map((s) => (
                <div key={s.k} className="border-t border-[#14261d] pt-3">
                  <dt className="font-mono text-[15px] font-semibold text-[#2bff9e]">{s.k}</dt>
                  <dd className="mt-1 text-[12px] leading-snug text-[#6f8a7b]">{s.v}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>

        {/* schéma */}
        <div className="relative">
          <div className="pointer-events-none absolute -inset-6 border border-[#14261d]" />
          <PipelineDiagram />
        </div>
      </div>

      {/* détail des passerelles — lignes alternées */}
      <div className="mt-24">
        {GATEWAYS.map((g, i) => {
          const rv = gwReveals[i];
          return (
            <div
              key={g.id}
              ref={rv.ref}
              className={`reveal group grid gap-6 border-t border-[#14261d] py-10 transition-colors duration-300 hover:bg-[#071009] md:grid-cols-[110px_1fr_1.3fr] md:gap-10 ${rv.inView ? "is-in" : ""}`}
            >
              <div
                className="font-display text-5xl font-bold leading-none transition-colors duration-300"
                style={{ color: g.accent, opacity: 0.9 }}
              >
                {g.id}
              </div>
              <div>
                <h3 className="font-display text-2xl font-bold text-[#eafff3]">{g.name}</h3>
                <p className="mt-2 font-mono text-[11px] uppercase tracking-[0.22em] text-[#6f8a7b]">{g.zone}</p>
                <span
                  className="mt-5 block h-[3px] w-14 transition-all duration-500 group-hover:w-28"
                  style={{ backgroundColor: g.accent }}
                />
              </div>
              <ul className="space-y-3 self-center">
                {g.bullets.map((b) => (
                  <li key={b} className="flex gap-3 text-[14px] leading-relaxed text-[#9db8a9]">
                    <span className="mt-[7px] h-[7px] w-[7px] shrink-0 rotate-45" style={{ backgroundColor: g.accent, opacity: 0.8 }} />
                    {b}
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </section>
  );
}
