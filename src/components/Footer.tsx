const MODULES = [
  { n: "packet.rs", d: "vectorisation ℝ¹² + FNV-1a" },
  { n: "matrix_engine.rs", d: "M · M⁻¹ + det(M) scellé" },
  { n: "shield.rs", d: "TracerPid · intégrité · LD_PRELOAD" },
  { n: "rain.rs", d: "leurre digital rain / COJ" },
];

const SECTIONS = [
  { href: "#architecture", label: "01 · Architecture" },
  { href: "#code", label: "02 · Code source" },
  { href: "#console", label: "03 · Démonstration" },
  { href: "#deploiement", label: "04 · Déploiement" },
];

const RESSOURCES = [
  { href: "https://docs.rs/nalgebra/latest/nalgebra/", label: "docs.rs — nalgebra" },
  { href: "https://doc.rust-lang.org/book/", label: "The Rust Book" },
  { href: "https://www.freedesktop.org/software/systemd/man/systemd.service.html", label: "systemd.service(5)" },
];

export default function Footer() {
  return (
    <footer className="mt-32 border-t border-[#14261d] bg-[#050b08]">
      <div className="mx-auto grid max-w-7xl gap-12 px-5 py-16 md:grid-cols-[1.4fr_1fr_1fr_1fr]">
        <div>
          <div className="flex items-center gap-3">
            <svg width="34" height="34" viewBox="0 0 40 40" fill="none" aria-hidden>
              <path d="M20 2.5 35 11v18L20 37.5 5 29V11L20 2.5Z" stroke="#2bff9e" strokeWidth="1.6" fill="rgba(43,255,158,0.06)" />
              <text x="20" y="24.5" textAnchor="middle" fontFamily="Chakra Petch, sans-serif" fontWeight="700" fontSize="10.5" fill="#2bff9e">
                COJ
              </text>
            </svg>
            <div className="font-display text-lg font-bold tracking-[0.2em] text-[#eafff3]">
              COJ-MATRIX <span className="text-[#2bff9e]">FIREWALL</span>
            </div>
          </div>
          <p className="mt-5 max-w-sm text-[13px] leading-relaxed text-[#6f8a7b]">
            Proof of Concept éducatif de défense en profondeur : algèbre linéaire appliquée au trafic, bouclier
            anti-inspection et leurre visuel anti-reverse engineering.
          </p>
          <p className="mt-6 font-mono text-[11px] tracking-[0.18em] text-[#3d5a4a]">
            V′ = M·V · det(M) ≠ 0 · V = M⁻¹·V′
          </p>
        </div>

        <nav>
          <h4 className="font-mono text-[11px] uppercase tracking-[0.28em] text-[#2bff9e]">Sections</h4>
          <ul className="mt-5 space-y-3">
            {SECTIONS.map((s) => (
              <li key={s.href}>
                <a href={s.href} className="text-[13px] text-[#8fae9d] transition-colors hover:text-[#2bff9e]">
                  {s.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>

        <div>
          <h4 className="font-mono text-[11px] uppercase tracking-[0.28em] text-[#2bff9e]">Modules du noyau</h4>
          <ul className="mt-5 space-y-3">
            {MODULES.map((m) => (
              <li key={m.n}>
                <div className="font-mono text-[12.5px] text-[#eafff3]">{m.n}</div>
                <div className="text-[11.5px] text-[#6f8a7b]">{m.d}</div>
              </li>
            ))}
          </ul>
        </div>

        <div>
          <h4 className="font-mono text-[11px] uppercase tracking-[0.28em] text-[#2bff9e]">Ressources</h4>
          <ul className="mt-5 space-y-3">
            {RESSOURCES.map((r) => (
              <li key={r.href}>
                <a
                  href={r.href}
                  target="_blank"
                  rel="noreferrer"
                  className="text-[13px] text-[#8fae9d] transition-colors hover:text-[#45e0ff]"
                >
                  {r.label} ↗
                </a>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="border-t border-[#14261d]">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-5 py-5">
          <span className="font-mono text-[11px] tracking-[0.16em] text-[#3d5a4a]">
            © 2026 COJ SECURITY LAB — PoC éducatif · ne constitue pas un audit de sécurité
          </span>
          <span className="flex items-center gap-2 font-mono text-[11px] tracking-[0.16em] text-[#3d5a4a]">
            <span className="led h-1.5 w-1.5 rounded-full bg-[#2bff9e] text-[#2bff9e]" />
            noyau matriciel en ligne
          </span>
        </div>
      </div>
    </footer>
  );
}
