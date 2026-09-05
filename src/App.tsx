import Nav from "./components/Nav";
import Pipeline from "./components/Pipeline";
import ConsoleDemo from "./components/ConsoleDemo";
import CodeSection from "./components/CodeSection";
import Deploy from "./components/Deploy";
import Footer from "./components/Footer";
import { useScramble, useTypedLines } from "./hooks";

const BOOT_LINES = [
  "$ cargo run --release",
  "   Compiling coj-matrix-firewall v0.1.0",
  "    Finished release [optimized] target(s) in 4.21s",
  "[shield ] TracerPid=0 · binaire intègre — ARMÉ",
  "[matrice] det(M) = +4.311782e+02 scellé",
  "[ingress] écoute active : 0.0.0.0:{80, 443, 8080}",
  "[coj    ] pare-feu matriciel en ligne ✔",
];

const TICKER = [
  "V′ = M·V",
  "det(M) ≠ 0 scellé",
  "GL(12, ℝ)",
  "FNV-1a 16-bit",
  "seed 0xC04AC0DE",
  "TracerPid watch",
  "strip = true",
  "panic = abort",
  "quarantaine 24 h",
  "VLAN dynamique",
  "COJ digital rain",
  "piste d'Ouméga",
];

function BootTerminal() {
  const t = useTypedLines(BOOT_LINES, true, 9, 160);
  return (
    <div className="relative border border-[#14261d] bg-[#050b08] shadow-[0_0_60px_rgba(43,255,158,0.06),inset_0_0_40px_rgba(43,255,158,0.03)]">
      <span className="hud-corner tl border-[#2bff9e]" />
      <span className="hud-corner tr border-[#2bff9e]" />
      <span className="hud-corner bl border-[#2bff9e]" />
      <span className="hud-corner br border-[#2bff9e]" />
      <div className="flex items-center justify-between border-b border-[#14261d] px-4 py-2.5">
        <span className="font-mono text-[10.5px] tracking-[0.18em] text-[#6f8a7b]">amorçage — stdout</span>
        <span className="flex items-center gap-2">
          <span className="led h-1.5 w-1.5 rounded-full bg-[#2bff9e] text-[#2bff9e]" />
          <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#2bff9e]">armé</span>
        </span>
      </div>
      <div className="min-h-[248px] p-5 font-mono text-[12px] leading-[1.85]">
        {BOOT_LINES.slice(0, t.line + 1).map((line, i) => {
          const text = i < t.line ? line : line.slice(0, t.char);
          const isCmd = line.startsWith("$");
          const tone = isCmd
            ? "text-[#eafff3]"
            : line.startsWith("[ALERTE")
              ? "text-[#ff6b85]"
              : line.includes("ARMÉ") || line.includes("✔")
                ? "text-[#2bff9e]"
                : "text-[#8fae9d]";
          return (
            <div key={i} className={`whitespace-pre-wrap ${tone}`}>
              {isCmd ? <span className="select-none text-[#2bff9e]">❯ </span> : null}
              {text}
              {i === Math.min(t.line, BOOT_LINES.length - 1) && !t.done && (
                <span className="cursor-blink text-[#2bff9e]"> ▍</span>
              )}
            </div>
          );
        })}
        {t.done && (
          <div className="text-[#eafff3]">
            <span className="select-none text-[#2bff9e]">❯ </span>
            <span className="cursor-blink text-[#2bff9e]">▍</span>
          </div>
        )}
      </div>
      <div className="border-t border-[#14261d] px-5 py-2.5 font-mono text-[10px] tracking-[0.16em] text-[#3d5a4a]">
        sortie réelle du PoC — cycle nominal
      </div>
    </div>
  );
}

function Hero() {
  const title = useScramble("LE TRAFIC DEVIENT MATRICE.", true, 26);
  return (
    <section className="blueprint relative overflow-hidden pt-32">
      <div className="mx-auto grid max-w-7xl gap-14 px-5 pb-20 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] lg:gap-12">
        <div className="rise-in">
          <div className="flex flex-wrap items-center gap-3 font-mono text-[10.5px] uppercase tracking-[0.3em]">
            <span className="border border-[#2a4d39] bg-[#0d1a14] px-3 py-1.5 text-[#2bff9e]">PoC · Rust</span>
            <span className="border border-[#14261d] px-3 py-1.5 text-[#6f8a7b]">nalgebra</span>
            <span className="border border-[#14261d] px-3 py-1.5 text-[#6f8a7b]">défense en profondeur</span>
            <span className="border border-[#14261d] px-3 py-1.5 text-[#6f8a7b]">anti-reverse</span>
          </div>

          <p className="mt-9 font-mono text-[13px] tracking-[0.14em] text-[#6f8a7b]">
            coj-matrix-firewall <span className="text-[#ffb347]">v0.1.0</span> — noyau matriciel &amp; leurre actif
          </p>
          <h1 className="font-display title-flicker mt-4 text-[42px] font-bold leading-[0.98] tracking-tight text-[#eafff3] sm:text-6xl xl:text-7xl">
            {title || " "}
          </h1>

          <p className="mt-8 max-w-xl text-[15.5px] leading-relaxed text-[#8fae9d]">
            Chaque paquet est projeté dans <span className="font-mono text-[#eafff3]">ℝ¹²</span>, multiplié par une
            matrice inversible <span className="font-mono text-[#ffb347]">M</span> dont seul le pare-feu détient
            l'inverse. Quiconque altère le flux — ou tente de disséquer le binaire — se retrouve face à un{" "}
            <span className="font-mono text-[#2bff9e]">crâne ASCII sous la pluie de code</span>, pendant que le
            trafic légitime, lui, passe.
          </p>

          <div className="mt-10 flex flex-wrap gap-4">
            <a
              href="#console"
              className="hud-btn bg-[#2bff9e] px-8 py-3.5 text-[13px] font-semibold text-[#04120b] hover:bg-[#7dffb9] hover:shadow-[0_0_36px_rgba(43,255,158,0.4)]"
            >
              ▶ Lancer la démonstration
            </a>
            <a
              href="#code"
              className="hud-btn border border-[#2a4d39] px-8 py-3.5 text-[13px] text-[#7dffb9] hover:border-[#2bff9e] hover:bg-[#0d1a14] hover:text-[#eafff3]"
            >
              ⌕ Lire le code source
            </a>
          </div>

          <dl className="mt-14 grid max-w-xl grid-cols-2 gap-x-8 gap-y-5 sm:grid-cols-4">
            {[
              { k: "GL(12, ℝ)", v: "groupe de la matrice-clé" },
              { k: "≤ 10⁻⁹", v: "dérive tolérée sur det(M)" },
              { k: "3", v: "sondes anti-inspection" },
              { k: "18 i/s", v: "rendu du leurre ANSI" },
            ].map((s) => (
              <div key={s.k} className="border-t-2 border-[#1c3527] pt-3 transition-colors duration-300 hover:border-[#2bff9e]">
                <dt className="font-display text-xl font-bold text-[#eafff3]">{s.k}</dt>
                <dd className="mt-1 text-[11.5px] leading-snug text-[#6f8a7b]">{s.v}</dd>
              </div>
            ))}
          </dl>
        </div>

        <div className="rise-in lg:pt-10" style={{ animationDelay: "0.15s" }}>
          <BootTerminal />
          <div className="mt-6 grid grid-cols-3 gap-px border border-[#14261d] bg-[#14261d]">
            {[
              { k: "ingress", v: "captage", c: "#2bff9e" },
              { k: "matrice", v: "M·V / det", c: "#ffb347" },
              { k: "egress", v: "M⁻¹·V′", c: "#45e0ff" },
            ].map((z) => (
              <div key={z.k} className="group bg-[#071009] px-4 py-3 text-center transition-colors hover:bg-[#0d1a14]">
                <div className="font-mono text-[10px] uppercase tracking-[0.24em]" style={{ color: z.c }}>
                  {z.k}
                </div>
                <div className="mt-1 font-mono text-[11px] text-[#8fae9d] group-hover:text-[#eafff3]">{z.v}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function Ticker() {
  return (
    <div className="overflow-hidden border-y border-[#14261d] bg-[#050b08] py-3">
      <div className="ticker-track flex w-max items-center gap-10">
        {[...TICKER, ...TICKER].map((t, i) => (
          <span key={i} className="flex items-center gap-10 font-mono text-[11.5px] tracking-[0.2em] text-[#6f8a7b]">
            <span className="transition-colors duration-300 hover:text-[#2bff9e]">{t}</span>
            <span className="text-[#2bff9e]">✦</span>
          </span>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  return (
    <div id="top" className="relative min-h-screen">
      {/* superpositions CRT */}
      <div className="crt-overlay" aria-hidden />
      <div className="noise-overlay" aria-hidden />
      <div className="vignette" aria-hidden />

      <Nav />
      <main>
        <Hero />
        <Ticker />
        <Pipeline />
        <ConsoleDemo />
        <CodeSection />
        <Deploy />
      </main>
      <Footer />
    </div>
  );
}
