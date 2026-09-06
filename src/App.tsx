import Nav from "./components/Nav";
import Pipeline from "./components/Pipeline";
import ConsoleDemo from "./components/ConsoleDemo";
import CodeSection from "./components/CodeSection";
import Deploy from "./components/Deploy";
import Footer from "./components/Footer";
import HoneypotOverlay from "./components/HoneypotOverlay";
import { useEffect, useState } from "react";
import { HONEYPOT_PATH, installSecurityInterceptor } from "./security/securityInterceptor";

const BOOT_LINES = [
  "$ atibon-core --release",
  "   Initialisation du noyau souverain ATIBON",
  "[dpi     ] inspection IPv4/TCP/UDP active",
  "[consensus] quorum byzantin prêt",
  "[crypto  ] politique PQC/HSM/TPM chargée",
  "[zero-trust] identité de service requise",
  "[atibon  ] système de défense en ligne ✔",
];

function BootTerminal() {
  return (
    <div className="glass-panel relative overflow-hidden p-5 font-mono text-xs leading-7">
      <div className="mb-4 flex items-center justify-between border-b border-cyan-300/15 pb-3">
        <span className="tracking-[.2em] text-slate-400">ATIBON / CORE TELEMETRY</span>
        <span className="text-cyan-300">● OPERATIONAL</span>
      </div>
      {BOOT_LINES.map((line) => <div key={line} className={line.includes("✔") ? "text-amber-300" : "text-slate-300"}>{line}</div>)}
    </div>
  );
}

export default function App() {
  const [honeypot, setHoneypot] = useState(() => window.location.pathname === HONEYPOT_PATH);

  useEffect(() => {
    const onThreat = () => setHoneypot(true);
    window.addEventListener("atibon:honeypot", onThreat);
    const uninstall = installSecurityInterceptor();
    return () => {
      window.removeEventListener("atibon:honeypot", onThreat);
      uninstall();
    };
  }, []);

  if (honeypot) return <HoneypotOverlay />;

  return (
    <div id="top" className="relative min-h-screen bg-[#050b10] text-slate-100">
      <div className="crt-overlay" aria-hidden />
      <div className="noise-overlay" aria-hidden />
      <div className="vignette" aria-hidden />
      <Nav />
      <main>
        <section className="blueprint relative overflow-hidden pt-32">
          <div className="mx-auto grid max-w-7xl gap-12 px-5 pb-20 lg:grid-cols-[1.1fr_.9fr] lg:items-center">
            <div className="rise-in">
              <div className="mb-6 flex flex-wrap gap-2 font-mono text-[10px] uppercase tracking-[.22em]">
                <span className="glass-chip border-amber-300/30 text-amber-300">ATIBON</span>
                <span className="glass-chip border-cyan-300/30 text-cyan-300">Souverain</span>
                <span className="glass-chip">Rust · Python · Zero Trust</span>
              </div>
              <p className="font-mono text-xs uppercase tracking-[.28em] text-cyan-300/70">Portail de défense numérique</p>
              <h1 className="mt-4 max-w-4xl font-display text-5xl font-bold tracking-tight sm:text-7xl">Le seuil sécurisé.</h1>
              <p className="mt-7 max-w-2xl text-base leading-8 text-slate-400">ATIBON unifie inspection réseau, décision distribuée, cryptographie post-quantique, intelligence défensive et confiance matérielle dans une architecture conçue pour être vérifiable et fail-closed.</p>
              <div className="mt-9 flex flex-wrap gap-4">
                <a href="#console" className="hud-btn border border-amber-300/40 bg-amber-300/10 px-7 py-3 text-amber-200 hover:bg-amber-300/20">▶ Ouvrir la console</a>
                <a href="#architecture" className="hud-btn border border-cyan-300/30 px-7 py-3 text-cyan-200 hover:bg-cyan-300/10">⌘ Architecture</a>
              </div>
              <div className="mt-12 grid max-w-2xl grid-cols-2 gap-5 sm:grid-cols-4">
                {[['DPI','paquet par paquet'],['BFT','état distribué'],['PQC','KEM + signature'],['TPM 2.0','attestation']].map(([k,v]) => <div key={k} className="border-t border-white/10 pt-3"><div className="font-display text-lg text-amber-200">{k}</div><div className="text-xs text-slate-500">{v}</div></div>)}
              </div>
            </div>
            <div className="rise-in" style={{animationDelay:'120ms'}}>
              <div className="arch-mark mx-auto mb-7" aria-label="Symbole ATIBON" role="img"><div className="arch-flow flow-a"/><div className="arch-flow flow-b"/><div className="arch-door"/></div>
              <BootTerminal />
            </div>
          </div>
        </section>
        <div className="overflow-hidden border-y border-white/10 bg-white/[.02] py-3 font-mono text-[10px] uppercase tracking-[.2em] text-slate-500"><div className="ticker-track flex w-max gap-10">{['ATIBON CORE','DPI','HONEYBADGER INTERFACE','ML-KEM / FALCON PROVIDER','HSM / PKCS#11','TPM 2.0','ZERO TRUST','AUDIT INTEGRITY','FAIL-CLOSED'].concat(['ATIBON CORE','DPI','ZERO TRUST']).map((x,i)=><span key={i}>✦ {x}</span>)}</div></div>
        <Pipeline />
        <ConsoleDemo />
        <CodeSection />
        <Deploy />
      </main>
      <Footer />
    </div>
  );
}
