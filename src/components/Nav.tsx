import { useNow } from "../hooks";

const LINKS = [
  { href: "#architecture", label: "Architecture" },
  { href: "#console", label: "Console" },
  { href: "#code", label: "Code source" },
  { href: "#deploiement", label: "Déploiement" },
];

function AtibonMark({ size = 34 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 40 40" fill="none" aria-hidden><rect x="2" y="2" width="36" height="36" rx="9" fill="rgba(245,158,11,.06)" stroke="#f59e0b"/><path d="M10 31V17l10-8 10 8v14M15 31V20h10v11" stroke="#45e0ff" strokeWidth="1.6"/><path d="M4 13h32M7 18h26" stroke="#f59e0b" strokeWidth=".8" opacity=".8"/></svg>;
}

export default function Nav() {
  const now = useNow(1000);
  const utc = new Date(now).toISOString().slice(11, 19);
  return <header className="fixed inset-x-0 top-0 z-40 border-b border-white/10 bg-[#050b10]/80 backdrop-blur-xl">
    <div className="mx-auto flex h-16 max-w-7xl items-center gap-4 px-5">
      <a href="#top" className="flex items-center gap-3"><AtibonMark /><div><div className="font-display text-base font-bold tracking-[.25em] text-white">ATIBON</div><div className="font-mono text-[9px] uppercase tracking-[.22em] text-slate-500">Souverain digital defense</div></div></a>
      <nav className="ml-auto hidden gap-1 md:flex">{LINKS.map(l=><a key={l.href} href={l.href} className="px-3 py-2 font-mono text-[10px] uppercase tracking-[.16em] text-slate-400 hover:text-cyan-300">{l.label}</a>)}</nav>
      <div className="ml-auto flex items-center gap-3 md:ml-4"><span className="led h-2 w-2 rounded-full bg-cyan-300 text-cyan-300"/><span className="hidden font-mono text-[9px] uppercase tracking-[.16em] text-cyan-300 sm:inline">Système armé</span><span className="font-mono text-[10px] text-slate-500">{utc} UTC</span></div>
    </div>
  </header>;
}
