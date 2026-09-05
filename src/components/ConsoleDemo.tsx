import { useEffect, useMemo, useRef, useState } from "react";
import { useReducedMotion, useReveal } from "../hooks";
import {
  DEFAULT_PACKET,
  MATRIX_SEED,
  checksumPacket,
  determinant,
  fmtHex16,
  fmtHex32,
  fmtSci,
  fnv1a32str,
  generateMatrix,
  identityError,
  invertMatrix,
  ipToStr,
  matVec,
} from "../lib/matrix";

type LineCls = "sys" | "cmd" | "ok" | "data" | "alert" | "title";
interface Line { step: number; cls: LineCls; text: string; delay: number; decoy?: boolean; }

export default function ConsoleDemo() {
  const reduced = useReducedMotion();
  const reveal = useReveal();
  const [tamper, setTamper] = useState(false);
  const [started, setStarted] = useState(false);
  const [runId, setRunId] = useState(0);
  const [lines, setLines] = useState<Line[]>([]);
  const [step, setStep] = useState(-1);
  const [done, setDone] = useState(false);
  const [decoyOn, setDecoyOn] = useState(false);
  const termRef = useRef<HTMLDivElement>(null);

  const core = useMemo(() => {
    const m = generateMatrix(MATRIX_SEED);
    const inv = invertMatrix(m)!;
    const pkt = DEFAULT_PACKET;
    const v = [...pkt.src, ...pkt.dst, (pkt.port >> 8) & 0xff, pkt.port & 0xff, 0, 0].slice(0, 12);
    const chk = checksumPacket(pkt.payload);
    v[10] = (chk >> 8) & 0xff;
    v[11] = chk & 0xff;
    const vPrime = matVec(m, v);
    const tamperedVp = vPrime.map((x, i) => (i === 3 ? x * 1.62 : i === 9 ? x + 47 : x));
    const restored = matVec(inv, vPrime);
    const restoredT = matVec(inv, tamperedVp);
    const b = (a: number[], i: number) => Math.min(255, Math.max(0, Math.round(a[i])));
    const chkObserved = ((b(restoredT, 10) & 0xff) << 8) | (b(restoredT, 11) & 0xff);
    return {
      v, vPrime, chk, chkObserved,
      detRef: determinant(m),
      idErr: identityError(m, inv),
      errMax: Math.max(...restored.map((x, i) => Math.abs(x - v[i]))),
      bootHash: fnv1a32str("atibon::poc"),
      vlan: (chk & 0x0f) + 10,
    };
  }, []);

  const script = useMemo<Line[]>(() => {
    const L: Line[] = [];
    const add = (step: number, cls: LineCls, text: string, delay = 260, decoy = false) => L.push({ step, cls, text, delay, decoy });
    const p = DEFAULT_PACKET;
    add(-1, "title", "┌────────────────────────────────────────────────────────┐", 40);
    add(-1, "title", "│  ATIBON · CONSOLE DE DÉFENSE · noyau souverain         │", 40);
    add(-1, "title", "│  DPI · BFT · PQC · ZERO TRUST · TPM 2.0               │", 40);
    add(-1, "title", "└────────────────────────────────────────────────────────┘", 320);
    add(-1, "cmd", "atibon-core --release", 500);
    add(0, "sys", `[shield ] empreinte binaire FNV-1a : ${fmtHex32(core.bootHash)}`, 300);
    add(0, "ok", "[shield ] noyau intègre — système ATIBON PRÊT.", 420);
    add(1, "data", `[paquet ] ${ipToStr(p.src)} → ${ipToStr(p.dst)}:${p.port} · ${p.payload.length} octets · chk ${fmtHex16(core.chk)}`, 380);
    add(2, "data", `[matrice] V  = [${core.v.map(x => x.toFixed(2)).join(", ")}]`, 420);
    add(3, "data", `[matrice] det(M) = ${fmtSci(core.detRef)} · ‖M·M⁻¹ − I‖∞ = ${core.idErr.toExponential(2)}`, 460);
    add(4, "data", `[matrice] V' = [${core.vPrime.map(x => x.toFixed(3)).join(", ")}]`, 420);
    add(5, "ok", `[matrice] intégrité de la transformation confirmée.`, 460);
    if (tamper) {
      add(6, "sys", "[trace  ] interception HOSTILE explicitement demandée", 620);
      add(7, "alert", `[ALERTE ] checksum attendu ${fmtHex16(core.chk)} ≠ observé ${fmtHex16(core.chkObserved)}`, 520);
      add(7, "alert", "[ALERTE ] paquet mis en quarantaine — simulation d'incident.", 480);
      add(8, "alert", "[ALERTE ] activation du Protocole Leurré COJ…", 700, true);
      add(8, "sys", "[coj    ] flux légitime isolé · environnement de leurre engagé.", 900);
    }
    add(9, "ok", `[egress ] restitution contrôlée · écart max |Δ| = ${core.errMax.toExponential(3)}`, 520);
    add(10, "ok", `[egress ] checksum FNV-1a ${fmtHex16(core.chk)} valide · VLAN 0x${core.vlan.toString(16).toUpperCase()}`, 520);
    add(10, "title", "[atibon ] ✔ CYCLE DE DÉMONSTRATION TERMINÉ", 400);
    return L;
  }, [tamper, core]);

  useEffect(() => {
    if (!started) return;
    setLines([]);
    setStep(-1);
    setDone(false);
    setDecoyOn(false);
    if (reduced) {
      setLines(script);
      setStep(10);
      setDone(true);
      if (tamper) setDecoyOn(true);
      return;
    }
    let i = 0;
    let cancelled = false;
    let t: ReturnType<typeof setTimeout>;
    const play = () => {
      if (cancelled) return;
      if (i >= script.length) { setDone(true); return; }
      const line = script[i++];
      setLines(prev => [...prev, line]);
      setStep(line.step);
      if (line.decoy) setDecoyOn(true);
      t = setTimeout(play, line.delay);
    };
    t = setTimeout(play, 250);
    return () => { cancelled = true; clearTimeout(t); };
  }, [started, runId, script, reduced, tamper]);

  useEffect(() => {
    const el = termRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setDecoyOn(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const startDemo = () => {
    setStarted(true);
    setRunId(r => r + 1);
  };
  const toggleTamper = () => {
    setTamper(v => !v);
    setStarted(false);
    setLines([]);
    setStep(-1);
    setDone(false);
    setDecoyOn(false);
  };
  const alarmed = started && step >= 7 && step < 10;
  const lineCls: Record<LineCls, string> = {
    sys: "text-[#6f8a7b]", cmd: "text-[#eafff3]", ok: "text-[#2bff9e]",
    data: "text-[#9db8a9]", alert: "font-semibold text-[#ff6b85]", title: "text-[#7dffb9]",
  };

  return (
    <section id="console" className="relative mx-auto mt-32 max-w-7xl px-5">
      <div ref={reveal.ref} className={`reveal ${reveal.inView ? "is-in" : ""}`}>
        <div className="border-b border-[#14261d] pb-8">
          <p className="font-mono text-[11px] uppercase tracking-[0.34em] text-[#ffb347]">03 · Démonstration interactive</p>
          <h2 className="mt-4 font-display text-4xl font-bold leading-tight text-[#eafff3] sm:text-5xl">Console ATIBON <span className="text-[#2bff9e]">prête</span>.</h2>
          <p className="mt-5 max-w-2xl text-[15px] leading-relaxed text-[#8fae9d]">
            Le tableau de bord reste dans son état nominal au chargement. Aucune simulation, alerte ou activation du leurre n'est déclenchée automatiquement.
          </p>
        </div>

        <div className="mt-8 flex flex-wrap items-center gap-4">
          <button onClick={startDemo} className="hud-btn border border-[#ffb347]/50 bg-[#ffb347]/10 px-7 py-3 text-[12px] text-[#ffd27d] hover:bg-[#ffb347]/20">
            ▶ LANCER LA DÉMONSTRATION
          </button>
          <button onClick={toggleTamper} role="switch" aria-checked={tamper} className={`hud-btn border px-6 py-3 text-[12px] ${tamper ? "border-[#ff3b5c] bg-[#2a0d14] text-[#ff6b85]" : "border-[#2a4d39] bg-[#0d1a14] text-[#2bff9e]"}`}>
            {tamper ? "⚠ TEST D'ATTAQUE ARMÉ" : "○ TEST D'ATTAQUE INACTIF"}
          </button>
          <button onClick={startDemo} className="hud-btn border border-[#2a4d39] bg-[#12241a] px-6 py-3 text-[12px] text-[#2bff9e] hover:border-[#2bff9e]">
            ⟳ Réexécuter
          </button>
          <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[.18em]">
            <span className={`h-2.5 w-2.5 rounded-full ${alarmed ? "alarm-flash bg-[#ff3b5c]" : "led bg-[#2bff9e]"}`} />
            <span className={decoyOn ? "text-[#ff6b85]" : "text-[#7dffb9]"}>{decoyOn ? "PROTOCOLE LEURRÉ COJ ACTIF" : !started ? "TABLEAU DE BORD NOMINAL" : alarmed ? "ALERTE — QUARANTAINE" : done ? "CYCLE TERMINÉ ✔" : "DÉMONSTRATION EN COURS"}</span>
          </div>
        </div>

        <div className="mt-8 grid gap-8 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
          <div className="relative border border-[#14261d] bg-[#050b08] shadow-[inset_0_0_60px_rgba(43,255,158,0.04)]">
            <span className="hud-corner tl border-[#2bff9e]" /><span className="hud-corner tr border-[#2bff9e]" />
            <span className="hud-corner bl border-[#2bff9e]" /><span className="hud-corner br border-[#2bff9e]" />
            <div className="flex items-center justify-between border-b border-[#14261d] px-5 py-3">
              <span className="font-mono text-[11px] tracking-[.14em] text-[#6f8a7b]">ATIBON — CONSOLE — 92×28</span>
              <span className="font-mono text-[10px] uppercase tracking-[.2em] text-[#6f8a7b]">stdout</span>
            </div>
            <div ref={termRef} className="code-scroll h-[480px] overflow-y-auto p-5 font-mono text-[12.5px] leading-[1.7]">
              {!started && <div className="flex h-full flex-col items-center justify-center text-center"><div className="font-display text-2xl text-[#eafff3]">Système ATIBON opérationnel</div><div className="mt-3 max-w-md text-xs leading-6 text-[#6f8a7b]">Aucune simulation n'est active. Utilisez « LANCER LA DÉMONSTRATION » pour commencer volontairement.</div></div>}
              {lines.map((l, i) => <div key={i} className="line-in whitespace-pre-wrap break-words"><span className={lineCls[l.cls]}>{l.text}</span></div>)}
            </div>
          </div>

          <div className="glass-panel relative overflow-hidden p-6">
            <div className="font-mono text-[10px] uppercase tracking-[.25em] text-[#ffb347]">État de sécurité</div>
            <div className="mt-6 space-y-4">
              {[
                ["DPI", "ACTIF"], ["Consensus BFT", "PRÊT"], ["PQC / HSM", "POLITIQUE CHARGÉE"], ["Zero Trust", "ENFORCÉ"], ["TPM 2.0", "ATTESTATION PRÊTE"],
              ].map(([name, value]) => <div key={name} className="flex items-center justify-between border-b border-white/5 pb-3"><span className="font-mono text-xs text-[#8fae9d]">{name}</span><span className="font-mono text-[10px] text-[#2bff9e]">{value}</span></div>)}
            </div>
            {decoyOn && <div className="mt-8 border border-[#ff3b5c]/40 bg-[#2a0d14]/60 p-4"><div className="font-display text-lg text-[#ff6b85]">Protocole Leurré COJ</div><div className="mt-2 text-xs leading-5 text-[#9db8a9]">Le leurre est actif uniquement parce que le test d'attaque a été explicitement lancé.</div><button onClick={() => setDecoyOn(false)} className="mt-4 text-xs text-[#ffd27d] underline">Fermer le leurre</button></div>}
          </div>
        </div>
      </div>
    </section>
  );
}
