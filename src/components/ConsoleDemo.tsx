import { useEffect, useMemo, useRef, useState } from "react";
import MatrixCanvas from "./MatrixCanvas";
import MatrixRain from "./MatrixRain";
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

/* ── Types du player ─────────────────────────────────────────── */
type LineCls = "sys" | "cmd" | "ok" | "data" | "alert" | "title";
interface Line {
  step: number;
  cls: LineCls;
  text: string;
  delay: number;
  decoy?: boolean;
}

const SKULL_ART = String.raw`      ______
   .-"      "-.
  /            \
 |              |
 |,  .-.  .-.  ,|
 | )(_o/  \o_)( |
 |/     /\     \|
 (_     ^^     _)
  \__|IIIIII|__/
   | \IIIIII/ |
   \          /
    '--------'`;

const STEP_NAMES = [
  "Bouclier anti-inspection",
  "Paquet simulé (Ingress)",
  "Vectorisation V ∈ ℝ¹²",
  "Matrice-clé M scellée",
  "Transformation V′ = M·V",
  "Contrôle det(M) live",
  "Interception simulée",
  "Inspection checksum",
  "Leurre « digital rain »",
  "Restitution M⁻¹·V′",
  "Intégrité Egress",
];

export default function ConsoleDemo() {
  const reduced = useReducedMotion();
  const reveal = useReveal();
  const [tamper, setTamper] = useState(true);
  const [runId, setRunId] = useState(0);
  const [lines, setLines] = useState<Line[]>([]);
  const [step, setStep] = useState(-1);
  const [done, setDone] = useState(false);
  const [decoyOn, setDecoyOn] = useState(false);
  const termRef = useRef<HTMLDivElement>(null);

  /* ── calculs du noyau (identiques au Rust) ── */
  const core = useMemo(() => {
    const m = generateMatrix(MATRIX_SEED);
    const inv = invertMatrix(m)!;
    const detRef = determinant(m);
    const idErr = identityError(m, inv);
    const pkt = DEFAULT_PACKET;
    const v = [
      ...pkt.src,
      ...pkt.dst,
      (pkt.port >> 8) & 0xff,
      pkt.port & 0xff,
      0,
      0,
    ].slice(0, 12);
    const chk = checksumPacket(pkt.payload);
    v[10] = (chk >> 8) & 0xff;
    v[11] = chk & 0xff;
    const vPrime = matVec(m, v);
    const tamperedVp = vPrime.map((x, i) => (i === 3 ? x * 1.62 : i === 9 ? x + 47 : x));
    const restored = matVec(inv, vPrime);
    const restoredT = matVec(inv, tamperedVp);
    const b = (arr: number[], i: number) => Math.min(255, Math.max(0, Math.round(arr[i])));
    const chkObserved = ((b(restoredT, 10) & 0xff) << 8) | (b(restoredT, 11) & 0xff);
    const errMax = Math.max(...restored.map((x, i) => Math.abs(x - v[i])));
    return {
      v,
      vPrime,
      tamperedVp,
      detRef,
      idErr,
      chk,
      chkObserved,
      errMax,
      bootHash: fnv1a32str("coj-matrix-firewall::poc"),
      vlan: (chk & 0x0f) + 10,
    };
  }, []);

  /* ── script du terminal ── */
  const script = useMemo<Line[]>(() => {
    const L: Line[] = [];
    const add = (st: number, cls: LineCls, text: string, delay = 260, decoy = false) =>
      L.push({ step: st, cls, text, delay, decoy });
    const c = core;
    const p = DEFAULT_PACKET;

    add(-1, "title", "┌────────────────────────────────────────────────────────┐", 40);
    add(-1, "title", "│  COJ-MATRIX FIREWALL · PoC v0.1.0 · noyau matriciel     │", 40);
    add(-1, "title", "│  V' = M·V  //  det(M) scellé  //  leurre anti-reverse   │", 40);
    add(-1, "title", "└────────────────────────────────────────────────────────┘", 320);
    add(-1, "cmd", "cargo run --release", 500);

    add(0, "sys", `[shield ] empreinte binaire FNV-1a : ${fmtHex32(c.bootHash)}`, 300);
    add(0, "ok", "[shield ] TracerPid=0 · binaire intègre — système ARMÉ.", 420);
    add(1, "data", `[paquet ] ${ipToStr(p.src)} → ${ipToStr(p.dst)}:${p.port} · ${p.payload.length} octets · chk ${fmtHex16(c.chk)}`, 380);
    add(2, "data", `[matrice] V  = [${c.v.map((x) => x.toFixed(2)).join(", ")}]`, 420);
    add(3, "data", `[matrice] M ∈ GL(12, ℝ) — det(M) = ${fmtSci(c.detRef)} scellé · ‖M·M⁻¹ − I‖∞ = ${c.idErr.toExponential(2)}`, 460);
    add(4, "data", `[matrice] V' = [${c.vPrime.map((x) => x.toFixed(3)).join(", ")}]`, 420);
    add(5, "ok", `[matrice] det(M) live = ${fmtSci(c.detRef)} — conforme au sceau de référence.`, 460);

    if (tamper) {
      add(6, "sys", "[trace  ] … interception simulée : V'[3] ×1.62 · V'[9] +47.0", 620);
      add(7, "alert", `[ALERTE ] checksum attendu ${fmtHex16(c.chk)} ≠ observé ${fmtHex16(c.chkObserved)}`, 520);
      add(7, "alert", "[ALERTE ] paquet mis en quarantaine — IP source blacklistée 24 h.", 480);
      add(8, "alert", "[ALERTE ] activation du protocole de leurre « COJ digital rain »…", 700, true);
      add(8, "sys", "[coj    ] ── le flux légitime, lui, poursuit son cycle ──", 1400);
    }

    add(9, "ok", `[matrice] V̂  = M⁻¹·V' restitué — écart max |Δ| = ${c.errMax.toExponential(3)}`, 520);
    add(10, "ok", `[egress ] checksum FNV-1a ${fmtHex16(c.chk)} valide — réencapsulé VLAN dynamique 0x${c.vlan.toString(16).toUpperCase().padStart(2, "0")}.`, 520);
    add(10, "title", "[coj    ] ✔ CYCLE COMPLET NOMINAL — trafic restitué à l'identique.", 400);
    add(10, "sys", "[coj    ] astuce : l'argument --serve démarre le proxy tokio (coj-config.yml).", 260);
    if (tamper) {
      add(10, "sys", "[coj    ] leurre maintenu pour l'analyste — fermer avec ✕ (Ctrl-C simulé).", 200);
    }
    return L;
  }, [tamper, core]);

  /* ── player ── */
  useEffect(() => {
    setLines([]);
    setStep(-1);
    setDone(false);
    setDecoyOn(false);
    if (reduced) {
      setLines(script);
      setStep(10);
      setDone(true);
      return;
    }
    let i = 0;
    let cancelled = false;
    let t: ReturnType<typeof setTimeout>;
    const play = () => {
      if (cancelled) return;
      if (i >= script.length) {
        setDone(true);
        return;
      }
      const line = script[i];
      setLines((prev) => [...prev, line]);
      setStep(line.step);
      if (line.decoy) setDecoyOn(true);
      i++;
      t = setTimeout(play, line.delay);
    };
    t = setTimeout(play, 700);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [runId, script, reduced]);

  /* ── auto-scroll terminal ── */
  useEffect(() => {
    const el = termRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  /* ── Échap ferme le leurre ── */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setDecoyOn(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const sessionTag = `COJ-${(0x1f3a).toString(16).toUpperCase()}-${fmtHex32(core.bootHash).slice(2)}`;
  const alarmed = step >= 7 && step < 10;

  const lineCls: Record<LineCls, string> = {
    sys: "text-[#6f8a7b]",
    cmd: "text-[#eafff3]",
    ok: "text-[#2bff9e]",
    data: "text-[#9db8a9]",
    alert: "text-[#ff6b85] font-semibold",
    title: "text-[#7dffb9]",
  };

  return (
    <section id="console" className="relative mx-auto mt-32 max-w-7xl px-5">
      <div ref={reveal.ref} className={`reveal ${reveal.inView ? "is-in" : ""}`}>
        <div className="border-b border-[#14261d] pb-8">
          <p className="font-mono text-[11px] uppercase tracking-[0.34em] text-[#ffb347]">03 · Démonstration interactive</p>
          <h2 className="font-display mt-4 text-4xl font-bold leading-tight text-[#eafff3] sm:text-5xl">
            Le cycle complet, <span className="text-[#2bff9e]">en direct</span>.
          </h2>
          <p className="mt-5 max-w-2xl text-[15px] leading-relaxed text-[#8fae9d]">
            Réplique exacte du <span className="font-mono text-[#eafff3]">main.rs</span>, exécutée dans votre navigateur
            avec les mêmes algorithmes (mêmes seeds, mêmes seuils). Injectez une interception pour voir le checksum
            diverger — et le leurre <span className="font-mono text-[#2bff9e]">COJ digital rain</span> prendre la main.
          </p>
        </div>

        {/* contrôles */}
        <div className="mt-8 flex flex-wrap items-center gap-x-8 gap-y-4">
          <label className="group flex cursor-pointer items-center gap-3 select-none">
            <button
              role="switch"
              aria-checked={tamper}
              onClick={() => setTamper((t) => !t)}
              className={`relative h-6 w-12 border transition-colors duration-300 ${
                tamper ? "border-[#ff3b5c] bg-[#2a0d14]" : "border-[#2a4d39] bg-[#0d1a14]"
              }`}
            >
              <span
                className={`absolute top-[3px] h-4 w-4 transition-all duration-300 ${
                  tamper ? "left-[26px] bg-[#ff3b5c]" : "left-[3px] bg-[#2bff9e]"
                }`}
              />
            </button>
            <span className="font-mono text-[12px] uppercase tracking-[0.16em] text-[#9db8a9] group-hover:text-[#eafff3]">
              Injecter une interception hostile
            </span>
          </label>

          <button
            onClick={() => setRunId((r) => r + 1)}
            className="hud-btn border border-[#2a4d39] bg-[#12241a] px-6 py-2.5 text-[12px] text-[#2bff9e] hover:border-[#2bff9e] hover:bg-[#173424] hover:shadow-[0_0_24px_rgba(43,255,158,0.25)]"
          >
            ⟳ Réexécuter le cycle
          </button>

          <div className="flex items-center gap-2">
            <span
              className={`h-2.5 w-2.5 rounded-full ${
                alarmed ? "alarm-flash bg-[#ff3b5c] text-[#ff3b5c]" : "led bg-[#2bff9e] text-[#2bff9e]"
              }`}
            />
            <span
              className={`font-mono text-[11px] uppercase tracking-[0.22em] ${
                alarmed ? "text-[#ff6b85]" : "text-[#7dffb9]"
              }`}
            >
              {decoyOn ? "mode leurre actif" : alarmed ? "alerte — quarantaine" : done ? "cycle nominal ✔" : "système armé"}
            </span>
          </div>
        </div>

        <div className="mt-8 grid gap-8 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
          {/* ── terminal ── */}
          <div className="relative border border-[#14261d] bg-[#050b08] shadow-[inset_0_0_60px_rgba(43,255,158,0.04)]">
            <span className="hud-corner tl border-[#2bff9e]" />
            <span className="hud-corner tr border-[#2bff9e]" />
            <span className="hud-corner bl border-[#2bff9e]" />
            <span className="hud-corner br border-[#2bff9e]" />
            <div className="flex items-center justify-between border-b border-[#14261d] px-5 py-3">
              <span className="font-mono text-[11px] tracking-[0.14em] text-[#6f8a7b]">
                coj-matrix-firewall — /bin/zsh — 92×28
              </span>
              <span className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[#6f8a7b]">
                <span className={`h-1.5 w-1.5 rounded-full ${alarmed ? "bg-[#ff3b5c]" : "bg-[#2bff9e]"}`} />
                stdout
              </span>
            </div>
            <div ref={termRef} className="code-scroll h-[480px] overflow-y-auto p-5 font-mono text-[12.5px] leading-[1.7]">
              {lines.map((l, i) => (
                <div key={i} className={`line-in whitespace-pre-wrap break-words ${lineCls[l.cls]}`}>
                  {l.cls === "cmd" ? <span className="select-none text-[#2bff9e]">❯ </span> : null}
                  {l.text}
                  {i === lines.length - 1 && !done && <span className="cursor-blink text-[#2bff9e]"> ▍</span>}
                </div>
              ))}
              {lines.length === 0 && <div className="text-[#3d5a4a]">amorçage du noyau…</div>}
            </div>
          </div>

          {/* ── télémétrie ── */}
          <div className="space-y-6">
            {/* tracker d'étapes */}
            <div className="border border-[#14261d] bg-[#071009] p-5">
              <h3 className="font-display text-xs font-bold uppercase tracking-[0.22em] text-[#eafff3]">
                Séquence d'exécution
              </h3>
              <ol className="mt-4 grid grid-cols-1 gap-y-1.5 sm:grid-cols-2 lg:grid-cols-1">
                {STEP_NAMES.map((name, i) => {
                  const bypassed = tamper ? false : i >= 6 && i <= 8;
                  const state =
                    step > i || done ? "done" : step === i ? "run" : "todo";
                  return (
                    <li
                      key={name}
                      className={`flex items-center gap-2.5 font-mono text-[11.5px] transition-all duration-300 ${
                        bypassed ? "text-[#3d5a4a] line-through" : state === "todo" ? "text-[#6f8a7b]" : state === "run" ? "text-[#ffb347]" : i === 7 || i === 8 ? "text-[#ff6b85]" : "text-[#2bff9e]"
                      }`}
                    >
                      <span className="w-4 text-center">
                        {bypassed ? "—" : state === "done" ? "■" : state === "run" ? "▸" : "▢"}
                      </span>
                      <span className="text-[#3d5a4a]">{String(i + 1).padStart(2, "0")}</span>
                      {name}
                    </li>
                  );
                })}
              </ol>
            </div>

            {/* vecteur V' */}
            <div className="border border-[#14261d] bg-[#071009] p-5">
              <MatrixCanvas
                mode="vector"
                height={210}
                vector={step >= 6 && tamper ? core.tamperedVp : core.vPrime}
                tampered={step >= 6 && tamper ? [3, 9] : []}
                title={step >= 6 && tamper ? "V′ intercepté — 2 composantes altérées" : "V′ = M·V — espace transformé"}
              />
            </div>

            {/* relevés */}
            <div className="grid grid-cols-2 gap-px border border-[#14261d] bg-[#14261d]">
              {[
                { k: "det(M) scellé", v: fmtSci(core.detRef), tone: step >= 3 ? "#2bff9e" : "#3d5a4a" },
                { k: "‖M·M⁻¹ − I‖∞", v: core.idErr.toExponential(2), tone: step >= 3 ? "#7dffb9" : "#3d5a4a" },
                { k: "chk attendu", v: fmtHex16(core.chk), tone: step >= 1 ? "#eafff3" : "#3d5a4a" },
                {
                  k: "chk observé",
                  v: tamper && step >= 7 ? fmtHex16(core.chkObserved) : fmtHex16(core.chk),
                  tone: tamper && step >= 7 ? "#ff3b5c" : step >= 7 ? "#2bff9e" : "#3d5a4a",
                },
                { k: "écart |Δ| max", v: done ? core.errMax.toExponential(3) : "…", tone: done ? "#2bff9e" : "#3d5a4a" },
                {
                  k: "verdict",
                  v: tamper && step >= 7 && step < 9 ? "DIVERGENCE" : done ? "LÉGITIME" : "—",
                  tone: tamper && step >= 7 && step < 9 ? "#ff3b5c" : done ? "#2bff9e" : "#3d5a4a",
                },
              ].map((r) => (
                <div key={r.k} className="bg-[#071009] px-4 py-3">
                  <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#6f8a7b]">{r.k}</div>
                  <div className="mt-1 font-mono text-[13px] font-semibold transition-colors duration-300" style={{ color: r.tone }}>
                    {r.v}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── overlay leurre COJ ── */}
      {decoyOn && (
        <div className="decoy-in fixed inset-0 z-[80] overflow-hidden bg-[#020805]">
          <div className="absolute inset-0 opacity-90">
            <MatrixRain />
          </div>
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(90%_70%_at_50%_45%,transparent_35%,rgba(2,8,5,0.85)_100%)]" />

          {/* contenu central */}
          <div className="relative flex h-full flex-col items-center justify-center px-6 text-center">
            <p className="font-mono text-[11px] uppercase tracking-[0.5em] text-[#ff6b85]">
              ██ intrusion détectée ██
            </p>
            <h3 className="font-display title-flicker mt-3 text-3xl font-bold tracking-[0.18em] text-[#eafff3] sm:text-5xl">
              PROTOCOLE LEURRE <span className="text-[#2bff9e]">COJ</span>
            </h3>
            <pre className="skull-flicker mt-6 font-mono text-[11px] leading-[1.25] text-[#2bff9e] sm:text-[14px]">
              {SKULL_ART}
            </pre>
            <p className="mt-6 max-w-md font-mono text-[12px] leading-relaxed text-[#8fae9d]">
              {done
                ? "le flux légitime a été restitué en arrière-plan — vous ne contempliez que du bruit."
                : "analyse en cours… chaque cycle de décryptage alimente la piste d'Ouméga."}
            </p>
            <div className="mt-5 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 font-mono text-[11px] tracking-[0.14em]">
              <span className="text-[#45e0ff]">session {sessionTag}</span>
              <span className="alarm-flash text-[#ff6b85]">IP en cours de blacklist…</span>
            </div>
          </div>

          {/* fermeture */}
          <button
            onClick={() => setDecoyOn(false)}
            className="hud-btn absolute right-5 top-5 border border-[#2a4d39] bg-[#050b08]/80 px-5 py-2.5 text-[11px] text-[#7dffb9] hover:border-[#2bff9e] hover:text-[#eafff3]"
          >
            ✕ Ctrl-C simulé — fermer
          </button>
          <div className="absolute bottom-4 left-1/2 -translate-x-1/2 font-mono text-[10px] uppercase tracking-[0.3em] text-[#3d5a4a]">
            échappement : touche Échap
          </div>
        </div>
      )}
    </section>
  );
}
