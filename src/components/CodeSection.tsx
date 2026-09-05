import { useState } from "react";
import CodeBlock from "./CodeBlock";
import { useCopy, useReveal } from "../hooks";
import { BUILD_STEPS, EXPECTED_OUTPUT, PROJECT_TREE, SOURCE_FILES } from "../data/rustSources";

function CopyBtn({ text, label }: { text: string; label: string }) {
  const [copied, copy] = useCopy();
  return (
    <button
      onClick={() => copy(text)}
      className="hud-btn border border-[#2a4d39] bg-[#0d1a14] px-4 py-2 text-[11px] text-[#7dffb9] hover:border-[#2bff9e] hover:bg-[#12241a] hover:text-[#eafff3]"
    >
      {copied ? "✔ copié dans le presse-papiers" : label}
    </button>
  );
}

export default function CodeSection() {
  const [active, setActive] = useState(1); // main.rs par défaut
  const file = SOURCE_FILES[active];
  const head = useReveal();
  const body = useReveal();

  const allCode = SOURCE_FILES.map((f) => `# ═══ ${f.path} ═══\n${f.code}`).join("\n\n");

  return (
    <section id="code" className="relative mx-auto mt-32 max-w-7xl px-5">
      <div ref={head.ref} className={`reveal ${head.inView ? "is-in" : ""}`}>
        <div className="flex flex-wrap items-end justify-between gap-6 border-b border-[#14261d] pb-8">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.34em] text-[#2bff9e]">02 · Code source Rust</p>
            <h2 className="font-display mt-4 text-4xl font-bold leading-tight text-[#eafff3] sm:text-5xl">
              Sept fichiers, un noyau,
              <br />
              zéro dépendance superflue.
            </h2>
            <p className="mt-5 max-w-2xl text-[15px] leading-relaxed text-[#8fae9d]">
              L'intégralité du PoC commentée en français — copiez l'arborescence, déposez les fichiers, lancez{" "}
              <span className="font-mono text-[#ffb347]">cargo run --release</span>. Cinq dépendances ciblées :{" "}
              <span className="font-mono text-[#eafff3]">nalgebra</span> (algèbre linéaire),{" "}
              <span className="font-mono text-[#eafff3]">rand</span> (génération seedée de M),{" "}
              <span className="font-mono text-[#eafff3]">tokio</span> (proxy asynchrone),{" "}
              <span className="font-mono text-[#eafff3]">serde</span> + <span className="font-mono text-[#eafff3]">serde_yaml</span>{" "}
              (configuration) et <span className="font-mono text-[#eafff3]">colored</span> (journalisation).
            </p>
          </div>
          <CopyBtn text={allCode} label="⧉ tout copier" />
        </div>
      </div>

      <div ref={body.ref} className={`reveal mt-12 grid gap-10 lg:grid-cols-12 ${body.inView ? "is-in" : ""}`}>
        {/* colonne gauche : arborescence + build + sortie */}
        <div className="space-y-10 lg:col-span-4">
          <div className="relative border border-[#14261d] bg-[#071009] p-6">
            <span className="hud-corner tl border-[#2bff9e]" />
            <span className="hud-corner br border-[#2bff9e]" />
            <h3 className="font-display text-sm font-bold uppercase tracking-[0.22em] text-[#eafff3]">Arborescence Cargo</h3>
            <pre className="mt-4 overflow-x-auto font-mono text-[12px] leading-[1.8] text-[#8fae9d]">{PROJECT_TREE}</pre>
          </div>

          <div className="border border-[#14261d] bg-[#071009] p-6">
            <h3 className="font-display text-sm font-bold uppercase tracking-[0.22em] text-[#eafff3]">Compiler & exécuter</h3>
            <ol className="mt-5 space-y-5">
              {BUILD_STEPS.map((s, i) => (
                <li key={s.cmd} className="group">
                  <div className="flex items-baseline gap-3">
                    <span className="font-display text-lg font-bold text-[#2bff9e]">{i + 1}</span>
                    <code className="block overflow-x-auto whitespace-pre font-mono text-[12px] leading-relaxed text-[#7dffb9] transition-colors group-hover:text-[#eafff3]">
                      <span className="select-none text-[#3d5a4a]">$ </span>
                      {s.cmd}
                    </code>
                  </div>
                  <p className="mt-1 pl-8 text-[12px] text-[#6f8a7b]">{s.note}</p>
                </li>
              ))}
            </ol>
            <div className="mt-6 flex gap-2 border-t border-[#14261d] pt-5">
              <CopyBtn text={BUILD_STEPS.map((s) => s.cmd.startsWith("#") ? "" : s.cmd).filter(Boolean).join("\n")} label="⧉ copier les commandes" />
            </div>
          </div>

          <div className="border border-[#14261d] bg-[#071009]">
            <div className="flex items-center justify-between border-b border-[#14261d] px-6 py-3">
              <h3 className="font-display text-sm font-bold uppercase tracking-[0.22em] text-[#ffb347]">Sortie attendue</h3>
              <span className="font-mono text-[10px] tracking-[0.2em] text-[#6f8a7b]">cycle nominal + alerte</span>
            </div>
            <pre className="code-scroll max-h-[420px] overflow-auto p-6 font-mono text-[11.5px] leading-[1.75] text-[#9db8a9]">
              {EXPECTED_OUTPUT}
            </pre>
          </div>
        </div>

        {/* colonne droite : visionneuse de code */}
        <div className="lg:col-span-8">
          <div className="relative border border-[#14261d] bg-[#071009]">
            <span className="hud-corner tl border-[#ffb347]" />
            <span className="hud-corner br border-[#ffb347]" />
            {/* onglets */}
            <div className="flex flex-wrap gap-1 border-b border-[#14261d] bg-[#060d0a] p-2">
              {SOURCE_FILES.map((f, i) => (
                <button
                  key={f.name}
                  onClick={() => setActive(i)}
                  className={`px-4 py-2 font-mono text-[12px] tracking-wide transition-all duration-200 ${
                    i === active
                      ? "bg-[#12241a] text-[#2bff9e] shadow-[inset_0_-2px_0_#2bff9e]"
                      : "text-[#6f8a7b] hover:bg-[#0d1a14] hover:text-[#9db8a9]"
                  }`}
                >
                  {f.name}
                </button>
              ))}
            </div>

            {/* méta + copie */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#14261d] px-6 py-3">
              <div className="min-w-0">
                <div className="font-mono text-[11px] text-[#6f8a7b]">
                  <span className="text-[#2bff9e]">▸</span> {file.path} · {file.code.split("\n").length} lignes
                </div>
                <p className="mt-1 truncate text-[12px] text-[#8fae9d]">{file.desc}</p>
              </div>
              <CopyBtn text={file.code} label={`⧉ ${file.name}`} />
            </div>

            <div className="max-h-[680px] overflow-y-auto">
              <CodeBlock code={file.code} lang={file.lang} />
            </div>
          </div>

          <p className="mt-4 font-mono text-[11px] leading-relaxed text-[#6f8a7b]">
            <span className="text-[#ffb347]">note</span> — le profil <span className="text-[#eafff3]">[profile.release]</span>{" "}
            retire les symboles (<span className="text-[#eafff3]">strip = true</span>) et interdit l'unwinding (
            <span className="text-[#eafff3]">panic = "abort"</span>) : premier rempart anti-reverse, complété par le
            bouclier <span className="text-[#eafff3]">shield.rs</span> à l'exécution.
          </p>
        </div>
      </div>
    </section>
  );
}
