import { useReveal } from "../hooks";

const CONFIG_YML = `# ═══════════════════════════════════════════════════════════
# coj-config.yml — configuration du pare-feu matriciel
# ═══════════════════════════════════════════════════════════
firewall:
  # ports exposés que le noyau matriciel prend en charge
  protected_ports: [80, 443, 8080]
  trusted_subnets:
    - 10.0.0.0/8          # réseau interne
    - 192.168.1.0/24      # administration

matrix:
  seed: 0xC04AC0DE        # ⚠ en production : HSM / TPM uniquement
  dimension: 12           # dimension fixe de l'espace d'état
  det_drift_eps: 1.0e-9   # dérive relative tolérée sur det(M)

shield:
  # normal | paranoid | matrix
  # matrix = scan continu + leurre visuel + quarantaine systématique
  aggression: matrix
  watch:
    tracer_pid: true      # détection gdb / strace / IDA attach
    binary_integrity: true  # FNV-1a de /proc/self/exe
    ld_preload: true      # hooking de syscalls
  response:
    quarantine_hours: 24  # blacklist de l'IP source
    visual_decoy: true    # digital rain + crâne ASCII + « COJ »
    trace_session: true   # piste d'Ouméga : tag de session intrus`;

const SYSTEMD_UNIT = `# /etc/systemd/system/coj-matrix-firewall.service
[Unit]
Description=COJ-Matrix Firewall — noyau matriciel & bouclier anti-reverse
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/coj-matrix-firewall \\
    --config /etc/coj/coj-config.yml
Restart=always
RestartSec=3
# durcissement systemd du daemon
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
MemoryDenyWriteExecute=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target`;

const CLI_ROWS = [
  { cmd: "coj-matrix-firewall --config /etc/coj/coj-config.yml", desc: "démarre le noyau avec sa configuration" },
  { cmd: "coj-matrix-firewall --check", desc: "audit à sec : det(M), intégrité binaire, sondes — puis quitte" },
  { cmd: "coj-matrix-firewall --rotate-key", desc: "régénère M et M⁻¹ depuis une nouvelle seed scellée" },
  { cmd: "coj-matrix-firewall --tail", desc: "suit le journal des anomalies en temps réel" },
  { cmd: "systemctl enable --now coj-matrix-firewall", desc: "active le daemon au démarrage et le lance" },
  { cmd: "journalctl -u coj-matrix-firewall -f", desc: "journal systemd du pare-feu" },
];

const HARDENING = [
  { t: "strip = true", d: "symboles retirés du binaire release" },
  { t: "panic = abort", d: "pas d'unwinding — surface d'analyse réduite" },
  { t: "det(M) scellé", d: "divergence structurelle détectée en une passe" },
  { t: "TracerPid + FNV-1a", d: "double sonde anti-debug & anti-patch mémoire" },
  { t: "quarantaine 24 h", d: "toute IP en divergence est blacklistée" },
  { t: "tag de session", d: "chaque analyste piégé est tracé (piste d'Ouméga)" },
];

function CheckIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden className="mt-1 shrink-0">
      <path d="M8 1.5 14 5v6l-6 3.5L2 11V5l6-3.5Z" stroke="#2bff9e" strokeWidth="1.2" fill="rgba(43,255,158,0.08)" />
      <path d="m5.2 8.2 2 2 3.6-4.2" stroke="#2bff9e" strokeWidth="1.4" strokeLinecap="square" />
    </svg>
  );
}

/** Mini-coloration YAML/INI : commentaires, clés, valeurs. */
function ConfigBlock({ code, filename, accent }: { code: string; filename: string; accent: string }) {
  return (
    <div className="relative border border-[#14261d] bg-[#071009]">
      <span className="hud-corner tl" style={{ borderColor: accent }} />
      <span className="hud-corner br" style={{ borderColor: accent }} />
      <div className="flex items-center justify-between border-b border-[#14261d] px-5 py-3">
        <span className="font-mono text-[11px] tracking-[0.14em] text-[#eafff3]">{filename}</span>
        <span className="font-mono text-[10px] uppercase tracking-[0.22em]" style={{ color: accent }}>
          {filename.endsWith(".yml") ? "yaml" : "systemd"}
        </span>
      </div>
      <pre className="code-scroll max-h-[440px] overflow-auto p-5 font-mono text-[12px] leading-[1.75]">
        {code.split("\n").map((line, i) => {
          const trimmed = line.trim();
          if (trimmed.startsWith("#"))
            return (
              <div key={i} className="tok-cmt">
                {line || " "}
              </div>
            );
          if (/^\[[^\]]+\]$/.test(trimmed))
            return (
              <div key={i} className="tok-sec">
                {line}
              </div>
            );
          const m = line.match(/^(\s*)([\w./-]+)(\s*[:=]\s*)(.*)$/);
          if (m) {
            const [, ind, key, sep, rest] = m;
            const cmt = rest.indexOf("#");
            const val = cmt > -1 ? rest.slice(0, cmt) : rest;
            const tail = cmt > -1 ? rest.slice(cmt) : "";
            return (
              <div key={i}>
                {ind}
                <span className="tok-key">{key}</span>
                <span className="text-[#8fae9d]">{sep}</span>
                <span className="text-[#9db8a9]">{val}</span>
                <span className="tok-cmt">{tail}</span>
              </div>
            );
          }
          return (
            <div key={i} className="text-[#9db8a9]">
              {line || " "}
            </div>
          );
        })}
      </pre>
    </div>
  );
}

export default function Deploy() {
  const head = useReveal();
  const grid = useReveal();
  const table = useReveal();

  return (
    <section id="deploiement" className="relative mx-auto mt-32 max-w-7xl px-5 pb-10">
      <div ref={head.ref} className={`reveal border-b border-[#14261d] pb-8 ${head.inView ? "is-in" : ""}`}>
        <p className="font-mono text-[11px] uppercase tracking-[0.34em] text-[#45e0ff]">04 · Industrialisation</p>
        <h2 className="font-display mt-4 text-4xl font-bold leading-tight text-[#eafff3] sm:text-5xl">
          Du PoC au <span className="text-[#45e0ff]">daemon de production</span>.
        </h2>
        <p className="mt-5 max-w-2xl text-[15px] leading-relaxed text-[#8fae9d]">
          La même ossature se déploie comme service système : un fichier{" "}
          <span className="font-mono text-[#eafff3]">coj-config.yml</span> pour les règles, une unité{" "}
          <span className="font-mono text-[#eafff3]">systemd</span> durcie pour l'exécution, et trois niveaux
          d'agressivité — <span className="font-mono text-[#2bff9e]">normal</span>,{" "}
          <span className="font-mono text-[#ffb347]">paranoid</span>,{" "}
          <span className="font-mono text-[#ff6b85]">matrix</span>.
        </p>
      </div>

      <div ref={grid.ref} className={`reveal mt-12 grid gap-8 lg:grid-cols-2 ${grid.inView ? "is-in" : ""}`}>
        <ConfigBlock code={CONFIG_YML} filename="coj-config.yml" accent="#2bff9e" />
        <div className="space-y-8">
          <ConfigBlock code={SYSTEMD_UNIT} filename="coj-matrix-firewall.service" accent="#45e0ff" />
          <div className="border border-[#14261d] bg-[#071009] p-6">
            <h3 className="font-display text-sm font-bold uppercase tracking-[0.22em] text-[#eafff3]">
              Checklist de durcissement
            </h3>
            <ul className="mt-5 grid gap-x-8 gap-y-3 sm:grid-cols-2">
              {HARDENING.map((h) => (
                <li key={h.t} className="group flex gap-3 border-b border-[#101f17] pb-3 transition-colors hover:border-[#2bff9e]/40">
                  <CheckIcon />
                  <div>
                    <div className="font-mono text-[12.5px] font-semibold text-[#eafff3] group-hover:text-[#2bff9e]">{h.t}</div>
                    <div className="mt-0.5 text-[12px] leading-snug text-[#6f8a7b]">{h.d}</div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* référence CLI */}
      <div ref={table.ref} className={`reveal mt-12 ${table.inView ? "is-in" : ""}`}>
        <div className="relative border border-[#14261d] bg-[#071009]">
          <span className="hud-corner tl border-[#ffb347]" />
          <span className="hud-corner br border-[#ffb347]" />
          <div className="border-b border-[#14261d] px-6 py-4">
            <h3 className="font-display text-sm font-bold uppercase tracking-[0.22em] text-[#eafff3]">Référence CLI</h3>
          </div>
          <div className="divide-y divide-[#101f17]">
            {CLI_ROWS.map((r) => (
              <div
                key={r.cmd}
                className="group grid gap-2 px-6 py-4 transition-colors duration-200 hover:bg-[#0d1a14] md:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)] md:gap-8"
              >
                <code className="overflow-x-auto whitespace-nowrap font-mono text-[12.5px] text-[#7dffb9] transition-colors group-hover:text-[#eafff3]">
                  <span className="select-none text-[#3d5a4a]">$ </span>
                  {r.cmd}
                </code>
                <p className="text-[13px] leading-relaxed text-[#6f8a7b] group-hover:text-[#8fae9d]">{r.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
