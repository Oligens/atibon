import { Fragment } from "react";

/* ── Coloration syntaxique légère Rust / TOML ────────────────── */

const RUST_KEYWORDS = new Set([
  "fn", "let", "mut", "pub", "use", "mod", "impl", "struct", "enum", "match",
  "if", "else", "return", "for", "while", "loop", "in", "const", "static",
  "type", "where", "self", "Self", "crate", "trait", "dyn", "move", "ref",
  "true", "false", "break", "continue", "async", "await",
]);

const RUST_RE =
  /(\/\/[^\n]*)|("(?:\\.|[^"\\\n])*")|(\b0x[0-9A-Fa-f_]+\b|\b\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?\b)|(#\[|#!\[)|('[A-Za-z_]\w*)|([A-Za-z_]\w*!)|([A-Z][A-Za-z0-9_]*)|([a-z_]\w*)/g;

function rustTokens(code: string): { text: string; cls: string }[] {
  const out: { text: string; cls: string }[] = [];
  let last = 0;
  RUST_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = RUST_RE.exec(code)) !== null) {
    if (m.index > last) out.push({ text: code.slice(last, m.index), cls: "" });
    const [full, cmt, str, num, attr, life, mac, ty, ident] = m;
    if (cmt) out.push({ text: cmt, cls: /Étape|ÉTAPE|──/.test(cmt) ? "tok-sec" : "tok-cmt" });
    else if (str) out.push({ text: str, cls: "tok-str" });
    else if (num) out.push({ text: num, cls: "tok-num" });
    else if (attr) out.push({ text: attr, cls: "tok-attr" });
    else if (life) out.push({ text: life, cls: "tok-life" });
    else if (mac) out.push({ text: mac, cls: "tok-mac" });
    else if (ty) out.push({ text: ty, cls: "tok-ty" });
    else if (ident) out.push({ text: ident, cls: RUST_KEYWORDS.has(ident) ? "tok-kw" : "" });
    else out.push({ text: full, cls: "" });
    last = m.index + full.length;
  }
  if (last < code.length) out.push({ text: code.slice(last), cls: "" });
  return out;
}

function tomlTokens(code: string): { text: string; cls: string }[] {
  const out: { text: string; cls: string }[] = [];
  code.split("\n").forEach((line, idx) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) {
      out.push({ text: line, cls: "tok-cmt" });
    } else if (/^\[[^\]]+\]$/.test(trimmed)) {
      out.push({ text: line, cls: "tok-sec" });
    } else {
      const eq = line.indexOf("=");
      const hash = line.indexOf("#");
      if (eq > -1 && (hash === -1 || hash > eq)) {
        out.push({ text: line.slice(0, eq), cls: "tok-key" });
        out.push({ text: "=", cls: "" });
        const rest = line.slice(eq + 1);
        const h2 = rest.indexOf("#");
        const valPart = h2 > -1 ? rest.slice(0, h2) : rest;
        const cmtPart = h2 > -1 ? rest.slice(h2) : "";
        // valeurs : strings, nombres, booléens
        valPart.split(/("[^"]*")/g).forEach((seg) => {
          if (/^"[^"]*"$/.test(seg)) out.push({ text: seg, cls: "tok-str" });
          else {
            seg.split(/(\b\d[\d_.]*\b|\btrue\b|\bfalse\b)/g).forEach((s2) => {
              if (/^\d/.test(s2) || s2 === "true" || s2 === "false") out.push({ text: s2, cls: "tok-num" });
              else out.push({ text: s2, cls: "" });
            });
          }
        });
        if (cmtPart) out.push({ text: cmtPart, cls: "tok-cmt" });
      } else {
        out.push({ text: line, cls: hash === 0 ? "tok-cmt" : "" });
      }
    }
    if (idx < code.split("\n").length - 1) out.push({ text: "\n", cls: "" });
  });
  return out;
}

interface Props {
  code: string;
  lang: "rust" | "toml";
  showLineNumbers?: boolean;
  className?: string;
}

/** Bloc de code avec numéros de ligne et coloration syntaxique. */
export default function CodeBlock({ code, lang, showLineNumbers = true, className = "" }: Props) {
  const tokens = lang === "toml" ? tomlTokens(code) : rustTokens(code);

  // découpe les tokens en lignes
  const lines: { text: string; cls: string }[][] = [[]];
  tokens.forEach((t) => {
    const parts = t.text.split("\n");
    parts.forEach((p, i) => {
      if (i > 0) lines.push([]);
      if (p) lines[lines.length - 1].push({ text: p, cls: t.cls });
    });
  });

  return (
    <pre className={`code-scroll overflow-auto text-[12.5px] leading-[1.62] font-mono ${className}`}>
      <code>
        {lines.map((line, i) => (
          <div key={i} className="flex min-w-max hover:bg-[#0f2018] transition-colors duration-150">
            {showLineNumbers && (
              <span className="sticky left-0 w-11 shrink-0 select-none border-r border-[#14261d] bg-[#071009] pr-3 text-right text-[#3d5a4a]">
                {i + 1}
              </span>
            )}
            <span className="whitespace-pre pl-4">
              {line.length === 0
                ? " "
                : line.map((seg, j) =>
                    seg.cls ? (
                      <span key={j} className={seg.cls}>
                        {seg.text}
                      </span>
                    ) : (
                      <Fragment key={j}>{seg.text}</Fragment>
                    )
                  )}
            </span>
          </div>
        ))}
      </code>
    </pre>
  );
}
