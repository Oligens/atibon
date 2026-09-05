import { useCallback, useEffect, useRef, useState } from "react";

/** Respecte `prefers-reduced-motion` (reactif). */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(
    () => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const onChange = () => setReduced(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  return reduced;
}

const GLYPHS = "01<>[]{}#$%&*+=/\\|アカサタナハマヤラワABCDEFXZ";

/** Effet « scramble-decode » : le texte se brouille puis se résout. */
export function useScramble(text: string, active: boolean, speed = 28): string {
  const reduced = useReducedMotion();
  const [out, setOut] = useState(reduced ? text : "");
  useEffect(() => {
    if (!active) return;
    if (reduced) {
      setOut(text);
      return;
    }
    let frame = 0;
    let raf = 0;
    let last = 0;
    const tick = (t: number) => {
      if (t - last >= speed) {
        last = t;
        frame++;
        const resolved = Math.floor(frame / 2.2);
        let s = "";
        for (let i = 0; i < text.length; i++) {
          if (text[i] === " " || text[i] === "\n") s += text[i];
          else if (i < resolved) s += text[i];
          else s += GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
        }
        setOut(s);
        if (resolved >= text.length) return;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [text, active, reduced, speed]);
  return out;
}

/** Révélation au scroll via IntersectionObserver. */
export function useReveal<T extends HTMLElement = HTMLDivElement>(threshold = 0.15) {
  const ref = useRef<T | null>(null);
  const [inView, setInView] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            setInView(true);
            obs.unobserve(e.target);
          }
        });
      },
      { threshold, rootMargin: "0px 0px -8% 0px" }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [threshold]);
  return { ref, inView };
}

/** Machine à écrire pour le terminal d'amorçage. */
export function useTypedLines(lines: string[], active: boolean, charDelay = 7, lineDelay = 110) {
  const reduced = useReducedMotion();
  const [count, setCount] = useState<{ line: number; char: number; done: boolean }>({
    line: 0,
    char: 0,
    done: false,
  });
  useEffect(() => {
    if (!active) return;
    if (reduced) {
      setCount({ line: lines.length, char: 0, done: true });
      return;
    }
    let line = 0;
    let char = 0;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const step = () => {
      if (cancelled) return;
      if (line >= lines.length) {
        setCount({ line, char: 0, done: true });
        return;
      }
      const current = lines[line];
      if (char < current.length) {
        char += 2;
        setCount({ line, char: Math.min(char, current.length), done: false });
        timer = setTimeout(step, charDelay);
      } else {
        line++;
        char = 0;
        setCount({ line, char: 0, done: false });
        timer = setTimeout(step, lineDelay);
      }
    };
    timer = setTimeout(step, 300);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [active, reduced, lines, charDelay, lineDelay]);
  return count;
}

export function useNow(intervalMs: number, active = true): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs, active]);
  return now;
}

export function useCopy(): [boolean, (text: string) => void] {
  const [copied, setCopied] = useState(false);
  const copy = useCallback((text: string) => {
    const done = () => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    };
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(done);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
      } catch {
        /* silencieux */
      }
      document.body.removeChild(ta);
      done();
    }
  }, []);
  return [copied, copy];
}
