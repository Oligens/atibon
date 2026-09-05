import { useEffect, useRef } from "react";
import { useReducedMotion } from "../hooks";

const GLYPHS = "アカサタナハマヤラワガザダバパイキシチニヒミリヰウクスツヌフムユル0123456789ABCDEF:+*#";
const COJ = ["C", "O", "J"];

/** Pluie de code verte (canvas) — signature « COJ » subliminale. */
export default function MatrixRain({ className = "" }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const reduced = useReducedMotion();

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const cell = 15;
    let W = 0;
    let H = 0;
    let cols: number[] = [];
    let frame = 0;
    let raf = 0;
    let last = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    const resize = () => {
      W = canvas.clientWidth;
      H = canvas.clientHeight;
      canvas.width = W * dpr;
      canvas.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cols = Array.from({ length: Math.ceil(W / cell) }, (_, i) => -((i * 7) % 25) - Math.random() * 12);
      ctx.fillStyle = "#020805";
      ctx.fillRect(0, 0, W, H);
    };

    const drawFrame = () => {
      frame++;
      ctx.fillStyle = "rgba(2, 8, 5, 0.14)";
      ctx.fillRect(0, 0, W, H);
      ctx.font = `${cell - 2}px "IBM Plex Mono", monospace`;

      cols.forEach((y, i) => {
        const ch = GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
        const px = i * cell;
        const py = y * cell;
        // tête de colonne en sur-brillance
        ctx.fillStyle = "#b9ffd9";
        ctx.fillText(ch, px, py);
        // corps en vert matriciel
        ctx.fillStyle = `rgba(43, 255, 158, ${0.55 + Math.random() * 0.3})`;
        const trail = GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
        if (py - cell > 0) ctx.fillText(trail, px, py - cell);

        cols[i] = y + 0.6 + (i % 5) * 0.12;
        if (cols[i] * cell > H + 120) cols[i] = -Math.random() * 18;
      });

      // incrustation subliminale « COJ » verticale, toutes les 36 frames
      if (frame % 36 === 0) {
        const cx = Math.floor(Math.random() * (cols.length - 2)) * cell;
        const cy = Math.random() * (H - 80) + 30;
        ctx.fillStyle = "#eafff3";
        ctx.shadowColor = "#2bff9e";
        ctx.shadowBlur = 12;
        COJ.forEach((c, k) => ctx.fillText(c, cx, cy + k * (cell + 2)));
        ctx.shadowBlur = 0;
      }
    };

    const loop = (t: number) => {
      if (t - last >= 55) {
        last = t;
        drawFrame();
      }
      raf = requestAnimationFrame(loop);
    };

    resize();
    if (reduced) {
      // frame statique unique — préférence système respectée
      for (let i = 0; i < 6; i++) drawFrame();
    } else {
      raf = requestAnimationFrame(loop);
    }

    const ro = new ResizeObserver(() => resize());
    ro.observe(canvas);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [reduced]);

  return <canvas ref={ref} className={`h-full w-full ${className}`} />;
}
