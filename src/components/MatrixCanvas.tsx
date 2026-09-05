import { useEffect, useRef } from "react";
import { N, VECTOR_LABELS, type MatN, type VecN } from "../lib/matrix";

interface Props {
  mode: "matrix" | "vector";
  matrix?: MatN;
  vector?: VecN;
  height?: number;
  /** indices de composantes altérées (surbrillance alarme) */
  tampered?: number[];
  title?: string;
}

/** Rendu canvas d'une matrice 12×12 ou d'un vecteur d'état. */
export default function MatrixCanvas({ mode, matrix, vector, height = 300, tampered = [], title }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const draw = () => {
      const canvas = canvasRef.current;
      const wrap = wrapRef.current;
      if (!canvas || !wrap) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = wrap.clientWidth;
      const h = height;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = w + "px";
      canvas.style.height = h + "px";
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, w, h);
      ctx.font = '10px "IBM Plex Mono", monospace';

      if (mode === "matrix" && matrix) {
        const pad = 4;
        const cell = Math.min((w - pad * 2) / N, (h - pad * 2 - 16) / N);
        const ox = (w - cell * N) / 2;
        const oy = 14;
        let maxAbs = 0;
        matrix.forEach((row) => row.forEach((v) => (maxAbs = Math.max(maxAbs, Math.abs(v)))));

        ctx.fillStyle = "#6f8a7b";
        ctx.textAlign = "left";
        ctx.fillText(title ?? "M ∈ GL(12, ℝ)", ox, 10);
        ctx.textAlign = "right";
        ctx.fillText(`‖max‖ = ${maxAbs.toFixed(2)}`, ox + cell * N, 10);

        for (let i = 0; i < N; i++) {
          for (let j = 0; j < N; j++) {
            const v = matrix[i][j];
            const t = Math.abs(v) / maxAbs;
            const x = ox + j * cell;
            const y = oy + i * cell;
            const diag = i === j;
            if (diag) {
              ctx.fillStyle = `rgba(255, 179, 71, ${0.14 + t * 0.5})`;
            } else {
              ctx.fillStyle = v >= 0 ? `rgba(43, 255, 158, ${t * 0.75})` : `rgba(69, 224, 255, ${t * 0.6})`;
            }
            ctx.fillRect(x + 0.5, y + 0.5, cell - 1, cell - 1);
            ctx.fillStyle = t > 0.45 ? "#04120b" : diag ? "#ffcf8f" : "#bfe8d2";
            ctx.textAlign = "center";
            if (cell >= 22) ctx.fillText(v.toFixed(1), x + cell / 2, y + cell / 2 + 3);
          }
        }
      } else if (mode === "vector" && vector) {
        const pad = 14;
        const plotW = w - pad * 2;
        const top = 22;
        const baseY = h - 34;
        const plotH = baseY - top - 8;
        const maxAbs = Math.max(...vector.map((v) => Math.abs(v)), 1);
        const slot = plotW / N;
        const barW = Math.min(slot * 0.62, 30);

        ctx.strokeStyle = "rgba(28, 53, 39, 0.9)";
        ctx.beginPath();
        ctx.moveTo(pad, baseY);
        ctx.lineTo(w - pad, baseY);
        ctx.stroke();

        ctx.fillStyle = "#6f8a7b";
        ctx.textAlign = "left";
        ctx.fillText(title ?? "V ∈ ℝ¹²", pad, 12);
        ctx.textAlign = "right";
        ctx.fillText(`‖V‖∞ = ${maxAbs.toFixed(1)}`, w - pad, 12);

        vector.forEach((v, i) => {
          const x = pad + i * slot + (slot - barW) / 2;
          const bh = (Math.abs(v) / maxAbs) * plotH;
          const y = v >= 0 ? baseY - bh : baseY;
          const isT = tampered.includes(i);
          ctx.fillStyle = isT
            ? "rgba(255, 59, 92, 0.85)"
            : v >= 0
              ? "rgba(43, 255, 158, 0.75)"
              : "rgba(69, 224, 255, 0.65)";
          ctx.fillRect(x, v >= 0 ? y : baseY, barW, Math.max(bh, 2));

          ctx.fillStyle = isT ? "#ff8ba0" : "#7dffb9";
          ctx.textAlign = "center";
          ctx.fillText(v.toFixed(0), x + barW / 2, (v >= 0 ? y - 4 : baseY + bh + 12), slot);
          ctx.fillStyle = isT ? "#ff3b5c" : "#6f8a7b";
          ctx.fillText(VECTOR_LABELS[i], pad + i * slot + slot / 2, h - 12);
        });
      }
    };

    draw();
    const ro = new ResizeObserver(draw);
    if (wrapRef.current) ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, [mode, matrix, vector, height, tampered, title]);

  return (
    <div ref={wrapRef} className="w-full">
      <canvas ref={canvasRef} className="block w-full" />
    </div>
  );
}
