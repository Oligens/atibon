import { useEffect, useRef } from "react";
import { useReducedMotion } from "../hooks";

const GLYPHS = "アカサタナハマヤラワガザダバパイキシチニヒミリヰウクスツヌフムユル0123456789ABCDEFabcdef<>[]{}:/\\|+-=*#@$%COJ";

function drawSkullMask(ctx: CanvasRenderingContext2D, w: number, h: number) {
  const cx = w * 0.5;
  const cy = h * 0.49;
  const scale = Math.min(w / 720, h / 560);

  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "white";

  // Cranium: broad forehead narrowing into the cheek bones.
  ctx.beginPath();
  ctx.ellipse(cx, cy - 58 * scale, 174 * scale, 190 * scale, 0, 0, Math.PI * 2);
  ctx.fill();

  // Temporal / cheek structure.
  ctx.beginPath();
  ctx.moveTo(cx - 156 * scale, cy - 28 * scale);
  ctx.lineTo(cx - 194 * scale, cy + 22 * scale);
  ctx.lineTo(cx - 156 * scale, cy + 106 * scale);
  ctx.lineTo(cx - 103 * scale, cy + 130 * scale);
  ctx.lineTo(cx - 76 * scale, cy + 208 * scale);
  ctx.lineTo(cx, cy + 232 * scale);
  ctx.lineTo(cx + 76 * scale, cy + 208 * scale);
  ctx.lineTo(cx + 103 * scale, cy + 130 * scale);
  ctx.lineTo(cx + 156 * scale, cy + 106 * scale);
  ctx.lineTo(cx + 194 * scale, cy + 22 * scale);
  ctx.lineTo(cx + 156 * scale, cy - 28 * scale);
  ctx.closePath();
  ctx.fill();

  // Eye sockets.
  ctx.globalCompositeOperation = "destination-out";
  ctx.beginPath();
  ctx.ellipse(cx - 72 * scale, cy - 38 * scale, 54 * scale, 48 * scale, -0.1, 0, Math.PI * 2);
  ctx.fill();
  ctx.beginPath();
  ctx.ellipse(cx + 72 * scale, cy - 38 * scale, 54 * scale, 48 * scale, 0.1, 0, Math.PI * 2);
  ctx.fill();

  // Nasal cavity.
  ctx.beginPath();
  ctx.moveTo(cx, cy + 3 * scale);
  ctx.lineTo(cx - 30 * scale, cy + 61 * scale);
  ctx.lineTo(cx, cy + 83 * scale);
  ctx.lineTo(cx + 30 * scale, cy + 61 * scale);
  ctx.closePath();
  ctx.fill();

  // Jaw / mouth cavity. Teeth are rendered separately as glyphs.
  ctx.beginPath();
  ctx.roundRect(cx - 91 * scale, cy + 91 * scale, 182 * scale, 66 * scale, 17 * scale);
  ctx.fill();

  ctx.globalCompositeOperation = "source-over";
}

export default function HoneypotOverlay() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const reduced = useReducedMotion();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const mask = document.createElement("canvas");
    const maskCtx = mask.getContext("2d");
    if (!maskCtx) return;

    let width = 0;
    let height = 0;
    let dpr = 1;
    let columns: number[] = [];
    let speeds: number[] = [];
    let frame = 0;
    let raf = 0;
    let last = 0;

    const resize = () => {
      width = Math.max(1, canvas.clientWidth);
      height = Math.max(1, canvas.clientHeight);
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      mask.width = width;
      mask.height = height;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      columns = Array.from({ length: Math.ceil(width / 13) + 2 }, () => -Math.random() * 70);
      speeds = columns.map(() => 0.38 + Math.random() * 0.72);
      drawSkullMask(maskCtx, width, height);
    };

    const randomGlyph = () => GLYPHS[Math.floor(Math.random() * GLYPHS.length)];

    const drawRain = () => {
      ctx.fillStyle = "rgba(0, 4, 2, 0.18)";
      ctx.fillRect(0, 0, width, height);
      ctx.font = "13px 'IBM Plex Mono', monospace";
      ctx.textAlign = "center";

      columns.forEach((y, i) => {
        const x = i * 13;
        const headY = y * 15;
        ctx.shadowBlur = 8;
        ctx.shadowColor = "rgba(43,255,158,0.8)";
        ctx.fillStyle = "rgba(215,255,232,0.92)";
        ctx.fillText(randomGlyph(), x, headY);
        ctx.shadowBlur = 0;

        for (let trail = 1; trail < 13; trail++) {
          const alpha = Math.max(0.025, 0.55 - trail * 0.043);
          ctx.fillStyle = `rgba(43,255,158,${alpha})`;
          ctx.fillText(randomGlyph(), x, headY - trail * 15);
        }

        columns[i] += speeds[i];
        if (columns[i] * 15 > height + 190) {
          columns[i] = -Math.random() * 35;
          speeds[i] = 0.38 + Math.random() * 0.72;
        }
      });
    };

    const drawSkull = () => {
      const pixels = maskCtx.getImageData(0, 0, width, height).data;
      const step = width < 700 ? 12 : 10;
      const cx = width * 0.5;
      const cy = height * 0.49;
      const scale = Math.min(width / 720, height / 560);

      ctx.save();
      ctx.beginPath();
      ctx.rect(0, 0, width, height);
      ctx.clip(mask);

      ctx.font = `${Math.max(10, 14 * scale)}px 'IBM Plex Mono', monospace`;
      ctx.textAlign = "center";
      for (let y = Math.max(0, cy - 250 * scale); y < Math.min(height, cy + 245 * scale); y += step) {
        for (let x = Math.max(0, cx - 205 * scale); x < Math.min(width, cx + 205 * scale); x += step) {
          const px = Math.floor(x);
          const py = Math.floor(y);
          const alpha = pixels[(py * width + px) * 4 + 3];
          if (alpha < 128) continue;

          const dx = (x - cx) / (190 * scale);
          const dy = (y - cy) / (235 * scale);
          const edge = Math.max(0, 1 - Math.sqrt(dx * dx + dy * dy));
          const flicker = 0.58 + Math.random() * 0.36;
          const brightness = Math.min(0.98, 0.34 + edge * 0.58) * flicker;
          ctx.fillStyle = `rgba(66,255,157,${brightness})`;
          ctx.shadowColor = "rgba(43,255,158,0.72)";
          ctx.shadowBlur = edge > 0.45 ? 5 : 2;
          ctx.fillText(randomGlyph(), x, y);
        }
      }
      ctx.restore();

      // Dense luminous contour makes the skull read cleanly without adding text.
      ctx.save();
      ctx.globalCompositeOperation = "screen";
      ctx.strokeStyle = "rgba(93,255,177,0.28)";
      ctx.lineWidth = Math.max(1, 1.2 * scale);
      ctx.shadowColor = "rgba(43,255,158,0.55)";
      ctx.shadowBlur = 12;
      ctx.beginPath();
      ctx.ellipse(cx, cy - 58 * scale, 174 * scale, 190 * scale, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();
    };

    const drawFrame = () => {
      frame += 1;
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = "#000402";
      ctx.fillRect(0, 0, width, height);
      drawRain();
      drawSkull();

      // Subtle scanlines and vignette, with no interface text.
      ctx.fillStyle = "rgba(0,0,0,0.13)";
      for (let y = 0; y < height; y += 4) ctx.fillRect(0, y, width, 1);
      const gradient = ctx.createRadialGradient(width / 2, height / 2, Math.min(width, height) * 0.15, width / 2, height / 2, Math.max(width, height) * 0.72);
      gradient.addColorStop(0, "rgba(0,0,0,0)");
      gradient.addColorStop(1, "rgba(0,0,0,0.68)");
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 0, width, height);

      void frame;
    };

    const loop = (time: number) => {
      if (time - last >= 48) {
        last = time;
        drawFrame();
      }
      raf = requestAnimationFrame(loop);
    };

    resize();
    drawFrame();
    if (!reduced) raf = requestAnimationFrame(loop);

    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [reduced]);

  return (
    <div className="fixed inset-0 z-[9999] overflow-hidden bg-black" aria-hidden="true">
      <canvas ref={canvasRef} className="block h-full w-full" />
    </div>
  );
}
