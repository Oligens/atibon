import MatrixRain from "./MatrixRain";

const SKULL = [
  "                 0000000000000                 ",
  "             0011ABCDEFABCDEF1100             ",
  "          001ABCDEF0123456789FEDCBA100        ",
  "        01ABCDEF0123456789ABCDEF01210         ",
  "      01ABCDEF0123456789ABCDEF01234510        ",
  "     1ABCDEF0123456789ABCDEF0123456781       ",
  "    1ABCDEF0123456       6543210FEDCBA1      ",
  "   1ABCDEF01234    0011100    43210FEDC1     ",
  "  1ABCDEF0123   01111111110   3210FEDCBA1    ",
  " 1ABCDEF012   01111      11110   210FEDCBA1 ",
  " 1ABCDEF01   0111          1110   10FEDCBA1 ",
  " 1ABCDEF0   011              110   0FEDCBA1 ",
  " 1ABCDEFF   11      0000      11   FFEDCBA1 ",
  " 1ABCDEEF   1     00000000     1   FEEDCBA1 ",
  "  1ABCDEE        0001111000        EEDCBA1  ",
  "  1ABCDEE          0110          EEDCBA1    ",
  "   1ABCDE        00111100        EDCBA1     ",
  "    1ABCD     00111111111100     DCBA1      ",
  "     1ABC   011111111111111110   CBA1       ",
  "      1AB  01111111111111111110  BA1        ",
  "       1A  01111111111111111110  A1         ",
  "       11  01110111011101110110  11         ",
  "       10  01010101010101010100  01         ",
  "        0  00100100100100100100  0          ",
  "          0000000000000000000000            ",
];

export default function HoneypotOverlay() {
  return (
    <div className="fixed inset-0 z-[9999] overflow-hidden bg-black" aria-hidden="true">
      <MatrixRain className="absolute inset-0 opacity-90" />
      <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
        <pre className="select-none whitespace-pre font-mono text-[clamp(7px,1.15vw,16px)] leading-[1.03] tracking-[0.02em] text-[#36ff9d] opacity-90 [text-shadow:0_0_4px_rgba(43,255,158,.95),0_0_18px_rgba(43,255,158,.55)] motion-safe:animate-pulse">{SKULL.join("\n")}</pre>
      </div>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_25%,rgba(0,0,0,.25)_60%,rgba(0,0,0,.78)_100%)]" />
    </div>
  );
}
