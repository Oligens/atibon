const blacklist = globalThis.__ATIBON_BLACKLIST__ || new Set();
globalThis.__ATIBON_BLACKLIST__ = blacklist;

const SENSITIVE = /(?:^|\/)(?:\.git|\.env|src|core-rust|bridge-python|ml-engine|zero-trust|deploy)(?:\/|$)|\.(?:map|rs|tsx?|jsx?|py|toml|lock)$/i;

function clientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length) return forwarded.split(",")[0].trim();
  const real = req.headers["x-real-ip"];
  if (typeof real === "string" && real.length) return real.trim();
  return "unknown";
}

export default function handler(req, res) {
  if (req.method !== "POST" && req.method !== "GET") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ ok: false, error: "method_not_allowed" });
  }

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = {}; }
  }

  const queryTarget = typeof req.query?.target === "string" ? req.query.target : "";
  const target = typeof body?.target === "string" ? body.target : queryTarget || "unknown";
  const ip = clientIp(req);
  const reason = SENSITIVE.test(target) ? "source_probe" : "security_probe";
  const event = {
    ip,
    target: target.slice(0, 512),
    method: typeof body?.method === "string" ? body.method.slice(0, 16) : req.method,
    kind: typeof body?.kind === "string" ? body.kind.slice(0, 32) : "server-route",
    reason,
    timestamp: new Date().toISOString(),
  };

  blacklist.add(ip);
  console.warn("[ATIBON][HONEYPOT] intercepted", event);

  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-ATIBON-Blacklisted", "true");

  if (req.method === "GET") {
    res.setHeader("Location", "/__atibon_honeypot");
    return res.status(302).end();
  }
  return res.status(202).json({ ok: true, intercepted: true, blacklisted: true });
}
