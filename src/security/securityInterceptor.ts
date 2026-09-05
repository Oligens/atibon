const HONEYPOT_PATH = "/__atibon_honeypot";
const REPORT_ENDPOINT = "/api/security/intercept";

const SENSITIVE_PATHS = [
  /(^|\/)\.git(?:\/|$)/i,
  /(^|\/)\.env(?:\.|\/|$)/i,
  /(^|\/)(?:src|core-rust|bridge-python|ml-engine|zero-trust|deploy)(?:\/|$)/i,
  /(^|\/)(?:package(?:-lock)?\.json|Cargo\.toml|Cargo\.lock|tsconfig(?:\.[^/]+)?\.json|vite\.config\.[^/]+|webpack\.config\.[^/]+)(?:$|\?)/i,
  /\.(?:map|rs|tsx?|jsx?|py|toml|lock)$/i,
  /(?:source|debug|dump|inspect|dissect|__webpack|__vite|\.git)/i,
];

let installed = false;
let triggered = false;

function normalizePath(input: string): string {
  try {
    return decodeURIComponent(new URL(input, window.location.origin).pathname);
  } catch {
    return input.split("?")[0].split("#")[0];
  }
}

function isSensitive(input: string): boolean {
  const path = normalizePath(input);
  if (!path || path === HONEYPOT_PATH || path.startsWith(REPORT_ENDPOINT)) return false;
  return SENSITIVE_PATHS.some((pattern) => pattern.test(path));
}

function reportThreat(target: string, method: string, kind: string) {
  if (triggered) return;
  triggered = true;

  const payload = JSON.stringify({
    target: normalizePath(target),
    method,
    kind,
    timestamp: new Date().toISOString(),
    referrer: document.referrer || null,
  });

  try {
    if (navigator.sendBeacon) {
      navigator.sendBeacon(REPORT_ENDPOINT, new Blob([payload], { type: "application/json" }));
    } else {
      void fetch(REPORT_ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: payload,
        keepalive: true,
      });
    }
  } catch {
    // The local redirect remains fail-closed even when telemetry is unavailable.
  }

  sessionStorage.setItem("atibon:honeypot-triggered", "1");
  window.history.replaceState({ atibonHoneypot: true }, "", HONEYPOT_PATH);
  window.dispatchEvent(new CustomEvent("atibon:honeypot", { detail: { target, method, kind } }));
}

function inspectNavigation(target: string, method = "GET", kind = "navigation"): boolean {
  if (!isSensitive(target)) return false;
  reportThreat(target, method, kind);
  return true;
}

export function installSecurityInterceptor() {
  if (installed) return () => undefined;
  installed = true;

  const originalFetch = window.fetch.bind(window);
  window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    const target = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (inspectNavigation(target, init?.method ?? (input instanceof Request ? input.method : "GET"), "fetch")) {
      return Promise.reject(new DOMException("ATIBON request intercepted", "SecurityError"));
    }
    return originalFetch(input, init);
  }) as typeof window.fetch;

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method: string, url: string | URL, ...rest: any[]) {
    if (inspectNavigation(String(url), method, "xhr")) {
      (this as XMLHttpRequest & { __atibonBlocked?: boolean }).__atibonBlocked = true;
    }
    return originalOpen.call(this, method, url, ...rest);
  } as typeof XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.send = function (body?: Document | XMLHttpRequestBodyInit | null) {
    if ((this as XMLHttpRequest & { __atibonBlocked?: boolean }).__atibonBlocked) {
      this.abort();
      return;
    }
    return originalSend.call(this, body);
  };

  const onClick = (event: MouseEvent) => {
    const anchor = (event.target as Element | null)?.closest("a[href]") as HTMLAnchorElement | null;
    if (!anchor) return;
    const url = new URL(anchor.href, window.location.origin);
    if (url.origin !== window.location.origin) return;
    if (inspectNavigation(url.href, "GET", "link")) event.preventDefault();
  };

  const onPopState = () => {
    if (inspectNavigation(window.location.href, "GET", "history")) return;
  };

  const originalPushState = history.pushState.bind(history);
  const originalReplaceState = history.replaceState.bind(history);
  history.pushState = ((state: any, title: string, url?: string | URL | null) => {
    if (url && inspectNavigation(String(url), "GET", "history")) return;
    originalPushState(state, title, url);
  }) as typeof history.pushState;
  history.replaceState = ((state: any, title: string, url?: string | URL | null) => {
    if (url && inspectNavigation(String(url), "GET", "history")) return;
    originalReplaceState(state, title, url);
  }) as typeof history.replaceState;

  document.addEventListener("click", onClick, true);
  window.addEventListener("popstate", onPopState);

  // A direct navigation that reached the SPA fallback is still a source-probing attempt.
  if (isSensitive(window.location.pathname)) reportThreat(window.location.pathname, "GET", "direct-navigation");

  return () => {
    document.removeEventListener("click", onClick, true);
    window.removeEventListener("popstate", onPopState);
    window.fetch = originalFetch;
    XMLHttpRequest.prototype.open = originalOpen;
    XMLHttpRequest.prototype.send = originalSend;
    history.pushState = originalPushState;
    history.replaceState = originalReplaceState;
    installed = false;
  };
}

export { HONEYPOT_PATH };
