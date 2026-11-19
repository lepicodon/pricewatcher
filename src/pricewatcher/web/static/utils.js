/**
 * Shared client-side helpers for CSRF-safe fetch, URL sanitization, escaping,
 * slug generation, and DOM-safe element construction.
 */

/**
 * Return the CSRF token embedded in the document head meta tag.
 */
export function getCsrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";
}

/**
 * Perform a fetch request, attaching X-CSRF-Token on mutating HTTP methods
 * and redirecting to /login on 401 responses.
 */
export async function csrfFetch(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
    const token = getCsrfToken();
    if (token) {
      headers.set("X-CSRF-Token", token);
    }
  }
  const res = await fetch(url, { ...options, headers });
  if (res.status === 401) {
    window.location.assign("/login");
    throw new Error("Authentication required");
  }
  return res;
}

/**
 * Escape HTML metacharacters for safe plain-text interpolation.
 */
export function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Allow only relative paths or http/https URLs; return "#" for unsafe schemes.
 */
export function safeUrl(raw) {
  const text = String(raw || "").trim();
  if (!text || /[\x00-\x1f\x7f]/.test(text)) {
    return "#";
  }
  if (text.startsWith("/") && !text.startsWith("//") && !text.startsWith("/\\")) {
    return text;
  }
  if (/^https?:/i.test(text) && !/^https?:\/\//i.test(text)) {
    return "#";
  }
  try {
    const parsed = new URL(text);
    if ((parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.hostname) {
      return text;
    }
  } catch {
    return "#";
  }
  return "#";
}

/**
 * Normalize an arbitrary name into a hyphenated slug identifier (max 63 chars).
 */
export function slugifyId(raw) {
  return String(raw || "")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}

/**
 * Build a preview <li> element for a discovered or probed listing item.
 */
export function buildPreviewListItem(item) {
  const li = document.createElement("li");
  const prefix = `$${Number(item.price).toLocaleString()} · ${item.merchant || ""} — `;
  li.append(document.createTextNode(prefix));
  const href = safeUrl(item.url);
  if (item.url && href !== "#") {
    const link = document.createElement("a");
    link.href = href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = item.title || "Open listing";
    li.appendChild(link);
  } else {
    li.append(document.createTextNode(item.title || ""));
  }
  return li;
}

/**
 * Construct an inline decorative SVG icon element using createElementNS.
 */
export function createSvgIcon(kind) {
  const svgNs = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNs, "svg");
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");

  const appendEl = (tag, attrs) => {
    const el = document.createElementNS(svgNs, tag);
    Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
    svg.appendChild(el);
  };

  if (kind === "save") {
    appendEl("path", { d: "M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z" });
    appendEl("polyline", { points: "17 21 17 13 7 13 7 21" });
    appendEl("polyline", { points: "7 3 7 8 15 8" });
  } else if (kind === "send") {
    appendEl("line", { x1: "22", y1: "2", x2: "11", y2: "13" });
    appendEl("polygon", { points: "22 2 15 22 11 13 2 9 22 2" });
  } else if (kind === "trash") {
    appendEl("polyline", { points: "3 6 5 6 21 6" });
    appendEl("path", { d: "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" });
    appendEl("path", { d: "M10 11v6M14 11v6" });
    appendEl("path", { d: "M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" });
  } else if (kind === "play") {
    appendEl("polygon", { points: "6 4 20 12 6 20 6 4" });
  } else if (kind === "plus") {
    appendEl("line", { x1: "12", y1: "5", x2: "12", y2: "19" });
    appendEl("line", { x1: "5", y1: "12", x2: "19", y2: "12" });
  }
  return svg;
}
