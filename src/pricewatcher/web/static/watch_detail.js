/**
 * Watch detail page behaviors: inspect last fetched items per source in a modal.
 */

function isSafeHttpUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl) return false;
  try {
    const parsed = new URL(rawUrl, window.location.origin);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function formatPrice(price) {
  if (typeof price !== "number" || Number.isNaN(price)) return "—";
  return `$${price.toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

export function initWatchDetailPage() {
  const dialog = document.getElementById("source-fetched-dialog");
  const titleEl = document.getElementById("source-fetched-title");
  const metaEl = document.getElementById("source-fetched-meta");
  const tbody = document.getElementById("source-fetched-tbody");
  if (!dialog || !titleEl || !metaEl || !tbody) return;

  let currentItems = [];
  let currentFilter = "all";
  const filterButtons = Array.from(dialog.querySelectorAll("[data-fetched-filter]"));

  function renderRows() {
    tbody.replaceChildren();
    const filtered = currentItems.filter((item) => {
      if (currentFilter === "matched") return Boolean(item.matched);
      if (currentFilter === "rejected") return !item.matched;
      return true;
    });

    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 6;
      td.className = "muted";
      td.textContent = "No items match this filter.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    for (const item of filtered) {
      const tr = document.createElement("tr");

      const statusTd = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = item.matched ? "badge badge-active" : "badge badge-bad";
      badge.textContent = item.matched ? "Matched" : "Rejected";
      statusTd.appendChild(badge);
      tr.appendChild(statusTd);

      const priceTd = document.createElement("td");
      priceTd.className = "num";
      priceTd.textContent = formatPrice(item.price);
      tr.appendChild(priceTd);

      const merchantTd = document.createElement("td");
      merchantTd.textContent = item.merchant || "—";
      tr.appendChild(merchantTd);

      const titleTd = document.createElement("td");
      if (isSafeHttpUrl(item.url)) {
        const link = document.createElement("a");
        link.href = item.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = item.title || item.url;
        titleTd.appendChild(link);
      } else {
        titleTd.textContent = item.title || "—";
      }
      tr.appendChild(titleTd);

      const condTd = document.createElement("td");
      condTd.textContent = item.in_stock === false ? `${item.condition || "new"} (OOS)` : (item.condition || "new");
      tr.appendChild(condTd);

      const reasonTd = document.createElement("td");
      reasonTd.textContent = item.reason || "—";
      tr.appendChild(reasonTd);

      tbody.appendChild(tr);
    }
  }

  function setFilter(nextFilter) {
    currentFilter = nextFilter;
    for (const btn of filterButtons) {
      btn.classList.toggle("btn-primary", btn.dataset.fetchedFilter === nextFilter);
    }
    renderRows();
  }

  for (const btn of filterButtons) {
    btn.addEventListener("click", () => {
      setFilter(btn.dataset.fetchedFilter || "all");
    });
  }

  document.querySelectorAll("[data-fetched-modal]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sourceName = btn.dataset.sourceName || "Source";
      const fetchedCount = Number(btn.dataset.fetchedCount || 0);
      const matchedCount = Number(btn.dataset.matchedCount || 0);
      const lastChecked = btn.dataset.lastChecked || "";

      try {
        const parsed = JSON.parse(btn.dataset.fetchedItems || "[]");
        currentItems = Array.isArray(parsed) ? parsed : [];
      } catch {
        currentItems = [];
      }

      titleEl.textContent = sourceName;
      const truncatedNote =
        fetchedCount > currentItems.length
          ? ` (showing first ${currentItems.length})`
          : "";
      metaEl.textContent =
        `${fetchedCount} fetched${truncatedNote} · ${matchedCount} matched` +
        (lastChecked ? ` · Last checked ${lastChecked} UTC` : "");

      setFilter("all");
      if (!dialog.open && typeof dialog.showModal === "function") {
        dialog.showModal();
      }
    });
  });
}
