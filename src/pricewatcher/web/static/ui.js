/**
 * Shared UI behaviors across all pages: theme toggle, progressive dialog and
 * Invoker Commands fallbacks, form validation hooks, dashboard check trigger,
 * WAI-ARIA tablist keyboard navigation, and sortable table headers.
 */

import { csrfFetch } from "./utils.js";

function initThemeToggle() {
  const themeMeta = document.querySelector('meta[name="color-scheme"]');
  const themeToggleBtn = document.getElementById("theme-toggle-btn");
  const systemDarkQuery = window.matchMedia("(prefers-color-scheme: dark)");

  function currentSystemScheme() {
    return systemDarkQuery.matches ? "dark" : "light";
  }

  function applyTheme(stored) {
    const mode = stored === "light" || stored === "dark" ? stored : "light dark";
    if (themeMeta) {
      themeMeta.content = mode;
    }
    document.documentElement.classList.remove("theme-light", "theme-dark");
    if (stored === "light" || stored === "dark") {
      document.documentElement.classList.add(`theme-${stored}`);
    }

    if (themeToggleBtn) {
      const effective = mode === "light dark" ? currentSystemScheme() : mode;
      const isPinned = mode === "light" || mode === "dark";
      const targetLabel = effective === "dark" ? "Light" : "Dark";
      const label = isPinned
        ? `Theme: ${effective[0].toUpperCase()}${effective.slice(1)} (click to reset)`
        : `Switch to ${targetLabel} theme`;
      themeToggleBtn.setAttribute("data-effective-theme", effective);
      themeToggleBtn.setAttribute("aria-label", label);
      themeToggleBtn.setAttribute("title", label);
      themeToggleBtn.setAttribute("aria-pressed", isPinned ? "true" : "false");
    }
  }

  if (themeToggleBtn) {
    applyTheme(localStorage.getItem("color-scheme"));

    themeToggleBtn.addEventListener("click", () => {
      const current = localStorage.getItem("color-scheme");
      if (current === "light" || current === "dark") {
        localStorage.removeItem("color-scheme");
        applyTheme(null);
      } else {
        const opposite = currentSystemScheme() === "dark" ? "light" : "dark";
        localStorage.setItem("color-scheme", opposite);
        applyTheme(opposite);
      }
    });

    systemDarkQuery.addEventListener("change", () => {
      if (!localStorage.getItem("color-scheme")) {
        applyTheme(null);
      }
    });
  }
}

function initDialogLightDismissFallback() {
  // Fallback for light-dismiss dialogs when closedBy is unsupported (e.g. Safari)
  document.querySelectorAll("dialog[closedby='any']").forEach((dialog) => {
    if (!("closedBy" in HTMLDialogElement.prototype)) {
      dialog.addEventListener("click", (event) => {
        if (event.target !== dialog) return;
        const rect = dialog.getBoundingClientRect();
        const inside =
          rect.top <= event.clientY &&
          event.clientY <= rect.top + rect.height &&
          rect.left <= event.clientX &&
          event.clientX <= rect.left + rect.width;
        if (!inside) {
          dialog.close();
        }
      });
    }
  });
}

function initInvokerCommandsFallback() {
  // Progressive fallback for Invoker Commands API (commandfor / command)
  if (!("commandForElement" in HTMLButtonElement.prototype)) {
    document.addEventListener("click", (event) => {
      const btn = event.target instanceof Element ? event.target.closest("button[commandfor]") : null;
      if (!btn) return;
      const targetId = btn.getAttribute("commandfor");
      const command = btn.getAttribute("command");
      const target = targetId ? document.getElementById(targetId) : null;
      if (!target || !(target instanceof HTMLDialogElement)) return;
      if (command === "show-modal" && !target.open) {
        target.showModal();
      } else if (command === "close" && target.open) {
        target.close();
      }
    });
  }
}

function initFormValidation() {
  // Blur / input validation feedback for forms
  document.querySelectorAll("form[data-validate]").forEach((form) => {
    form.addEventListener(
      "blur",
      (event) => {
        const el = event.target;
        if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
          el.checkValidity();
        }
      },
      true
    );
    form.addEventListener("input", (event) => {
      const el = event.target;
      if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
        el.setCustomValidity("");
      }
    });
  });
}

function initRunWatchButtons() {
  // "Run Check Now" async buttons on dashboard
  document.querySelectorAll("[data-run-watch]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const watchId = btn.getAttribute("data-run-watch");
      if (!watchId) return;
      const origText = btn.textContent;
      btn.setAttribute("disabled", "");
      btn.textContent = "Checking...";
      try {
        const res = await csrfFetch(`/api/watches/${encodeURIComponent(watchId)}/run`, {
          method: "POST",
        });
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        window.location.reload();
      } catch (err) {
        btn.removeAttribute("disabled");
        btn.textContent = origText || "Run Check Now";
        alert(`Check failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    });
  });
}

/**
 * Shared WAI-ARIA tablist keyboard navigation (ArrowLeft/Right, Home, End).
 */
export function bindTablistKeyboard(tablistEl, tabSelector, activateFn) {
  if (!tablistEl) return;
  const syncTabIndices = () => {
    tablistEl.querySelectorAll(tabSelector).forEach((tab) => {
      const selected = tab.getAttribute("aria-selected") === "true";
      tab.setAttribute("tabindex", selected ? "0" : "-1");
    });
  };
  syncTabIndices();

  tablistEl.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    const tabs = Array.from(tablistEl.querySelectorAll(tabSelector));
    if (tabs.length === 0) return;
    const currentIdx = tabs.indexOf(document.activeElement);
    if (currentIdx === -1) return;

    event.preventDefault();
    let nextIdx = currentIdx;
    if (event.key === "ArrowRight") nextIdx = (currentIdx + 1) % tabs.length;
    else if (event.key === "ArrowLeft") nextIdx = (currentIdx - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") nextIdx = 0;
    else if (event.key === "End") nextIdx = tabs.length - 1;

    const targetTab = tabs[nextIdx];
    const attrName = tabSelector.replace(/^\[|\]$/g, "");
    activateFn(targetTab.getAttribute(attrName) || "");
    syncTabIndices();
    targetTab.focus();
  });
}

function parseSortValue(rawText) {
  const text = rawText.trim();
  if (!text || text === "—" || text === "-") {
    return { empty: true, num: 0, text: "" };
  }
  const numericCandidate = text.replace(/^\$/, "").replace(/,/g, "").replace(/\s*ms$/i, "");
  if (/^-?\d+(\.\d+)?$/.test(numericCandidate)) {
    return { empty: false, num: Number(numericCandidate), isNum: true, text };
  }
  return { empty: false, num: 0, isNum: false, text: text.toLowerCase() };
}

function initSortableTables() {
  // Sortable table headers across all data tables
  document.querySelectorAll(".table-wrap table").forEach((table) => {
    const tbody = table.querySelector("tbody");
    const headers = Array.from(table.querySelectorAll("thead th"));
    if (!tbody || headers.length === 0) return;

    headers.forEach((th, colIndex) => {
      if (th.hasAttribute("data-no-sort")) return;
      const label = th.textContent.trim();
      th.setAttribute("aria-sort", "none");
      th.textContent = "";

      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "sort-header-btn";
      const labelSpan = document.createElement("span");
      labelSpan.textContent = label;
      const indicator = document.createElement("span");
      indicator.className = "sort-indicator";
      indicator.setAttribute("aria-hidden", "true");
      indicator.textContent = "⇅";
      btn.append(labelSpan, indicator);
      th.appendChild(btn);

      btn.addEventListener("click", () => {
        const current = th.getAttribute("aria-sort");
        const nextDir = current === "ascending" ? "descending" : "ascending";

        headers.forEach((other) => {
          if (other.hasAttribute("data-no-sort")) return;
          other.setAttribute("aria-sort", other === th ? nextDir : "none");
          const ind = other.querySelector(".sort-indicator");
          if (ind) {
            ind.textContent = other === th ? (nextDir === "ascending" ? "▲" : "▼") : "⇅";
          }
        });

        const rows = Array.from(tbody.querySelectorAll("tr"));
        const multiplier = nextDir === "ascending" ? 1 : -1;
        rows.sort((a, b) => {
          const cellA = a.children[colIndex]?.textContent || "";
          const cellB = b.children[colIndex]?.textContent || "";
          const valA = parseSortValue(cellA);
          const valB = parseSortValue(cellB);
          if (valA.empty && valB.empty) return 0;
          if (valA.empty) return 1;
          if (valB.empty) return -1;
          if (valA.isNum && valB.isNum) {
            return (valA.num - valB.num) * multiplier;
          }
          return valA.text.localeCompare(valB.text, undefined, { numeric: true }) * multiplier;
        });
        rows.forEach((row) => tbody.appendChild(row));
      });
    });
  });
}

/**
 * Initialize global theme toggle, progressive dialog/command fallbacks,
 * validation hooks, dashboard check triggers, and sortable table headers.
 */
export function initThemeAndUi() {
  initThemeToggle();
  initDialogLightDismissFallback();
  initInvokerCommandsFallback();
  initFormValidation();
  initRunWatchButtons();
  initSortableTables();
}
