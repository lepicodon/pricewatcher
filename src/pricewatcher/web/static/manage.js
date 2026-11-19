/**
 * Manage page behaviors: delete-watch confirmation dialog, dynamic source rows,
 * watch form auto-fill, vendor search, source pack loader, live probe tool,
 * and manage watch form tabs.
 */

import { bindTablistKeyboard } from "./ui.js";
import { buildPreviewListItem, csrfFetch, slugifyId } from "./utils.js";

let sourceRowSeq = 0;

/**
 * Check whether the Manage page source list already contains the given URL.
 */
export function hasSourceUrl(url) {
  const sourcesContainer = document.getElementById("sources-list");
  if (!sourcesContainer || !url) return false;
  const normalized = url.trim();
  return Array.from(sourcesContainer.querySelectorAll('input[name="source_url"]')).some(
    (inp) => inp.value.trim() === normalized
  );
}

/**
 * Append a new source configuration row to #sources-list unless the URL is duplicate.
 */
export function appendSourceRow(src = {}) {
  const sourcesContainer = document.getElementById("sources-list");
  if (!sourcesContainer) return false;
  if (src.url && hasSourceUrl(src.url)) {
    return false;
  }
  sourceRowSeq += 1;
  const rowId = sourceRowSeq;
  const row = document.createElement("div");
  row.className = "source-row";

  const nameWrap = document.createElement("div");
  const nameLbl = document.createElement("label");
  nameLbl.htmlFor = `source-name-${rowId}`;
  nameLbl.textContent = "Source Name";
  const nameInp = document.createElement("input");
  nameInp.id = `source-name-${rowId}`;
  nameInp.type = "text";
  nameInp.name = "source_name";
  nameInp.required = true;
  nameInp.value = src.name || "";
  nameWrap.append(nameLbl, nameInp);

  const adapterWrap = document.createElement("div");
  const adapterLbl = document.createElement("label");
  adapterLbl.htmlFor = `source-adapter-${rowId}`;
  adapterLbl.textContent = "Adapter";
  const adapterSel = document.createElement("select");
  adapterSel.id = `source-adapter-${rowId}`;
  adapterSel.name = "source_adapter";
  for (const optVal of ["rss", "json_api", "html_css", "appleinsider"]) {
    const opt = document.createElement("option");
    opt.value = optVal;
    opt.textContent = optVal;
    if ((src.adapter || "rss") === optVal) opt.selected = true;
    adapterSel.appendChild(opt);
  }
  adapterWrap.append(adapterLbl, adapterSel);

  const urlWrap = document.createElement("div");
  const urlLbl = document.createElement("label");
  urlLbl.htmlFor = `source-url-${rowId}`;
  urlLbl.textContent = "URL";
  const urlInp = document.createElement("input");
  urlInp.id = `source-url-${rowId}`;
  urlInp.type = "url";
  urlInp.name = "source_url";
  urlInp.required = true;
  urlInp.value = src.url || "";
  const optInp = document.createElement("input");
  optInp.type = "hidden";
  optInp.name = "source_options_json";
  optInp.value = JSON.stringify(src.options || {});
  const renderInp = document.createElement("input");
  renderInp.type = "hidden";
  renderInp.name = "source_render_js";
  renderInp.value = src.render_js ? "true" : "false";
  urlWrap.append(urlLbl, urlInp, optInp, renderInp);

  const rmBtn = document.createElement("button");
  rmBtn.type = "button";
  rmBtn.className = "btn btn-sm btn-danger";
  rmBtn.textContent = "Remove";
  rmBtn.addEventListener("click", () => row.remove());

  row.append(nameWrap, adapterWrap, urlWrap, rmBtn);
  sourcesContainer.appendChild(row);
  return true;
}

function initDeleteWatchDialog() {
  const deleteDialog = document.getElementById("delete-watch-dialog");
  const deleteNameSpan = document.getElementById("delete-watch-name");
  const deleteForm = document.getElementById("delete-watch-form");
  document.querySelectorAll("[data-delete-watch-id]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const wid = btn.getAttribute("data-delete-watch-id");
      const wname = btn.getAttribute("data-delete-watch-name") || wid;
      if (deleteNameSpan) deleteNameSpan.textContent = wname || "";
      if (deleteForm && wid) {
        deleteForm.action = `/api/watches/${encodeURIComponent(wid)}/delete`;
      }
      if (deleteDialog instanceof HTMLDialogElement && !deleteDialog.open) {
        deleteDialog.showModal();
      }
    });
  });
}

function initWatchFormAutoFields() {
  const queryInput = document.getElementById("watch-query");
  const watchNameInput = document.getElementById("watch-name");
  const watchIdInput = document.getElementById("watch-id");
  const includeGroupsInput = document.getElementById("include-groups");
  const vendorSearchInput = document.getElementById("vendor-search-input");
  const vendorSearchBtn = document.getElementById("vendor-search-btn");

  if (queryInput) {
    queryInput.addEventListener("input", () => {
      queryInput.dataset.touched = "true";
    });
  }
  if (includeGroupsInput) {
    includeGroupsInput.addEventListener("input", () => {
      includeGroupsInput.dataset.touched = "true";
    });
  }
  if (vendorSearchInput) {
    vendorSearchInput.addEventListener("input", () => {
      vendorSearchInput.dataset.touched = "true";
    });
    vendorSearchInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && vendorSearchBtn) {
        event.preventDefault();
        vendorSearchBtn.click();
      }
    });
  }

  if (watchNameInput && watchIdInput && !watchIdInput.readOnly) {
    watchNameInput.addEventListener("input", () => {
      const rawName = watchNameInput.value;
      if (watchIdInput.dataset.touched !== "true") {
        watchIdInput.value = slugifyId(rawName);
      }
      if (queryInput && queryInput.dataset.touched !== "true") {
        queryInput.value = rawName.trim();
      }
      if (vendorSearchInput && vendorSearchInput.dataset.touched !== "true") {
        vendorSearchInput.value = rawName.trim();
      }
      if (includeGroupsInput && includeGroupsInput.dataset.touched !== "true") {
        const genericWords = new Set([
          "pickup", "truck", "car", "suv", "sedan", "coupe", "van", "vehicle",
          "auto", "automobile", "motorcycle", "bike", "bicycle", "ebike",
          "chair", "desk", "sofa", "couch", "table", "phone", "smartphone",
          "cellphone", "laptop", "computer", "notebook", "desktop", "monitor",
          "tv", "television", "camera", "watch", "headphones", "earbuds",
          "speaker", "appliance", "tool",
        ]);
        const synonymGroups = {
          combi: "Kombi, Combi, Type 2, Microbus, Transporter, Westfalia, Vanagon, Bus",
          kombi: "Kombi, Combi, Type 2, Microbus, Transporter, Westfalia, Vanagon, Bus",
          volkswagen: "Volkswagen, VW",
          vw: "VW, Volkswagen",
          chevrolet: "Chevrolet, Chevy",
          chevy: "Chevy, Chevrolet",
          mercedes: "Mercedes, Mercedes-Benz",
        };
        const rawTokens = (rawName.match(/[A-Za-z0-9.+-]+/g) || []).filter((t) => t.length >= 2);
        const coreTokens = rawTokens.filter((t) => !genericWords.has(t.toLowerCase()));
        const finalTokens = coreTokens.length > 0 ? coreTokens : rawTokens;
        includeGroupsInput.value = finalTokens
          .map((t) => synonymGroups[t.toLowerCase()] || t)
          .join("\n");
      }
    });
    watchIdInput.addEventListener("input", () => {
      watchIdInput.dataset.touched = "true";
    });
  }
}

function initVendorSearch() {
  const queryInput = document.getElementById("watch-query");
  const watchNameInput = document.getElementById("watch-name");
  const vendorSearchInput = document.getElementById("vendor-search-input");
  const vendorSearchBtn = document.getElementById("vendor-search-btn");
  const vendorSearchOutput = document.getElementById("vendor-search-output");

  if (!vendorSearchBtn || !vendorSearchInput || !vendorSearchOutput) return;

  vendorSearchBtn.addEventListener("click", async () => {
    const searchQuery = (
      vendorSearchInput.value ||
      queryInput?.value ||
      watchNameInput?.value ||
      ""
    ).trim();
    if (searchQuery.length < 2) {
      vendorSearchOutput.replaceChildren();
      const msg = document.createElement("p");
      msg.className = "notice notice-bad";
      msg.textContent = "Enter an item name first (at least 2 characters).";
      vendorSearchOutput.appendChild(msg);
      return;
    }

    if (queryInput && !queryInput.value.trim()) {
      queryInput.value = searchQuery;
    }

    vendorSearchBtn.setAttribute("disabled", "");
    vendorSearchBtn.textContent = "Searching Vendors...";
    vendorSearchOutput.replaceChildren();

    try {
      const res = await csrfFetch("/api/vendors/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: searchQuery }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }

      const candidates = Array.isArray(data.candidates) ? data.candidates : [];
      const working = candidates.filter((c) => c.status === "A_CLEAN_HTTP");

      const headerBar = document.createElement("div");
      headerBar.className = "actions-row";
      const countLabel = document.createElement("span");
      countLabel.className = "muted";
      countLabel.textContent = `Checked ${candidates.length} sources — ${working.length} have matching items.`;
      headerBar.appendChild(countLabel);

      const addVendorButtons = [];
      if (working.length > 0) {
        const addAllBtn = document.createElement("button");
        addAllBtn.type = "button";
        addAllBtn.className = "btn btn-primary btn-sm";
        addAllBtn.textContent = `Add All Working Vendors (${working.length})`;
        addAllBtn.addEventListener("click", () => {
          working.forEach((cand) => {
            appendSourceRow({
              name: cand.name,
              adapter: cand.adapter,
              url: cand.url,
              options: cand.options || {},
              render_js: false,
            });
          });
          addVendorButtons.forEach(({ btn, url }) => {
            if (hasSourceUrl(url)) {
              btn.textContent = "Added";
              btn.setAttribute("disabled", "");
            }
          });
        });
        headerBar.appendChild(addAllBtn);
      }
      vendorSearchOutput.appendChild(headerBar);

      candidates.forEach((cand) => {
        const card = document.createElement("div");
        card.className = "card stack-sm";

        const topRow = document.createElement("div");
        topRow.className = "card-header";

        const titleWrap = document.createElement("div");
        const titleStrong = document.createElement("strong");
        titleStrong.textContent = `${cand.name} (${cand.adapter})`;
        const metaLine = document.createElement("p");
        metaLine.className = "muted mb-0";
        metaLine.textContent = `${cand.matching_count} matches · ${cand.total_fetched} fetched · HTTP ${cand.http_status ?? "?"}`;
        titleWrap.append(titleStrong, metaLine);

        const badge = document.createElement("span");
        badge.className =
          cand.status === "A_CLEAN_HTTP"
            ? "badge badge-active"
            : cand.status === "EMPTY"
              ? "badge badge-paused"
              : "badge badge-bad";
        badge.textContent = cand.status;

        topRow.append(titleWrap, badge);
        card.appendChild(topRow);

        if (Array.isArray(cand.preview_items) && cand.preview_items.length > 0) {
          const ul = document.createElement("ul");
          cand.preview_items.slice(0, 4).forEach((item) => {
            ul.appendChild(buildPreviewListItem(item));
          });
          card.appendChild(ul);
        } else if (Array.isArray(cand.notes) && cand.notes.length > 0) {
          const noteP = document.createElement("p");
          noteP.className = "muted";
          noteP.textContent = cand.notes.join(" ");
          card.appendChild(noteP);
        }

        if (cand.status !== "ERROR") {
          const addBtn = document.createElement("button");
          addBtn.type = "button";
          addBtn.className = "btn btn-sm";
          if (hasSourceUrl(cand.url)) {
            addBtn.textContent = "Already Added";
            addBtn.setAttribute("disabled", "");
          } else {
            addBtn.textContent = "Add Vendor";
            addBtn.addEventListener("click", () => {
              appendSourceRow({
                name: cand.name,
                adapter: cand.adapter,
                url: cand.url,
                options: cand.options || {},
                render_js: false,
              });
              addBtn.textContent = "Added";
              addBtn.setAttribute("disabled", "");
            });
          }
          addVendorButtons.push({ btn: addBtn, url: cand.url });
          card.appendChild(addBtn);
        }

        vendorSearchOutput.appendChild(card);
      });
    } catch (err) {
      const errBox = document.createElement("p");
      errBox.className = "notice notice-bad";
      errBox.textContent = `Vendor search failed: ${err instanceof Error ? err.message : String(err)}`;
      vendorSearchOutput.appendChild(errBox);
    } finally {
      vendorSearchBtn.removeAttribute("disabled");
      vendorSearchBtn.textContent = "Search Vendors for Item";
    }
  });
}

function initSourceRowControls() {
  const addSourceBtn = document.getElementById("add-source-btn");
  const loadPackBtn = document.getElementById("load-pack-btn");
  const packSelect = document.getElementById("source-pack-select");
  const queryInput = document.getElementById("watch-query");
  const watchNameInput = document.getElementById("watch-name");

  document.querySelectorAll("[data-remove-source]").forEach((btn) => {
    btn.addEventListener("click", () => {
      btn.closest(".source-row")?.remove();
    });
  });

  if (addSourceBtn) {
    addSourceBtn.addEventListener("click", () => appendSourceRow());
  }

  if (loadPackBtn && packSelect) {
    loadPackBtn.addEventListener("click", async () => {
      const packId = packSelect.value;
      const query = (queryInput?.value || watchNameInput?.value || "").trim();
      if (!packId) return;
      loadPackBtn.setAttribute("disabled", "");
      try {
        const res = await csrfFetch("/api/source-packs/render", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pack_id: packId, query }),
        });
        const data = await res.json();
        if (Array.isArray(data.sources)) {
          data.sources.forEach((s) => appendSourceRow(s));
        }
      } finally {
        loadPackBtn.removeAttribute("disabled");
      }
    });
  }
}

function initProbeTool() {
  const probeBtn = document.getElementById("probe-url-btn");
  const probeInput = document.getElementById("probe-url-input");
  const probeOutput = document.getElementById("probe-output");
  if (!probeBtn || !probeInput || !probeOutput) return;

  probeBtn.addEventListener("click", async () => {
    const targetUrl = probeInput.value.trim();
    if (!targetUrl) return;
    probeBtn.setAttribute("disabled", "");
    probeBtn.textContent = "Probing...";
    probeOutput.replaceChildren();
    try {
      const res = await csrfFetch("/api/probe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl }),
      });
      const data = await res.json();
      const box = document.createElement("div");
      box.className = "card stack-sm";

      const badge = document.createElement("span");
      badge.className =
        data.classification === "A_CLEAN_HTTP"
          ? "badge badge-active"
          : data.classification === "B_NEEDS_PLAYWRIGHT"
            ? "badge badge-paused"
            : "badge badge-bad";
      badge.textContent = `${data.classification} · ${data.format_detected} (HTTP ${data.http_status ?? "?"})`;

      const summary = document.createElement("p");
      summary.textContent = `Items extracted: ${data.item_count}. ${(data.notes || []).join(" ")}`;

      box.append(badge, summary);

      if (Array.isArray(data.preview_items) && data.preview_items.length > 0) {
        const ul = document.createElement("ul");
        data.preview_items.slice(0, 5).forEach((item) => {
          ul.appendChild(buildPreviewListItem(item));
        });
        box.appendChild(ul);
      }

      if (data.recommended_adapter) {
        const addBtn = document.createElement("button");
        addBtn.type = "button";
        addBtn.className = "btn btn-primary btn-sm";
        addBtn.textContent = `Add as ${data.recommended_adapter} source`;
        addBtn.addEventListener("click", () => {
          appendSourceRow({
            name: data.recommended_name || "Custom Source",
            adapter: data.recommended_adapter,
            url: data.recommended_url || data.url,
            options: data.recommended_options || {},
            render_js: data.classification === "B_NEEDS_PLAYWRIGHT",
          });
        });
        box.appendChild(addBtn);
      }
      probeOutput.appendChild(box);
    } catch (err) {
      const errBox = document.createElement("p");
      errBox.className = "notice notice-bad";
      errBox.textContent = `Probe failed: ${err instanceof Error ? err.message : String(err)}`;
      probeOutput.appendChild(errBox);
    } finally {
      probeBtn.removeAttribute("disabled");
      probeBtn.textContent = "Probe Source";
    }
  });
}

function initManageFormTabs() {
  const manageTabsEl = document.getElementById("manage-form-tabs");
  const manageFormEl = document.getElementById("manage-watch-form");

  function activateManageTab(tabId) {
    if (!manageTabsEl || !tabId) return;
    manageTabsEl.querySelectorAll("[data-manage-tab]").forEach((tab) => {
      const active = tab.getAttribute("data-manage-tab") === tabId;
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.setAttribute("tabindex", active ? "0" : "-1");
    });
    document.querySelectorAll("[data-manage-panel]").forEach((panel) => {
      const active = panel.getAttribute("data-manage-panel") === tabId;
      panel.hidden = !active;
    });
  }

  if (manageTabsEl) {
    manageTabsEl.addEventListener("click", (event) => {
      const tab = event.target instanceof Element ? event.target.closest("[data-manage-tab]") : null;
      if (!tab) return;
      activateManageTab(tab.getAttribute("data-manage-tab") || "");
    });
    bindTablistKeyboard(manageTabsEl, "[data-manage-tab]", activateManageTab);
  }

  if (manageFormEl) {
    manageFormEl.addEventListener(
      "invalid",
      (event) => {
        const target = event.target;
        if (!(target instanceof Element)) return;
        const panel = target.closest("[data-manage-panel]");
        if (panel && panel.hasAttribute("hidden")) {
          activateManageTab(panel.getAttribute("data-manage-panel") || "");
        }
      },
      true
    );
  }
}

/**
 * Initialize all interactive handlers on the Manage Watches page.
 */
export function initManagePage() {
  initDeleteWatchDialog();
  initWatchFormAutoFields();
  initVendorSearch();
  initSourceRowControls();
  initProbeTool();
  initManageFormTabs();
}
