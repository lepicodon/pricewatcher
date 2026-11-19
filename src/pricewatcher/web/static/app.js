(() => {
  function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";
  }

  async function csrfFetch(url, options = {}) {
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

  function esc(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function safeUrl(raw) {
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

  function slugifyId(raw) {
    return String(raw || "")
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 63);
  }

  function buildPreviewListItem(item) {
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

  function createSvgIcon(kind) {
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

  // Delete dialog binding on /manage
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

  // Manage page: Dynamic source rows, Vendor Search, Source Pack loader, and Live Probe tool
  const sourcesContainer = document.getElementById("sources-list");
  const addSourceBtn = document.getElementById("add-source-btn");
  const loadPackBtn = document.getElementById("load-pack-btn");
  const packSelect = document.getElementById("source-pack-select");
  const queryInput = document.getElementById("watch-query");
  const watchNameInput = document.getElementById("watch-name");
  const watchIdInput = document.getElementById("watch-id");
  const includeGroupsInput = document.getElementById("include-groups");
  const vendorSearchInput = document.getElementById("vendor-search-input");
  const vendorSearchBtn = document.getElementById("vendor-search-btn");
  const vendorSearchOutput = document.getElementById("vendor-search-output");

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
        watchIdInput.value = rawName
          .toLowerCase()
          .replace(/[^a-z0-9_-]+/g, "-")
          .replace(/^-+|-+$/g, "")
          .slice(0, 63);
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

  function hasSourceUrl(url) {
    if (!sourcesContainer || !url) return false;
    const normalized = url.trim();
    return Array.from(sourcesContainer.querySelectorAll('input[name="source_url"]')).some(
      (inp) => inp.value.trim() === normalized
    );
  }

  function appendSourceRow(src = {}) {
    if (!sourcesContainer) return false;
    if (src.url && hasSourceUrl(src.url)) {
      return false;
    }
    appendSourceRow._seq = (appendSourceRow._seq || 0) + 1;
    const rowId = appendSourceRow._seq;
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

  if (vendorSearchBtn && vendorSearchInput && vendorSearchOutput) {
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

  // Live "Probe Source" button
  const probeBtn = document.getElementById("probe-url-btn");
  const probeInput = document.getElementById("probe-url-input");
  const probeOutput = document.getElementById("probe-output");
  if (probeBtn && probeInput && probeOutput) {
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

  // Users & Test Alerts management on /settings (Admin)
  const usersSection = document.getElementById("users-section");
  const recipientsTableWrap = document.getElementById("recipients-table-wrap");
  const recipientsTbody = document.getElementById("recipients-tbody");
  const recipientsEmptyMsg = document.getElementById("recipients-empty-msg");
  const newRecBtn = document.getElementById("new-recipient-btn");
  const newRecWrap = document.getElementById("new-recipient-form-wrap");
  const newRecNameInput = document.getElementById("new-recipient-name");
  const newRecKeyInput = document.getElementById("new-recipient-key");
  const newRecWahaInput = document.getElementById("new-recipient-waha");
  const newRecEmailInput = document.getElementById("new-recipient-email");
  const createRecConfirmBtn = document.getElementById("create-recipient-confirm-btn");
  const createRecCancelBtn = document.getElementById("create-recipient-cancel-btn");
  const newRecStatus = document.getElementById("new-recipient-status");

  function buildRecipientRow(key, rec) {
    const tr = document.createElement("tr");
    tr.setAttribute("data-recipient-row", "");
    tr.setAttribute("data-recipient-key", key);

    const keyTd = document.createElement("td");
    const code = document.createElement("code");
    code.textContent = key;
    keyTd.appendChild(code);

    const nameTd = document.createElement("td");
    const nameInp = document.createElement("input");
    nameInp.type = "text";
    nameInp.setAttribute("aria-label", `Name for ${key}`);
    nameInp.setAttribute("data-rec-name", "");
    nameInp.value = rec.name || key;
    nameInp.required = true;
    nameTd.appendChild(nameInp);

    const wahaTd = document.createElement("td");
    const wahaInp = document.createElement("input");
    wahaInp.type = "text";
    wahaInp.setAttribute("aria-label", `WAHA Chat ID for ${key}`);
    wahaInp.setAttribute("data-rec-waha", "");
    wahaInp.value = rec.waha_chat_id || "";
    wahaInp.placeholder = "15551234567@c.us";
    wahaTd.appendChild(wahaInp);

    const emailTd = document.createElement("td");
    const emailInp = document.createElement("input");
    emailInp.type = "text";
    emailInp.setAttribute("aria-label", `Email for ${key}`);
    emailInp.setAttribute("data-rec-email", "");
    emailInp.value = rec.email || "";
    emailInp.placeholder = "name@example.com";
    emailTd.appendChild(emailInp);

    const actTd = document.createElement("td");
    const actRow = document.createElement("div");
    actRow.className = "actions-row actions-nowrap";

    const saveBtn = document.createElement("button");
    saveBtn.type = "button";
    saveBtn.className = "btn btn-primary btn-sm btn-icon";
    saveBtn.setAttribute("data-save-recipient", "");
    saveBtn.setAttribute("aria-label", `Save ${key}`);
    saveBtn.title = "Save user";
    saveBtn.appendChild(createSvgIcon("save"));

    const testBtn = document.createElement("button");
    testBtn.type = "button";
    testBtn.className = "btn btn-sm btn-icon";
    testBtn.setAttribute("data-test-recipient", key);
    testBtn.setAttribute("aria-label", `Send test alert to ${key}`);
    testBtn.title = "Send test alert";
    testBtn.appendChild(createSvgIcon("send"));

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "btn btn-sm btn-icon btn-danger";
    delBtn.setAttribute("data-delete-recipient", "");
    delBtn.setAttribute("aria-label", `Delete ${key}`);
    delBtn.title = "Delete user";
    delBtn.appendChild(createSvgIcon("trash"));

    const statusSpan = document.createElement("span");
    statusSpan.id = `test-status-${key}`;
    statusSpan.className = "muted";
    statusSpan.setAttribute("data-rec-status", "");
    statusSpan.setAttribute("aria-live", "polite");

    actRow.append(saveBtn, testBtn, delBtn, statusSpan);
    actTd.appendChild(actRow);
    tr.append(keyTd, nameTd, wahaTd, emailTd, actTd);
    return tr;
  }

  function syncRecipientsVisibility() {
    if (!recipientsTbody || !recipientsTableWrap || !recipientsEmptyMsg) return;
    const hasRows = recipientsTbody.querySelectorAll("[data-recipient-row]").length > 0;
    recipientsTableWrap.hidden = !hasRows;
    recipientsEmptyMsg.hidden = hasRows;
  }

  if (newRecBtn && newRecWrap) {
    newRecBtn.addEventListener("click", () => {
      newRecWrap.hidden = !newRecWrap.hidden;
      if (!newRecWrap.hidden && newRecNameInput) newRecNameInput.focus();
    });
  }

  if (createRecCancelBtn && newRecWrap) {
    createRecCancelBtn.addEventListener("click", () => {
      newRecWrap.hidden = true;
      if (newRecStatus) newRecStatus.textContent = "";
    });
  }

  if (newRecNameInput && newRecKeyInput) {
    newRecNameInput.addEventListener("input", () => {
      if (!newRecKeyInput.dataset.touched) {
        newRecKeyInput.value = slugifyId(newRecNameInput.value);
      }
    });
    newRecKeyInput.addEventListener("input", () => {
      newRecKeyInput.dataset.touched = "true";
    });
  }

  if (createRecConfirmBtn && recipientsTbody) {
    createRecConfirmBtn.addEventListener("click", async () => {
      const name = (newRecNameInput?.value || "").trim();
      const key = (newRecKeyInput?.value || "").trim().toLowerCase();
      const wahaChatId = (newRecWahaInput?.value || "").trim();
      const email = (newRecEmailInput?.value || "").trim();
      if (!name || !key) {
        if (newRecStatus) newRecStatus.textContent = "Name and User Key are required.";
        return;
      }
      createRecConfirmBtn.setAttribute("disabled", "");
      if (newRecStatus) newRecStatus.textContent = "Saving...";
      try {
        const res = await csrfFetch(`/api/recipients/${encodeURIComponent(key)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, waha_chat_id: wahaChatId, email }),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          throw new Error(data.error || `HTTP ${res.status}`);
        }
        const existing = recipientsTbody.querySelector(
          `[data-recipient-row][data-recipient-key="${CSS.escape(data.recipient_key)}"]`
        );
        const newRow = buildRecipientRow(data.recipient_key, data.recipient);
        if (existing) {
          existing.replaceWith(newRow);
        } else {
          recipientsTbody.appendChild(newRow);
        }
        syncRecipientsVisibility();
        if (newRecNameInput) newRecNameInput.value = "";
        if (newRecKeyInput) {
          newRecKeyInput.value = "";
          delete newRecKeyInput.dataset.touched;
        }
        if (newRecWahaInput) newRecWahaInput.value = "";
        if (newRecEmailInput) newRecEmailInput.value = "";
        if (newRecWrap) newRecWrap.hidden = true;
        if (newRecStatus) newRecStatus.textContent = "";
      } catch (err) {
        if (newRecStatus) {
          newRecStatus.textContent = `Error: ${err instanceof Error ? err.message : String(err)}`;
        }
      } finally {
        createRecConfirmBtn.removeAttribute("disabled");
      }
    });
  }

  if (usersSection) {
    usersSection.addEventListener("click", async (event) => {
      const btn = event.target instanceof Element ? event.target.closest("button") : null;
      if (!btn) return;
      const row = btn.closest("[data-recipient-row]");
      if (!row) return;
      const key = row.getAttribute("data-recipient-key") || "";
      const statusEl = row.querySelector("[data-rec-status]");
      if (!key) return;

      if (btn.hasAttribute("data-test-recipient")) {
        btn.setAttribute("disabled", "");
        if (statusEl) statusEl.textContent = "Sending...";
        try {
          const res = await csrfFetch("/api/test-alert", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ recipient_key: key }),
          });
          const data = await res.json();
          if (statusEl) statusEl.textContent = data.summary || "Done";
        } catch (err) {
          if (statusEl) {
            statusEl.textContent = `Error: ${err instanceof Error ? err.message : String(err)}`;
          }
        } finally {
          btn.removeAttribute("disabled");
        }
        return;
      }

      if (btn.hasAttribute("data-save-recipient")) {
        const name = (row.querySelector("[data-rec-name]")?.value || "").trim();
        const wahaChatId = (row.querySelector("[data-rec-waha]")?.value || "").trim();
        const email = (row.querySelector("[data-rec-email]")?.value || "").trim();
        if (!name) {
          if (statusEl) statusEl.textContent = "Name is required.";
          return;
        }
        btn.setAttribute("disabled", "");
        if (statusEl) statusEl.textContent = "Saving...";
        try {
          const res = await csrfFetch(`/api/recipients/${encodeURIComponent(key)}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, waha_chat_id: wahaChatId, email }),
          });
          const data = await res.json();
          if (!res.ok || !data.ok) {
            throw new Error(data.error || `HTTP ${res.status}`);
          }
          if (statusEl) statusEl.textContent = "Saved";
        } catch (err) {
          if (statusEl) {
            statusEl.textContent = `Save failed: ${err instanceof Error ? err.message : String(err)}`;
          }
        } finally {
          btn.removeAttribute("disabled");
        }
        return;
      }

      if (btn.hasAttribute("data-delete-recipient")) {
        if (!window.confirm(`Delete user "${key}" from config/settings.yaml?`)) {
          return;
        }
        btn.setAttribute("disabled", "");
        try {
          const res = await csrfFetch(`/api/recipients/${encodeURIComponent(key)}`, {
            method: "DELETE",
          });
          const data = await res.json();
          if (!res.ok || !data.ok) {
            throw new Error(data.error || `HTTP ${res.status}`);
          }
          row.remove();
          syncRecipientsVisibility();
        } catch (err) {
          if (statusEl) {
            statusEl.textContent = `Delete failed: ${err instanceof Error ? err.message : String(err)}`;
          }
          btn.removeAttribute("disabled");
        }
      }
    });
  }

  // Curated Category Source Pack Manager on /settings
  const sourcePacksList = document.getElementById("source-packs-list");
  const newPackBtn = document.getElementById("new-pack-btn");
  const newPackWrap = document.getElementById("new-pack-form-wrap");
  const newPackIdInput = document.getElementById("new-pack-id");
  const newPackLabelInput = document.getElementById("new-pack-label");
  const newPackDescInput = document.getElementById("new-pack-desc");
  const createPackConfirmBtn = document.getElementById("create-pack-confirm-btn");
  const createPackCancelBtn = document.getElementById("create-pack-cancel-btn");
  const newPackStatus = document.getElementById("new-pack-status");

  let packRowSeq = 0;

  function buildPackSourceRow(packId, src = {}) {
    packRowSeq += 1;
    const suffix = `${packId}-dyn-${packRowSeq}`;
    const row = document.createElement("div");
    row.className = "pack-source-row";
    row.setAttribute("data-pack-source-row", "");

    const nameWrap = document.createElement("div");
    const nameLbl = document.createElement("label");
    nameLbl.htmlFor = `psrc-name-${suffix}`;
    nameLbl.textContent = "Source Name Template";
    const nameInp = document.createElement("input");
    nameInp.type = "text";
    nameInp.id = `psrc-name-${suffix}`;
    nameInp.setAttribute("data-psrc-name", "");
    nameInp.required = true;
    nameInp.placeholder = "e.g. Classic.com ({query})";
    nameInp.value = src.name || "";
    nameWrap.append(nameLbl, nameInp);

    const adapterWrap = document.createElement("div");
    const adapterLbl = document.createElement("label");
    adapterLbl.htmlFor = `psrc-adapter-${suffix}`;
    adapterLbl.textContent = "Adapter";
    const adapterSel = document.createElement("select");
    adapterSel.id = `psrc-adapter-${suffix}`;
    adapterSel.setAttribute("data-psrc-adapter", "");
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
    urlLbl.htmlFor = `psrc-url-${suffix}`;
    urlLbl.textContent = "URL Template";
    const urlInp = document.createElement("input");
    urlInp.type = "text";
    urlInp.id = `psrc-url-${suffix}`;
    urlInp.setAttribute("data-psrc-url", "");
    urlInp.required = true;
    urlInp.placeholder = "https://example.com/search?q={query_encoded}";
    urlInp.value = src.url_template || "";
    urlWrap.append(urlLbl, urlInp);

    const optsWrap = document.createElement("div");
    const optsLbl = document.createElement("label");
    optsLbl.htmlFor = `psrc-opts-${suffix}`;
    optsLbl.textContent = "Options JSON";
    const optsInp = document.createElement("input");
    optsInp.type = "text";
    optsInp.id = `psrc-opts-${suffix}`;
    optsInp.setAttribute("data-psrc-options", "");
    optsInp.value = JSON.stringify(src.options || {});
    optsWrap.append(optsLbl, optsInp);

    const actionsDiv = document.createElement("div");
    actionsDiv.className = "actions-row actions-nowrap";
    const testBtn = document.createElement("button");
    testBtn.type = "button";
    testBtn.className = "btn btn-sm btn-icon";
    testBtn.setAttribute("data-test-pack-source", "");
    testBtn.setAttribute("aria-label", "Test source");
    testBtn.title = "Test source";
    testBtn.appendChild(createSvgIcon("play"));
    const rmBtn = document.createElement("button");
    rmBtn.type = "button";
    rmBtn.className = "btn btn-sm btn-icon btn-danger";
    rmBtn.setAttribute("data-remove-pack-source", "");
    rmBtn.setAttribute("aria-label", "Remove vendor");
    rmBtn.title = "Remove vendor";
    rmBtn.appendChild(createSvgIcon("trash"));
    actionsDiv.append(testBtn, rmBtn);

    const testOut = document.createElement("div");
    testOut.className = "pack-source-test-result muted";
    testOut.setAttribute("data-psrc-test-output", "");
    testOut.setAttribute("aria-live", "polite");

    row.append(nameWrap, adapterWrap, urlWrap, optsWrap, actionsDiv, testOut);
    return row;
  }

  function buildPackCard(packId, pack) {
    const card = document.createElement("article");
    card.className = "card stack-sm";
    card.setAttribute("data-pack-card", "");
    card.setAttribute("data-pack-id", packId);

    const header = document.createElement("div");
    header.className = "card-header";
    const titleBox = document.createElement("div");
    const h3 = document.createElement("h3");
    h3.append(document.createTextNode(`${pack.label} `));
    const code = document.createElement("code");
    code.textContent = packId;
    h3.appendChild(code);
    const descP = document.createElement("p");
    descP.className = "muted mb-0";
    descP.textContent = pack.description || "No description";
    titleBox.append(h3, descP);

    const headerActions = document.createElement("div");
    headerActions.className = "actions-row actions-nowrap";
    const addVBtn = document.createElement("button");
    addVBtn.type = "button";
    addVBtn.className = "btn btn-sm btn-icon";
    addVBtn.setAttribute("data-add-pack-source", "");
    addVBtn.setAttribute("aria-label", `Add vendor to ${pack.label || packId}`);
    addVBtn.title = "Add vendor to pack";
    addVBtn.appendChild(createSvgIcon("plus"));
    const saveBtn = document.createElement("button");
    saveBtn.type = "button";
    saveBtn.className = "btn btn-primary btn-sm btn-icon";
    saveBtn.setAttribute("data-save-pack", "");
    saveBtn.setAttribute("aria-label", `Save ${pack.label || packId}`);
    saveBtn.title = "Save pack";
    saveBtn.appendChild(createSvgIcon("save"));
    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "btn btn-danger btn-sm btn-icon";
    delBtn.setAttribute("data-delete-pack", "");
    delBtn.setAttribute("aria-label", `Delete ${pack.label || packId}`);
    delBtn.title = "Delete pack";
    delBtn.appendChild(createSvgIcon("trash"));
    headerActions.append(addVBtn, saveBtn, delBtn);
    header.append(titleBox, headerActions);

    const metaGrid = document.createElement("div");
    metaGrid.className = "form-grid";

    const lblWrap = document.createElement("div");
    lblWrap.className = "form-group mb-xs";
    const lblLbl = document.createElement("label");
    lblLbl.htmlFor = `pack-label-${packId}`;
    lblLbl.textContent = "Pack Label";
    const lblInp = document.createElement("input");
    lblInp.type = "text";
    lblInp.id = `pack-label-${packId}`;
    lblInp.setAttribute("data-pack-label", "");
    lblInp.value = pack.label || packId;
    lblInp.required = true;
    lblWrap.append(lblLbl, lblInp);

    const descWrap = document.createElement("div");
    descWrap.className = "form-group mb-xs";
    const dLbl = document.createElement("label");
    dLbl.htmlFor = `pack-desc-${packId}`;
    dLbl.textContent = "Description";
    const dInp = document.createElement("input");
    dInp.type = "text";
    dInp.id = `pack-desc-${packId}`;
    dInp.setAttribute("data-pack-description", "");
    dInp.value = pack.description || "";
    descWrap.append(dLbl, dInp);

    const qWrap = document.createElement("div");
    qWrap.className = "form-group mb-xs";
    const qLbl = document.createElement("label");
    qLbl.htmlFor = `pack-query-${packId}`;
    qLbl.textContent = "Sample Test Query";
    const qInp = document.createElement("input");
    qInp.type = "text";
    qInp.id = `pack-query-${packId}`;
    qInp.setAttribute("data-pack-test-query", "");
    qInp.placeholder = "Sample item to test pack, e.g. Toyota Tundra";
    qInp.value = "Mac Studio";
    qWrap.append(qLbl, qInp);

    metaGrid.append(lblWrap, descWrap, qWrap);

    const sourcesWrap = document.createElement("div");
    sourcesWrap.className = "stack-sm";
    sourcesWrap.setAttribute("data-pack-sources", "");
    (pack.sources || []).forEach((s) => {
      sourcesWrap.appendChild(buildPackSourceRow(packId, s));
    });

    const statusP = document.createElement("p");
    statusP.className = "muted mb-0";
    statusP.setAttribute("data-pack-status", "");
    statusP.setAttribute("aria-live", "polite");

    card.append(header, metaGrid, sourcesWrap, statusP);
    return card;
  }

  if (newPackBtn && newPackWrap) {
    newPackBtn.addEventListener("click", () => {
      newPackWrap.hidden = !newPackWrap.hidden;
      if (!newPackWrap.hidden && newPackLabelInput) {
        newPackLabelInput.focus();
      }
    });
  }

  if (createPackCancelBtn && newPackWrap) {
    createPackCancelBtn.addEventListener("click", () => {
      newPackWrap.hidden = true;
      if (newPackStatus) newPackStatus.textContent = "";
    });
  }

  if (newPackLabelInput && newPackIdInput) {
    newPackLabelInput.addEventListener("input", () => {
      if (newPackIdInput.dataset.touched !== "true") {
        newPackIdInput.value = newPackLabelInput.value
          .toLowerCase()
          .replace(/[^a-z0-9_-]+/g, "_")
          .replace(/^_+|_+$/g, "")
          .slice(0, 63);
      }
    });
    newPackIdInput.addEventListener("input", () => {
      newPackIdInput.dataset.touched = "true";
      newPackIdInput.setCustomValidity("");
    });
  }

  if (createPackConfirmBtn && sourcePacksList) {
    createPackConfirmBtn.addEventListener("click", async () => {
      const packId = (newPackIdInput?.value || "").trim().toLowerCase();
      const label = (newPackLabelInput?.value || "").trim();
      const description = (newPackDescInput?.value || "").trim();
      if (!packId || !label) {
        if (newPackStatus) {
          newPackStatus.textContent = "Pack ID and Display Label are required.";
        }
        return;
      }
      createPackConfirmBtn.setAttribute("disabled", "");
      if (newPackStatus) newPackStatus.textContent = "Creating...";
      try {
        const res = await csrfFetch(`/api/source-packs/${encodeURIComponent(packId)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ label, description, sources: [] }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || `HTTP ${res.status}`);
        }
        const card = buildPackCard(data.pack_id, data.pack);
        card.setAttribute("role", "tabpanel");
        card.id = `pack-panel-${data.pack_id}`;
        card.setAttribute("aria-labelledby", `pack-tab-${data.pack_id}`);
        const listEl = card.querySelector("[data-pack-sources]");
        if (listEl) listEl.appendChild(buildPackSourceRow(data.pack_id));
        sourcePacksList.appendChild(card);
        if (typeof syncPackTab === "function") {
          syncPackTab(data.pack_id, data.pack.label, data.pack.sources?.length || 1);
          activatePackTab(data.pack_id);
        }
        if (newPackIdInput) {
          newPackIdInput.value = "";
          delete newPackIdInput.dataset.touched;
        }
        if (newPackLabelInput) newPackLabelInput.value = "";
        if (newPackDescInput) newPackDescInput.value = "";
        if (newPackWrap) newPackWrap.hidden = true;
        if (newPackStatus) newPackStatus.textContent = "";
      } catch (err) {
        if (newPackStatus) {
          newPackStatus.textContent = `Error: ${err instanceof Error ? err.message : String(err)}`;
        }
      } finally {
        createPackConfirmBtn.removeAttribute("disabled");
      }
    });
  }

  if (sourcePacksList) {
    sourcePacksList.addEventListener(
      "blur",
      (event) => {
        const target = event.target;
        if (!(target instanceof HTMLInputElement)) return;
        if (!target.hasAttribute("data-psrc-options")) return;
        const raw = target.value.trim() || "{}";
        try {
          const parsed = JSON.parse(raw);
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            target.setCustomValidity("Options must be a JSON object.");
          } else {
            target.setCustomValidity("");
          }
        } catch {
          target.setCustomValidity("Invalid JSON syntax.");
        }
      },
      true
    );

    sourcePacksList.addEventListener("input", (event) => {
      const target = event.target;
      if (target instanceof HTMLInputElement && target.hasAttribute("data-psrc-options")) {
        target.setCustomValidity("");
      }
    });

    sourcePacksList.addEventListener("click", async (event) => {
      const btn = event.target instanceof Element ? event.target.closest("button") : null;
      if (!btn) return;
      const card = btn.closest("[data-pack-card]");
      if (!card) return;
      const packId = card.getAttribute("data-pack-id") || "";
      const packStatusEl = card.querySelector("[data-pack-status]");

      if (btn.hasAttribute("data-add-pack-source")) {
        const container = card.querySelector("[data-pack-sources]");
        if (container) {
          container.appendChild(buildPackSourceRow(packId));
        }
        return;
      }

      if (btn.hasAttribute("data-remove-pack-source")) {
        btn.closest("[data-pack-source-row]")?.remove();
        return;
      }

      if (btn.hasAttribute("data-test-pack-source")) {
        const row = btn.closest("[data-pack-source-row]");
        if (!row) return;
        const nameInp = row.querySelector("[data-psrc-name]");
        const adapterSel = row.querySelector("[data-psrc-adapter]");
        const urlInp = row.querySelector("[data-psrc-url]");
        const optsInp = row.querySelector("[data-psrc-options]");
        const outEl = row.querySelector("[data-psrc-test-output]");
        const sampleQuery = (
          card.querySelector("[data-pack-test-query]")?.value || ""
        ).trim();

        let parsedOpts = {};
        try {
          const rawOpts = (optsInp?.value || "{}").trim() || "{}";
          parsedOpts = JSON.parse(rawOpts);
        } catch {
          if (outEl) {
            outEl.className = "pack-source-test-result notice notice-bad";
            outEl.textContent = "Invalid Options JSON in this vendor row.";
          }
          return;
        }

        btn.setAttribute("disabled", "");
        btn.textContent = "Testing...";
        if (outEl) {
          outEl.className = "pack-source-test-result muted";
          outEl.textContent = "Fetching live endpoint...";
        }

        try {
          const res = await csrfFetch("/api/source-packs/test-source", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              name: nameInp?.value || "Test Source",
              adapter: adapterSel?.value || "rss",
              url_template: urlInp?.value || "",
              options: parsedOpts,
              query: sampleQuery,
            }),
          });
          const data = await res.json();
          if (!outEl) return;
          outEl.replaceChildren();

          if (!res.ok || !data.ok) {
            outEl.className = "pack-source-test-result notice notice-bad";
            outEl.textContent = `Test failed (HTTP ${data.http_status ?? res.status}): ${data.error || "Unknown error"}`;
            return;
          }

          outEl.className =
            data.matching_count > 0
              ? "pack-source-test-result notice notice-good"
              : "pack-source-test-result notice";
          const summary = document.createElement("div");
          summary.textContent =
            `HTTP ${data.http_status ?? 200} (${data.latency_ms}ms) · ` +
            `${data.matching_count} matches / ${data.item_count} fetched for "${data.query}"`;
          outEl.appendChild(summary);

          if (data.rendered_url) {
            const urlLine = document.createElement("div");
            urlLine.className = "muted";
            const href = safeUrl(data.rendered_url);
            if (href !== "#") {
              const urlLink = document.createElement("a");
              urlLink.href = href;
              urlLink.target = "_blank";
              urlLink.rel = "noopener noreferrer";
              urlLink.textContent = data.rendered_url;
              urlLine.appendChild(urlLink);
            } else {
              urlLine.textContent = data.rendered_url;
            }
            outEl.appendChild(urlLine);
          }

          if (Array.isArray(data.preview_items) && data.preview_items.length > 0) {
            const ul = document.createElement("ul");
            data.preview_items.slice(0, 4).forEach((item) => {
              ul.appendChild(buildPreviewListItem(item));
            });
            outEl.appendChild(ul);
          }
        } catch (err) {
          if (outEl) {
            outEl.className = "pack-source-test-result notice notice-bad";
            outEl.textContent = `Error: ${err instanceof Error ? err.message : String(err)}`;
          }
        } finally {
          btn.removeAttribute("disabled");
          btn.textContent = "Test Source";
        }
        return;
      }

      if (btn.hasAttribute("data-save-pack")) {
        const label = (card.querySelector("[data-pack-label]")?.value || "").trim();
        const description = (
          card.querySelector("[data-pack-description]")?.value || ""
        ).trim();
        const rows = Array.from(card.querySelectorAll("[data-pack-source-row]"));
        const sources = [];

        for (const row of rows) {
          const name = (row.querySelector("[data-psrc-name]")?.value || "").trim();
          const adapter = row.querySelector("[data-psrc-adapter]")?.value || "rss";
          const urlTemplate = (row.querySelector("[data-psrc-url]")?.value || "").trim();
          const optsRaw = (row.querySelector("[data-psrc-options]")?.value || "{}").trim() || "{}";
          if (!urlTemplate) continue;
          let opts = {};
          try {
            opts = JSON.parse(optsRaw);
          } catch {
            if (packStatusEl) {
              packStatusEl.textContent = `Invalid JSON in vendor "${name || urlTemplate}".`;
            }
            return;
          }
          sources.push({
            name: name || "Vendor Source",
            adapter,
            url_template: urlTemplate,
            options: opts,
          });
        }

        btn.setAttribute("disabled", "");
        if (packStatusEl) packStatusEl.textContent = "Saving pack...";
        try {
          const res = await csrfFetch(`/api/source-packs/${encodeURIComponent(packId)}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ label, description, sources }),
          });
          const data = await res.json();
          if (!res.ok || !data.ok) {
            throw new Error(data.error || `HTTP ${res.status}`);
          }
          const h3 = card.querySelector("h3");
          if (h3) {
            const codeEl = document.createElement("code");
            codeEl.textContent = data.pack_id;
            h3.replaceChildren(document.createTextNode(`${data.pack.label} `), codeEl);
          }
          if (packStatusEl) {
            packStatusEl.textContent = `Saved (${data.pack.sources.length} vendors) to config/settings.yaml.`;
          }
          if (typeof syncPackTab === "function") {
            syncPackTab(data.pack_id, data.pack.label, data.pack.sources.length);
          }
        } catch (err) {
          if (packStatusEl) {
            packStatusEl.textContent = `Save failed: ${err instanceof Error ? err.message : String(err)}`;
          }
        } finally {
          btn.removeAttribute("disabled");
        }
        return;
      }

      if (btn.hasAttribute("data-delete-pack")) {
        if (!window.confirm(`Delete source pack "${packId}" from config/settings.yaml?`)) {
          return;
        }
        btn.setAttribute("disabled", "");
        try {
          const res = await csrfFetch(`/api/source-packs/${encodeURIComponent(packId)}`, {
            method: "DELETE",
          });
          const data = await res.json();
          if (!res.ok || !data.ok) {
            throw new Error(data.error || `HTTP ${res.status}`);
          }
          card.remove();
          const tab = document.querySelector(`[data-pack-tab="${CSS.escape(packId)}"]`);
          tab?.remove();
          const nextTab = document.querySelector("[data-pack-tab]");
          if (nextTab && typeof activatePackTab === "function") {
            activatePackTab(nextTab.getAttribute("data-pack-tab") || "");
          }
        } catch (err) {
          if (packStatusEl) {
            packStatusEl.textContent = `Delete failed: ${err instanceof Error ? err.message : String(err)}`;
          }
          btn.removeAttribute("disabled");
        }
      }
    });
  }

  // Shared WAI-ARIA tablist keyboard navigation
  function bindTablistKeyboard(tablistEl, tabSelector, activateFn) {
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

  // Source Pack Tabs on /settings
  const packTabsEl = document.getElementById("source-packs-tabs");

  function activatePackTab(packId) {
    if (!packTabsEl || !sourcePacksList || !packId) return;
    packTabsEl.querySelectorAll("[data-pack-tab]").forEach((tab) => {
      const active = tab.getAttribute("data-pack-tab") === packId;
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.setAttribute("tabindex", active ? "0" : "-1");
    });
    sourcePacksList.querySelectorAll("[data-pack-card]").forEach((card) => {
      const active = card.getAttribute("data-pack-id") === packId;
      card.hidden = !active;
    });
  }

  function syncPackTab(packId, label, count) {
    if (!packTabsEl) return;
    let tab = packTabsEl.querySelector(`[data-pack-tab="${CSS.escape(packId)}"]`);
    if (!tab) {
      tab = document.createElement("button");
      tab.type = "button";
      tab.className = "pack-tab";
      tab.setAttribute("role", "tab");
      tab.id = `pack-tab-${packId}`;
      tab.setAttribute("aria-controls", `pack-panel-${packId}`);
      tab.setAttribute("aria-selected", "false");
      tab.setAttribute("tabindex", "-1");
      tab.setAttribute("data-pack-tab", packId);
      const lblSpan = document.createElement("span");
      const cntSpan = document.createElement("span");
      cntSpan.className = "pack-tab-count";
      tab.append(lblSpan, cntSpan);
      packTabsEl.appendChild(tab);
    }
    const spans = tab.querySelectorAll("span");
    if (spans[0]) spans[0].textContent = label;
    if (spans[1]) spans[1].textContent = String(count);
  }

  if (packTabsEl) {
    packTabsEl.addEventListener("click", (event) => {
      const tab = event.target instanceof Element ? event.target.closest("[data-pack-tab]") : null;
      if (!tab) return;
      activatePackTab(tab.getAttribute("data-pack-tab") || "");
    });
    bindTablistKeyboard(packTabsEl, "[data-pack-tab]", activatePackTab);
  }

  // Sync Built-in Packs & Live Probe on /packs
  const syncPacksBtn = document.getElementById("sync-builtin-packs-btn");
  const syncPacksStatus = document.getElementById("sync-packs-status");
  if (syncPacksBtn) {
    syncPacksBtn.addEventListener("click", async () => {
      syncPacksBtn.disabled = true;
      if (syncPacksStatus) syncPacksStatus.textContent = "Syncing built-in packs...";
      try {
        const res = await csrfFetch("/api/source-packs/sync", { method: "POST" });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          if (syncPacksStatus) syncPacksStatus.textContent = data.error || "Sync failed.";
          return;
        }
        const addedPacks = Array.isArray(data.packs_added) ? data.packs_added.length : 0;
        const addedSources = Number(data.sources_added || 0);
        if (addedPacks === 0 && addedSources === 0) {
          if (syncPacksStatus) {
            syncPacksStatus.textContent = "Your packs already include all built-in packs and sources.";
          }
        } else {
          if (syncPacksStatus) {
            syncPacksStatus.textContent = `Added ${addedPacks} built-in pack(s) and ${addedSources} new source(s) without overwriting your edits. Reloading...`;
          }
          window.setTimeout(() => window.location.reload(), 600);
        }
      } catch (err) {
        if (syncPacksStatus) syncPacksStatus.textContent = `Sync error: ${err.message}`;
      } finally {
        syncPacksBtn.disabled = false;
      }
    });
  }

  const packProbeBtn = document.getElementById("pack-probe-btn");
  const packProbeUrlInput = document.getElementById("pack-probe-url");
  const packProbeResult = document.getElementById("pack-probe-result");
  if (packProbeBtn && packProbeUrlInput && packProbeResult) {
    packProbeUrlInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        packProbeBtn.click();
      }
    });

    packProbeBtn.addEventListener("click", async () => {
      if (packProbeBtn.disabled) return;
      const rawUrl = packProbeUrlInput.value.trim();
      if (!rawUrl || (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://"))) {
        packProbeResult.hidden = false;
        packProbeResult.textContent = "Enter a full URL starting with http:// or https://.";
        packProbeUrlInput.focus();
        return;
      }
      const probeUrl = rawUrl
        .replaceAll("{query_encoded}", "Mac+Studio")
        .replaceAll("{query}", "Mac Studio")
        .replaceAll("{make}", "toyota")
        .replaceAll("{model}", "tundra");

      packProbeBtn.disabled = true;
      packProbeResult.hidden = false;
      packProbeResult.textContent = "Probing URL (this may take a few seconds)...";

      try {
        const res = await csrfFetch("/api/sources/probe", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: probeUrl }),
          signal: typeof AbortSignal !== "undefined" && AbortSignal.timeout
            ? AbortSignal.timeout(35000)
            : undefined,
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          packProbeResult.textContent = data.error || `Probe failed (HTTP ${res.status}).`;
          return;
        }

        packProbeResult.replaceChildren();
        const summaryRow = document.createElement("div");
        summaryRow.className = "actions-row";

        const clsBadge = document.createElement("span");
        const clsCode = data.classification || "UNKNOWN";
        clsBadge.className = clsCode === "A_CLEAN_HTTP"
          ? "badge badge-hit"
          : clsCode === "B_NEEDS_PLAYWRIGHT"
            ? "badge badge-paused"
            : "badge badge-bad";
        clsBadge.textContent = clsCode === "A_CLEAN_HTTP"
          ? "Ready (HTTP)"
          : clsCode === "B_NEEDS_PLAYWRIGHT"
            ? "Needs Playwright JS"
            : clsCode === "C_BOT_BLOCKED"
              ? "Bot-Blocked"
              : clsCode;

        const infoText = document.createElement("span");
        const adapterLabel = data.recommended_adapter || "none";
        const countLabel = Number(data.item_count || 0);
        infoText.textContent = `Adapter: ${adapterLabel} · Found ${countLabel} item(s)`;

        summaryRow.append(clsBadge, infoText);

        if (data.recommended_adapter) {
          const addBtn = document.createElement("button");
          addBtn.type = "button";
          addBtn.className = "btn btn-sm btn-primary";
          addBtn.textContent = "Add to Active Pack";
          addBtn.addEventListener("click", () => {
            if (!sourcePacksList) return;
            const activeCard = sourcePacksList.querySelector("[data-pack-card]:not([hidden])");
            if (!activeCard) {
              const emptyMsg = document.createElement("p");
              emptyMsg.className = "muted mb-0";
              emptyMsg.textContent = "Create or sync a pack first before adding a probed source.";
              packProbeResult.appendChild(emptyMsg);
              return;
            }
            const packId = activeCard.getAttribute("data-pack-id") || "";
            const packLabelEl = activeCard.querySelector("[data-pack-label]");
            const packLabel = packLabelEl ? packLabelEl.value.trim() || packId : packId;
            const sourcesWrap = activeCard.querySelector("[data-pack-sources]");
            if (!sourcesWrap) return;

            const existingUrls = Array.from(sourcesWrap.querySelectorAll("[data-psrc-url]"))
              .map((el) => el.value.trim().toLowerCase());
            const statusEl = activeCard.querySelector("[data-pack-status]");
            if (existingUrls.includes(rawUrl.toLowerCase())) {
              if (statusEl) {
                statusEl.textContent = `This URL template is already in "${packLabel}".`;
              }
              return;
            }

            const row = buildPackSourceRow(packId, {
              name: data.recommended_name || "New Source",
              adapter: data.recommended_adapter,
              url_template: rawUrl,
              options: data.recommended_options || {},
            });
            sourcesWrap.appendChild(row);
            if (statusEl) {
              statusEl.textContent = `Added to "${packLabel}". Click Save (disk icon) on this pack to keep it.`;
            }
          });
          summaryRow.appendChild(addBtn);
        }

        packProbeResult.appendChild(summaryRow);
        if (Array.isArray(data.sample_items) && data.sample_items.length > 0) {
          const sampleList = document.createElement("ul");
          sampleList.className = "muted mb-0";
          for (const item of data.sample_items.slice(0, 3)) {
            const li = document.createElement("li");
            const priceStr = item.price != null ? ` — $${Number(item.price).toLocaleString()}` : "";
            li.textContent = `${item.title || "Untitled"}${priceStr}`;
            sampleList.appendChild(li);
          }
          packProbeResult.appendChild(sampleList);
        }
        if (Array.isArray(data.notes) && data.notes.length > 0) {
          const notesP = document.createElement("p");
          notesP.className = "muted mb-0";
          notesP.textContent = data.notes.join(" ");
          packProbeResult.appendChild(notesP);
        }
      } catch (err) {
        const msg = err && err.name === "TimeoutError"
          ? "Probe timed out after 35s. The target site may be slow or blocking requests."
          : `Probe error: ${err.message}`;
        packProbeResult.textContent = msg;
      } finally {
        packProbeBtn.disabled = false;
      }
    });
  }

  // Manage Watch Form Tabs on /manage
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

  // Sortable table headers across all data tables
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
})();
