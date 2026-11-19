/**
 * Admin (/settings) and Source Packs (/packs) page behaviors:
 * recipients/users CRUD & test alerts, source pack tabs, source pack cards/rows
 * CRUD & test-source, sync built-in packs, and pack URL probe.
 */

import { bindTablistKeyboard } from "./ui.js";
import { buildPreviewListItem, createSvgIcon, csrfFetch, safeUrl, slugifyId } from "./utils.js";

let packRowSeq = 0;

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
  const recipientsTbody = document.getElementById("recipients-tbody");
  const recipientsTableWrap = document.getElementById("recipients-table-wrap");
  const recipientsEmptyMsg = document.getElementById("recipients-empty-msg");
  if (!recipientsTbody || !recipientsTableWrap || !recipientsEmptyMsg) return;
  const hasRows = recipientsTbody.querySelectorAll("[data-recipient-row]").length > 0;
  recipientsTableWrap.hidden = !hasRows;
  recipientsEmptyMsg.hidden = hasRows;
}

function initUsersSection() {
  const usersSection = document.getElementById("users-section");
  const recipientsTbody = document.getElementById("recipients-tbody");
  const newRecBtn = document.getElementById("new-recipient-btn");
  const newRecWrap = document.getElementById("new-recipient-form-wrap");
  const newRecNameInput = document.getElementById("new-recipient-name");
  const newRecKeyInput = document.getElementById("new-recipient-key");
  const newRecWahaInput = document.getElementById("new-recipient-waha");
  const newRecEmailInput = document.getElementById("new-recipient-email");
  const createRecConfirmBtn = document.getElementById("create-recipient-confirm-btn");
  const createRecCancelBtn = document.getElementById("create-recipient-cancel-btn");
  const newRecStatus = document.getElementById("new-recipient-status");

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
}

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

/**
 * Activate a source pack tab and reveal its corresponding panel card.
 */
export function activatePackTab(packId) {
  const packTabsEl = document.getElementById("source-packs-tabs");
  const sourcePacksList = document.getElementById("source-packs-list");
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

/**
 * Create or update a source pack tab button with its label and source count.
 */
export function syncPackTab(packId, label, count) {
  const packTabsEl = document.getElementById("source-packs-tabs");
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

function initSourcePacksManager() {
  const sourcePacksList = document.getElementById("source-packs-list");
  const newPackBtn = document.getElementById("new-pack-btn");
  const newPackWrap = document.getElementById("new-pack-form-wrap");
  const newPackIdInput = document.getElementById("new-pack-id");
  const newPackLabelInput = document.getElementById("new-pack-label");
  const newPackDescInput = document.getElementById("new-pack-desc");
  const createPackConfirmBtn = document.getElementById("create-pack-confirm-btn");
  const createPackCancelBtn = document.getElementById("create-pack-cancel-btn");
  const newPackStatus = document.getElementById("new-pack-status");
  const packTabsEl = document.getElementById("source-packs-tabs");

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
        syncPackTab(data.pack_id, data.pack.label, data.pack.sources?.length || 1);
        activatePackTab(data.pack_id);
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
          syncPackTab(data.pack_id, data.pack.label, data.pack.sources.length);
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
          if (nextTab) {
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

  if (packTabsEl) {
    packTabsEl.addEventListener("click", (event) => {
      const tab = event.target instanceof Element ? event.target.closest("[data-pack-tab]") : null;
      if (!tab) return;
      activatePackTab(tab.getAttribute("data-pack-tab") || "");
    });
    bindTablistKeyboard(packTabsEl, "[data-pack-tab]", activatePackTab);
  }
}

function initSyncBuiltinPacks() {
  const syncPacksBtn = document.getElementById("sync-builtin-packs-btn");
  const syncPacksStatus = document.getElementById("sync-packs-status");
  if (!syncPacksBtn) return;

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
      if (syncPacksStatus) {
        syncPacksStatus.textContent = `Sync error: ${err?.message || String(err)}`;
      }
    } finally {
      syncPacksBtn.disabled = false;
    }
  });
}

function initPackProbe() {
  const sourcePacksList = document.getElementById("source-packs-list");
  const packProbeBtn = document.getElementById("pack-probe-btn");
  const packProbeUrlInput = document.getElementById("pack-probe-url");
  const packProbeResult = document.getElementById("pack-probe-result");
  if (!packProbeBtn || !packProbeUrlInput || !packProbeResult) return;

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
        : `Probe error: ${err?.message || String(err)}`;
      packProbeResult.textContent = msg;
    } finally {
      packProbeBtn.disabled = false;
    }
  });
}

/**
 * Initialize Admin (/settings) and Source Packs (/packs) interactive controls.
 */
export function initSettingsPage() {
  initUsersSection();
  initSourcePacksManager();
  initSyncBuiltinPacks();
  initPackProbe();
}
