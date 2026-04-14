"use strict";

const state = {
  data: null,
  filteredEntries: [],
  selectedEntry: null,
  changedOnly: false,
  sortDirection: "desc",
  themeMode: "system",
};

const el = {
  summaryCards: document.getElementById("summaryCards"),
  summaryScopeNote: document.getElementById("summaryScopeNote"),
  methodCounters: document.getElementById("methodCounters"),
  fileSearch: document.getElementById("fileSearch"),
  fileList: document.getElementById("fileList"),
  selectedFileTitle: document.getElementById("selectedFileTitle"),
  changedOnlyToggle: document.getElementById("changedOnlyToggle"),
  sortChangedBtn: document.getElementById("sortChangedBtn"),
  sortChangedLabel: document.getElementById("sortChangedLabel"),
  themeToggle: document.getElementById("themeToggle"),
  hashTableWrap: document.getElementById("hashTableWrap"),
  diffViewport: document.getElementById("diffViewport"),
  reportHashTables: document.getElementById("reportHashTables"),
  rowTemplate: document.getElementById("rowTemplate"),
};

function number(value) {
  return typeof value === "number" ? value.toLocaleString("en-US") : "-";
}

function formatPercent(value) {
  if (typeof value !== "number") return "-";
  return `${value.toFixed(2)}%`;
}

function htmlEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function rendererChangedLineTotal(entry) {
  if (typeof entry.changed_lines_renderer === "number") return entry.changed_lines_renderer;
  return entry.row_counts.added + entry.row_counts.removed + entry.row_counts.modified;
}

function changedLineTotal(entry) {
  if (typeof entry.changed_lines_display === "number") return entry.changed_lines_display;
  return rendererChangedLineTotal(entry);
}

function lineHashMetric(summary) {
  const identical = summary?.line_hash_identical_files;
  const comparable = summary?.line_hash_comparable_files;
  if (typeof identical !== "number" || typeof comparable !== "number" || comparable <= 0) return "-";
  return `${number(identical)} / ${number(comparable)}`;
}

function activeSummary() {
  return state.data.summary_expanded_scope || state.data.summary || {};
}

function entriesForScope() {
  return state.data.entries;
}

function isEntryMatch(entry, query) {
  if (!query) return true;
  return entry.relative_path.toLowerCase().includes(query);
}

function isStatusCell(value) {
  if (typeof value !== "string") return "";
  const low = value.toLowerCase();
  if (low === "true" || low === "yes") return "status-true";
  if (low === "false" || low === "no") return "status-false";
  return "";
}

function renderMethodCounters() {
  const counters = state.data.method_counters || {};
  const direct = number(counters.direct_source_vs_script_files);
  const decompiled = number(counters.dll_decompilation_files);
  el.methodCounters.innerHTML = `
    <span class="method-chip">Direct file-to-file: <strong>${direct}</strong></span>
    <span class="method-chip">Required DLL decompilation files: <strong>${decompiled}</strong></span>
  `;
}

function renderSummary() {
  const summary = activeSummary();
  const cards = [
    ["Files Compared", number(summary.files_total)],
    ["Files With Changes", number(summary.files_changed)],
    ["Code Match", formatPercent(summary.code_match_pct)],
    ["Line-Hash Identical Files", lineHashMetric(summary)],
    ["Equal Lines", number(summary.lines_equal)],
    ["Added Lines (Right)", number(summary.lines_added_right)],
    ["Removed Lines (Left)", number(summary.lines_removed_left)],
    ["Modified Lines", number(summary.lines_modified)],
  ];

  el.summaryCards.innerHTML = cards
    .map(
      ([label, value]) => `
      <div class="summary-card">
        <div class="label">${htmlEscape(label)}</div>
        <div class="value">${htmlEscape(value)}</div>
      </div>`
    )
    .join("");

  el.summaryScopeNote.textContent = summary.scope_note || "";
}

function renderSortLabel() {
  el.sortChangedLabel.textContent =
    state.sortDirection === "desc"
      ? "Changed lines: high to low"
      : "Changed lines: low to high";
}

function sortedScopeEntries() {
  const query = el.fileSearch.value.trim().toLowerCase();
  return entriesForScope()
    .filter((entry) => isEntryMatch(entry, query))
    .sort((a, b) => {
      const delta = changedLineTotal(a) - changedLineTotal(b);
      if (delta === 0) {
        return a.relative_path.localeCompare(b.relative_path);
      }
      return state.sortDirection === "asc" ? delta : -delta;
    });
}

function renderFileList() {
  const entries = sortedScopeEntries();
  state.filteredEntries = entries;

  el.fileList.innerHTML = entries
    .map((entry) => {
      const changed = changedLineTotal(entry);
      const active = state.selectedEntry && state.selectedEntry.id === entry.id ? "active" : "";
      const method = entry.comparison_method_label || "-";
      return `
      <button class="file-btn ${active}" data-id="${htmlEscape(entry.id)}" type="button">
        <div class="path">${htmlEscape(entry.relative_path)}</div>
        <div class="meta">
          Changed lines: ${number(changed)} | Method: ${htmlEscape(method)}
        </div>
      </button>
      `;
    })
    .join("");

  for (const button of el.fileList.querySelectorAll(".file-btn")) {
    button.addEventListener("click", () => {
      const selected = state.data.entries.find((entry) => entry.id === button.dataset.id);
      state.selectedEntry = selected || null;
      renderFileList();
      renderSelectedEntry();
    });
  }
}

function chooseDefaultEntry(entries) {
  if (!entries.length) return null;
  const withChanges = entries.find((entry) => changedLineTotal(entry) > 0);
  return withChanges || entries[0];
}

function ensureSelectedEntryInScope() {
  const scopeEntries = entriesForScope();
  if (!scopeEntries.length) {
    state.selectedEntry = null;
    return;
  }
  if (!state.selectedEntry || !scopeEntries.some((entry) => entry.id === state.selectedEntry.id)) {
    state.selectedEntry = chooseDefaultEntry(scopeEntries);
  }
}

function renderHashPanel(entry) {
  const left = entry.left_hash || {};
  const right = entry.right_hash || {};

  const compare = (a, b) => {
    if (!a || !b) return "n/a";
    return a === b ? "equal" : "different";
  };

  const changedShown = changedLineTotal(entry);
  const changedRenderer = rendererChangedLineTotal(entry);

  const rows = [
    ["Comparison Method", entry.comparison_method_label || "-", "-", "-"],
    ["Scope", "Complete public check", "-", "-"],
    ["Exists", entry.left_exists ? "yes" : "no", entry.right_exists ? "yes" : "no", compare(entry.left_exists, entry.right_exists)],
    ["Size (bytes)", number(left.size_bytes), number(right.size_bytes), compare(left.size_bytes, right.size_bytes)],
    ["SHA-256", left.sha256 || "-", right.sha256 || "-", compare(left.sha256, right.sha256)],
    ["Line Hash", left.line_hash || "-", right.line_hash || "-", compare(left.line_hash, right.line_hash)],
    [
      "Whitespace-Free Hash",
      left.whitespace_free_hash || "-",
      right.whitespace_free_hash || "-",
      compare(left.whitespace_free_hash, right.whitespace_free_hash),
    ],
    ["Line Count (non-empty)", number(entry.left_line_count), number(entry.right_line_count), compare(entry.left_line_count, entry.right_line_count)],
    ["Changed Lines (shown)", "-", number(changedShown), "-"],
  ];
  if (changedShown !== changedRenderer) {
    rows.push(["Changed Lines (renderer)", "-", number(changedRenderer), "-"]);
  }

  el.hashTableWrap.innerHTML = `
    <div class="hash-grid">
      <div class="cell head">Field</div>
      <div class="cell head">${htmlEscape(state.data.labels.left)}</div>
      <div class="cell head">${htmlEscape(state.data.labels.right)}</div>
      ${rows
        .map(
          ([field, l, r, status]) => `
          <div class="cell key">${htmlEscape(field)}</div>
          <div class="cell mono">${htmlEscape(l)}</div>
          <div class="cell mono ${isStatusCell(String(status))}">${htmlEscape(r)}</div>
        `
        )
        .join("")}
    </div>
  `;
}

function applyChangedOnly(rows) {
  if (!state.changedOnly) return rows;
  return rows.filter((row) => row.row_type !== "equal");
}

function renderRowsIncremental(rows) {
  el.diffViewport.innerHTML = "";
  const filteredRows = applyChangedOnly(rows);
  const total = filteredRows.length;
  const chunkSize = 400;
  let index = 0;

  const appendChunk = () => {
    const fragment = document.createDocumentFragment();
    const end = Math.min(index + chunkSize, total);

    for (; index < end; index += 1) {
      const row = filteredRows[index];
      const node = el.rowTemplate.content.firstElementChild.cloneNode(true);
      node.classList.add(`row-${row.row_type}`);

      node.querySelector(".ln-left").textContent = row.left_no ?? "";
      node.querySelector(".ln-right").textContent = row.right_no ?? "";
      node.querySelector(".code-left").textContent = row.left_text ?? "";
      node.querySelector(".code-right").textContent = row.right_text ?? "";
      fragment.appendChild(node);
    }

    el.diffViewport.appendChild(fragment);
    if (index < total) requestAnimationFrame(appendChunk);
  };

  appendChunk();
}

function renderSelectedEntry() {
  if (!state.selectedEntry) {
    el.selectedFileTitle.textContent = "Select a file";
    el.hashTableWrap.innerHTML = "";
    el.diffViewport.innerHTML = `<div class="empty-note">No file available for this report.</div>`;
    return;
  }

  const entry = state.selectedEntry;
  el.selectedFileTitle.textContent = entry.relative_path;
  renderHashPanel(entry);
  renderRowsIncremental(entry.rows || []);
}

function renderReportHashTables() {
  const blocks = (state.data.hash_tables_from_report || []).map((table) => {
    const head = table.columns.map((col) => `<th>${htmlEscape(col)}</th>`).join("");
    const body = table.rows
      .map((row) => {
        const cells = table.columns
          .map((col) => {
            const value = row[col] ?? "";
            return `<td class="${isStatusCell(String(value))}">${htmlEscape(value)}</td>`;
          })
          .join("");
        return `<tr>${cells}</tr>`;
      })
      .join("");

    return `
      <div class="hash-table-block">
        <h3>${htmlEscape(table.name)}</h3>
        <table>
          <thead><tr>${head}</tr></thead>
          <tbody>${body}</tbody>
        </table>
      </div>
    `;
  });

  el.reportHashTables.innerHTML = blocks.join("");
}

async function loadData() {
  if (window.__COMPARISON_DATA__) return window.__COMPARISON_DATA__;
  const response = await fetch("data/comparison-data.json", { cache: "no-store" });
  if (!response.ok) throw new Error(`Failed to load data: ${response.status}`);
  return response.json();
}

function effectiveSystemTheme() {
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function effectiveTheme() {
  return state.themeMode === "system" ? effectiveSystemTheme() : state.themeMode;
}

function applyTheme() {
  const current = effectiveTheme();
  document.documentElement.setAttribute("data-theme", current);
  if (el.themeToggle) {
    const isDark = current === "dark";
    el.themeToggle.setAttribute("aria-pressed", isDark ? "true" : "false");
    el.themeToggle.setAttribute("aria-label", isDark ? "Switch to light theme" : "Switch to dark theme");
  }
}

function animateThemeSwitch() {
  if (!el.themeToggle) return;
  el.themeToggle.classList.remove("is-animating");
  void el.themeToggle.offsetWidth;
  el.themeToggle.classList.add("is-animating");
  window.setTimeout(() => {
    el.themeToggle?.classList.remove("is-animating");
  }, 220);
}

function setThemeMode(mode) {
  state.themeMode = mode;
  localStorage.setItem("comparison-theme-mode", mode);
  applyTheme();
  animateThemeSwitch();
}

function toggleThemeMode() {
  const current = effectiveTheme();
  setThemeMode(current === "dark" ? "light" : "dark");
}

async function init() {
  state.data = await loadData();

  const savedThemeMode = localStorage.getItem("comparison-theme-mode");
  state.themeMode = savedThemeMode === "light" || savedThemeMode === "dark" ? savedThemeMode : "system";
  applyTheme();

  renderMethodCounters();
  renderSummary();
  renderSortLabel();
  renderReportHashTables();

  ensureSelectedEntryInScope();
  renderFileList();
  renderSelectedEntry();

  el.fileSearch.addEventListener("input", () => {
    renderFileList();
  });

  el.changedOnlyToggle.addEventListener("change", (event) => {
    state.changedOnly = event.target.checked;
    renderSelectedEntry();
  });

  el.sortChangedBtn.addEventListener("click", () => {
    state.sortDirection = state.sortDirection === "desc" ? "asc" : "desc";
    renderSortLabel();
    renderFileList();
  });

  el.themeToggle.addEventListener("click", toggleThemeMode);

  const media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", () => {
    if (state.themeMode === "system") applyTheme();
  });

  if (window.lucide) window.lucide.createIcons();
}

init().catch((error) => {
  document.body.innerHTML = `
    <div style="padding:20px; font-family:Manrope, 'Segoe UI', sans-serif;">
      <h1>Error Loading Report</h1>
      <p>${htmlEscape(error.message || String(error))}</p>
    </div>
  `;
});
