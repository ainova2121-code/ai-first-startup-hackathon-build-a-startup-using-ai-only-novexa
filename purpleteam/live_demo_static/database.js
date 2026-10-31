"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };

  let snapshot = null;
  let selectedTable = "";
  let selectedRowKey = "";
  let loading = false;
  let loadingUrl = "";
  let requestGeneration = 0;
  let baseIndex = null;  // seeded baseline indexed by table -> primary key, to mark what the run changed (red)
  let view = "after";    // "breach": the unpatched agent's database the moment an attack breached it

  function pkColumns(columns) {
    const pk = columns.filter((c) => c.primary_key).map((c) => c.name);
    return pk.length ? pk : (columns.some((c) => c.name === "id") ? ["id"] : columns.map((c) => c.name));
  }
  function rowKeyForCols(columns, row) {
    return pkColumns(columns).map((name) => JSON.stringify(row[name] ?? null)).join("|");
  }
  function baselineIndex(baseline) {
    const index = {};
    for (const table of baseline?.tables || []) {
      const map = new Map();
      for (const row of table.rows) map.set(rowKeyForCols(table.columns, row), row);
      index[table.name] = map;
    }
    return index;
  }
  const sameValue = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

  function activeUrl() {
    const picker = $("runPicker");
    const selected = picker?.value;
    const base = selected && selected !== "live" ? `/runs/${encodeURIComponent(selected)}/database` : "/database";
    return view === "breach" ? `${base}?view=breach` : base;
  }

  function formatValue(value) {
    if (value === null || value === undefined) return "NULL";
    if (typeof value === "object") {
      if (value.kind === "binary") return `Binary attachment · ${Number(value.bytes || 0).toLocaleString()} bytes`;
      return JSON.stringify(value, null, 2);
    }
    return String(value);
  }

  function renderOverview(data) {
    const box = $("dbOverview");
    box.replaceChildren();
    const kind = data.snapshot_kind || "assessment";
    const runValue = kind === "seed_preview" ? "Seed preview" : (data.run_id || "Current");
    const runNote = kind === "seed_preview" ? "not tied to a run"
      : kind === "breach" ? "breach snapshot"
      : kind === "run_baseline" ? "pre-attack baseline"
      : data.live ? "live snapshot" : "saved snapshot";
    const items = [
      ["ENGINE", data.engine || "SQLite", "read only"],
      ["TABLES", data.tables.length, "discovered"],
      ["RECORDS", Number(data.total_rows || 0).toLocaleString(), "across all tables"],
      ["RUN", runValue, runNote],
    ];
    for (const [label, value, note] of items) {
      const stat = el("div", "db-stat");
      stat.append(el("div", "db-stat-label", label));
      stat.append(addValue(value, note));
      box.append(stat);
    }
    const badge = $("dbConnectionState");
    badge.className = `db-connection ${kind === "seed_preview" ? "preview" : kind === "breach" ? "breach"
      : data.live ? "live" : "snapshot"}`;
    $("dbConnectionText").textContent = kind === "seed_preview" ? "SEEDED PREVIEW · no run data"
      : kind === "breach" ? "BREACH · unpatched agent"
      : kind === "run_baseline" ? "RUN BASELINE · before agent activity"
      : data.live ? "LIVE · reading target" : "SAVED · run snapshot";
    $("dbExplainerText").textContent = kind === "breach"
      ? `The unpatched agent's own database, captured the moment an attack breached it. Everything the attack changed `
        + `against the original is marked in red.${data.proof ? ` Proof: ${data.proof}.` : ""}`
      : kind === "seed_preview"
      ? "This is the real seeded LedgerPilot SQLite database, shown as a preview because no target run data is available yet. Start a full assessment to switch to its isolated live database; Quick Scan does not create one."
      : kind === "run_baseline"
        ? "This is the real SQLite baseline captured for this run before agent activity. The run ended before a final database snapshot was saved."
        : "Demo data only. This view reads the assessment’s isolated target database; it is separate from the signed audit ledger. Binary invoice attachments are identified by size.";
    const updated = data.captured_at ? new Date(data.captured_at * 1000).toLocaleTimeString() : "—";
    $("dbUpdatedAt").textContent = `${data.live ? "Last read" : "Captured"} ${updated}`;
    $("dbSourceText").textContent = kind === "seed_preview" ? "Source: seeded LedgerPilot SQLite preview"
      : kind === "breach" ? "Source: unpatched target at the moment of breach"
      : kind === "run_baseline" ? "Source: this run’s captured SQLite baseline"
      : data.live ? "Source: live SQLite target snapshot" : "Source: saved SQLite target snapshot";
  }

  function addValue(value, note) {
    const line = el("div", "db-stat-value");
    line.append(el("span", "", value), el("small", "", note));
    return line;
  }

  function renderTabs(data) {
    const tabs = $("dbTableTabs");
    tabs.replaceChildren();
    for (const table of data.tables) {
      const button = el("button", `db-table-tab${table.name === selectedTable ? " active" : ""}`);
      button.type = "button";
      button.setAttribute("role", "tab");
      button.setAttribute("aria-selected", String(table.name === selectedTable));
      button.append(el("span", "", table.label), el("span", "db-table-tab-count", table.row_count));
      button.addEventListener("click", () => {
        selectedTable = table.name;
        selectedRowKey = "";
        renderSnapshot(data);
      });
      tabs.append(button);
    }
  }

  function matchesSearch(row, query) {
    return !query || JSON.stringify(row).toLowerCase().includes(query);
  }

  function renderDetail(table, row, rowKey) {
    const detail = $("dbRecordDetail");
    if (!row || !rowKey) {
      detail.classList.add("hidden");
      detail.replaceChildren();
      return;
    }
    detail.classList.remove("hidden");
    detail.replaceChildren();
    const header = el("div", "db-detail-head");
    header.append(el("span", "db-detail-title", `${table.name} · record ${row.id ?? "—"}`),
      el("span", "db-detail-hint", "Full row values from SQLite"));
    const grid = el("div", "db-detail-grid");
    for (const [key, value] of Object.entries(row)) {
      const field = el("div", "db-detail-field");
      const rendered = formatValue(value);
      field.append(el("div", "db-detail-key", key),
        el("div", `db-detail-value${value?.kind === "binary" ? " binary" : ""}`, rendered));
      grid.append(field);
    }
    detail.append(header, grid);
  }

  function resetGrid(head, body, columns) {
    head.replaceChildren();
    body.replaceChildren();
    const headerRow = el("tr");
    headerRow.append(el("th", "", "#"));
    for (const column of columns) headerRow.append(el("th", "", column.name));
    head.append(headerRow);
  }

  function emptyRow(columns, text) {
    const empty = el("tr", "db-empty-row");
    empty.append(el("td", "", text));
    empty.firstElementChild.colSpan = columns.length + 1;
    return empty;
  }

  function valueCell(value, className = "") {
    const td = el("td", className);
    if (value?.kind === "binary") {
      td.append(el("span", "db-binary", `BINARY · ${Number(value.bytes || 0).toLocaleString()} B`));
      return td;
    }
    const text = value === null || value === undefined ? "NULL" : formatValue(value);
    const cell = el("span", `db-cell${value === null || value === undefined ? " null" : ""}`, text);
    cell.title = text;
    td.append(cell);
    return td;
  }

  // The untouched seeded state captured before any attack; the seeded preview and a run baseline are that state.
  function originalOf(data) {
    if (data.baseline) return data.baseline;
    return data.snapshot_kind === "seed_preview" || data.snapshot_kind === "run_baseline" ? data : null;
  }

  function renderOriginal(data, query) {
    const original = originalOf(data);
    const table = original?.tables.find((item) => item.name === selectedTable);
    for (const id of ["dbOriginalCaption", "dbOriginalWrap"]) $(id).classList.toggle("hidden", !table);
    if (!table) return;
    $("dbOriginalTitle").textContent = `Original · ${table.label}`;
    $("dbOriginalDescription").textContent = "before any attack";
    const decoys = new Set(table.decoys || []);  // planted by the platform, never the target's own data
    const own = table.rows.filter((row) => !decoys.has(row.id));
    const rows = own.filter((row) => matchesSearch(row, query));
    $("dbOriginalCount").textContent = `${rows.length.toLocaleString()} of ${own.length.toLocaleString()} records`;
    const body = $("dbOriginalBody");
    resetGrid($("dbOriginalHead"), body, table.columns);
    if (!rows.length) body.append(emptyRow(table.columns, query ? "No records match this search." : "This table had no records."));
    for (const [index, row] of rows.entries()) {
      const tr = el("tr");
      tr.append(el("td", "", row.id ?? index + 1));
      for (const column of table.columns) tr.append(valueCell(row[column.name]));
      body.append(tr);
    }
  }

  function renderTable(data) {
    const table = data.tables.find((item) => item.name === selectedTable) || data.tables[0];
    if (!table) return;
    selectedTable = table.name;
    renderOriginal(data, $("dbSearch").value.trim().toLowerCase());
    $("dbTableTitle").textContent = `${view === "breach" ? "Breach" : "Current"} · ${table.label}`;
    $("dbTableDescription").textContent = view === "breach" ? "the unpatched agent, right after the attack"
      : `${table.columns.length} columns · select a row for full values`;
    const query = $("dbSearch").value.trim().toLowerCase();
    const rows = table.rows.filter((row) => matchesSearch(row, query));
    const decoys = new Set(table.decoys || []);
    $("dbRecordCount").textContent = `${rows.length.toLocaleString()} of ${table.row_count.toLocaleString()} records`
      + (decoys.size ? ` · ${decoys.size} planted decoy` : "");
    const head = $("dbTableHead");
    const body = $("dbTableBody");
    resetGrid(head, body, table.columns);
    if (!rows.length) {
      body.append(emptyRow(table.columns, query ? "No records match this search." : "This table has no records yet."));
      renderDetail(table, null, "");
      return;
    }
    const baseMap = baseIndex ? baseIndex[table.name] : null;
    for (const [index, row] of rows.entries()) {
      const rowKey = `${table.name}:${row.id ?? index}`;
      const baseRow = baseMap ? baseMap.get(rowKeyForCols(table.columns, row)) : null;
      const isNew = Boolean(baseMap) && !baseRow;  // a row the run created
      const decoy = decoys.has(row.id);  // the platform's planted honeytoken: a tripwire, not a change the run made
      const classes = [rowKey === selectedRowKey && "selected", isNew && "db-row-new", decoy && "db-row-decoy"];
      const tr = el("tr", classes.filter(Boolean).join(" "));
      const first = el("td", "", row.id ?? index + 1);
      if (decoy) {
        const tag = el("span", "db-decoy", "PLANTED DECOY");
        tag.title = "Planted by PurpleTeam before any attack: if its value ever appears in an answer, that proves a leak.";
        first.append(tag);
      }
      tr.append(first);
      for (const column of table.columns) {
        const value = row[column.name];
        const changed = !isNew && baseRow && !sameValue(value, baseRow[column.name]);  // a value the run altered
        tr.append(valueCell(value, changed ? "db-cell-changed" : ""));
      }
      tr.addEventListener("click", () => {
        selectedRowKey = rowKey;
        renderTable(data);
        renderDetail(table, row, rowKey);
      });
      body.append(tr);
      if (rowKey === selectedRowKey) renderDetail(table, row, rowKey);
    }
  }

  function renderSnapshot(data) {
    snapshot = data;
    baseIndex = data.baseline ? baselineIndex(data.baseline) : null;  // null -> nothing to diff, mark nothing
    if (!data.tables.some((table) => table.name === selectedTable)) selectedTable = data.tables[0]?.name || "";
    $("dbMessage").classList.add("hidden");
    $("dbTableWrap").classList.remove("hidden");
    renderOverview(data);
    renderViewSwitch(data);
    renderTabs(data);
    renderTable(data);
  }

  function renderViewSwitch(data) {
    const box = $("dbView");
    box.classList.toggle("hidden", !data.breach_available);
    for (const option of box.children) {
      const on = option.dataset.view === view;
      option.classList.toggle("active", on);
      option.setAttribute("aria-checked", String(on));
    }
  }

  function switchView(next) {
    if (next === view) return;
    view = next;
    selectedRowKey = "";
    loadDatabase(true);
  }

  function showMessage(message, error = false) {
    if (snapshot) {
      const badge = $("dbConnectionState");
      badge.className = "db-connection";
      $("dbConnectionText").textContent = "RETRYING · last snapshot shown";
      return;
    }
    $("dbOverview").replaceChildren();
    $("dbTableTabs").replaceChildren();
    $("dbRecordDetail").replaceChildren();
    $("dbRecordDetail").classList.add("hidden");
    $("dbTableTitle").textContent = "Tables";
    $("dbTableDescription").textContent = "";
    $("dbRecordCount").textContent = "";
    $("dbUpdatedAt").textContent = "No snapshot yet";
    $("dbConnectionState").className = "db-connection";
    $("dbConnectionText").textContent = "Waiting for a target run";
    $("dbMessage").textContent = message;
    $("dbMessage").classList.toggle("error", error);
    $("dbMessage").classList.remove("hidden");
    $("dbTableWrap").classList.add("hidden");
    for (const id of ["dbOriginalCaption", "dbOriginalWrap"]) $(id).classList.add("hidden");
  }

  async function loadDatabase(force = false) {
    if (!force && location.hash !== "#/database") return;
    const url = activeUrl();
    if (loading && loadingUrl === url && !force) return;
    const generation = ++requestGeneration;
    loading = true;
    loadingUrl = url;
    try {
      const response = await fetch(url, { cache: "no-store" });
      const data = await response.json().catch(() => ({}));
      if (generation !== requestGeneration) return;
      if (!response.ok && view === "breach" && response.status === 404) {  // this run has no breach: show after-patch
        view = "after";
        loading = false;
        loadDatabase(true);
        return;
      }
      if (!response.ok) {
        const detail = data.detail || "Could not read the target database.";
        if (response.status === 404) showMessage(activeUrl().startsWith("/runs/")
          ? "This saved run did not capture a LedgerPilot database snapshot (Quick Scan runs do not create the target database). Select Current run to view the seeded database preview."
          : detail);
        else showMessage(detail, true);
        return;
      }
      renderSnapshot(data);
    } catch {
      if (generation === requestGeneration) showMessage("Database view is temporarily unavailable. Try refreshing.", true);
    } finally {
      if (generation === requestGeneration) loading = false;
    }
  }

  $("dbRefresh").addEventListener("click", () => loadDatabase(true));
  $("dbSearch").addEventListener("input", () => { if (snapshot) renderTable(snapshot); });
  $("dbView").addEventListener("click", (event) => {
    const option = event.target.closest(".db-view-option");
    if (option) switchView(option.dataset.view);
  });
  $("runPicker").addEventListener("change", () => {
    view = "after";
    snapshot = null;
    selectedTable = "";
    selectedRowKey = "";
    showMessage("Loading the selected run's database snapshot…");
    loadDatabase(true);
  });
  window.addEventListener("hashchange", () => loadDatabase());
  window.setInterval(() => {
    if (location.hash === "#/database") loadDatabase();
  }, 2500);
  window.loadDatabase = loadDatabase;
})();
