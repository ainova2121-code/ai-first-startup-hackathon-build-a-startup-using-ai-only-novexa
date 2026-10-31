// The audit ledger page: every signed event of a run, re-verified from disk by the server, filterable by
// kind, each expandable to its full payload, hash and the compliance clauses it evidences.
"use strict";

let ledgerView = null;
let ledgerFilter = null;

const ledgerOpen = new Set();  // rows the reader expanded, kept open across live refreshes
let ledgerSeen = null;          // seqs already listed: a new one slides in

// ``live``: a refresh while the run signs events -- keep the filter, the open rows and the reader's place.
async function loadLedger(runId, live = false) {
  const head = $("ledgerHead");
  if (!live || !ledgerView || ledgerView.run.id !== runId) {
    head.textContent = "";
    $("ledgerFilters").textContent = "";
    $("ledgerTable").textContent = "";
    ledgerFilter = null; ledgerSeen = null; ledgerOpen.clear();
    if (!runId) { head.appendChild(el("span", "muted", "No run yet — start one to produce a signed ledger.")); return; }
    head.appendChild(el("span", "muted", "Verifying the signed ledger…"));
  }
  const response = await fetch(`/runs/${encodeURIComponent(runId)}/ledger`);
  if (!response.ok) { if (!live) { head.textContent = ""; head.appendChild(el("span", "muted", "This run's ledger is not available.")); } return; }
  ledgerView = await response.json();
  renderLedger();
}

function verificationBadge(v) {
  if (v.ok === null) return el("span", "verdict-badge warn", "Not sealed yet");
  if (v.ok) return el("span", "verdict-badge ok", v.anchored ? "Chain verifies · anchored to its signed checkpoint" : "Chain verifies");
  return el("span", "verdict-badge bad", `Chain broken${v.broken_at !== null ? ` at event ${v.broken_at}` : ""}`);
}

function summarize(e) {
  const p = e.payload || {};
  const list = (x) => (x || []).join(", ");
  switch (e.kind) {
    case "attack": return `${p.id} (${p.technique})`;
    case "breach": return `${p.proof || p.kind} — ${p.agent}.${p.tool}`;
    case "attempt": return `held, but ${p.proof}`;
    case "patch": return `${list(p.patch_ids) || "no runtime guard"}${p.escalation ? ` · escalation level ${p.escalation}` : ""}`
                         + `${(p.source_changes || []).length ? ` · ${p.source_changes.length} file(s) edited` : ""}`;
    case "verdict": return p.safe_to_ship ? "safe to ship"
                                          : `not safe to ship — ${(p.errors || []).length + (p.failures || []).length} reason(s)`;
    case "review": return `${p.action} ${p.agent ? `${p.agent}.` : ""}${p.tool || ""}`;
    case "source_patch": return `${p.path}:${p.line} edited (${list(p.verified_by)})`;
    case "source_patch_skipped": return `${p.path}:${p.line} not edited — ${p.reason}`;
    case "source_patch_approved": return `${p.path}: ${p.approval}`;
    case "static": return `${(p.findings || []).length} static finding(s)`;
    case "identity": return `${p.agents} agents · ${(p.findings || []).length} identity finding(s)`;
    case "seal": return `Merkle root ${String(p.merkle_root || "").slice(0, 16)}…`;
    default: { const s = JSON.stringify(p); return s.length > 140 ? `${s.slice(0, 140)}…` : s; }
  }
}

function renderLedger() {
  const v = ledgerView;
  const head = $("ledgerHead");
  head.textContent = "";
  add(head, verificationBadge(v.verification),
      el("span", "muted mono", `${v.verification.count} signed events · run ${v.run.id}${v.run.target ? ` · ${v.run.target}` : ""}`));
  if (v.verification.reason) head.appendChild(el("span", "faint", v.verification.reason));

  const counts = {};
  for (const e of v.events) counts[e.kind] = (counts[e.kind] || 0) + 1;
  const filters = $("ledgerFilters");
  filters.textContent = "";
  const chip = (label, kind) => {
    const button = el("button", `filter${ledgerFilter === kind ? " active" : ""}`, label);
    button.addEventListener("click", () => { ledgerFilter = kind; renderLedger(); });
    filters.appendChild(button);
  };
  chip(`all ${v.events.length}`, null);
  for (const [kind, n] of Object.entries(counts)) chip(`${kind} ${n}`, kind);

  const table = $("ledgerTable");
  const scrolled = table.scrollTop;  // a live refresh rebuilds the rows; keep the reader where they were
  table.textContent = "";
  const seen = ledgerSeen;
  ledgerSeen = new Set(v.events.map((e) => e.seq));
  for (const e of v.events.filter((x) => ledgerFilter === null || x.kind === ledgerFilter)) {
    const row = el("div", seen && !seen.has(e.seq) ? "ledger-row arrive" : "ledger-row");
    const toggle = add(el("button", "ledger-head"), el("span", "mono faint", `#${e.seq}`),
                       el("span", "mono faint", new Date(e.ts * 1000).toLocaleTimeString()),
                       el("span", "mono", e.actor), pill(e.kind, `kind-${e.kind}`), el("span", "ledger-summary", summarize(e)),
                       el("span", "faint", e.clauses.length ? `${e.clauses.length} clause(s)` : ""));
    const wasOpen = ledgerOpen.has(e.seq);
    toggle.setAttribute("aria-expanded", String(wasOpen));
    const detail = add(el("div", `ledger-detail${wasOpen ? "" : " hidden"}`), el("div", "label", `event hash ${e.hash}…`),
                       el("pre", "reply", JSON.stringify(e.payload, null, 2)));
    if (e.clauses.length) detail.appendChild(el("div", "label", `Evidences: ${e.clauses.join(" · ")}`));
    toggle.addEventListener("click", () => {
      const open = detail.classList.toggle("hidden") === false;
      if (open) ledgerOpen.add(e.seq); else ledgerOpen.delete(e.seq);
      toggle.setAttribute("aria-expanded", String(open));
    });
    table.appendChild(add(row, toggle, detail));
  }
  table.scrollTop = scrolled;
}
