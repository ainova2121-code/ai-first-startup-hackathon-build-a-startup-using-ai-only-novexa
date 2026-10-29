// Renderers for the live run. Every string that came from the target or a model is set with
// textContent only (el()); nothing here builds HTML from event data.
"use strict";

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function add(parent, ...children) {
  for (const child of children) if (child) parent.appendChild(child);
  return parent;
}

function pill(text, cls) { return el("span", `pill ${cls}`, text); }

function clearPlaceholder(box) {
  const first = box.firstElementChild;
  if (first && first.classList.contains("muted")) first.remove();
}

function stat(label, value) {
  return add(el("div", "stat"), el("div", "stat-label", label), el("div", "stat-value", value));
}

function normPath(path) { return String(path || "").replaceAll("\\", "/"); }

// -- discovery ------------------------------------------------------------------------------------

function renderDiscovery(e) {
  $("discoveryEmpty").classList.add("hidden");
  const chip = $("targetChip");
  chip.textContent = "";
  add(chip, el("span", "dot"), document.createTextNode(`${e.target} · ${e.totals.agents} agents · ${e.totals.tools} tools`));
  chip.style.color = "var(--steel)";
  const summary = $("discoverySummary");
  summary.textContent = "";
  add(summary, document.createTextNode(`Discovered ${e.totals.agents} agents, ${e.totals.tools} tools (${e.totals.dangerous} dangerous, `
      + `${e.totals.retrieval} RAG surfaces, ${e.totals.memory} memory surfaces) and ${e.findings.length} posture findings. `));
  const link = el("a", null, "Open the full discovery ›");
  link.href = "#/discovery";
  summary.appendChild(link);
  summary.classList.remove("hidden");

  discoveryMap(e);

  const list = $("postureList");
  list.textContent = "";
  for (const f of e.findings) {
    add(list, add(el("div", "finding"), pill(f.severity, `sev-${f.severity}`), el("span", "mono", f.kind),
                  el("span", null, f.detail)));
  }
  if (e.needs_review.length) {
    add(list, add(el("div", "finding"), pill("review", "sev-low"),
                  el("span", null, `classified read-only from the name alone: ${e.needs_review.join(", ")}`)));
  }
}

// -- defense --------------------------------------------------------------------------------------

function defenseCard(title, tagText, tagCls, note, box = $("defense")) {
  clearPlaceholder(box);
  const card = el("div", "card");
  const head = add(el("div", "card-title"), el("span", null, title));
  if (tagText) head.appendChild(pill(tagText, tagCls));
  add(card, head);
  if (note) card.appendChild(el("div", "card-note", note));
  box.appendChild(card);
  box.scrollTop = box.scrollHeight;
  return card;
}

function renderRuntimeGuards(e) {
  const escalated = e.escalation > 0;
  const card = defenseCard(escalated ? `Escalated defense — level ${e.escalation}` : "Runtime guards attached",
                           "no file changed", escalated ? "risk-delete" : "risk-external",
                           escalated ? `The previous defense still let a replay through, so the defender tightened: ${e.escalation_note}.`
                                     : "Attached to the agent through its Guard port. The agent's source files are untouched.");
  const scopes = e.scopes || [];
  const seen = new Set();
  for (const patch of e.patches) {
    if (seen.has(patch.id)) continue;  // one row per patch; its scopes below list every place it applies
    seen.add(patch.id);
    const covers = [...new Set(scopes.filter((s) => s.id === patch.id).map((s) => `${s.agent}→${s.tool}`))];
    const text = `${patch.summary}${covers.length ? ` — scope: ${covers.join(", ")}` : " — whole target"}`;
    add(card, add(el("div", "guard"), el("span", "guard-id", patch.id), el("span", null, text),
                  el("span", "faint mono", `code ${patch.hash}`)));
  }
  if (!e.patches.length) card.appendChild(el("div", "card-note", "No runtime guard applies to these findings."));
  for (const gap of e.source_gaps || []) add(card, el("div", "card-note", `Unresolved: ${gap}`));
  for (const note of e.advisories || []) add(card, el("div", "card-note", `Advisory (does not block): ${note}`));
}

function fmtDuration(seconds) {
  const s = Math.round(seconds);
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} m ${String(s % 60).padStart(2, "0")} s`;
}

function renderPromptFindings(e) {
  const card = defenseCard("Prompt rules (inspection)", `${e.findings.length} finding(s)`, e.findings.length ? "risk-write" : "risk-read",
                           "Pattern rules on each agent's own prompt: they predict a weakness, an attack is what proves one.");
  for (const f of e.findings) {
    add(card, add(el("div", "guard"), pill(f.severity, `sev-${f.severity}`), el("span", "mono", `${f.agent} · ${f.kind}`),
                  el("span", "muted", f.detail)));
  }
  for (const gap of e.gaps || []) add(card, el("div", "card-note", `Not covered: ${gap}`));
}

function renderStaticScan(e) {
  const card = defenseCard("Static analysis of the agent's source", `${e.findings.length} finding(s)`,
                           e.findings.length || (e.gaps || []).length ? "risk-write" : "risk-read");
  for (const f of e.findings) {
    add(card, add(el("div", "guard"), el("span", "guard-id", f.kind), el("span", "mono", `${normPath(f.file)}:${f.line}`),
                  el("span", "muted", f.blocking === false ? `${f.severity} · advisory` : f.severity)));
  }
  for (const gap of e.gaps || []) add(card, el("div", "card-note", `Not covered: ${gap}`));
}

const fixRows = {};

function renderFixAttempt(e) {
  const key = `${e.path}:${e.line}`;
  const card = defenseCard(`Fixing ${e.kind} at ${key}`, "drafting + verifying", "risk-external");
  fixRows[key] = card;
}

function settleFix(e) {
  const key = `${e.path}:${e.line}`;
  if (fixRows[key]) fixRows[key].remove();
  return key;
}

function renderSourcePatch(e) {
  settleFix(e);
  fileCard(e, $("defense"), true);       // open on the live timeline: the edit is shown before the re-attack
  fileCard(e, $("filesList"), false);    // one click to open on its own page
  $("filesEmpty").classList.add("hidden");
  const count = $("filesCount");
  count.textContent = String(Number(count.textContent || 0) + 1);
  count.classList.remove("hidden");
  refreshModified();
}

function fileCard(e, box, open) {
  const card = defenseCard(`File modified: ${e.path}`, "real edit on disk", "risk-delete",
                           `${e.kind} at line ${e.line} · ${e.approval}. Verified by: ${e.verified_by.join(" + ")}. `
                           + `sha256 ${e.sha256.slice(0, 16)}…`, box);
  const lines = e.content.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  const toggle = el("button", "file-toggle", "");
  const body = el("div", open ? "file-body" : "file-body hidden");
  const label = () => `${body.classList.contains("hidden") ? "▸ Show" : "▾ Hide"} the full file (${lines.length} lines) with the change in place`;
  toggle.textContent = label();
  toggle.setAttribute("aria-expanded", String(open));
  add(card, toggle, body);
  if (e.explanation) body.appendChild(el("div", "card-note", e.explanation));
  const viewer = el("div", "file-view");
  const start = e.line - 1;  // the first replaced line, 0-based, in the file as written
  let firstChange = null;
  const row = (num, sign, text, cls) => {
    const line = add(el("div", `file-line ${cls}`), el("span", "file-num", num), el("span", "file-sign", sign),
                     el("span", "file-code", text.length ? text : " "));
    viewer.appendChild(line);
    return line;
  };
  lines.forEach((text, i) => {
    if (i === start) {
      for (const removed of e.before_lines) {
        const r = row("", "−", removed, "rm");
        firstChange = firstChange || r;
      }
    }
    const added = i >= start && i < start + e.after_lines.length;
    row(String(i + 1), added ? "+" : "", text, added ? "add" : "");
  });
  body.appendChild(viewer);
  const scrollToChange = () => { if (firstChange) viewer.scrollTop = Math.max(0, firstChange.offsetTop - 120); };
  requestAnimationFrame(scrollToChange);
  viewer.scrollToChange = scrollToChange;  // a hidden page has no layout yet; re-run when it is shown
  toggle.addEventListener("click", () => {
    const opening = body.classList.toggle("hidden") === false;
    toggle.textContent = label();
    toggle.setAttribute("aria-expanded", String(opening));
    if (opening) requestAnimationFrame(scrollToChange);
  });
}

function renderSourceSkipped(e) {
  const key = settleFix(e);
  defenseCard(`Not modified: ${key}`, "no file changed", "risk-read", `${e.kind}: ${e.reason}`);
  add($("skippedList"), add(el("div", "finding"), pill("not modified", "sev-low"),
                            el("span", "mono", key), el("span", null, `${e.kind}: ${e.reason}`)));
}

function renderReloaded(e) {
  defenseCard("Agent reloaded from the edited files", "re-attacking edited code", "risk-read",
              `Re-imported from disk: ${e.files.join(", ")}. Every replay below runs the edited code.`);
}

// -- verdict --------------------------------------------------------------------------------------

function renderVerdict(e, sealed) {
  $("verdictPanel").classList.remove("hidden");
  const head = $("verdictHead");
  head.textContent = "";
  if (e.mode === "static") {  // inspection proves nothing either way: never a ship / no-ship badge
    add(head, el("span", "verdict-badge warn", "Static scan · not a release verdict"));
  } else {
    add(head, el("span", `verdict-badge ${e.safe_to_ship ? "ok" : "bad"}`, e.safe_to_ship ? "Safe to ship" : "Not safe to ship"));
  }
  if (e.seconds) head.appendChild(el("span", "verdict-time", `${e.mode || "full"} run · assessed in ${fmtDuration(e.seconds)}`));
  if (e.residual !== null && e.residual !== undefined) {
    head.appendChild(el("span", "muted mono", `worst replay residual ≤${Math.round(e.residual * 100)}% at 95% confidence`));
  }
  const gate = $("gateList");
  gate.textContent = "";
  // Everything that blocks: the release gate's own checks, and anything configured that could not be checked.
  const blocking = [...new Set([...(e.gate || []), ...((sealed && sealed.coverage_gaps) || [])])];
  for (const reason of blocking) gate.appendChild(el("div", "gate-item", reason));
  if (!blocking.length) {
    gate.appendChild(e.safe_to_ship ? el("div", "gate-item pass", "every release-gate check passed")
      : el("div", "gate-item", "not safe to ship, but this saved run did not record why (it predates the reasons being kept) — re-run to see them"));
  }
  if (sealed && sealed.not_tested) {
    const scope = add(el("div", "card-note"), el("strong", null, "Not tested in this run (the verdict covers only what ran): "));
    scope.appendChild(document.createTextNode(sealed.not_tested));
    gate.appendChild(scope);
  }
  if (!sealed) return;
  const card = $("scorecard");
  card.textContent = "";
  add(card, stat("Audit chain", sealed.chain_ok ? "verifies" : "BROKEN"), stat("Findings", sealed.findings),
      stat("Compliance clauses", (sealed.coverage || []).length), stat("Merkle root", (sealed.merkle_root || "").slice(0, 12)));
  const expl = $("explanations");
  expl.textContent = "";
  for (const x of sealed.explanations || []) {
    const row = el("div", "finding");
    if (x.verified) add(row, pill("explained", "risk-read"), el("span", null, x.text));
    else add(row, pill("unverified", "sev-medium"), el("span", null, `explanation withheld: ${(x.issues || []).join("; ")}`));
    expl.appendChild(row);
  }
}
