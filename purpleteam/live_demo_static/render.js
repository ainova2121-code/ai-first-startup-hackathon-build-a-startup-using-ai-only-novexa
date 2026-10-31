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
  window.TOPOLOGY = { agents: e.agents || [], dangerous: new Set(e.dangerous_tools || []) };  // for the per-attack tree
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
  const sourceChanges = e.source_changes || [];
  const card = defenseCard(escalated ? `Escalated defense — level ${e.escalation}` : "Runtime guards attached",
                           "no file changed", escalated ? "risk-delete" : "risk-external",
                           escalated ? `The previous defense still let a replay through, so the defender tightened: ${e.escalation_note}.`
                                     : "Attached to the agent through its Guard port before reverification. No target source file was changed.");
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
  // If the assessment also made a verified source edit, keep that real file diff in view as
  // reverification starts. Runtime-only guards have no target-file diff to display.
  const patchedFile = sourceChanges.map((change) => liveSourcePatchCards.get(change.path)).find((node) => node?.isConnected);
  if (patchedFile) requestAnimationFrame(() => revealDefenseCard(patchedFile));
}

function renderSourceBaseline(e) {
  const restored = e.restored || [], adopted = e.adopted || [];
  const title = adopted.length ? "Your edited target source is the baseline"
              : restored.length ? "Original target source restored" : "Target source reloaded";
  const detail = adopted.length
      ? "Files you hand-edited were adopted as this run's baseline — discovery and the attack phase use exactly those edited contents."
      : restored.length
      ? "Previous platform-applied source edits were restored before this run. The initial attack starts against those original file contents."
      : "No previous platform source edits needed restoration. The current target source was reloaded from disk before this run.";
  const card = defenseCard(title, adopted.length ? "edits adopted" : restored.length ? "baseline reset" : "baseline ready",
                           "risk-read", detail);
  for (const path of restored) add(card, add(el("div", "guard"), el("span", "mono", path), el("span", "faint", "restored")));
  for (const path of adopted) add(card, add(el("div", "guard"), el("span", "mono", path), el("span", "faint", "your edit · adopted")));
}

const liveSourcePatchCards = new Map();
function revealDefenseCard(card) {
  const box = $("defense");
  const top = card.getBoundingClientRect().top - box.getBoundingClientRect().top + box.scrollTop;
  box.scrollTo({ top: Math.max(0, top - 8), behavior: "smooth" });
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

function renderFindingDetected(e) {
  const where = e.tool ? `${e.agent || "agent"} → ${e.tool}` : (e.agent || "the agent");
  defenseCard(`Breach proven at ${where}`, "defender patching", "risk-delete",
              `${e.id}: the defender chose ${(e.patch_ids || []).join(", ") || "no runtime guard"} and is writing the `
              + "code fix now. Both load after the last attack, so every attack still meets the original agent.");
}

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

// Every edit to a file, so the file is shown once with all of them highlighted. Edits within a file arrive bottom-up,
// so an edit that changes the line count moves the earlier-recorded edits below it, never above.
const patchedFiles = new Map();  // path -> {edits: [{start, before, after, meta}], content, sha256, live, list}

function renderSourcePatch(e) {
  settleFix(e);
  let file = patchedFiles.get(e.path);
  if (!file || !file.list.isConnected) {  // a new run (or a replayed one) starts every file afresh
    file = { edits: [], live: null, list: null };
    patchedFiles.set(e.path, file);
  }
  const start = e.line - 1;  // the first replaced line, 0-based, in the file as written by this edit
  const shift = e.after_lines.length - e.before_lines.length;
  for (const edit of file.edits) if (edit.start > start) edit.start += shift;
  file.edits.push({ start, before: e.before_lines, after: e.after_lines, explanation: e.explanation,
                    meta: `${e.kind} at line ${e.line} · ${e.approval}. Verified by: ${e.verified_by.join(" + ")}.` });
  file.edits.sort((a, b) => a.start - b.start);
  Object.assign(file, { content: e.content, sha256: e.sha256 });
  file.live = place(fileCard(e.path, file, $("defense"), true), file.live);  // the real edit, before the re-attack
  file.list = place(fileCard(e.path, file, $("filesList"), false), file.list);  // one click to open on its own page
  liveSourcePatchCards.set(e.path, file.live);
  $("filesEmpty").classList.add("hidden");
  const count = $("filesCount");
  count.textContent = String([...patchedFiles.values()].filter((f) => f.list.isConnected).length);  // files, not edits
  count.classList.remove("hidden");
  refreshModified();
}

function place(card, previous) {  // a rebuilt card takes its earlier card's place, so the feed keeps its order
  if (previous?.isConnected) previous.replaceWith(card);
  return card;
}

function fileCard(path, file, box, open) {
  const edits = file.edits;
  const card = defenseCard(`Source patch before reverification: ${path}`, "EDIT Successfully applied", "risk-delete",
                           `${edits.length} edit${edits.length === 1 ? "" : "s"}: ${edits.map((x) => x.meta).join(" · ")} `
                           + `sha256 ${file.sha256.slice(0, 16)}…`, box);
  const lines = file.content.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  const toggle = el("button", "file-toggle", "");
  const body = el("div", open ? "file-body" : "file-body hidden");
  const label = () => `${body.classList.contains("hidden") ? "▸ Show" : "▾ Hide"} the full file (${lines.length} lines) `
    + `with ${edits.length === 1 ? "the change" : `all ${edits.length} changes`} in place`;
  toggle.textContent = label();
  toggle.setAttribute("aria-expanded", String(open));
  add(card, toggle, body);
  for (const edit of edits) if (edit.explanation) body.appendChild(el("div", "card-note", edit.explanation));
  const viewer = el("div", "file-view");
  let firstChange = null;
  const row = (num, sign, text, cls) => {
    const line = add(el("div", `file-line ${cls}`), el("span", "file-num", num), el("span", "file-sign", sign),
                     el("span", "file-code", text.length ? text : " "));
    viewer.appendChild(line);
    return line;
  };
  lines.forEach((text, i) => {
    for (const edit of edits.filter((x) => x.start === i)) {
      for (const removed of edit.before) {
        const r = row("", "−", removed, "rm");
        firstChange = firstChange || r;
      }
    }
    const added = edits.some((x) => i >= x.start && i < x.start + x.after.length);
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
  return card;
}

function renderSourceSkipped(e) {
  const key = settleFix(e);
  defenseCard(`Not modified: ${key}`, "no file changed", "risk-read", `${e.kind}: ${e.reason}`);
  add($("skippedList"), add(el("div", "finding"), pill("not modified", "sev-low"),
                            el("span", "mono", key), el("span", null, `${e.kind}: ${e.reason}`)));
}

function renderReloaded(e) {
  const patchedFile = (e.files || []).map((path) => liveSourcePatchCards.get(path)).find((node) => node?.isConnected);
  const note = `Re-imported from disk before reverification: ${(e.files || []).join(", ")}. The replay runs the edited code.`;
  if (patchedFile) patchedFile.appendChild(el("div", "card-note", note));
  else defenseCard("Agent reloaded from the edited files", "re-attacking edited code", "risk-read", note);
}

// -- verdict --------------------------------------------------------------------------------------

function renderVerdict(e, sealed) {
  $("verdictPanel").classList.remove("hidden");
  const head = $("verdictHead");
  head.textContent = "";
  if (e.status === "stopped") {
    add(head, el("span", "verdict-badge warn", "Stopped · incomplete assessment"));
  } else if (e.mode === "static") {  // inspection proves nothing either way: never a ship / no-ship badge
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
