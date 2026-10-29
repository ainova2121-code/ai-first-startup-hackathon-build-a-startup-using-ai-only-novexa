// The attack feed: one collapsible section per kind of attack, each row the real payload, the agent's real reply
// and the proof of any breach. A section opens by itself while one of its attacks is running and folds once they
// have all finished, unless the reader opened or closed it themselves; its header keeps the tally either way.
"use strict";

let rows = {};      // attack id -> its row
let rowGroup = {};  // attack id -> the section it sits in
let groups = {};    // section title -> its state
const timers = {};

const KINDS = {
  claim: "Business-claim injection",
  "claim in a document": "Indirect injection · hidden in a document",
  "claim in a form field": "Indirect injection · in a form field",
  "prompt-injection": "Prompt injection",
  "social-engineering": "Social engineering",
  "trigger-condition": "Targeted · crafted from each agent's own prompt",
  tap: "Adaptive search · TAP",
  pair: "Adaptive search · PAIR",
  reverify: "Re-attack · the same payloads against the patched agent",
};

// PyRIT names its jailbreak templates (DAN, AIM...), so each family gets its own section.
function attackKind(technique, id) {
  if (technique === "jailbreak") return /dan/i.test(id) ? "Jailbreak · DAN" : `Jailbreak · ${id.split(/[:_]/)[0].toUpperCase()}`;
  return KINDS[technique] || (technique ? technique[0].toUpperCase() + technique.slice(1) : "Other attacks");
}

function resetFeed() {
  for (const id in timers) clearInterval(timers[id]);
  rows = {}; rowGroup = {}; groups = {};
}

function setOpen(group, open) {
  group.box.classList.toggle("open", open);
  group.head.setAttribute("aria-expanded", String(open));
}

function showGroup(group) {
  const settled = group.total - group.running;
  group.stats.textContent = `${group.total} attack${group.total === 1 ? "" : "s"}`
    + (settled ? ` · ${group.breached} breached · ${group.held} held` : "")
    + (group.persuaded ? ` (${group.persuaded} only because a control stopped the agent)` : "");
  const state = group.running ? "running" : group.breached ? "breached" : settled ? "held" : "";
  group.state.className = `agroup-state ${state}`;
  group.state.textContent = { running: "● running", breached: "BREACHED", held: "HELD", "": "" }[state];
}

function attackGroup(e) {
  const title = attackKind(e.technique, e.id);
  if (groups[title]) return groups[title];
  const stats = el("span", "agroup-stats"), state = el("span", "agroup-state");
  const head = add(el("button", "agroup-head"), el("span", "agroup-chevron", "▸"), el("span", "agroup-title", title), stats, state);
  head.type = "button";
  const body = el("div", "agroup-body");
  const group = { box: add(el("section", "agroup"), head, body), head, body, stats, state,
                  total: 0, running: 0, breached: 0, held: 0, persuaded: 0, pinned: false };
  head.addEventListener("click", () => { group.pinned = true; setOpen(group, !group.box.classList.contains("open")); });
  setOpen(group, false);
  const feed = $("feed");
  clearPlaceholder(feed);
  feed.appendChild(group.box);
  return (groups[title] = group);
}

// Held, yet the agent tried the attacker's call and a control stopped it: fooled, not resisting.
const persuaded = (e) => e.outcome === "held" && e.persuaded > 0;

function fmtOutcome(e) {
  if (e.outcome === "breached") return e.technique === "reverify" ? "STILL BREACHES" : "BREACHED";
  if (persuaded(e)) return `HELD · AGENT PERSUADED ${e.persuaded}/${e.trials || e.conclusive}`;
  if (e.outcome === "held") return `held ${e.conclusive}/${e.trials || e.conclusive} · ≤${Math.round(e.upper_bound * 100)}%`;
  return "inconclusive";
}

function onAttackStart(e) {
  const reverify = e.technique === "reverify";
  advance(reverify ? 3 : 1);
  $("attackSub").textContent = reverify ? "re-attacking the patched agent with the same payloads" : "attacks running · grouped by type";
  const group = attackGroup(e);
  const head = add(el("div", "arow-head"), el("div", "arow-dot"), el("span", "arow-id", e.id));
  if (reverify) head.appendChild(el("span", "arow-tag", e.replays ? `↻ re-attack of ${e.replays}` : "↻ same payload"));
  const waiting = el("span", "arow-result faint", replaying ? "no result recorded" : "waiting for the agent… 0.0s");
  head.appendChild(waiting);
  const row = add(el("div", reverify ? "arow reverify" : "arow"), head, add(el("div", "arow-body"), el("pre", "payload", e.payload)));
  group.body.appendChild(row);
  rows[e.id] = row; rowGroup[e.id] = group;
  group.total += 1; group.running += 1;
  showGroup(group);
  clearInterval(timers[e.id]);
  if (replaying) return;
  if (!group.pinned) setOpen(group, true);  // the section with something running is the one shown
  row.scrollIntoView({ block: "nearest", behavior: "smooth" });
  const started = Date.now();
  timers[e.id] = setInterval(() => { waiting.textContent = `waiting for the agent… ${((Date.now() - started) / 1000).toFixed(1)}s`; }, 200);
}

function onAttackResult(e) {
  const row = rows[e.id], group = rowGroup[e.id];
  if (!row) return;
  clearInterval(timers[e.id]);
  row.querySelector(".arow-dot").className = `arow-dot ${e.outcome}`;
  const result = row.querySelector(".arow-result");
  result.className = "arow-result";
  result.style.color = e.outcome === "breached" ? "var(--crimson)" : persuaded(e) ? "var(--amber)"
    : e.outcome === "held" ? "var(--sage)" : "var(--text-faint)";
  if (persuaded(e)) row.querySelector(".arow-dot").classList.add("persuaded");
  result.textContent = `${fmtOutcome(e)} · ${(e.seconds || 0).toFixed(1)}s`;
  const body = row.querySelector(".arow-body");
  if (e.reply) add(body, el("div", "label", "The agent's real reply:"), el("pre", "reply", e.reply));
  if (e.breached) body.appendChild(el("div", "proof", `Breach proven — ${e.detail}`));
  else if (persuaded(e)) body.appendChild(el("div", "proof attempt", `Attempt detected — ${e.detail}`));
  else if (e.technique === "reverify") body.appendChild(el("div", "label", e.detail));
  group.running = Math.max(0, group.running - 1);
  if (e.breached) group.breached += 1; else if (e.outcome === "held") group.held += 1;
  if (persuaded(e)) group.persuaded += 1;
  showGroup(group);
  if (!replaying && !group.running && !group.pinned) {  // finished: fold it a moment later, unless it starts again
    setTimeout(() => { if (!group.running && !group.pinned) setOpen(group, false); }, 1500);
  }
}
