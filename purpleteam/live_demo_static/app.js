// The app: tab routing, the run picker, the live SSE stream, and the event dispatch that drives every
// page. A past run is shown by replaying its saved events through the same renderers. render.js,
// feed.js and ledger.js hold the page renderers.
"use strict";

const STEPS = ["Discover", "Attack", "Patch", "Re-attack", "Verdict"];
let phase = -1;
let sealed = null;
let running = false;      // the server's real state, never a replayed run's
let replaying = false;    // dispatching a saved run: no timers, no button changes
let viewing = "live";     // "live" or a past run id
let liveRunId = null;
let liveEvents = [];
let shownEvents = [];      // the run on screen: its recorded events, to replay the discovery map from
let runMode = "full";      // static | full | advanced, chosen with the mode switch

function renderSteps() {
  const bar = $("stepBar");
  bar.textContent = "";
  STEPS.forEach((name, i) => {
    if (i) bar.appendChild(el("div", "step-line"));
    const state = i < phase ? "done" : i === phase ? "now" : "";
    bar.appendChild(add(el("div", `step ${state}`), el("div", "step-dot", i < phase ? "✓" : i + 1), el("span", null, name)));
  });
}

function advance(i) {
  if (i > phase) { phase = i; renderSteps(); }
}

function setRunChip(text, color) {
  const chip = $("runChip");
  chip.textContent = "";
  add(chip, el("span", "dot"), document.createTextNode(text));
  chip.style.color = color;
}

function setRunning(value) {
  if (replaying) return;
  running = value;
  $("startBtn").disabled = value;
  $("restoreBtn").disabled = value;
}

function onError(e) {
  setRunning(false);
  setRunChip("error", "var(--crimson)");
  const banner = $("errorBanner");
  banner.textContent = e.detail;
  banner.classList.remove("hidden");
}

// An event was just signed: redraw the open ledger page from the server's own verification, batched so a burst
// of signatures arrives as one smooth step rather than a flicker.
let ledgerRefresh = null;
function onSigned() {
  if (replaying || viewing !== "live" || route() !== "ledger" || ledgerRefresh) return;
  ledgerRefresh = setTimeout(() => { ledgerRefresh = null; loadSigning(liveRunId, true); loadLedger(liveRunId, true); }, 700);
}

function dispatch(e) {
  switch (e.type) {
    case "discovered": setRunning(true); setRunChip("running", "var(--steel)"); advance(0); renderDiscovery(e); break;
    case "attack_start": onAttackStart(e); break;
    case "attack_result": onAttackResult(e); break;
    case "patch_applied": advance(2); renderRuntimeGuards(e); break;
    case "static_scan": advance(2); renderStaticScan(e); break;
    case "prompt_findings": advance(1); renderPromptFindings(e); break;
    case "source_fix_attempt": advance(2); renderFixAttempt(e); break;
    case "source_patch": renderSourcePatch(e); break;
    case "source_patch_skipped": renderSourceSkipped(e); break;
    case "target_reloaded": renderReloaded(e); break;
    case "trace": discoveryTrace(e); break;
    case "found_agent": case "found_tool": discoveryFound(e); break;
    case "decision_baseline": case "decision_drift": renderDecisionEvent(e); break;
    case "signed": onSigned(); break;
    case "sealed": sealed = e; break;
    case "done":
      advance(4); setRunning(false); discoveryDone();
      setRunChip(e.safe_to_ship ? "safe to ship" : "not safe to ship", e.safe_to_ship ? "var(--sage)" : "var(--crimson)");
      renderVerdict(e, sealed); break;
    case "error": onError(e); break;
  }
}

function resetView() {
  phase = -1; sealed = null; driftEvent = null; dmReset(); resetFeed();
  for (const id of ["errorBanner", "verdictPanel", "discoverySummary"]) $(id).classList.add("hidden");
  for (const id of ["feed", "defense", "postureList", "filesList", "skippedList"]) $(id).textContent = "";
  add($("feed"), el("div", "muted", "Attacks appear here once discovery finishes."));
  add($("defense"), el("div", "muted", "Nothing patched yet."));
  $("discoveryEmpty").classList.remove("hidden");
  $("filesEmpty").classList.remove("hidden");
  $("filesCount").textContent = ""; $("filesCount").classList.add("hidden");
  $("attackSub").textContent = "every attack against the unpatched agent, grouped by type";
  setRunChip(running ? "running" : "idle", running ? "var(--steel)" : "var(--text-muted)");
  renderSteps();
}

function renderAll(events, isReplay) {
  resetView();
  shownEvents = events;
  DM.seen = route() === "discovery";  // built in front of the user, or replayed when they open the tab
  replaying = isReplay;
  events.forEach(dispatch);
  replaying = false;
}

// -- pages and runs ---------------------------------------------------------------------------------

const ROUTES = ["run", "discovery", "files", "drift", "ledger"];
const route = () => { const r = location.hash.replace("#/", ""); return ROUTES.includes(r) ? r : "run"; };
const viewedRunId = () => (viewing === "live" ? liveRunId : viewing);

function showPage() {
  const current = route();
  if (current !== "discovery") DM.autoReturn = false;  // the user went elsewhere: never pull them back
  document.querySelectorAll(".page").forEach((p) => p.classList.toggle("hidden", p.dataset.page !== current));
  document.querySelectorAll(".tabs a").forEach((a) => a.classList.toggle("active", a.dataset.route === current));
  if (current === "ledger") { loadLedger(viewedRunId()); loadSigning(viewedRunId()); }
  if (current === "discovery" && !DM.seen) { DM.seen = true; dmReplay(viewing === "live" ? liveEvents : shownEvents); }
  if (current === "drift") loadDrift(viewedRunId());
  if (current === "files") document.querySelectorAll("#filesList .file-view").forEach((v) => v.scrollToChange && v.scrollToChange());
}

async function refreshRuns() {
  const { runs, current } = await fetch("/runs").then((r) => r.json());
  liveRunId = liveRunId || current;
  const picker = $("runPicker");
  picker.textContent = "";
  picker.appendChild(el("option", null, "Current run"));
  picker.lastChild.value = "live";
  for (const run of runs) {
    const when = run.started_at ? new Date(run.started_at * 1000).toLocaleString() : run.id;
    const verdict = run.status === "done" ? (run.safe_to_ship ? "safe to ship" : "not safe") : run.status;
    const option = el("option", null, `${when} · ${run.target || "?"} · ${run.mode || "full"} · ${run.mode === "static" && run.status === "done" ? "static scan" : verdict}`);
    option.value = run.id;
    picker.appendChild(option);
  }
  picker.value = viewing;
}

$("runPicker").addEventListener("change", async (ev) => {
  viewing = ev.target.value;
  const banner = $("historyBanner");
  if (viewing === "live") {
    banner.classList.add("hidden");
    renderAll(liveEvents, false);
  } else {
    const { events } = await fetch(`/runs/${encodeURIComponent(viewing)}/events`).then((r) => r.json());
    renderAll(events, true);
    banner.textContent = `Viewing a saved run (${viewing}), rebuilt from its recorded evidence. Pick "Current run" to follow the live one.`;
    banner.classList.remove("hidden");
  }
  showPage();
});

// -- restore and start ------------------------------------------------------------------------------

async function refreshModified() {
  try {
    const { modified } = await fetch("/source-status").then((r) => r.json());
    const badge = $("modifiedCount");
    badge.textContent = modified.length;
    badge.classList.toggle("hidden", !modified.length);
    const button = $("restoreBtn");
    button.title = modified.length ? `Will restore: ${modified.join(", ")}` : "No file is currently modified by the platform";
    button.setAttribute("aria-label", `Restore original files${modified.length ? ` (${modified.length} modified)` : ""}`);
  } catch { /* status is a convenience; the restore itself reports the truth */ }
}

$("restoreBtn").addEventListener("click", async () => {
  if (running || !confirm("Restore every file the platform edited to its original bytes?")) return;
  const response = await fetch("/restore", { method: "POST" });
  const body = await response.json();
  const banner = $("infoBanner");
  banner.classList.remove("hidden");
  if (!response.ok) { banner.textContent = body.detail || "restore refused"; return; }
  const lines = body.results.map((r) => `${r.path}: ${r.status}${r.reason ? ` (${r.reason})` : ""}`);
  banner.textContent = lines.length ? `Restored — ${lines.join(" · ")}` : "Nothing to restore: no file is modified by the platform.";
  refreshModified();
});

$("startBtn").addEventListener("click", async () => {
  setRunning(true);
  viewing = "live";
  $("runPicker").value = "live";
  $("historyBanner").classList.add("hidden");
  $("infoBanner").classList.add("hidden");
  // Wherever the run is started from: watch discovery build, then come back to the live run for the attacks
  // (discovery.js returns once the map is complete, unless the reader has gone to another tab meanwhile).
  resetView();
  DM.seen = true;  // the map is about to build in front of the user: nothing to replay
  DM.autoReturn = true;
  location.hash = "#/discovery";
  const response = await fetch(`/run?mode=${encodeURIComponent(runMode)}`, { method: "POST" });
  if (!response.ok) onError({ detail: (await response.json()).detail || "could not start the run" });
});

const stream = new EventSource("/stream");
stream.onmessage = (msg) => {
  const e = JSON.parse(msg.data);
  if (e.type === "run_started") {
    liveEvents = [];
    liveRunId = e.run_id;
    DM.runStart = Date.now();  // the map's elapsed time counts from the run's start, not from a page re-render
    DM.seen = route() === "discovery";
    if (viewing === "live") resetView();
  }
  liveEvents.push(e);
  if (viewing === "live") dispatch(e);
  if (e.type === "source_patch" || e.type === "done") refreshModified();
  if (e.type === "done" || e.type === "error") {
    refreshRuns();
    if (route() === "ledger" && viewing === "live") { loadLedger(liveRunId); loadSigning(liveRunId); }
    if (route() === "drift" && viewing === "live") loadDrift(liveRunId);
  }
};

window.addEventListener("hashchange", showPage);
document.querySelectorAll(".mode-switch button").forEach((b) => b.addEventListener("click", () => {
  runMode = b.dataset.mode;
  document.querySelectorAll(".mode-switch button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
  $("modeNote").textContent = b.title;
}));
$("dmReplayBtn").addEventListener("click", () => dmReplay(viewing === "live" ? liveEvents : shownEvents));
dmReset();
renderSteps();
refreshModified();
refreshRuns().then(showPage);
