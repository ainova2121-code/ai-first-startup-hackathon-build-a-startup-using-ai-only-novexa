// The app: tab routing, the run picker, the live SSE stream, and the event dispatch that drives every
// page. A past run is shown by replaying its saved events through the same renderers. render.js,
// feed.js and ledger.js hold the page renderers.
"use strict";

const STEPS = ["Discover", "Attack", "Patch", "Re-attack", "Verdict"];
const STATIC_STEPS = ["Discover", "Prompt rules", "Source scan", "Report"];  // a quick scan runs no attacks
let stepNames = STEPS;
let phase = -1;
let sealed = null;
let running = false;      // the server's real state, never a replayed run's
let runState = "idle";     // running | pausing | paused | stopping | idle
let replaying = false;    // dispatching a saved run: no timers, no button changes
let viewing = "live";     // "live" or a past run id
let liveRunId = null;
let liveEvents = [];
let liveRunDiscovered = false;
let shownEvents = [];      // the run on screen: its recorded events, to replay the discovery map from

function renderSteps() {
  const bar = $("stepBar");
  bar.textContent = "";
  stepNames.forEach((name, i) => {
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

function setLiveRunTabStatus(status) {
  const mark = $("liveRunStatus");
  const icon = { paused: "Ⅱ", complete: "✓", stopped: "!", failed: "!" }[status] || "";
  const label = { running: "Run in progress", paused: "Run paused", stopping: "Run stopping",
    complete: "Run complete", stopped: "Run stopped before completion", failed: "Run failed" }[status] || "";
  mark.className = "run-tab-status " + status;
  mark.textContent = icon;
  mark.classList.toggle("hidden", !label);
  mark.setAttribute("aria-hidden", String(!label));
  mark.title = label;
  $("liveRunTab").setAttribute("aria-label", label ? "Live run · " + label.toLowerCase() : "Live run");
}

function updateLiveRunTabFromEvent(event) {
  if (event.type === "run_started") {
    liveRunDiscovered = false;
    setLiveRunTabStatus("idle");
  } else if (event.type === "discovered") {
    liveRunDiscovered = true;
    setLiveRunTabStatus("running");
  } else if (event.type === "run_resumed") {
    setLiveRunTabStatus(liveRunDiscovered ? "running" : "idle");
  } else if (event.type === "run_paused") {
    setLiveRunTabStatus(liveRunDiscovered ? "paused" : "idle");
  } else if (event.type === "run_stopping") {
    setLiveRunTabStatus(liveRunDiscovered ? "stopping" : "idle");
  } else if (event.type === "done") setLiveRunTabStatus(event.status === "done" ? "complete" : "stopped");
  else if (event.type === "error") setLiveRunTabStatus("failed");
}

function setRunning(value) {
  if (replaying) return;
  running = value;
  if (!value) runState = "idle";
  else if (runState === "idle") runState = "running";
  $("startBtn").disabled = value;
  $("restoreBtn").disabled = value;
  $("logoutBtn").disabled = value;
  updateRunControls();
}

function updateRunControls() {
  const active = running && viewing === "live" && !replaying;
  $("pauseBtn").disabled = !active || runState !== "running";
  $("resumeBtn").disabled = !active || runState !== "paused";
  $("stopBtn").disabled = !active || !["running", "pausing", "paused"].includes(runState);
}

async function sendRunControl(action) {
  try {
    const response = await fetch(`/${action}`, { method: "POST" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || `could not ${action} the run`);
  } catch (error) {
    const banner = $("infoBanner");
    banner.textContent = error.message || `could not ${action} the run`;
    banner.classList.remove("hidden");
  }
}

function onError(e) {
  setRunning(false);
  if (!replaying) setLiveRunTabStatus("failed");
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
    case "run_started":
      stepNames = e.mode === "static" ? STATIC_STEPS : STEPS;  // a quick scan has its own, attack-free steps
      phase = -1; renderSteps();
      if (!replaying) { runState = "running"; setRunning(true); setRunChip("running", "var(--steel)"); }
      break;
    case "run_pausing":
      if (!replaying) { runState = "pausing"; setRunChip("pausing…", "var(--amber)"); updateRunControls(); }
      break;
    case "run_paused":
      if (!replaying) { runState = "paused"; setRunChip("paused", "var(--amber)"); updateRunControls(); }
      break;
    case "run_resumed":
      if (!replaying) { runState = "running"; setRunChip("running", "var(--steel)"); updateRunControls(); }
      break;
    case "run_stopping":
      if (!replaying) { runState = "stopping"; setRunChip("stopping…", "var(--amber)"); updateRunControls(); }
      break;
    case "discovered":
      setRunning(true);
      if (!replaying && runState === "running") setRunChip("running", "var(--steel)");
      advance(0); renderDiscovery(e); break;
    case "attack_start": onAttackStart(e); break;
    case "attack_result": onAttackResult(e); break;
    case "patch_applied": advance(2); renderRuntimeGuards(e); break;
    case "source_baseline": renderSourceBaseline(e); break;
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
    case "sealed":
      sealed = e;
      if (!replaying && running) { runState = "finishing"; updateRunControls(); }
      break;
    case "done":
      stepNames = e.mode === "static" ? STATIC_STEPS : STEPS;
      advance(4); setRunning(false); discoveryDone();
      if (e.status === "stopped") {
        setRunChip("stopped · incomplete", "var(--amber)");
        const banner = $("infoBanner");
        banner.textContent = "Run stopped. Partial evidence was retained; this run has no release verdict. Start a new run to complete the assessment.";
        banner.classList.remove("hidden");
      } else if (e.mode === "static") {  // a quick scan makes no ship verdict and runs no attacks
        setRunChip("scan complete", "var(--steel)");
        $("feed").textContent = "";
        add($("feed"), el("div", "muted", "Quick scan — no attacks were run. This is inspection only. "
          + "Uncheck Quick scan and pick Custom dataset, Full assessment or a PyRIT mode to attack."));
      } else {
        setRunChip(e.safe_to_ship ? "safe to ship" : "not safe to ship", e.safe_to_ship ? "var(--sage)" : "var(--crimson)");
      }
      renderVerdict(e, sealed); break;
    case "error": onError(e); break;
  }
}

function resetView() {
  phase = -1; stepNames = STEPS; sealed = null; driftEvent = null; dmReset(); resetFeed();
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
  updateTabGates();
}

// -- pages and runs ---------------------------------------------------------------------------------

const ROUTES = ["run", "discovery", "database", "files", "drift", "ledger"];
const route = () => { const r = location.hash.replace("#/", ""); return ROUTES.includes(r) ? r : "run"; };
const viewedRunId = () => (viewing === "live" ? liveRunId : viewing);

function showPage() {
  const current = route();
  if (current !== "discovery") DM.autoReturn = false;  // the user went elsewhere: never pull them back
  document.querySelectorAll(".page").forEach((p) => p.classList.toggle("hidden", p.dataset.page !== current));
  document.querySelectorAll(".tabs a").forEach((a) => a.classList.toggle("active", a.dataset.route === current));
  if (current === "ledger") { loadLedger(viewedRunId()); loadSigning(viewedRunId()); }
  // Replay (re-animate) only into an empty canvas; once the map is drawn, revisiting shows it stable, not from scratch.
  if (current === "discovery" && !DM.seen && !DM.agents.length) { DM.seen = true; dmReplay(viewing === "live" ? liveEvents : shownEvents); }
  else if (current === "discovery") DM.seen = true;
  // A resize can happen while this page is hidden, when the map has no measurable width. Refit after it is visible,
  // without replaying the discovery animation or changing the evidence already drawn.
  if (current === "discovery") requestAnimationFrame(() => {
    if (route() === "discovery" && DM.svg) dmLayout();
  });
  if (current === "drift") loadDrift(viewedRunId());
  if (current === "database" && window.loadDatabase) window.loadDatabase();
  if (current === "files") document.querySelectorAll("#filesList .file-view").forEach((v) => v.scrollToChange && v.scrollToChange());
  updateTabGates();
}

async function refreshRuns() {
  const { runs, current, active, control_status } = await fetch("/runs").then((r) => r.json());
  liveRunId = liveRunId || current;
  const currentRun = runs.find((run) => run.id === current);
  if (active && liveRunDiscovered) setLiveRunTabStatus(control_status === "paused" ? "paused"
    : control_status === "stopping" ? "stopping" : "running");
  else if (active) setLiveRunTabStatus("idle");
  else if (currentRun?.status === "done") setLiveRunTabStatus("complete");
  else if (currentRun?.status === "stopped" || currentRun?.status === "interrupted") setLiveRunTabStatus("stopped");
  else if (currentRun?.status === "error") setLiveRunTabStatus("failed");
  else setLiveRunTabStatus("idle");
  if (viewing === "live") {
    running = Boolean(active);
    runState = active ? (control_status || "running") : "idle";
    updateRunControls();
  }
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
  updateRunControls();
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

$("logoutBtn").addEventListener("click", async () => {
  if (running || !confirm("Restore every patched file to its original state and log out of the demo?")) return;
  try {
    const response = await fetch("/logout", { method: "POST" });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      const banner = $("infoBanner");
      banner.classList.remove("hidden");
      banner.textContent = body.detail || "log out refused";
      return;
    }
  } catch { /* even if the request fails, send the visitor back to the start */ }
  window.location.href = "/";  // the server sends a signed-out visitor on to its login page
});

$("startBtn").addEventListener("click", async () => {
  setRunning(true);
  liveRunDiscovered = false;
  setLiveRunTabStatus("idle");
  viewing = "live";
  $("runPicker").value = "live";
  $("historyBanner").classList.add("hidden");
  $("infoBanner").classList.add("hidden");
  // Wherever the run is started from: watch discovery build, then come back to the live run for the attacks
  // (discovery.js returns once the map is lit up by real traffic, unless the reader has gone to another tab).
  resetView();
  DM.seen = true;  // the map is about to build in front of the user: nothing to replay
  DM.autoReturn = true;
  location.hash = "#/discovery";
  const response = await fetch(`/run?${new URLSearchParams(runParams())}`, { method: "POST" });
  if (!response.ok) onError({ detail: (await response.json()).detail || "could not start the run" });
});

$("pauseBtn").addEventListener("click", () => sendRunControl("pause"));
$("resumeBtn").addEventListener("click", () => sendRunControl("resume"));
$("stopBtn").addEventListener("click", () => sendRunControl("stop"));

// The target database becomes readable once discovery is done and keeps changing as the agents run; refresh
// the open Database page on those events, batched so a burst of traces is one update, not a flicker.
let dbRefresh = null;
function scheduleDbRefresh() {
  if (dbRefresh || !window.loadDatabase) return;
  dbRefresh = setTimeout(() => { dbRefresh = null; window.loadDatabase(); }, 600);
}

const stream = new EventSource("/stream");
stream.onmessage = (msg) => {
  const e = JSON.parse(msg.data);
  if (e.type === "run_started") {
    liveEvents = [];
    liveRunDiscovered = false;
    liveRunId = e.run_id;
    DM.runStart = Date.now();  // the map's elapsed time counts from the run's start, not from a page re-render
    DM.seen = route() === "discovery";
    if (viewing === "live") resetView();
  }
  liveEvents.push(e);
  updateLiveRunTabFromEvent(e);
  if (viewing === "live") { dispatch(e); updateTabGates(); }
  if (["discovered", "trace", "done"].includes(e.type) && route() === "database" && viewing === "live") scheduleDbRefresh();
  if (e.type === "source_patch" || e.type === "done") refreshModified();
  if (e.type === "done" || e.type === "error") {
    refreshRuns();
    if (route() === "ledger" && viewing === "live") { loadLedger(liveRunId); loadSigning(liveRunId); }
    if (route() === "drift" && viewing === "live") loadDrift(liveRunId);
  }
};

window.addEventListener("hashchange", showPage);

// -- run controls: mode, custom suite, PyRIT strategy, attacker model, quick scan -------------------
const MODE_NOTES = {
  quick: "Seconds · inspection only: discovery, posture, source scan, prompt rules, catalog fixes. No attacks, no verdict.",
  custom: "Minutes · the model-free custom dataset (claims, jailbreak/injection corpus, obfuscation) against the unpatched agent, then patch, re-attack, verdict.",
  pyrit: "Model-driven · PyRIT searches for a working phrasing with the chosen attacker model. Needs an attacker key.",
  full: "Longest · the custom dataset PLUS context-aware (per-agent) and adaptive attacks with the chosen attacker model.",
};

function runParams() {  // the exact /run query the chosen controls mean
  if ($("quickScan").checked) return { mode: "static", attack_type: "all", attacker_model: "" };
  const suite = $("runSuite").value;
  if (suite === "pyrit") return { mode: "full", attack_type: $("pyritStrategy").value, attacker_model: $("attackerModel").value };
  if (suite === "full") return { mode: "full", attack_type: "full", attacker_model: $("attackerModel").value };
  return { mode: "full", attack_type: $("customSuite").value, attacker_model: "" };  // custom dataset
}

function syncControls() {  // show only the inputs the chosen mode uses, and describe it
  const quick = $("quickScan").checked, suite = $("runSuite").value;
  $("runSuite").disabled = quick;
  $("customSuite").classList.toggle("hidden", quick || suite !== "custom");
  $("datasetJsonLink").classList.toggle("hidden", quick || suite !== "custom");
  $("pyritStrategy").classList.toggle("hidden", quick || suite !== "pyrit");
  $("attackerModel").classList.toggle("hidden", quick || !(suite === "pyrit" || suite === "full"));
  $("modeNote").textContent = MODE_NOTES[quick ? "quick" : suite];
}

["runSuite", "customSuite", "pyritStrategy", "attackerModel", "quickScan"].forEach(
  (id) => $(id).addEventListener("change", syncControls));

fetch("/attack-types").then((r) => r.json()).then((config) => {
  const sel = $("attackerModel");
  sel.textContent = "";
  for (const model of config.attacker_models || []) { const o = el("option", null, model); o.value = model; sel.appendChild(o); }
  if (!config.attacker_key_present) {  // no attacker key here: the model-driven modes cannot run
    for (const value of ["pyrit", "full"]) {
      const o = $("runSuite").querySelector(`option[value="${value}"]`);
      if (o) { o.disabled = true; o.title = "Needs an attacker key (PURPLETEAM_ATTACKER_KEY / GROQ_API_KEY)."; }
    }
  }
  syncControls();
}).catch(() => syncControls());

// -- tab gating: a tab stays frozen until its page has data; never freeze the tab in view -----------
function tabGates(ev) {
  const any = (...types) => ev.some((e) => types.includes(e.type));
  return {
    run: any("discovered"), discovery: any("found_agent", "found_tool", "discovered"),
    database: any("attack_setup"),  // a target is instantiated only for an attack run, after discovery
    files: ev.some((e) => e.type === "source_patch"),
    drift: any("decision_baseline", "decision_drift"), ledger: any("signed", "sealed"),
  };
}

function updateTabGates() {
  const ev = viewing === "live" ? liveEvents : shownEvents;
  const started = ev.length > 0 || (viewing === "live" && running);  // has a run begun this session/view?
  const gates = tabGates(ev), current = route();
  document.querySelectorAll(".tabs a").forEach((a) => {
    const r = a.dataset.route;
    // Before the first run: only Live run and Discovery are open, everything else frozen. During/after a run:
    // a tab opens only once its page has data. The tab in view is never frozen, so the viewer is never stranded.
    const open = r === current || (started ? Boolean(gates[r]) : (r === "run" || r === "discovery"));
    a.classList.toggle("disabled", !open);
  });
}

$("dmReplayBtn").addEventListener("click", () => dmReplay(viewing === "live" ? liveEvents : shownEvents));
dmReset();
renderSteps();
refreshModified();
refreshRuns().then(showPage);
