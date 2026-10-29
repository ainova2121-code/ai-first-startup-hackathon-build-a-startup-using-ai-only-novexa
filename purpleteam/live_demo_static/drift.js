// Policy-decision drift: the decisions a run's verified defense made, how a later policy compares, and
// what-if replays of the same decisions with patches removed. Every string from the target or a model
// is set with textContent, never as HTML.
"use strict";

let driftEvent = null;  // this run's own comparison against the last approved run, if one was made

function renderDecisionEvent(e) {
  if (e.type === "decision_baseline") {
    const origins = e.origins || {};
    defenseCard("Decisions pinned", "policy-decision baseline", "risk-read",
                `${e.probes} decision(s) the verified defense made — ${origins.attack || 0} on attack input, `
                + `${origins.legit || 0} on legitimate work — pinned in the ledger (digest ${e.digest.slice(0, 12)}…).`);
    return;
  }
  driftEvent = e;
  const high = e.counts.high;
  defenseCard(high ? "Decision drift: this policy is looser than the approved one" : "No loosening against the approved policy",
              `vs run ${e.against_run || e.against.slice(0, 12)}`, high ? "risk-delete" : "risk-read",
              `${e.compared} approved decision(s) replayed through this run's policy: ${high} high, `
              + `${e.counts.medium} medium, ${e.counts.low} low.`);
}

function flipTable(flips, box) {
  box.textContent = "";
  if (!flips.length) { box.appendChild(el("div", "gate-item pass", "every decision is exactly what was approved")); return; }
  for (const f of flips) {
    const row = add(el("div", "finding drift-row"), pill(f.severity, `sev-${f.severity}`),
                    el("span", "mono", `${f.before} → ${f.after}`),
                    el("span", "faint mono", `${f.by_before || "—"} → ${f.by_after || "—"}`));
    add(row, el("div", "drift-label mono", f.label), el("div", "muted", `${f.why} · from ${f.origins.join(" + ")}`));
    box.appendChild(row);
  }
}

async function loadDrift(runId) {
  const head = $("driftHead"), compareBox = $("driftCompare"), whatIf = $("whatIf");
  for (const box of [head, compareBox, whatIf, $("whatIfResult")]) box.textContent = "";
  if (!runId) { head.appendChild(el("div", "muted", "No run selected yet.")); return; }
  const response = await fetch(`/runs/${encodeURIComponent(runId)}/decisions`);
  const body = await response.json();
  if (!response.ok) { head.appendChild(el("div", "muted", body.detail || "no decisions for this run")); return; }
  add(head, stat("Decisions pinned", body.probes), stat("On attack input", body.origins.attack || 0),
      stat("On legitimate work", body.origins.legit || 0), stat("Digest", body.digest.slice(0, 12)));
  if (body.dropped) head.appendChild(el("div", "card-note", `${body.dropped} further decision(s) exceeded the cap and were not pinned.`));

  if (driftEvent) {
    compareBox.appendChild(el("div", "panel-sub", `Replayed against approved run ${driftEvent.against_run || driftEvent.against.slice(0, 12)}: `
                                                  + `${driftEvent.compared} decision(s).`));
    const table = el("div", "findings");
    compareBox.appendChild(table);
    flipTable(driftEvent.flips, table);
  } else {
    compareBox.appendChild(el("div", "muted", "No earlier approved run to compare against: this run's decisions become the baseline once it passes the gate."));
  }

  if (!body.what_if) { whatIf.appendChild(el("div", "muted", "This run kept no rebuildable policy.")); return; }
  const boxes = body.patches.map((id) => {
    const input = el("input");
    input.type = "checkbox"; input.value = id;
    whatIf.appendChild(add(el("label", "chip-check"), input, document.createTextNode(` ${id}`)));
    return input;
  });
  const button = el("button", "btn", "Replay every decision without the selected patches");
  whatIf.appendChild(button);
  button.addEventListener("click", () => runWhatIf(runId, boxes.filter((b) => b.checked).map((b) => b.value)));
}

async function runWhatIf(runId, without) {
  const box = $("whatIfResult");
  box.textContent = "";
  box.appendChild(el("div", "muted", "Replaying…"));
  const response = await fetch(`/runs/${encodeURIComponent(runId)}/what-if`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ without }) });
  const body = await response.json();
  box.textContent = "";
  if (!response.ok) { box.appendChild(el("div", "gate-item", body.detail || "what-if refused")); return; }
  const removed = body.without.length ? `without ${body.without.join(", ")}` : "unchanged";
  box.appendChild(el("div", "panel-sub", `The verified policy ${removed}: ${body.compared} decision(s) replayed — `
                                          + `${body.counts.high} high, ${body.counts.medium} medium, ${body.counts.low} low.`));
  const table = el("div", "findings");
  box.appendChild(table);
  flipTable(body.flips, table);
}
