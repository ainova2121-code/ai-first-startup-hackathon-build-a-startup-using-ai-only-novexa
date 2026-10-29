// The signing flow of a run's ledger, drawn from the server's step-by-step verification (/ledger/explain):
// one lane per signing actor, each event chained to its actor's previous one, every event folded into the
// Merkle tree whose root the checkpoint signs. During a run it is redrawn as each event is signed, and only
// what is new animates in. Click anything to see every check and every raw value.
"use strict";

const SVG = "http://www.w3.org/2000/svg";
const COL = 62, LANE = 60, TOP = 22, LEFT = 22;
let signingView = null;
const SF = { run: null, shown: null, inspected: false, request: 0 };  // what is already on screen, per run

function svg(tag, attrs, text) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

function failed(checks) { return (checks || []).some((c) => c.ok === false); }

// ``live``: a refresh while the run signs events -- keep what is on screen and animate only what is new.
async function loadSigning(runId, live = false) {
  const box = $("signingFlow"), detail = $("signingDetail"), request = ++SF.request;
  if (!live || SF.run !== runId) {
    box.textContent = ""; detail.textContent = "";
    Object.assign(SF, { run: runId, shown: null, inspected: false });
    mxReset();
  }
  if (!runId) return;
  const response = await fetch(`/runs/${encodeURIComponent(runId)}/ledger/explain`);
  if (request !== SF.request) return;  // a newer refresh is already on its way
  if (!response.ok) {
    if (!signingView || SF.run !== runId || !live) { box.textContent = ""; box.appendChild(el("div", "muted", "The signing flow appears as soon as the run signs its first event.")); }
    return;
  }
  signingView = await response.json();
  if (request !== SF.request) return;
  renderMerkle(signingView);
  drawSigning(false);
}

// Every drawn piece has a key; a piece whose key was not on screen before is new and animates in, in the
// order the ledger really made it: the signed event, then its link to its signer's previous event. The
// Merkle tree those events fold into is the explorer above. ``replay`` treats everything as new.
function drawSigning(replay) {
  const view = signingView, box = $("signingFlow");
  const previous = box.querySelector(".sf-scroll");
  const followEnd = !previous || previous.scrollLeft + previous.clientWidth >= previous.scrollWidth - 80;
  const keptScroll = previous ? previous.scrollLeft : 0;
  box.textContent = "";
  const first = SF.shown === null;
  const shown = replay || first ? new Set() : SF.shown;
  const animate = replay || !first;
  const next = new Set();
  const newSeqs = view.events.filter((e) => e.actor && !shown.has(`e${e.seq}`)).map((e) => e.seq);
  const order = Object.fromEntries(newSeqs.map((seq, i) => [seq, i]));
  const at = (seq, part) => order[seq] * (replay ? 70 : 160) + part;
  const mark = (node, key, ms, kind = "sf-pop") => {
    next.add(key);
    if (animate && !shown.has(key)) { node.classList.add(kind); node.style.animationDelay = `${Math.max(0, ms)}ms`; }
    return node;
  };

  const actors = [...new Set(view.events.map((e) => e.actor).filter(Boolean))];
  const lane = Object.fromEntries(actors.map((a, i) => [a, i]));
  const height = TOP + actors.length * LANE + 14;
  const width = LEFT + Math.max(view.events.length, 1) * COL + 40;
  const x = (seq) => LEFT + seq * COL + COL / 2, y = (actor) => TOP + lane[actor] * LANE + LANE / 2;

  const signed = view.events.filter((e) => e.actor);
  const heads = new Set(actors.map((a) => signed.filter((e) => e.actor === a).pop().seq));  // each chain's newest link
  const verified = signed.every((e) => !failed(e.checks));
  const title = add(el("div"), el("div", "mx-card-title", "Signing flow"),
    el("div", "muted", "One hash chain per signer · each event is signed and linked to its signer's previous one · every event folds into the Merkle tree above"));
  const legend = el("div", "mx-legend");
  for (const [kind, label] of [["attack", "attack"], ["breach", "breach"], ["patch", "patch / fix"], ["verdict", "verdict / seal"], ["other", "evidence"]]) {
    add(legend, el("span", `sf-key kind-${kind}`), document.createTextNode(label));
  }
  const state = view.sealed
    ? badge(verified ? "EVERY SIGNATURE VERIFIED" : "SIGNATURE FAILED", verified)
    : add(el("span", "mx-badge live"), el("span", "sf-live-dot"), document.createTextNode(`LIVE · ${signed.length} SIGNED`));
  const replayButton = el("button", "btn", "▶ Replay signing");
  replayButton.addEventListener("click", () => drawSigning(true));
  const expand = el("button", "expand-btn", (document.fullscreenElement === box || box.classList.contains("expanded")) ? "✕" : "⛶");
  expand.type = "button";
  expand.setAttribute("aria-label", "Show the signing flow full screen");
  box.appendChild(add(el("div", "mx-card-head"), title, add(el("div", "sf-controls"), state, replayButton, expand)));
  box.appendChild(legend);

  const frame = el("div", "sf-frame");
  const labels = el("div", "sf-labels");
  labels.style.height = `${height}px`;
  actors.forEach((actor, i) => {
    const count = signed.filter((e) => e.actor === actor).length;
    const label = add(el("div", "sf-label"), el("span", `sf-actor a${i % 6}`), add(el("div"), el("div", "sf-actor-name", actor),
                      el("div", "sf-actor-meta", `${count} signed · key ${shortHash(signed.find((e) => e.actor === actor).kid)}`)));
    label.style.top = `${TOP + lane[actor] * LANE + LANE / 2 - 16}px`;
    labels.appendChild(label);
  });
  const scroller = el("div", "sf-scroll");
  const canvas = svg("svg", { width, height, viewBox: `0 0 ${width} ${height}`, role: "img",
                               "aria-label": "Signing flow of the audit ledger" });
  const defs = canvas.appendChild(svg("defs"));
  defs.appendChild(svg("marker", { id: "sf-arrow", viewBox: "0 0 8 8", refX: 7, refY: 4, markerWidth: 6, markerHeight: 6,
    orient: "auto" })).appendChild(svg("path", { d: "M0,0 L8,4 L0,8 z", class: "sf-arrowhead" }));
  const fill = defs.appendChild(svg("radialGradient", { id: "sf-node-fill", cx: "38%", cy: "32%", r: "75%" }));
  fill.appendChild(svg("stop", { offset: "0%", class: "sf-fill-hi" }));
  fill.appendChild(svg("stop", { offset: "100%", class: "sf-fill-lo" }));
  const chain = defs.appendChild(svg("linearGradient", { id: "sf-chain-grad", x1: "0%", x2: "100%" }));
  chain.appendChild(svg("stop", { offset: "0%", class: "sf-chain-from" }));
  chain.appendChild(svg("stop", { offset: "100%", class: "sf-chain-to" }));
  actors.forEach((actor, i) => {
    canvas.appendChild(svg("rect", { x: 0, y: TOP + i * LANE, width, height: LANE, class: i % 2 ? "sf-lane alt" : "sf-lane" }));
    canvas.appendChild(svg("line", { x1: 0, y1: y(actor), x2: width, y2: y(actor), class: "sf-rail" }));
  });

  for (const e of signed) {
    if (e.prev_seq === null || e.prev_seq === undefined) continue;
    const x1 = x(e.prev_seq) + 13, x2 = x(e.seq) - 13, yy = y(e.actor) - 9, lift = Math.min(26, 10 + (e.seq - e.prev_seq) * 3);
    const live = !view.sealed && heads.has(e.seq) ? " head" : "";  // the newest link of a chain still being written
    canvas.appendChild(mark(svg("path", { d: `M${x1},${yy} Q${(x1 + x2) / 2},${yy - lift} ${x2},${yy}`, pathLength: 1,
      class: `sf-chain${failed(e.checks) ? " bad" : ""}${live}`, "marker-end": "url(#sf-arrow)" }), `c${e.seq}`, at(e.seq, 90), "sf-draw"));
  }
  for (const e of signed) {
    const key = `e${e.seq}`, fresh = animate && !shown.has(key);
    const group = mark(svg("g", { class: `sf-node kind-${e.kind}${failed(e.checks) ? " bad" : ""}${!view.sealed && heads.has(e.seq) ? " head" : ""}`,
                                  tabindex: 0, role: "button", "aria-label": `event ${e.seq}, ${e.kind}, signed by ${e.actor}` }), key, at(e.seq, 0));
    if (fresh) {  // the instant of signing: a ring flashes out from the new event
      const ring = svg("circle", { cx: x(e.seq), cy: y(e.actor), r: 13, class: "sf-ring" });
      ring.style.animationDelay = `${at(e.seq, 0)}ms`;
      group.appendChild(ring);
    }
    group.appendChild(svg("circle", { cx: x(e.seq), cy: y(e.actor), r: 18, class: "sf-halo" }));
    group.appendChild(svg("circle", { cx: x(e.seq), cy: y(e.actor), r: 13, class: "sf-core" }));
    group.appendChild(svg("text", { x: x(e.seq), y: y(e.actor) + 3.5, "text-anchor": "middle" }, String(e.seq)));
    group.appendChild(svg("title", {}, `#${e.seq} ${e.kind} · signed by ${e.actor} (key ${e.kid})`));
    const open = () => { SF.inspected = true; inspectEvent(e); };
    group.addEventListener("click", open);
    group.addEventListener("keydown", (k) => { if (k.key === "Enter") open(); });
    canvas.appendChild(group);
  }
  const sealedNow = Boolean(view.checkpoint) && !shown.has("sealed");
  if (view.checkpoint) next.add("sealed");
  scroller.appendChild(canvas);
  box.appendChild(add(frame, labels, scroller));
  SF.shown = next;
  // Follow the newest signature while the reader is at the live edge; otherwise keep their place.
  scroller.scrollLeft = keptScroll;
  if (!view.sealed && followEnd) requestAnimationFrame(() => scroller.scrollTo({ left: scroller.scrollWidth, behavior: first ? "auto" : "smooth" }));
  if (!SF.inspected || sealedNow) inspectCheckpoint(view.checkpoint);
}

function field(label, value, long) {
  const row = add(el("div", "sf-field"), el("div", "label", label));
  const text = value === null || value === undefined ? "—" : typeof value === "string" ? value : JSON.stringify(value, null, 2);
  if (long && text.length > 200) {
    const details = add(el("details"), el("summary", "faint", `${text.length} characters — show all`), el("pre", "sf-raw", text));
    row.appendChild(details);
  } else {
    row.appendChild(el("pre", "sf-raw", text));
  }
  return row;
}

function checkList(checks) {
  const list = el("div", "sf-checks");
  for (const c of checks || []) {
    list.appendChild(add(el("div", `sf-check ${c.ok === false ? "bad" : "ok"}`), el("span", "sf-mark", c.ok === false ? "✗" : "✓"),
                         el("span", null, c.check), el("span", "faint mono", c.detail)));
  }
  return list;
}

function inspectEvent(e) {
  const box = $("signingDetail");
  box.textContent = "";
  const pub = e.public && typeof e.public === "object" ? e.public : { ed25519: e.public };
  add(box, el("div", "panel-title", `Event #${e.seq} · ${e.kind} · signed by ${e.actor}`), checkList(e.checks),
      field("Links to (its actor's previous event)", e.prev_seq === null ? `genesis ${e.prev}` : `#${e.prev_seq} ${e.prev}`),
      field("Exactly what was hashed (previous hash + canonical event JSON)", e.hashed, true),
      field("SHA-256 recorded in the log", e.hash), field("SHA-256 recomputed now", e.recomputed),
      field(`Signed message: the event hash, under context "${e.context}"`, e.signed),
      field(`Signing key id (${e.actor})`, e.kid), field("Ed25519 public key", pub.ed25519),
      field("ML-DSA-65 public key", pub.mldsa65, true), field("Ed25519 signature", e.sig), field("ML-DSA-65 signature", e.pqsig, true));
}

function inspectCheckpoint(c) {
  const box = $("signingDetail");
  box.textContent = "";
  if (!c) {
    box.appendChild(el("div", "muted", signingView && !signingView.sealed
      ? "No checkpoint yet: each event above is already signed and verified against its signer's public key. When the run ends, one checkpoint signs the Merkle root of every event — click any event or tree node meanwhile."
      : "This run has no checkpoint yet."));
    return;
  }
  add(box, el("div", "panel-title", `Checkpoint · signs the Merkle root of the first ${c.size} events`), checkList(c.checks),
      field("Root in the checkpoint", c.root), field("Root recomputed from the events now", c.recomputed_root),
      field(`Signed message (context "${c.context}")`, c.message), field("Ledger key id", c.kid),
      field("Ed25519 signature", c.sig), field("ML-DSA-65 signature", c.pqsig, true));
  if (c.hardware) add(box, field(`Hardware signature (${c.hardware.kind})`, c.hwsig), field("Hardware public key", c.hardware.public));
  else box.appendChild(el("div", "card-note", "No hardware signer was configured for this run: the checkpoint is signed by software keys only."));
}
