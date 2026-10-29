// Merkle explorer: the run's real Merkle tree as cards, the inclusion proof of a chosen event recomputed in
// this browser (SHA-256 via Web Crypto, not taken from the server), and the checkpoint that signs the root.
// Every badge is derived from the server's step-by-step verification; nothing is shown as verified unless it was.
"use strict";

const MX_LEAF_W = 172, MX_GAP = 18, MX_ROW = 112, MX_TOP = 18, MX_CARD_H = 64;
let mxSelected = null;
const MX = { shown: null, pinned: false };  // hashes already on screen; did the reader pick a leaf

function mxReset() { mxSelected = null; Object.assign(MX, { shown: null, pinned: false }); MX_ZOOM.mode = "focus"; }

const shortHash = (h) => (h ? `${h.slice(0, 4)}…${h.slice(-4)}` : "—");
const allOk = (checks) => (checks || []).length > 0 && checks.every((c) => c.ok !== false);

function copyButton(value) {
  const button = el("button", "mx-copy", "⧉");
  button.type = "button";
  button.setAttribute("aria-label", "Copy the full value");
  button.title = value;
  button.addEventListener("click", async (event) => {
    event.stopPropagation();
    try { await navigator.clipboard.writeText(value); button.textContent = "✓"; } catch { button.textContent = "!"; }
    setTimeout(() => { button.textContent = "⧉"; }, 1200);
  });
  return button;
}

function hashLine(value, cls) { return add(el("div", `mx-hash ${cls || ""}`), el("span", null, shortHash(value)), copyButton(value)); }

function layoutTree(tree) {
  const nodes = [];
  let leaves = 0;
  const walk = (node, level, parent) => {
    node.level = level; node.parent = parent; nodes.push(node);
    if ("leaf" in node) { node.x = leaves++ * (MX_LEAF_W + MX_GAP); return; }
    walk(node.left, level + 1, node); walk(node.right, level + 1, node);
    node.x = (node.left.x + node.right.x) / 2;
  };
  walk(tree, 0, null);
  const height = Math.max(...nodes.map((n) => n.level));
  for (const n of nodes) n.y = MX_TOP + ("leaf" in n ? height : n.level) * MX_ROW;
  return { nodes, height, width: leaves * (MX_LEAF_W + MX_GAP), rows: height + 1 };
}

function proofPath(tree, seq) {
  const path = new Set(), siblings = new Set();
  let node = null;
  const find = (n) => { if ("leaf" in n) { if (n.leaf === seq) node = n; return; } find(n.left); find(n.right); };
  find(tree);
  for (let n = node; n; n = n.parent) {
    path.add(n);
    if (n.parent) siblings.add(n.parent.left === n ? n.parent.right : n.parent.left);
  }
  return { leaf: node, path, siblings };
}

async function sha256(...parts) {
  const bytes = new Uint8Array(parts.reduce((size, p) => size + p.length, 0));
  let offset = 0;
  for (const p of parts) { bytes.set(p, offset); offset += p.length; }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
const fromHex = (h) => new Uint8Array(h.match(/../g).map((b) => parseInt(b, 16)));
const toHex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

async function recompute(view, proof) {
  // RFC 6962: leaf = SHA-256(0x00 ‖ event hash); node = SHA-256(0x01 ‖ left ‖ right)
  const event = view.events[proof.leaf.leaf];
  let running = await sha256(new Uint8Array([0]), fromHex(event.hash));
  const steps = [{ label: "leaf = SHA-256(0x00 ‖ event hash)", hash: toHex(running), matches: toHex(running) === proof.leaf.hash }];
  for (let n = proof.leaf; n.parent; n = n.parent) {
    const parent = n.parent, isLeft = parent.left === n, sibling = isLeft ? parent.right : parent.left;
    running = isLeft ? await sha256(new Uint8Array([1]), running, fromHex(sibling.hash))
                     : await sha256(new Uint8Array([1]), fromHex(sibling.hash), running);
    steps.push({ label: `with sibling (${isLeft ? "right" : "left"})`, sibling: sibling.hash, hash: toHex(running),
                 matches: toHex(running) === parent.hash });
  }
  return { steps, root: toHex(running) };
}

// Redrawn as each event is signed: a card or edge whose hash was not on screen before rises in, leaves first,
// then each re-folded parent level by level, and the root glows each time it changes. While the run signs,
// the proof follows the newest event unless the reader picked one.
function renderMerkle(view) {
  const box = $("merkleTree");
  const previous = box.querySelector(".mx-scroll"), keptScroll = previous ? previous.scrollLeft : 0;
  box.textContent = "";
  if (!view || !view.tree) { box.appendChild(el("div", "muted", "The Merkle tree grows here as the run signs its events.")); return; }
  const events = view.events.filter((e) => e.actor);
  const live = !view.sealed;
  if (mxSelected === null || !events[mxSelected] || (live && !MX.pinned)) {
    const patch = !live && events.find((e) => e.kind === "patch");
    mxSelected = (patch || events[events.length - 1]).seq;
  }
  const layout = layoutTree(view.tree), proof = proofPath(view.tree, mxSelected);
  const signing = live ? proofPath(view.tree, events[events.length - 1].seq) : null;  // the event being signed now
  const first = MX.shown === null, shown = MX.shown || new Set(), next = new Set();
  const isNew = (hash) => !first && !shown.has(hash);
  const rise = (n) => (layout.height - n.level) * 120;  // leaves first, the root last
  const rootOk = view.checkpoint && view.checkpoint.checks.some((c) => c.check === "Merkle root" && c.ok);
  $("merkleSub").textContent = `RFC 6962 binary tree · ${events.length} events · SHA-256 · height ${layout.height}`
    + (live ? " · growing live as events are signed" : "");

  const canvas = el("div", "mx-canvas");
  const totalH = MX_TOP + layout.height * MX_ROW + MX_CARD_H + 24;
  canvas.style.width = `${layout.width}px`;
  canvas.style.height = `${totalH}px`;
  const lines = svg("svg", { width: layout.width, height: totalH, class: "mx-lines", "aria-hidden": "true" });
  for (const n of layout.nodes) {
    if (!n.parent) continue;
    const cx = n.x + MX_LEAF_W / 2, cy = n.y, px = n.parent.x + MX_LEAF_W / 2, py = n.parent.y + MX_CARD_H, mid = (cy + py) / 2;
    const d = `M${cx},${cy} V${mid} H${px} V${py}`;
    const edge = svg("path", { d, pathLength: 1, class: proof.path.has(n) ? "mx-edge on" : "mx-edge" });
    if (isNew(n.parent.hash)) { edge.classList.add("mx-draw"); edge.style.animationDelay = `${rise(n) + 60}ms`; }
    lines.appendChild(edge);
    if (signing && signing.path.has(n)) {  // a green light runs up from the event being signed to the root
      lines.appendChild(svg("path", { d, class: isNew(signing.leaf.hash) ? "mx-signal fresh" : "mx-signal" }));
    }
  }
  canvas.appendChild(lines);
  for (const n of layout.nodes) {
    const isLeaf = "leaf" in n, isRoot = !n.parent, onPath = proof.path.has(n), sibling = proof.siblings.has(n);
    const card = el("div", `mx-node${isRoot ? " root" : ""}${isLeaf ? " leaf" : ""}${onPath ? " on" : ""}${sibling ? " sibling" : ""}`);
    card.style.left = `${n.x}px`;
    card.style.top = `${n.y}px`;
    card.style.width = `${MX_LEAF_W}px`;
    next.add(n.hash);
    if (isNew(n.hash)) { card.classList.add(isRoot ? "mx-root-new" : "mx-enter"); card.style.animationDelay = `${rise(n)}ms`; }
    if (sibling) card.appendChild(el("span", "mx-sibling-dot"));
    if (signing && (n === signing.leaf || isRoot)) card.classList.add("signing");
    if (signing && n === signing.leaf) card.appendChild(el("span", "mx-signing-tag", "● signing now"));
    if (isRoot) {
      const state = rootOk ? "ok" : live ? "live" : "bad";
      add(card, add(el("div", "mx-root-label"), el("span", `mx-dot ${state}`), document.createTextNode(live ? "LIVE ROOT" : "MERKLE ROOT")),
          hashLine(n.hash, "big"), el("div", "mx-foot", `SHA-256 | height ${layout.height} | ${events.length} leaves`));
    } else if (isLeaf) {
      const e = view.events[n.leaf];
      add(card, add(el("div", "mx-leaf-row"), el("span", "mx-doc", "▤"), add(el("div"), el("div", "mx-leaf-title", `seq ${e.seq} · ${e.kind}`),
          hashLine(e.hash))));
      card.title = `leaf hash ${n.hash} = SHA-256(0x00 ‖ ${e.hash})`;
      card.tabIndex = 0;
      card.setAttribute("role", "button");
      card.setAttribute("aria-label", `Show the inclusion proof of event ${e.seq}`);
      const choose = () => { mxSelected = e.seq; MX.pinned = true; renderMerkle(view); };
      card.addEventListener("click", choose);
      card.addEventListener("keydown", (k) => { if (k.key === "Enter") choose(); });
    } else {
      add(card, el("div", "mx-formula", "H(0x01 ‖ left ‖ right)"), hashLine(n.hash));
    }
    canvas.appendChild(card);
  }
  const scroller = add(el("div", "mx-scroll"), canvas);
  box.appendChild(scroller);
  MX.shown = next;
  // Focus on the event being signed now -- or, once picked, the reader's own -- from its leaf up to the root.
  const focused = MX.pinned || !signing ? proof : signing, xs = [...focused.path].map((n) => n.x);
  scroller.scrollLeft = keptScroll;
  mxApplyZoom(scroller, canvas, { left: Math.min(...xs) - 24, right: Math.max(...xs) + MX_LEAF_W + 24,
                                  leaf: [focused.leaf.x, focused.leaf.x + MX_LEAF_W] }, !first);
  // Zoomed by hand, glide from where the reader was to the chosen leaf -- unless, mid-run, they picked one to
  // study: then the view stays where they left it.
  if (MX_ZOOM.mode === "manual" && (first || !live || !MX.pinned)) {
    const left = (proof.leaf.x + MX_LEAF_W / 2) * MX_ZOOM.value - scroller.clientWidth / 2;
    requestAnimationFrame(() => scroller.scrollTo({ left: Math.max(0, left), behavior: first ? "auto" : "smooth" }));
  }
  renderCheckpointCard(view);
  renderProofCard(view, proof);
  renderAnchors(view);
}

function kv(label, value, copy) {
  return add(el("div", "mx-kv"), el("span", "mx-k", label), add(el("span", "mx-v"), document.createTextNode(value), copy ? copyButton(copy) : null));
}

function badge(text, ok) { return el("span", `mx-badge ${ok ? "ok" : ok === false ? "bad" : "off"}`, text); }

function signers(checks) { return checks.filter((c) => /signature/.test(c.check) && !/hardware/.test(c.check)).map((c) => c.check.replace(" signature", "")).join(" + "); }

function renderCheckpointCard(view) {
  const box = $("mxCheckpoint"), c = view.checkpoint;
  box.textContent = "";
  if (!c) {  // mid-run: what the checkpoint will sign, honestly marked as not signed yet
    const events = view.events.filter((e) => e.actor).length;
    add(box, add(el("div", "mx-card-head"), el("div", "mx-card-title", "Checkpoint"), badge("SIGNED WHEN THE RUN ENDS", null)),
        add(el("div", "mx-hero"), el("div", "mx-chip-icon pending", "▣"), add(el("div"),
            add(el("div", "mx-hero-title"), el("span", "mx-dot live"), document.createTextNode(`PENDING · ${events} events so far`)),
            el("div", "muted", "every event is already signed and verified; the checkpoint seals them all"))),
        kv("Current root", shortHash(view.tree.hash), view.tree.hash), kv("Tree height", String(layoutTree(view.tree).height)),
        kv("Hardware signer", view.hardware_note || "not configured"));
    return;
  }
  const linked = c.checks.some((x) => x.check === "Merkle root" && x.ok);
  const hw = c.checks.find((x) => /hardware/.test(x.check));
  add(box, add(el("div", "mx-card-head"), el("div", "mx-card-title", "Checkpoint"), badge(linked ? "LINKED TO ROOT" : "ROOT MISMATCH", linked)),
      add(el("div", "mx-hero"), el("div", "mx-chip-icon", "▣"), add(el("div"),
          add(el("div", "mx-hero-title"), el("span", `mx-dot ${allOk(c.checks) ? "ok" : "bad"}`), document.createTextNode(`CHECKPOINT · ${c.size} events`)),
          el("div", "muted", `signed ${new Date(c.ts * 1000).toISOString().replace("T", " ").slice(0, 19)} UTC`))),
      kv("Root hash", shortHash(c.root), c.root), kv("Tree height", String(layoutTree(view.tree).height)),
      kv("Checkpoint size", String(c.size)), kv("Signature", signers(c.checks)), kv("Signed by", `ledger key · key id ${shortHash(c.kid)}`, c.kid),
      add(el("div", `mx-tpm ${hw ? (hw.ok ? "ok" : "bad") : "off"}`), el("span", "mx-chip-icon small", "▣"),
          el("span", null, hw ? `${hardwareName(c.hardware)} signature verified` : `No hardware signature: ${view.hardware_note || "not configured for this run"}`),
          badge(hw ? (hw.ok ? "VERIFIED" : "FAILED") : "NOT CONFIGURED", hw ? hw.ok : null)));
  if (c.hardware) box.appendChild(kv("Hardware key", `${hardwareName(c.hardware)} · P-256 · ${shortHash(c.hwkid)}`, c.hwkid));
}

function hardwareName(hardware) {
  const kind = (hardware || {}).kind || "unknown";
  return { tpm2: "TPM 2.0", "tpm1.2": "TPM 1.2", secure_enclave: "Secure Enclave", hsm: "HSM", kms: "Cloud KMS", software: "Software key" }[kind] || kind;
}

function anchorStage(view) {
  const anchors = view.anchors || [];
  if (anchors.length) {
    const ok = anchors.every((a) => a.ok), first = anchors[0];
    const when = first.time ? new Date(first.time * 1000).toISOString().replace("T", " ").slice(0, 19) : "";
    const label = ok ? `VERIFIED · ${first.authority} · ${when} UTC` : `FAILED · ${first.detail}`;
    return { status: label, ok, title: anchors.map((a) => `${a.authority}: ${a.detail}`).join("\n") };
  }
  if ((view.anchor_errors || []).length) return { status: "FAILED", ok: false, title: view.anchor_errors.join("\n") };
  return { status: view.anchoring === "off" ? "TURNED OFF" : "NOT CONFIGURED", ok: null, title: "" };
}

async function renderProofCard(view, proof) {
  const box = $("mxProof"), e = view.events[proof.leaf.leaf], c = view.checkpoint;
  box.textContent = "";
  const head = add(el("div", "mx-card-head"), el("div", "mx-card-title", `Event proof · seq ${e.seq}`), badge("recomputing…", null));
  add(box, head, add(el("div", "mx-hero"), el("div", "mx-chip-icon", "▤"),
      add(el("div"), el("div", "mx-hero-title", `seq ${e.seq} · ${e.kind}`), hashLine(e.hash))),
      kv("Event type", e.kind), kv("Signed by", `${e.actor} key · key id ${shortHash(e.kid)}`, e.kid), kv("Signature", signers(e.checks)),
      kv("Checkpoint size", c ? String(c.size) : "—"));
  const details = add(el("details", "mx-path"), el("summary", null, `Merkle proof path (${proof.siblings.size} hashes)`));
  details.open = true;
  box.appendChild(details);
  const more = el("button", "btn", "Open every signing check for this event");
  more.addEventListener("click", () => inspectEvent(e));
  box.appendChild(more);
  const result = await recompute(view, proof);
  result.steps.forEach((step, i) => {
    details.appendChild(add(el("div", `mx-step ${step.matches ? "ok" : "bad"}`), el("span", "mx-num", String(i)), el("span", null, step.label),
                            add(el("span", "mx-v"), document.createTextNode(shortHash(step.sibling || step.hash)), copyButton(step.sibling || step.hash))));
  });
  if (!c) {  // not sealed yet: the proof can only be checked against the tree as it stands now
    const current = result.root === view.tree.hash && result.steps.every((s) => s.matches);
    head.lastChild.replaceWith(badge(current ? "IN THE CURRENT ROOT" : "NOT PROVEN", current ? true : false));
    details.appendChild(el("div", `mx-result ${current ? "ok" : "bad"}`, current
      ? `Recomputed in this browser: ${shortHash(result.root)} — matches the current root; the checkpoint that signs it comes when the run ends`
      : `Recomputed in this browser: ${shortHash(result.root)} — does not match the current root`));
    return;
  }
  const included = e.seq < c.size && result.root === c.root && result.steps.every((s) => s.matches);
  head.lastChild.replaceWith(badge(included ? "INCLUDED IN CHECKPOINT" : "NOT PROVEN", included));
  details.appendChild(el("div", `mx-result ${included ? "ok" : "bad"}`, included
    ? `Recomputed in this browser: ${shortHash(result.root)} — matches the signed checkpoint root`
    : `Recomputed in this browser: ${shortHash(result.root)} — does not match the checkpoint root`));
}

function renderAnchors(view) {
  const box = $("mxAnchors"), c = view.checkpoint;
  box.textContent = "";
  const stage = (icon, label, status, ok) => add(el("div", "mx-stage"), el("span", "mx-chip-icon small", icon),
    add(el("span", "mx-stage-label"), el("span", `mx-dot ${ok ? "ok" : ok === false ? "bad" : "off"}`), document.createTextNode(label)), badge(status, ok));
  const signed = c && allOk(c.checks.filter((x) => /signature/.test(x.check) && !/hardware/.test(x.check)));
  const hw = c && c.checks.find((x) => /hardware/.test(x.check));
  const anchor = c ? anchorStage(view) : { status: "AFTER THE CHECKPOINT", ok: null, title: "" };
  const anchorBox = stage("⏱", "Timestamp anchor (RFC 3161)", anchor.status, anchor.ok);
  anchorBox.title = anchor.title;
  const stages = [stage("✎", "Signed checkpoint", c ? (signed ? "VERIFIED" : "FAILED") : "PENDING", c ? Boolean(signed) : null),
    stage("▣", hw ? `Hardware signature · ${hardwareName(c.hardware)}` : "Hardware signature",
          hw ? (hw.ok ? "VERIFIED" : "FAILED") : c ? "NOT CONFIGURED" : "PENDING", hw ? hw.ok : null),
    anchorBox, stage("⛁", "Write-once storage", "NOT DETECTABLE HERE", null)];
  const flow = el("div", "mx-stages");
  stages.forEach((s, i) => { if (i) flow.appendChild(el("span", "mx-arrow", "⟶")); flow.appendChild(s); });
  const chained = view.events.every((e) => allOk(e.checks));
  const evident = c && allOk(c.checks) && chained;
  const verdict = c ? badge(evident ? "TAMPER-EVIDENT" : "BROKEN", Boolean(evident))
                    : badge(chained ? "EVERY EVENT VERIFIED · SEALING AT END" : "BROKEN", chained ? null : false);
  add(box, add(el("div", "mx-strip-head"), el("div", "mx-card-title", "Independent anchoring · tamper evidence"),
               el("div", "muted", "What protects this checkpoint beyond its own signatures — each shown as it really is for this run.")),
      add(el("div", "mx-strip-row"), flow, add(el("div", "mx-final"),
          add(el("div"), el("div", "mx-hero-title", c ? `Checkpoint · ${c.size} events` : `${view.events.length} events signed so far`),
              el("div", "muted", c ? `${new Date(c.ts * 1000).toISOString().slice(11, 19)} UTC` : "live")),
          verdict)));
}
