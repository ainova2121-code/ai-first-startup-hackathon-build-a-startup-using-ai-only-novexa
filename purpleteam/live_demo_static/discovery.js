// Live topology of the target: nodes appear as discovery finds them, edges draw themselves in as evidence
// arrives. Discovery evidence gives agent→tool edges (dashed: declared); runtime evidence -- every real request's
// tool calls, the "trace" events -- turns a tool's edge solid and draws agent→agent handoffs with calls flowing
// along them. Nothing is drawn without evidence. Only the drawing is paced (so the eye can follow it); order and
// the event log's times are the real ones. Works for any target. Panels: discovery_panels.js.
"use strict";

const DM_W = 212, DM_GAP = 86, DM_PAD = 26, DM_TOP = 70, DM_CARD = 86, DM_SOURCE = "Incoming requests";
const DM_PACE = { found_agent: 520, found_tool: 140, trace: 260 };  // ms between reveals, live or replayed alike
const DM = { agents: [], byName: {}, links: {}, edges: {}, queue: Promise.resolve(), start: 0, timer: null };
const dmSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const dmCalm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

let dmResizing = null;
window.addEventListener("resize", () => { clearTimeout(dmResizing); dmResizing = setTimeout(() => DM.svg && dmLayout(), 150); });

function dmEnqueue(step, wait) {  // ``wait`` may be a function, decided once the step has run
  const generation = DM.generation;
  DM.queue = DM.queue.then(() => {
    if (generation !== DM.generation) return 0;  // a replay restarted the map: this step belongs to the old one
    step();
    return dmCalm ? 0 : typeof wait === "function" ? wait() : wait;
  }).then(dmSleep).catch(() => {});
}

// Play the build-up again from a run's recorded events, at the same pace as live: used when the map was built
// while another tab was showing, and by the Replay button.
function dmReplay(events) {
  dmReset();
  for (const e of events) {
    if (e.type === "found_agent" || e.type === "found_tool") discoveryFound(e);
    else if (e.type === "discovered") discoveryMap(e);
    else if (e.type === "trace") dmTrace(e.calls || [], DM_PACE.trace);
    else if (e.type === "done") discoveryDone();
  }
}

function dmReset() {
  Object.assign(DM, { agents: [], byName: {}, links: {}, edges: {}, queue: Promise.resolve(), selected: null, sources: new Set(),
                      requests: 0, pending: 0, done: false, discovered: false, order: 0, start: DM.runStart || Date.now(),
                      autoReturnArmed: false, lastTraceAt: 0, generation: (DM.generation || 0) + 1 });
  clearInterval(DM.timer);
  for (const id of ["dmCanvas", "dmFeed", "dmStats", "dmDetail"]) $(id).textContent = "";
  $("dmDetail").classList.add("hidden");
  DM.svg = svg("svg", { class: "dm-links", "aria-hidden": "true" });
  DM.svg.appendChild(svg("defs")).appendChild(svg("marker", { id: "dm-arrow", viewBox: "0 0 8 8", refX: 7, refY: 4,
    markerWidth: 7, markerHeight: 7, orient: "auto" })).appendChild(svg("path", { d: "M0,0 L8,4 L0,8 z", class: "dm-arrowhead" }));
  const source = add(el("div", "dm-agent dm-source"), add(el("div", "dm-agent-head"), dmIcon("source"),
    add(el("div"), el("div", "dm-agent-name", DM_SOURCE), el("div", "faint", "attacks · replays · legit checks"))), el("div", "dm-spark"));
  Object.assign(source.style, { left: `${DM_PAD}px`, top: `${DM_TOP}px` });
  add($("dmCanvas"), DM.svg, source);
  DM.sourceCard = source;
  dmLayout();
  dmStatus();
}

function dmIcon(kind) {
  return el("span", `dm-icon dm-icon-${kind}`, { agent: "◉", read: "⌕", write: "⛁", execute: "›_", external: "⇄", source: "≋" }[kind] || "•");
}

const dmLeft = (column) => DM_PAD + column * (DM_W + DM_GAP);

function dmAddAgent(info, candidate) {
  if (DM.byName[info.name]) return DM.byName[info.name];
  const agent = { name: info.name, info, candidate, tools: {}, column: DM.agents.length + 1, observed: 0, last: null, first: null };
  DM.agents.push(agent);
  DM.byName[info.name] = agent;
  agent.element = el("div", "dm-column arrive");
  Object.assign(agent.element.style, { left: `${dmLeft(agent.column)}px`, top: `${DM_TOP}px` });
  agent.card = add(el("button", `dm-agent${candidate ? " candidate" : ""}`), add(el("div", "dm-agent-head"), dmIcon("agent"),
    add(el("div"), el("div", "dm-agent-name", info.name), el("div", "faint dm-agent-sub", ""))), el("span", "dm-badge", candidate ? "CANDIDATE" : "DISCOVERED"));
  agent.card.type = "button";
  agent.card.addEventListener("click", () => dmSelect(agent));
  agent.list = el("div", "dm-tools");
  $("dmCanvas").appendChild(add(agent.element, agent.card, agent.list));
  dmLayout();
  dmFeedItem("agent", candidate ? `New agent candidate: ${info.name}` : `Found agent: ${info.name}`,
             candidate ? "seen only in live traffic" : info.prompt_chars !== undefined
               ? `constructed by the target · prompt fingerprinted (${info.prompt_chars} chars)` : "found by introspection");
  return agent;
}

function dmAddTool(agent, tool, observedOnly) {
  if (agent.tools[tool.name]) return agent.tools[tool.name];
  const risk = tool.risk || "read";
  const row = add(el("div", "dm-tool"), dmIcon(risk), add(el("div", "dm-tool-text"), el("div", "dm-tool-name", tool.name),
    add(el("div", "dm-tool-meta faint"), el("span", null, [risk, tool.retrieval && "RAG", tool.memory && "memory"].filter(Boolean).join(" · ")),
        el("span", "dm-badge", observedOnly ? "OBSERVED" : "DECLARED"))));
  row.title = [tool.description, tool.source && `defined at ${tool.source}`].filter(Boolean).join("\n");
  agent.list.appendChild(row);
  agent.tools[tool.name] = { row, count: 0, risk, edge: `holds:${agent.name}:${tool.name}` };
  agent.card.querySelector(".dm-agent-sub").textContent = `${Object.keys(agent.tools).length} tools`;
  if (!observedOnly) dmFeedItem("tool", `Declared tool: ${tool.name}`, `${agent.name} · ${risk}${tool.source ? ` · ${tool.source}` : ""}`);
  dmLayout();
  dmStats();
  return agent.tools[tool.name];
}

function discoveryFound(e) {
  dmEnqueue(() => {
    $("discoveryEmpty").classList.add("hidden");
    DM.sources.add("introspection");
    DM.eventTime = e.ts;
    if (e.type === "found_agent") dmAddAgent(e, false);
    else dmAddTool(DM.byName[e.agent] || dmAddAgent({ name: e.agent }, false), e.tool, false);
    DM.eventTime = null;
    dmStatus();
  }, DM_PACE[e.type]);
}

// The summary once construction finishes: what only the whole build reveals (credentials, posture findings)
// enriches the nodes already there. A run recorded before streaming existed is built from it alone.
function discoveryMap(e) {
  for (const info of e.agents) {
    let added = false;
    dmEnqueue(() => { added = !DM.byName[info.name]; Object.assign((DM.byName[info.name] || dmAddAgent(info, false)).info, info); },
              () => (added ? DM_PACE.found_agent : 0));
    for (const tool of info.tools) {
      let fresh = false;
      dmEnqueue(() => { fresh = !DM.byName[info.name].tools[tool.name]; dmAddTool(DM.byName[info.name], tool, false); },
                () => (fresh ? DM_PACE.found_tool : 0));
    }
  }
  dmEnqueue(() => {
    for (const finding of e.findings) dmFeedItem("finding", `Posture finding: ${finding.kind}`, finding.detail);
    DM.discovered = true;
    dmStatus();
  }, 1600);  // a moment to take in the finished map
  // Started from the live run: don't leave on a timer. The green (observed) edges and agent→agent handoffs are
  // only drawn once real traffic reaches the target in the attack phase, so hold here until the map has actually
  // lit up and settled, then return to watch the attacks.
  dmEnqueue(() => { if (DM.autoReturn) armAutoReturn(); }, 0);
}

// Wait until the discovery map is visibly alive -- at least one observed handoff drawn and the burst settled --
// before pulling the viewer back to the run, with a hard cap so a sparse-traffic run never strands them.
function armAutoReturn() {
  DM.autoReturnArmed = true;
  const armedAt = performance.now();
  const tick = () => {
    if (!DM.autoReturnArmed || !DM.autoReturn || route() !== "discovery") { DM.autoReturnArmed = false; return; }
    const connected = Object.keys(DM.links).length > 0;                 // a real request crossed between agents
    const settled = performance.now() - DM.lastTraceAt > 900;           // the latest hops have had a beat to draw
    if ((connected && settled) || performance.now() - armedAt > 14000) {
      DM.autoReturnArmed = false;
      if (DM.autoReturn && route() === "discovery") location.hash = "#/run";
      DM.autoReturn = false;
      return;
    }
    setTimeout(tick, 250);
  };
  setTimeout(tick, 250);
}

function discoveryTrace(e) { dmTrace(e.calls || [], 0); }  // live traffic is already paced by reality

// One request, hop by hop in the order its calls ran: each step lights its tool and, when the work moves to
// another agent, draws that handoff with a call travelling along it before the next hop. If traffic arrives
// faster than it can be shown, the hops quicken so the map never lags far behind.
function dmTrace(calls, after) {
  DM.pending = (DM.pending || 0) + 1;
  dmEnqueue(() => dmRequest(calls.length), 0);
  let previous = DM_SOURCE;
  calls.forEach(([agent, tool], i) => {
    const hop = agent !== previous;
    previous = agent;
    // The first requests always play at full pace, so the path visibly forms; a backlog after that is compressed.
    dmEnqueue(() => dmStep(calls[i - 1] ? calls[i - 1][0] : DM_SOURCE, agent, tool),
              () => (DM.pending > 3 && DM.requests > 2 ? 40 : hop ? 520 : 140));
  });
  dmEnqueue(() => { DM.pending -= 1; }, after);
}

function discoveryDone() { dmEnqueue(() => { DM.done = true; dmStatus(); }, 0); }

function dmRequest(size) {  // a new request arrived: one bar on the source's sparkline
  DM.sources.add("runtime traces");
  DM.requests += 1;
  const spark = DM.sourceCard.querySelector(".dm-spark"), bar = el("i");
  bar.style.height = `${Math.min(100, 18 + size * 14)}%`;
  spark.appendChild(bar);
  while (spark.children.length > 34) spark.firstChild.remove();
}

function dmStep(from, agentName, toolName) {
  DM.lastTraceAt = performance.now();  // a hop just drew green: the auto-return watcher waits for this to settle
  const agent = DM.byName[agentName] || dmAddAgent({ name: agentName }, true);
  const tool = agent.tools[toolName] || dmAddTool(agent, { name: toolName }, true);
  tool.count += 1;
  if (tool.count === 1) dmFeedItem("call", `Observed call: ${agentName} → ${toolName}`, "ran in a real request this run");
  tool.row.classList.add("observed");
  tool.row.querySelector(".dm-badge").textContent = `OBSERVED ×${tool.count}`;
  tool.row.classList.remove("pulse"); void tool.row.offsetWidth; tool.row.classList.add("pulse");
  agent.observed += 1;
  agent.last = new Date();
  if (agent.first === null) agent.first = DM.order = (DM.order || 0) + 1;  // when it first acted in real traffic
  agent.card.classList.add("observed");
  agent.card.querySelector(".dm-badge").textContent = "OBSERVED";
  if (agentName !== from) dmLink(from, agentName);
  dmReorder();
  dmLayout();
  dmStats();
  if (DM.selected) dmSelect(DM.selected);
}

function dmReorder() {
  // Agents that acted come first, in the order they first acted, so the real flow reads left to right; the rest
  // keep discovery order after them. Columns glide to their new places (CSS), and the edges follow them.
  const ranked = [...DM.agents].sort((a, b) => (a.first ?? Infinity) - (b.first ?? Infinity) || a.column - b.column);
  let moved = false;
  ranked.forEach((agent, i) => {
    if (agent.column !== i + 1) {
      agent.column = i + 1;
      agent.element.style.left = `${dmLeft(agent.column)}px`;
      moved = true;
    }
  });
  if (moved) dmFollow(700);
}

function dmFollow(duration) {  // re-route the edges every frame while the columns glide
  const end = performance.now() + duration;
  const frame = () => { dmLayout(true); if (performance.now() < end) requestAnimationFrame(frame); };
  requestAnimationFrame(frame);
}

function dmLink(from, to) {
  const key = `${from}→${to}`;
  const link = DM.links[key] || (DM.links[key] = { from, to, count: 0 });
  link.count += 1;
  if (link.count === 1 && from !== DM_SOURCE) dmFeedItem("link", `Observed handoff: ${from} → ${to}`, "one request crossed from one agent to the next");
  link.fresh = true;
}

function dmBox(name) {  // where a node is right now (mid-glide too), in canvas coordinates
  const agent = DM.byName[name], node = agent ? agent.element : DM.sourceCard;
  return { left: node.offsetLeft, top: node.offsetTop, column: agent ? agent.column : 0 };
}

function dmEdge(key, d, cls, label) {
  let edge = DM.edges[key];
  if (!edge) {  // a new edge draws itself in from its source to its target
    edge = DM.edges[key] = { path: svg("path", { class: cls }) };
    if (label !== undefined) edge.text = svg("text", { class: "dm-link-label", "text-anchor": "middle" });
    DM.svg.append(edge.path, ...(edge.text ? [edge.text] : []));
    edge.path.setAttribute("d", d);
    if (!dmCalm) {
      const length = edge.path.getTotalLength();
      Object.assign(edge.path.style, { strokeDasharray: `${length}`, strokeDashoffset: `${length}` });
      edge.path.getBoundingClientRect();
      Object.assign(edge.path.style, { transition: "stroke-dashoffset .75s cubic-bezier(.4,0,.2,1)", strokeDashoffset: "0" });
      setTimeout(() => Object.assign(edge.path.style, { strokeDasharray: "", strokeDashoffset: "", transition: "" }), 800);
    }
  }
  edge.path.setAttribute("d", d);
  edge.path.setAttribute("class", cls);
  if (edge.text) {
    const mid = edge.path.getPointAtLength(edge.path.getTotalLength() / 2);
    edge.text.setAttribute("x", mid.x);
    edge.text.setAttribute("y", mid.y - 8);
    edge.text.textContent = label;
  }
  return edge;
}

function dmLayout(following) {
  const width = DM_PAD * 2 + (DM.agents.length + 1) * (DM_W + DM_GAP);
  const height = Math.max(380, ...DM.agents.map((a) => DM_TOP + a.element.offsetHeight)) + 30;
  const canvas = $("dmCanvas");
  Object.assign(canvas.style, { width: `${width}px`, height: `${height}px` });
  // The whole system in view: scale down to the stage's width, but never below half size (then it scrolls).
  const room = canvas.parentElement.clientWidth;
  canvas.style.zoom = room ? Math.max(0.5, Math.min(1, room / width)) : 1;
  DM.svg.setAttribute("width", width);
  DM.svg.setAttribute("height", height);
  for (const agent of DM.agents) {  // agent → tool: dashed while declared, solid once it ran
    const box = dmBox(agent.name), x = box.left + 22;
    for (const tool of Object.values(agent.tools)) {
      const y = box.top + tool.row.offsetTop + tool.row.offsetHeight / 2, end = box.left + tool.row.offsetLeft;
      dmEdge(tool.edge, `M${x},${box.top + DM_CARD} V${y - 10} Q${x},${y} ${x + 10},${y} H${end}`,
             tool.count ? "dm-holds on" : "dm-holds");
    }
  }
  for (const link of Object.values(DM.links)) {  // agent → agent: drawn only once a real request crossed it
    const a = dmBox(link.from), b = dmBox(link.to), y = DM_TOP + DM_CARD / 2, span = Math.abs(b.column - a.column);
    let d;
    if (b.column > a.column && span === 1) d = `M${a.left + DM_W},${y} C${a.left + DM_W + 44},${y} ${b.left - 44},${y} ${b.left},${y}`;
    else {  // skipping columns or going back: arc over the cards in between
      const lift = DM_TOP - 22 - Math.min(span, 4) * 9, back = b.column <= a.column;
      const sx = back ? a.left + DM_W / 2 : a.left + DM_W, ex = back ? b.left + DM_W / 2 : b.left;
      d = `M${sx},${back ? DM_TOP : y} C${sx},${lift} ${ex},${lift} ${ex},${back ? DM_TOP : y}`;
    }
    const edge = dmEdge(`link:${link.from}→${link.to}`, d, "dm-link", `observed · ${link.count} call${link.count === 1 ? "" : "s"}`);
    edge.path.setAttribute("marker-end", "url(#dm-arrow)");
    if (link.fresh && !following && !dmCalm) dmParticle(edge.path);
    if (!following) link.fresh = false;
  }
}

function dmParticle(path) {
  const dot = svg("circle", { r: 4, class: "dm-particle" });
  DM.svg.appendChild(dot);
  const start = performance.now(), duration = 900;
  const step = (now) => {
    const t = Math.min(1, (now - start) / duration), eased = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
    const point = path.getPointAtLength(eased * path.getTotalLength());
    dot.setAttribute("cx", point.x); dot.setAttribute("cy", point.y);
    if (t < 1 && dot.isConnected) requestAnimationFrame(step); else dot.remove();
  };
  requestAnimationFrame(step);
}
