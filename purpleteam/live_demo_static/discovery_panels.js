// The panels around the live discovery map: its event log, progress stats, status clock and agent detail.
// They read the map's state (DM, discovery.js) and never change it.
"use strict";

function dmFeedItem(kind, title, detail) {
  const at = DM.eventTime ? new Date(DM.eventTime * 1000) : new Date();  // the real moment, when the event carries it
  const time = at.toLocaleTimeString([], { hour12: false });
  const item = add(el("div", `dm-event dm-event-${kind}`), el("span", "dm-event-time mono", time), dmIcon(kind === "agent" ? "agent" : kind === "link" ? "external" : "read"),
                   add(el("div"), el("div", "dm-event-title", title), el("div", "faint", detail || "")));
  const feed = $("dmFeed");
  feed.prepend(item);
  while (feed.children.length > 80) feed.lastChild.remove();
}

function dmStats() {
  const box = $("dmStats");
  box.textContent = "";
  const tools = DM.agents.flatMap((a) => Object.values(a.tools));
  const observed = tools.filter((t) => t.count).length;
  const confirmed = DM.agents.filter((a) => !a.candidate).length, candidates = DM.agents.length - confirmed;
  const tile = (icon, label, value, ratio) => add(el("div", "dm-stat"), dmIcon(icon), add(el("div"), el("div", "faint", label),
    el("div", "dm-stat-value", value)), add(el("div", "dm-bar"), Object.assign(el("i"), { style: `width:${Math.round(ratio * 100)}%` })));
  add(box, tile("agent", "Agents found", `${confirmed}${candidates ? ` + ${candidates} candidate${candidates > 1 ? "s" : ""}` : ""}`, DM.agents.length ? 1 : 0),
      tile("read", "Tools observed / declared", `${observed} / ${tools.length}`, tools.length ? observed / tools.length : 0),
      tile("external", "Links observed", String(Object.values(DM.links).filter((l) => l.from !== DM_SOURCE).length), DM.requests ? 1 : 0),
      tile("source", "Sources", [...DM.sources].join(" + ") || "—", DM.sources.size / 2));
}

function dmStatus() {
  const box = $("dmStatus");
  if (!box) return;
  clearInterval(DM.timer);
  const draw = () => {
    box.textContent = "";
    const seconds = Math.round((Date.now() - DM.start) / 1000), clock = `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
    const [label, cls] = DM.done ? ["DISCOVERY COMPLETE", "ok"] : !DM.agents.length ? ["WAITING FOR A RUN", "off"]
      : DM.discovered ? ["OBSERVING LIVE TRAFFIC", "live"] : ["DISCOVERY IN PROGRESS", "live"];
    add(box, el("span", `dm-dot ${cls}`), el("span", "dm-status-label", label), el("span", "faint mono", DM.agents.length && !DM.done ? `${clock} elapsed` : ""));
  };
  draw();
  if (!DM.done && !replaying) DM.timer = setInterval(draw, 1000);
}

function dmSelect(agent) {
  DM.selected = agent;
  const box = $("dmDetail"), info = agent.info, tools = Object.entries(agent.tools);
  const privilege = ["execute", "write", "read"].find((r) => tools.some(([, t]) => t.risk === r)) || "none";
  box.textContent = "";
  const close = el("button", "mx-copy", "✕");
  close.addEventListener("click", () => { DM.selected = null; box.classList.add("hidden"); });
  add(box, add(el("div", "mx-card-head"), add(el("div", "dm-agent-head"), dmIcon("agent"), add(el("div"), el("div", "mx-card-title", agent.name),
        el("div", "faint", agent.candidate ? "agent candidate (traffic only)" : "AI agent"))), close),
      kv("Identity", info.credential || "not reported"), kv("Model", info.model || "not reported"),
      kv("Tools observed", `${tools.filter(([, t]) => t.count).length} of ${tools.length}`), kv("Highest privilege", privilege),
      kv("Prompt", info.prompt_sha256 ? `sha256 ${info.prompt_sha256}… · ${info.prompt_chars} chars (never shown)` : "not captured"),
      kv("Last seen", agent.last ? agent.last.toLocaleTimeString() : "not yet in this run's traffic"));
  for (const [name, t] of tools) box.appendChild(kv(name, t.count ? `${t.risk} · ran ${t.count}×` : `${t.risk} · declared, not yet run`));
  box.classList.remove("hidden");
}
