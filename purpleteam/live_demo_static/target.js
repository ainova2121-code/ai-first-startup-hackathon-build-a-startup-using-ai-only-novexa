// Target overview: the target in its owner's words, then what discovery found -- agents, tools and their risk, and the
// data it starts with. Everything comes from the server's discovery and is set with textContent, never as HTML.
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };

  function stat(label, value, note) {
    const box = el("div", "db-stat");
    const line = el("div", "db-stat-value");
    line.append(el("span", "", value), el("small", "", note));
    box.append(el("div", "db-stat-label", label), line);
    return box;
  }

  function agentCard(agent, index) {
    const card = el("article", "tp-agent");
    const head = el("div", "tp-agent-head");
    head.append(el("span", "tp-agent-index", String(index + 1).padStart(2, "0")), el("span", "tp-agent-name", agent.name),
      el("span", "tp-agent-count", `${agent.tools.length} tool${agent.tools.length === 1 ? "" : "s"}`));
    const tools = el("div", "tp-tools");
    for (const tool of agent.tools) {
      const row = el("div", "tp-tool");
      row.append(el("span", `tp-risk ${tool.risk}`, tool.risk), el("span", "tp-tool-name", tool.name),
        el("span", "tp-tool-desc", tool.description));
      tools.append(row);
    }
    card.append(head, tools);
    return card;
  }

  async function load() {
    try {
      const response = await fetch("/target/overview", { cache: "no-store" });
      if (!response.ok) throw new Error();
      const data = await response.json();
      document.title = `purpleteam — ${data.title}`;
      $("tpTitle").textContent = data.title;
      $("tpSummary").replaceChildren(...data.paragraphs.map((text) => el("p", "", text)));
      const t = data.totals;
      $("tpStats").replaceChildren(stat("Agents", t.agents, "discovered"), stat("Tools", t.tools, "across all agents"),
        stat("Tools that act", t.acting, "change or send something"), stat("Records", t.records, "in its database"));
      $("tpAgents").replaceChildren(...data.agents.map(agentCard));
      $("tpTables").replaceChildren(...data.tables.map((table) => {
        const chip = el("span", "tp-table");
        chip.append(el("span", "", table.label), el("strong", "", table.rows));
        return chip;
      }));
      $("tpMessage").classList.add("hidden");
      $("tpBody").classList.remove("hidden");
    } catch {
      $("tpTitle").textContent = "Target under test";
      $("tpMessage").textContent = "The target could not be read right now. You can still open the console.";
      $("tpMessage").classList.add("error");
    }
  }

  load();
})();
