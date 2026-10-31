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

  // Discovery progress: while the server builds the target the bar only creeps (we cannot see inside that call); once
  // the overview arrives, each later step resolves with what was really found, so nothing shown here is invented.
  const STEPS = [["Build the target from its own code", "Building the target from its own code…"],
    ["Find its agents", "Finding its agents…"], ["Map each agent's tools", "Mapping each agent's tools…"],
    ["Classify what each tool can do", "Classifying what each tool can do…"],
    ["Read the data it starts with", "Reading the data it starts with…"]];
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, reducedMotion ? 0 : ms));

  function scanner() {
    const rows = STEPS.map(([label]) => {
      const row = el("li", "tp-step");
      row.append(el("span", "tp-step-icon"), el("span", "tp-step-label", label), el("span", "tp-step-result"));
      return row;
    });
    $("tpSteps").replaceChildren(...rows);
    let shown = 0;
    let goal = 0;
    let current = -1;
    let creeping = setInterval(() => { goal += (34 - goal) * 0.09; }, 120);
    let frame = 0;
    const draw = () => {
      shown = goal - shown < 0.3 ? goal : shown + (goal - shown) * 0.09;
      $("tpBarFill").style.width = `${shown}%`;
      $("tpScanPct").textContent = `${Math.floor(shown)}%`;
      frame = requestAnimationFrame(draw);
    };
    draw();
    return {
      start(index) {
        current = index;
        rows[index].classList.add("active");
        $("tpScanStatus").textContent = STEPS[index][1];
      },
      progress(index, result, percent) {
        clearInterval(creeping);
        rows[index].lastChild.textContent = result;
        goal = percent;
      },
      done(index, result, percent) {
        this.progress(index, result, percent);
        rows[index].classList.replace("active", "done");
      },
      log(text) {
        const line = el("div", "tp-log-line");
        line.append(el("span", "tp-log-mark", "›"), el("span", "", text));
        $("tpLog").append(line);
        $("tpLog").scrollTop = $("tpLog").scrollHeight;
      },
      finish(status) {
        shown = goal;
        $("tpScanStatus").textContent = status;
        $("tpScan").classList.add("complete");
        setTimeout(() => cancelAnimationFrame(frame), 1500);
      },
      fail(message) {
        clearInterval(creeping);
        cancelAnimationFrame(frame);
        if (current >= 0) rows[current].classList.replace("active", "failed");
        $("tpScan").classList.add("failed");
        $("tpScanStatus").textContent = message;
      },
    };
  }

  async function discover(scan, data) {
    const { agents, tables, totals } = data;
    scan.done(0, "built", 40);
    scan.start(1);
    await pause(380);
    scan.log(`agents  ${agents.map((agent) => agent.name).join(" → ")}`);
    scan.done(1, `${totals.agents} agents`, 52);
    scan.start(2);
    const width = Math.max(...agents.map((agent) => agent.name.length));
    for (const [index, agent] of agents.entries()) {
      await pause(140);
      scan.log(`${agent.name.padEnd(width)}  ${agent.tools.map((tool) => tool.name).join(" · ") || "no tools"}`);
      scan.progress(2, `${index + 1}/${agents.length}`, 52 + (22 * (index + 1)) / agents.length);
    }
    scan.done(2, `${totals.tools} tools`, 74);
    scan.start(3);
    await pause(420);
    scan.log(`risk    ${totals.acting} of ${totals.tools} tools change or send something`);
    scan.done(3, `${totals.acting} act`, 88);
    scan.start(4);
    await pause(380);
    scan.log(`data    ${totals.records} records across ${tables.length} tables`);
    scan.done(4, `${totals.records} records`, 100);
    await pause(450);
    scan.finish("Discovery complete");
    await pause(650);
  }

  async function load() {
    const scan = scanner();
    scan.start(0);
    scan.log("reading the target's own code · no model is called");
    try {
      const [response] = await Promise.all([fetch("/target/overview", { cache: "no-store" }), pause(800)]);
      if (!response.ok) throw new Error();
      const data = await response.json();
      await discover(scan, data);
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
      $("tpScan").classList.add("hidden");
      $("tpBody").classList.remove("hidden");
    } catch {
      $("tpTitle").textContent = "Target under test";
      scan.fail("The target could not be read right now. You can still open the console.");
    }
  }

  load();
})();
