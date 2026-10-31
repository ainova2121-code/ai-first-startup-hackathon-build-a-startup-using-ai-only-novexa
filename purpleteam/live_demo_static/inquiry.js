// Agent inquiry: ask the target's supplier-portal agent a question as one vendor, unpatched or behind the newest
// verified defense, and show its answer, every query it ran and whether the answer leaked someone else's data.
// Everything from the agent is set with textContent, never as HTML.
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };
  const MAX_CARDS = 12;
  const OUTCOMES = { leak: "LEAK", blocked: "BLOCKED", clean: "NO LEAK" };
  let defense = null;
  let patched = false;
  let asking = false;

  function setMode(next) {
    patched = next && Boolean(defense);
    for (const option of $("iqMode").children) {
      const on = (option.dataset.patched === "true") === patched;
      option.classList.toggle("active", on);
      option.setAttribute("aria-checked", String(on));
    }
    $("iqModeNote").textContent = patched
      ? `Behind the runtime defense run ${defense.run} verified (${defense.patches.join(", ")}).`
      : "The agent exactly as built, with no runtime defense.";
  }

  async function loadInquiry() {
    try {
      const response = await fetch("/inquiry/context", { cache: "no-store" });
      if (!response.ok) throw new Error();
      const context = await response.json();
      defense = context.defense;
      const select = $("iqVendor"), chosen = select.value;
      select.replaceChildren(...context.vendors.map((v) => Object.assign(el("option", "", v.name), { value: v.id })));
      if (chosen) select.value = chosen;
      const patchedOption = $("iqMode").querySelector('[data-patched="true"]');
      patchedOption.disabled = !defense;
      patchedOption.title = defense ? "" : "Complete a full run first: the patched agent runs behind its verified defense.";
      setMode(patched);
    } catch {
      showMessage("The inquiry agent is not available right now. Try refreshing.", true);
    }
  }

  function showMessage(text, error = false) {
    const message = $("iqMessage");
    message.textContent = text;
    message.classList.toggle("error", error);
    message.classList.toggle("hidden", !text);
  }

  function card(vendor, question, mode, result) {
    const outcome = result ? result.outcome : "";
    const article = el("article", `iq-card ${result ? outcome : "iq-pending"}`);
    const head = el("header", "iq-card-head");
    head.append(el("span", "iq-vendor", vendor),
      el("span", `iq-tag ${mode.patched ? "patched" : "unpatched"}`, mode.patched ? `Patched · ${mode.run}` : "Unpatched"),
      el("span", "iq-time", new Date().toLocaleTimeString()));
    if (result) head.append(el("span", `iq-outcome ${outcome}`, OUTCOMES[outcome]));
    const body = el("div", "iq-body");
    body.append(el("div", "iq-question", question),
      el("pre", "iq-answer", result ? result.answer || "(no answer)" : "Asking the agent…"));
    if (result) {
      const queries = el("div", "iq-queries");
      for (const q of result.queries) {
        const row = el("div", "iq-query");
        row.append(el("code", "", q.sql), el("span", "", q.rows === null ? "ran" : `${q.rows} row${q.rows === 1 ? "" : "s"}`));
        queries.append(row);
      }
      for (const q of result.stopped) {
        const row = el("div", "iq-query stopped");
        row.append(el("code", "", q.sql), el("span", "", `stopped by ${q.by || "the defense"}`));
        queries.append(row);
      }
      const count = result.queries.length + result.stopped.length;
      if (count) body.append(el("div", "iq-section", `Queries the agent tried · ${count}`), queries);
      if (outcome === "leak") body.append(el("div", "iq-proof", `Proof · ${result.detail}`));
    }
    article.append(head, body);
    return article;
  }

  $("iqMode").addEventListener("click", (event) => {
    const option = event.target.closest(".iq-mode-option");
    if (option && !option.disabled) setMode(option.dataset.patched === "true");
  });

  $("iqQuestion").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) $("iqForm").requestSubmit();
  });

  $("iqForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const question = $("iqQuestion").value.trim(), select = $("iqVendor");
    if (asking || !question || !select.value) return;
    const vendor = select.options[select.selectedIndex].textContent;
    const mode = { patched, run: defense ? defense.run : null };
    asking = true;
    $("iqAsk").disabled = true;
    showMessage("");
    const pending = card(vendor, question, mode, null);
    $("iqResults").prepend(pending);
    try {
      const response = await fetch("/inquiry", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vendor_id: Number(select.value), question, patched: mode.patched }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The agent could not answer.");
      pending.replaceWith(card(vendor, question, { patched: data.patched, run: data.run }, data));
      $("iqQuestion").value = "";
    } catch (error) {
      pending.remove();
      showMessage(error.message || "The agent could not answer.", true);
    } finally {
      asking = false;
      $("iqAsk").disabled = false;
      const results = $("iqResults");
      while (results.children.length > MAX_CARDS) results.lastElementChild.remove();
      if (!results.children.length && !$("iqMessage").classList.contains("error")) {
        showMessage("Ask a question to see the agent's answer and every query it ran.");
      }
    }
  });

  window.loadInquiry = loadInquiry;
})();
