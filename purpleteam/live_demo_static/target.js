// Landing page after sign-in: what purpleteam does (an animated purple-team cycle), then a target picker. Choosing a
// target shows it in its owner's words and the Start button, which opens Discovery and starts the run there.
// Nothing here runs discovery or calls a model. Text is set with textContent, never as HTML.
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const SVG = "http://www.w3.org/2000/svg";
  const CX = 160, CY = 160, R = 118, STEP_MS = 2600;
  const NODES = [["Discover", "#7FB2F2"], ["Attack", "#E0534F"], ["Patch", "#4C93EC"], ["Verify", "#9B8AF0"],
    ["Sign", "#3FB96B"]];
  const calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const angleOf = (i) => (-90 + i * (360 / NODES.length)) * (Math.PI / 180);
  const svg = (tag, attrs) => {
    const node = document.createElementNS(SVG, tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    return node;
  };

  // -- the cycle: five nodes on a ring, a runner going round, the matching step lit beside it ---------------
  const nodes = NODES.map(([label, color], i) => {
    const a = angleOf(i), x = CX + R * Math.cos(a), y = CY + R * Math.sin(a);
    const group = svg("g", { class: "ab-node", style: `--node:${color}` });
    group.append(svg("circle", { cx: x, cy: y, r: 19, class: "ab-node-disc" }),
      Object.assign(svg("text", { x, y: y + 4, "text-anchor": "middle", class: "ab-node-num" }), { textContent: `0${i + 1}` }));
    const lx = CX + (R + 36) * Math.cos(a), ly = CY + (R + 36) * Math.sin(a) + 4;
    const caption = svg("text", { x: lx, y: ly, "text-anchor": Math.abs(lx - CX) < 8 ? "middle" : lx > CX ? "start" : "end",
      class: "ab-node-label" });
    caption.textContent = label;
    group.append(caption);
    $("abNodes").append(group);
    return group;
  });
  const steps = [...document.querySelectorAll("#abSteps li")];
  const runner = document.querySelector(".ab-runner");
  let held = null;  // a step the reader pointed at: the cycle waits on it

  function light(index) {
    nodes.forEach((node, i) => node.classList.toggle("on", i === index));
    steps.forEach((step, i) => step.classList.toggle("on", i === index));
  }

  function place(turn) {  // turn: 0..NODES.length, the runner's position in node units
    const a = angleOf(turn);
    runner.setAttribute("cx", CX + R * Math.cos(a));
    runner.setAttribute("cy", CY + R * Math.sin(a));
  }

  steps.forEach((step, i) => {
    step.addEventListener("mouseenter", () => { held = i; light(i); place(i); });
    step.addEventListener("mouseleave", () => { held = null; });
  });

  if (calm) {
    light(0);
    place(0);
  } else {
    let started = performance.now(), pausedAt = 0;
    const frame = (now) => {
      if (held !== null) {
        pausedAt = pausedAt || now;
      } else {
        if (pausedAt) { started += now - pausedAt; pausedAt = 0; }
        const turn = ((now - started) / STEP_MS) % NODES.length;
        place(turn);
        light(Math.floor(turn + 0.5) % NODES.length);  // a node lights as the runner arrives at it
      }
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  }

  // -- target picker -------------------------------------------------------------------------------------
  function card(target) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ab-target-card";
    button.setAttribute("role", "radio");
    button.setAttribute("aria-checked", "false");
    const name = document.createElement("span"), blurb = document.createElement("span"), mark = document.createElement("span");
    name.className = "ab-card-name";
    name.textContent = target.title;
    blurb.className = "ab-card-blurb";
    blurb.textContent = (target.paragraphs[0] || "").split(/(?<=\.)\s/)[0];
    mark.className = "ab-card-mark";
    mark.setAttribute("aria-hidden", "true");
    button.append(mark, name, blurb);
    button.addEventListener("click", () => choose(target, button));
    return button;
  }

  function choose(target, button) {
    document.querySelectorAll(".ab-target-card").forEach((b) => b.setAttribute("aria-checked", String(b === button)));
    $("abTargetTitle").textContent = target.title;
    $("abTargetStory").replaceChildren(...target.paragraphs.map((text, i) => {
      const p = document.createElement("p");
      p.className = i === 0 ? "ab-story-lead" : "";
      p.textContent = text;
      return p;
    }));
    const section = $("abTarget");
    section.classList.remove("hidden");
    section.classList.remove("reveal"); void section.offsetWidth; section.classList.add("reveal");
    section.scrollIntoView({ behavior: calm ? "auto" : "smooth", block: "start" });
  }

  fetch("/targets", { cache: "no-store" })
    .then((response) => { if (!response.ok) throw new Error(); return response.json(); })
    .then((targets) => $("abTargets").replaceChildren(...targets.map(card)))
    .catch(() => $("abTargetsError").classList.remove("hidden"));
})();
