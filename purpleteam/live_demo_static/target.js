// About page: the target in its owner's own words, then one button that starts the assessment. Discovery is not
// run here -- it runs once, in the run, live in the Discovery tab. Text is set with textContent, never as HTML.
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const STAGGER_MS = 140;  // each paragraph rises a beat after the one before

  function paragraph(text, index) {
    const node = document.createElement("p");
    node.className = index === 0 ? "ab-lead" : "";
    node.style.animationDelay = `${180 + index * STAGGER_MS}ms`;
    node.textContent = text;
    return node;
  }

  async function load() {
    try {
      const response = await fetch("/target/about", { cache: "no-store" });
      if (!response.ok) throw new Error();
      const data = await response.json();
      document.title = `purpleteam — ${data.title}`;
      $("abTitle").textContent = data.title;
      $("abStory").replaceChildren(...data.paragraphs.map(paragraph));
    } catch {
      $("abTitle").textContent = "Target under test";
      $("abStory").replaceChildren(paragraph("Its description could not be read right now. You can still start the "
        + "assessment: discovery will show what the target is built from.", 0));
    }
  }

  load();
})();
