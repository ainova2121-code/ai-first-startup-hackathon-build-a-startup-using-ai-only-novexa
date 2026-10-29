"use strict";

// Large visualizations (the discovery map, the Merkle tree, the signing flow): full screen, and drag to pan.

// ⛶ on a panel fills the screen with it: the browser's own full screen where allowed, else the panel fills the
// window (an embedded viewer may refuse full screen). Esc or ✕ always leaves it.
const expanded = () => document.fullscreenElement || document.querySelector("[data-fullscreen].expanded");
function syncExpand() {
  const on = expanded();
  document.body.classList.toggle("has-expanded", Boolean(on));
  document.querySelectorAll(".expand-btn").forEach((b) => {
    const mine = b.closest("[data-fullscreen]") === on;
    b.textContent = mine ? "✕" : "⛶";
    b.title = mine ? "Leave full screen (Esc)" : "Full screen";
  });
  window.dispatchEvent(new Event("resize"));  // the discovery map lays itself out for the new size
}
function leaveExpand() {
  if (document.fullscreenElement) document.exitFullscreen();
  document.querySelectorAll("[data-fullscreen].expanded").forEach((p) => p.classList.remove("expanded"));
  syncExpand();
}
document.addEventListener("click", async (ev) => {
  const button = ev.target.closest(".expand-btn");
  if (!button) return;
  const panel = button.closest("[data-fullscreen]");
  if (expanded()) { leaveExpand(); return; }
  // Some viewers neither grant nor refuse (a pending permission): give it a moment, then fill the window instead.
  const granted = await Promise.race([panel.requestFullscreen().then(() => true, () => false),
                                      new Promise((resolve) => setTimeout(() => resolve(false), 400))]);
  if (!granted && !document.fullscreenElement) panel.classList.add("expanded");
  syncExpand();
});
document.addEventListener("fullscreenchange", () => {  // granted late: the real full screen replaces the fallback
  if (document.fullscreenElement) document.querySelectorAll("[data-fullscreen].expanded").forEach((p) => p.classList.remove("expanded"));
  syncExpand();
});
document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && expanded()) leaveExpand(); });

// Drag anywhere on a wide visualization to move it left, right, up or down. A press that does not move still
// clicks what is under it; the click that ends a drag is swallowed so it never opens a node by accident.
const PANNABLE = ".dm-scroll, .mx-scroll, .sf-scroll";
let pan = null;
const scrollsY = (node) => node && node.scrollHeight > node.clientHeight + 1;

document.addEventListener("pointerdown", (ev) => {
  const area = ev.pointerType === "mouse" && ev.button === 0 && ev.target.closest(PANNABLE);
  if (!area) return;
  // Up and down move whichever of these actually scrolls: the area, the full-screen panel, else the page.
  pan = { area, vertical: [area, expanded()].find(scrollsY) || null, x: ev.clientX, y: ev.clientY, id: ev.pointerId, moved: false };
});
document.addEventListener("pointermove", (ev) => {
  if (!pan || ev.pointerId !== pan.id) return;
  const dx = ev.clientX - pan.x, dy = ev.clientY - pan.y;
  if (!pan.moved) {
    if (Math.hypot(dx, dy) < 5) return;
    pan.moved = true;
    pan.area.setPointerCapture(pan.id);
    document.body.classList.add("panning");
    window.getSelection()?.removeAllRanges();
  }
  pan.area.scrollLeft -= dx;
  if (pan.vertical) pan.vertical.scrollTop -= dy; else window.scrollBy(0, -dy);
  pan.x = ev.clientX; pan.y = ev.clientY;
});
function endPan(ev) {
  if (!pan || ev.pointerId !== pan.id) return;
  if (pan.moved) {
    document.body.classList.remove("panning");
    const swallow = (click) => { click.stopPropagation(); click.preventDefault(); };
    window.addEventListener("click", swallow, { capture: true, once: true });
    setTimeout(() => window.removeEventListener("click", swallow, { capture: true }), 0);
  }
  pan = null;
}
document.addEventListener("pointerup", endPan);
document.addEventListener("pointercancel", endPan);
