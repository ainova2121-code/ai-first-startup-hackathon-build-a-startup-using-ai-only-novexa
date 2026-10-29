// Merkle tree zoom. Three modes:
//   focus  (default) -- readable, centred on the event being signed (or the reader's chosen one): just its path
//                       from leaf to root fills the view, and the view follows each new signature;
//   fit              -- the whole tree fits the panel's width;
//   manual           -- the mouse wheel zooms around the cursor (up zooms in, down zooms out), − / + around the
//                       centre; the reader's zoom then holds until they press Focus or Fit.
// Focus and fit re-apply as the tree grows and when the panel goes full screen.
"use strict";

const MX_ZOOM = { value: 0.6, min: 0.02, max: 1.5, mode: "focus", focus: null };

const mxParts = () => {
  const scroller = document.querySelector("#merkleTree .mx-scroll");
  return { scroller, canvas: scroller && scroller.querySelector(".mx-canvas") };
};
const mxClamp = (z) => Math.min(MX_ZOOM.max, Math.max(MX_ZOOM.min, z));
const mxFitZoom = (scroller, canvas) => mxClamp((scroller.clientWidth - 8) / parseFloat(canvas.style.width));
const mxFocusZoom = (scroller, focus) => Math.min(0.8, Math.max(0.3, (scroller.clientWidth - 40) / (focus.right - focus.left)));

function mxShowZoom() {
  const label = $("mxZoomLabel");
  if (label) label.textContent = `${Math.round(MX_ZOOM.value * 100)}%`;
  for (const mode of ["fit", "focus"]) document.querySelector(`[data-mx-zoom="${mode}"]`)?.classList.toggle("on", MX_ZOOM.mode === mode);
}

// Centre the path; if it is wider than the view even at the smallest readable zoom, the leaf stays fully in view.
function mxCenter(scroller, focus, smooth) {
  const z = MX_ZOOM.value, width = scroller.clientWidth;
  let left = ((focus.left + focus.right) / 2) * z - width / 2;
  left = Math.min(left, focus.leaf[0] * z - 24);           // the leaf's left edge is not cut off
  left = Math.max(left, focus.leaf[1] * z - width + 24);   // nor its right edge
  requestAnimationFrame(() => scroller.scrollTo({ left: Math.max(0, left), behavior: smooth ? "smooth" : "auto" }));
}

// Called by each render with its fresh scroller and canvas (already on the page, so it can be measured) and the
// horizontal span, in tree units, of the path to keep in view.
function mxApplyZoom(scroller, canvas, focus, smooth) {
  MX_ZOOM.focus = focus;
  if (MX_ZOOM.mode === "fit") MX_ZOOM.value = mxFitZoom(scroller, canvas);
  if (MX_ZOOM.mode === "focus") MX_ZOOM.value = mxFocusZoom(scroller, focus);
  canvas.style.zoom = MX_ZOOM.value;
  mxShowZoom();
  if (MX_ZOOM.mode === "focus") mxCenter(scroller, focus, smooth);
  scroller.addEventListener("wheel", (ev) => {
    if (Math.abs(ev.deltaY) <= Math.abs(ev.deltaX)) return;  // a sideways swipe still scrolls sideways
    ev.preventDefault();
    mxZoomBy(Math.exp(-ev.deltaY * 0.0015), ev.clientX, ev.clientY);
  }, { passive: false });
}

// Zoom by ``factor`` keeping the point under (clientX, clientY) -- default: the view's centre -- where it is.
function mxZoomBy(factor, clientX, clientY, mode = "manual") {
  const { scroller, canvas } = mxParts();
  if (!canvas) return;
  MX_ZOOM.mode = mode;
  const old = MX_ZOOM.value, z = mxClamp(old * factor);
  if (z === old) { mxShowZoom(); return; }
  const view = scroller.getBoundingClientRect();
  const ax = clientX ?? view.left + view.width / 2, ay = clientY ?? view.top + view.height / 2;
  const before = canvas.getBoundingClientRect();
  const x = (ax - before.left) / old, y = (ay - before.top) / old;  // that point, in the tree's own units
  MX_ZOOM.value = z;
  canvas.style.zoom = z;
  mxShowZoom();
  const after = canvas.getBoundingClientRect();
  scroller.scrollLeft += after.left + x * z - ax;
  const dy = after.top + y * z - ay;  // the tree grew or shrank: keep the point at the cursor's height too
  const panel = expanded();  // in full screen the panel scrolls, otherwise the page
  if (panel) panel.scrollTop += dy; else window.scrollBy(0, dy);
}

function mxFit() {
  const { scroller, canvas } = mxParts();
  if (canvas) mxZoomBy(mxFitZoom(scroller, canvas) / MX_ZOOM.value, undefined, undefined, "fit");
}

function mxFocus() {
  const { scroller, canvas } = mxParts();
  if (!canvas || !MX_ZOOM.focus) return;
  MX_ZOOM.mode = "focus";
  MX_ZOOM.value = mxFocusZoom(scroller, MX_ZOOM.focus);
  canvas.style.zoom = MX_ZOOM.value;
  mxShowZoom();
  mxCenter(scroller, MX_ZOOM.focus, true);
}

document.addEventListener("click", (ev) => {
  const how = ev.target.closest("[data-mx-zoom]")?.dataset.mxZoom;
  if (how === "fit") mxFit();
  else if (how === "focus") mxFocus();
  else if (how) mxZoomBy(how === "in" ? 1.25 : 0.8);
});
window.addEventListener("resize", () => { if (MX_ZOOM.mode === "fit") mxFit(); else if (MX_ZOOM.mode === "focus") mxFocus(); });
