# AIQ Security — Demo Video Script

**Target length:** 3–5 min (this runs ~4:15). **Format:** screen recording of the live console with voiceover.
**Golden rule:** say what the screen shows, let the proof carry the claim. Don't oversell — the artifacts do the talking.

> Tabs, left to right: **Live run · Discovery · Patched files · Decision drift · Audit ledger**.
> Before recording: `uv run uvicorn --factory ledgerpilot.main:create_app` on the target, start the console, set mode to **Full**, attack type **Full assessment**, and have the browser already signed in (past the "Enter the demo" page). Do a dry run once so the cache is warm and the full run lands in ~3 min.

---

## 0:00 — Cold open (hook)  ~20s

**On screen:** console at the **Live run** tab, idle. `target not yet discovered` chip visible.

**VO:**
> "AI agents don't just chat anymore — they pay invoices, move money, change records. So the real question isn't *can my agent be tricked into saying something* — it's *can it be tricked into **doing** something*.
>
> This is AIQ Security. It attacks your agent, patches it, attacks it again to prove the fix held, and seals cryptographic evidence an auditor can verify. Let me show you — live, on a real agent, in about three minutes."

**Action:** click **Start run**.

---

## 0:20 — Discovery tab  ~40s

**On screen:** the console auto-jumps to **Discovery**. The map builds node by node; the **Discovery events** feed streams on the right; the `target` chip fills in.

**VO:**
> "First it discovers the target on its own — no configuration. It watches real traffic and draws the agent graph: every agent, every tool, every handoff.
>
> Notice we never hard-coded anything about this customer. The platform is domain-agnostic — point it at *any* agent system and it learns the shape itself. Green nodes it actually exercised, the others it found but hasn't run yet.
>
> And prompts are fingerprinted, never shown — so we can prove what we tested without leaking the customer's IP."

**Action:** hover one node to show the detail card; let the posture findings populate underneath. Then the run auto-returns to **Live run**.

> *If asked why discovery matters:* "This is what lets us attack a system we've never seen — the attacks are written from the target's own discovered tool schema."

---

## 1:00 — Live run tab — Attack console  ~60s

**On screen:** auto-returned to **Live run**. Left panel **Attack console** fills with grouped, collapsible attack sections (Prompt injection, Jailbreak, Business-claim injection, Obfuscation, …). Breaches turn red; persuaded-but-stopped turn amber.

**VO:**
> "Now the attacks. Every one of these runs against the **unpatched** agent first, so the breach count is the agent's true exposure — not a number we flatter.
>
> They're grouped by technique — expand any one to watch it fire. Here's the part most tools get wrong:" *(expand the classic jailbreak group)* "the famous jailbreaks — DAN, roleplay, 'ignore previous instructions' — all of them *held*. Zero breaches.
>
> But watch this —" *(expand Business-claim injection, point at a red row)* "a single ordinary-looking line buried in an invoice tells the agent to pay a different account. No jailbreak. And the agent pays the attacker.
>
> That red row isn't a risk score. It's a **breach**: our canary account — `US00ATTACKER0666` — reached the arguments of a real payment tool call. That's a hard artifact. It either happened or it didn't."

**Action:** point at an amber row.

**VO:**
> "Amber means the agent was *persuaded* — it tried the attacker's call — but a control stopped it before it landed. We report that too, because 'nearly breached' is something a security team needs to know."

---

## 2:00 — Live run tab — Defense panel  ~40s

**On screen:** right panel **Defense** fills as patches attach; the step bar advances to re-attack; red rows flip to held on the second pass.

**VO:**
> "Then it defends. Runtime guards snap in without touching a single file. Where a source fix is needed, it's a verified codemod — exact-match, independently checked, and labelled as machine-generated, never silently shipped.
>
> And here's the loop that makes this real: it re-runs **the same attacks** against the patched agent." *(point as rows flip)* "The invoice attack that paid the attacker a moment ago — now held. We don't claim the fix works. We re-attack and show it."

---

## 2:40 — Live run tab — Verdict  ~20s

**On screen:** **Verdict** panel appears with the gate list and scorecard.

**VO:**
> "That gives us a verdict. 'Safe to ship' is *earned*, not asserted — it stays withheld until the edited target is reloaded, re-attacked, and the evidence chain verifies. Every number here is from this run."

---

## 3:00 — Patched files tab  ~25s

**On screen:** click **Patched files**. Each edited file shown whole, change in place. Point at the **Restore original files** button in the top bar.

**VO:**
> "Every file the platform actually edited is shown here in full, with the change in place — nothing hidden in a diff. And it's all reversible: one click on **Restore original files** puts every byte back. We snapshot the original before we touch it, so a customer can run us against production code without fear."

---

## 3:25 — Decision drift tab  ~20s

**On screen:** click **Decision drift**. Show the pinned decisions and the "what if a patch were removed?" control.

**VO:**
> "We also pin every decision the verified defense made — every call allowed, held, or blocked — with its exact inputs. If someone later loosens a policy on an input we already proved was an attack, the gateway refuses to enforce it. Security can't quietly regress."

---

## 3:45 — Audit ledger tab (the finale)  ~30s

**On screen:** click **Audit ledger**. The **Merkle tree** renders; the **signing flow** animates; the checkpoint and RFC 3161 anchor cards show. Click one event to light its proof path.

**VO:**
> "And everything is sealed. Every event is signed — Ed25519 *and* post-quantum ML-DSA — chained per actor, and rolled into a Merkle checkpoint. A hardware TPM co-signs it, and an independent RFC 3161 timestamp proves when it existed.
>
> Click any event" *(click one)* "and the inclusion proof recomputes right here in the browser. Change one byte anywhere and the root breaks. This is evidence you can hand an auditor — and verify without trusting us."

> *Honesty note for Q&A:* if the live deployment runs the software signer instead of a TPM, say so — "on our hosted demo this is a software key, honestly labelled; the hardware TPM co-signature runs on the local demo." Never call software 'hardware'.

---

## 4:15 — Close  ~15s

**On screen:** back to the Verdict, or the one-liner slide.

**VO:**
> "Scanners flag risks. We prove them, close them, and prove they're closed — with evidence you can take to an auditor. Break it. Fix it. Prove it. Sign it. That's AIQ Security."

---

## Shot checklist (capture these no matter what)
- [ ] Discovery map building itself (domain-agnostic proof)
- [ ] A **red** breach row expanded — canary in a real tool call
- [ ] Classic jailbreaks group showing **held / 0 breaches**
- [ ] An **amber** persuaded-but-stopped row
- [ ] The same attack flipping **breached → held** on re-attack
- [ ] Verdict panel with real numbers
- [ ] Patched file shown whole + Restore button
- [ ] Merkle tree with a proof path lit + signing flow animating

## If you have to cut to 3:00
Drop **Decision drift** (3:25) and trim the Defense panel VO. Keep Discovery, the breach, the re-attack flip, and the ledger — those four are the pitch.

## Recording tips
- Record at 1920×1080, console in full-window; zoom the browser so rows are legible on a phone screen.
- Keep each reply under 30s so the recording stays tight (the run is tuned for this).
- One continuous take of the run is more convincing than cuts — the live loop *is* the demo.
- Add captions; judges often watch muted first.
