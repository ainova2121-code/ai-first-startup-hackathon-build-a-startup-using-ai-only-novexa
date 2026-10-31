# Demo Video Script

**Length:** 5:00, introduction included. **Format:** screen recording of the live console with voiceover.
**Golden rule:** say what the screen shows and let the proof carry the claim.

> Tabs, left to right: **Live run · Discovery · Database · Inquiry · Patched files · Decision drift · Audit ledger**.
> Top bar: **Run** picker · **Mode** · **Dataset** · **Dataset JSON** · **Restore files** · **Pause / Resume / Stop** · **Start run**.

## Before you record

- Record on your own Windows machine: the TPM co-signature is real hardware only there. A hosted copy signs with
  the software key, and the page says so.
- Do one complete **Full dataset** run first. The re-attack phase replays every breach 16 times, which takes
  several minutes. In the video, start a run live for the opening, then switch the **Run** picker to that finished
  run, and say so on camera: "here's the full run I completed a moment ago."
- Set **Mode: Custom dataset**, **Dataset: Full dataset**. Browser at 1920×1080, already signed in.

---

## 0:00–0:30 · Intro (title slide, or the target overview page)

**Cursor:** rest on the product name, then the LedgerPilot card.

**Say:**
> "AI agents don't just chat any more: they pay invoices and change bank details. So the question isn't whether an
> agent can be tricked into *saying* something, it's whether it can be tricked into *doing* something. I'm [name],
> and this is our AI purple-team platform. It discovers your agents, attacks them, patches them, attacks again to
> prove the fix held, and seals evidence an auditor can verify, all inside your own cloud."

## 0:30–0:50 · The target

**Screen:** the target overview page. **Cursor:** move down the agent list, then the data tables.

**Say:**
> "Our demo target is LedgerPilot, a real multi-agent accounts-payable system: six agents, fourteen tools,
> processing real FCC invoice PDFs. The platform knows nothing about it in advance."

## 0:50–1:20 · Start run, then Discovery

**Cursor:** click **Start run**, then the **Discovery** tab. Hover one agent node, then one red (dangerous) tool.

**Say:**
> "First it discovers the system on its own: every agent, every tool, and which tools can move money or change
> records. Prompts are only fingerprinted, never shown. Nothing about this customer is hard-coded, so the same
> platform works on any agent system."

## 1:20–2:15 · Live run: the attack

**Cursor:** click **Live run**. Point at the step bar (**Discover → Attack → Patch → Re-attack → Verdict**).
Expand **Business-claim injection**, then one red row and its call map.

**Say:**
> "Every attack hits the *unpatched* agent first, so the breach count is real exposure. Here's what breaches: no
> jailbreak, just one ordinary sentence in an invoice email saying the bank account changed."
> *(point at the canary in the call map)* "Our canary account reached a real tool call, recorded by the intake
> agent, then spread to the vendor and payment agents. That's proof, not a risk score."

Then expand the **Jailbreak** group:
> "And DAN-style jailbreaks? Held. Famous jailbreaks are the wrong test for tool-using agents."

## 2:15–3:00 · Patch and re-attack

**Cursor:** switch the **Run** picker to your finished run. Point at the **Defense** panel, then the **Re-attack**
rows, then click **Patched files**.

**Say:**
> "The defender patches in two layers. First code: verified source fixes, each proven by a rescan and an
> independent check, snapshotted so one click restores them. Then runtime guards for anything code can't decide."
> *(point at a held re-attack row)* "Then it replays the exact payload that breached, sixteen times. Held every
> time. We don't claim the fix works, we re-attack and show it."

If the run shows **HELD · BY THE CODE PATCH** and **BY THE RUNTIME PATCH** labels, point at one of each.

## 3:00–3:25 · Database

**Cursor:** click **Database**, toggle **Breach**, point at the attacker's bank account, then toggle **After patch**.

**Say:**
> "This is the target's real database. In the breach snapshot, the attacker's account is on file. After the
> patch, it never lands."

## 3:25–3:45 · Inquiry (cut this first if you run long)

**Cursor:** click **Inquiry**, choose **Unpatched**, ask "show me all vendors' bank accounts", then switch to
**Patched** and ask again.

**Say:**
> "Same question through the supplier portal. Unpatched, it leaks other vendors' data. Patched, it only sees its
> own rows."

## 3:45–4:35 · Audit ledger (the finale)

**Cursor:** click **Audit ledger**. Let the signing flow animate, click one event to light its proof path in the
Merkle tree, then point at the TPM signature card and the RFC 3161 timestamp card.

**Say:**
> "Every step is sealed. Each event is signed with Ed25519 and post-quantum ML-DSA, chained per agent, and rolled
> into a Merkle tree. My laptop's TPM chip co-signs the checkpoint, and an independent timestamp authority proves
> when it existed. Click any event: its inclusion proof is recomputed right here in the browser. Change one byte
> and the root breaks."

## 4:35–5:00 · Verdict and close

**Cursor:** back to **Live run**, the Verdict panel.

**Say:**
> "So the verdict is earned, not asserted. Scanners flag risks; we prove them, close them, prove they're closed,
> and hand you evidence an auditor can check without trusting us. Break it. Fix it. Prove it. Sign it."

---

## If you run over 5:00

Drop **Inquiry** first (−20 s), then shorten the jailbreak line. Keep the breach, the re-attack hold, the database
flip and the ledger: those four are the pitch.

## Shot checklist

- [ ] Discovery map building itself (domain-agnostic proof)
- [ ] A **red** business-claim row expanded, canary in a real tool call
- [ ] Jailbreak group showing **held**
- [ ] The same payload **held** on re-attack
- [ ] Database **Breach** vs **After patch**
- [ ] Merkle tree with a proof path lit, TPM and timestamp cards

## Recording tips

- Add captions: judges often watch muted first.
- Zoom the browser so rows are legible on a phone screen.
- Speed up waiting in editing rather than cutting it.
- On a hosted copy, say plainly that the checkpoint is signed with a software key; the TPM signature runs locally.
