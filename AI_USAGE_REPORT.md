# AI Usage Report

**Project:** AIQ Security — an autonomous AI purple-team platform for AI agent systems (B2B, bring-your-own-cloud), with a deliberately vulnerable accounts-payable multi-agent system ("LedgerPilot") as the demo target.
**Team:** Novexa · HackIndia — AI-First Startup Hackathon

## Summary

This product was built **AI-first**. AI was the primary builder across the entire lifecycle — ideation, market and competitor research, architecture, data sourcing, coding, testing, cryptography, security/compliance research, UI/UX, the pitch deck, and this demo. The human founder set the direction and made every product decision; AI did the building. **About 99% of the code and written artifacts in this repository were AI-generated**, satisfying the hackathon's AI-first requirement.

Beyond *being built* with AI, the product *is* AI: it runs an AI red-team engine (PyRIT) and ML guardrail classifiers at runtime, and it writes most of its own attacks from the target's discovered tool schema.

## AI tools used

| Tool | Role in the project |
|---|---|
| **Claude (Opus, via Claude Code)** | Primary builder — research, architecture, all code, tests, docs, UI, the live console, the pitch deck, the demo script |
| **Claude Skill: orchestrating-llm-attacks-with-pyrit** | Guided the attack engine (PyRIT orchestrators, scorers, converters) |
| **Claude Skill: defending-llms-with-guardrails** | Guided the defender (LLM Guard / Llama Guard integration) |
| **Claude Artifacts + design skills** | The live attack→defend console and the architecture diagram |
| **Claude Code + the PowerPoint skill** | The 13-slide pitch deck (`demo/novexa-pitch-deck.pdf` / `.pptx`, shown in the README) and the captioned demo video |
| **AI web research (via Claude)** | Competitor analysis, market sizing, white-space analysis, EU AI Act / DORA / DPDP legal research |
| **Microsoft PyRIT 1.1.0** | AI-driven adversarial red-teaming — *in the product* |
| **Protect AI LLM Guard (DeBERTa classifier)** | ML prompt-injection detection — *in the product* |
| **OpenAI-compatible LLM endpoint (hosted `gpt-oss-20b` for the demo)** | Drives the LedgerPilot target agents; the platform works against any OpenAI-compatible model |

## AI across the product lifecycle

**1. Ideation & problem framing.** AI helped refine the concept into a focused B2B, BYOC purple-team platform for agentic AI, chose the accounts-payable target (business-email-compromise is a billions-per-year fraud class), and shaped the domain-agnostic, proof-first positioning.

**2. Market & competitor research.** AI researched the live competitive landscape with sources — Lakera→Check Point, Protect AI→Palo Alto, Robust Intelligence→Cisco, Straiker, and others — plus market sizing and white-space analysis, to sharpen the differentiation: proof-based detection, a patch-and-re-verify loop, and cryptographic evidence, rather than detection scores alone.

**3. Architecture.** AI designed the whole platform: the Target adapter seam, auto-discovery, the proof-based oracle (canary + honeytoken), the attack engine, the defender (reviewed guard catalog + verified source codemods), the verifier, the signed audit ledger, the policy-decision-drift guard, and the BYOC gateway.

**4. Data.** AI sourced a **real** invoice dataset (FCC public-file invoices), curated the usable invoices, and **verified every curated field against the source PDFs** — no fabricated data.

**5. Coding.** AI wrote essentially all the code: LedgerPilot's gated LangGraph pipeline (intake → vendor → matching → approval → payment), and the `purpleteam` platform — discovery, adapter, proof oracle, the PyRIT-backed attack engine (incl. model-free attacks written from the discovered schema, obfuscation converters, system-prompt extraction and tool-output injection), the defender with real LLM Guard, the verifier, the cryptographic audit ledger, the provenance guard, and the BYOC gateway.

**6. Cryptographic evidence.** AI built the full evidence stack: per-event hybrid signatures (**Ed25519 + ML-DSA-65**, post-quantum-ready), per-actor hash chains, an **RFC 6962 Merkle checkpoint**, a **TPM 2.0 (Windows) hardware co-signature** with an honestly-labelled software fallback for hosts without a TPM, and an **RFC 3161** independent timestamp — all re-verifiable in the viewer's own browser.

**7. Testing.** AI wrote the test suite (**1,400+ automated tests**) using the real FCC invoice PDFs through the API with a scripted deterministic model, so tool-call sequences are reproducible and no model credits are spent. It ran live attack/defend campaigns end to end, including the headline case: ordinary business-claim injection that pays an attacker account on the unpatched agent, then held after patching and re-attack with the same payloads.

**8. Security & compliance research.** AI mapped the platform to the EU AI Act, NIST AI RMF, DORA, ISO 42001 and OWASP LLM, and researched applicable laws (GDPR, India DPDP, Cyber Resilience Act).

**9. UI/UX, deck & demo.** AI built the live console (Live run · Discovery · Database · Inquiry · Patched files · Decision drift · Audit ledger), with the animated Merkle tree and signing flow; produced the architecture diagram; built the 13-slide pitch deck from the live run's verified results; and wrote the tab-by-tab demo video script.

## Representative prompts / workflow

The build was driven by iterative founder direction and AI execution. Representative founder prompts:

- "Build an autonomous AI purple-team: attacker attacks, defender applies patches, a verifier confirms behaviour isn't broken, plus a signed, tamper-evident audit trail."
- "The purple team must plug into any multi-agent system — auto-discover its agents and purpose; no domain hard-coding."
- "Use a real PDF dataset so everything is real."
- "There should be maximum honest breaches — show the agent's true exposure."
- "Build an attempt detector — flag when the agent was persuaded but a control stopped it."
- "Add system-prompt extraction, tool-output injection, and obfuscation families."
- "Make TPM signing optional for the hosted URL, but never label software signing as hardware."
- "Make the signing flow as premium as the Merkle trees."

Each produced research, design, code, and tests from AI, reviewed and steered by the founder.

## Evidence

- **Git attribution:** Claude is the author or co-author (`Co-Authored-By: Claude`) of most commits in this repository.
- **Tests:** 1,400+ automated tests across the platform.
- **This repository:** the structure, code, tests, data curation, cryptography, UI, deck and docs were AI-generated.

## Honest scope — the human role, and what is built vs. designed

- **The human founder** provided all direction and product decisions, ran the terminal, supplied API keys, and contributed a *separate* earlier project of their own, used **read-only as a reference** — its code was **not** copied into this repository.
- **Built and tested:** LedgerPilot, discovery, the attack engine (incl. model-free, obfuscation, extraction, tool-output injection), the proof oracle, the defender (incl. real LLM Guard and the provenance guard), the verifier, the cryptographic audit ledger (hybrid signatures, Merkle, TPM/software signer, RFC 3161), policy-decision drift, and the BYOC gateway.
- **One honesty guarantee worth stating plainly:** software-key signatures are never presented as hardware. Where no TPM is present (e.g. a hosted demo), the ledger labels the key as software and the hardware-required verification correctly rejects it. The local demo uses a real TPM.
- **Deployed:** the live demo runs on Hugging Face Spaces (https://aishwaryar24-hackathon-purple-teaming.hf.space).
- **Designed / in progress:** roadmap research (memory poisoning, MCP/tool-description poisoning, and an attacker model trained by the oracle via RLAIHF).

We have kept this report accurate rather than inflated: AI did the overwhelming majority of the building, the product genuinely runs, and we are transparent about what is complete versus planned.
