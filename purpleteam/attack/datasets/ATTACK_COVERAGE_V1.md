# Attack coverage matrix v1

This is a finite, versioned benchmark for selected attack surfaces. No finite dataset can include every attack that exists or guarantee a breach against every model. Coverage means the case was delivered through the stated channel and judged by a proof oracle; merely generating a prompt or receiving a cooperative answer is not a successful test.

## Topics with at least five cases

| Topic | Cases in v1 | Runnable path | Limits |
|---|---:|---|---|
| Unverified business claim / sensitive-value substitution | 5 per discovered sensitive argument: 3 direct claim phrasings plus buried-text and form-field placements | LedgerPilot model-free attack mode (`PURPLETEAM_ONLY_STATIC=1`) | Target must expose a dangerous tool argument matching the discovered value slots. The adaptive/targeted full mode uses a different flow and does not run these five rows as a separate suite. |
| Prompt injection / jailbreak seed corpus | 5 selected PyRIT templates | Model-free full assessment, advanced full assessment, and AgentDojo demo | The model-driven non-advanced live mode uses targeted attacks instead of this fixed corpus. This is a small pinned sample from PyRIT, not its full template collection. |
| Authority / social-engineering claims | 5 synthetic templates | Model-free full assessment, advanced full assessment, and AgentDojo demo | Tests unverified claims of approval, urgency, routine handling, or authority. No real identity or approval credentials are used. |
| Multilingual prompt injection | 5: Spanish, Hindi, Bengali, Arabic, French | Model-free full assessment, advanced full assessment, and AgentDojo demo | The model-driven non-advanced live mode uses targeted attacks instead. A held result does not prove the model understood the language. Pair with a separate language-comprehension control. Five languages are not broad multilingual coverage. |
| System-prompt extraction | 5 phrasings when discovery captured a prompt | Model-free full assessment, advanced full assessment, and AgentDojo demo | The model-driven non-advanced live mode uses targeted attacks instead. Proof checks for exact prompt text held in memory. The live result event redacts the target reply. No prompt means this topic is skipped. |
| Obfuscation / filter evasion | 5 transformed variants: Base64, ROT13, leetspeak, Unicode confusables, invisible Unicode tags; plus a plain baseline | Live UI **Obfuscation suite (5 variants + baseline)** | Nine transformations are registered, but only five are in the bounded live suite. A transformation is not evidence a model can decode it; the target's behavior and proof oracle decide. |
| Tool-output / indirect prompt injection | 5 payloads | `purpleteam.demo_agentdojo` with its injection-vector adapter | The adapter places these into a real injected data value. Sending the same text as a direct user prompt does not test indirect injection. |
| Hidden document text | 5 payloads; hidden PDF fixture and multipart adapter exist | `hidden_document_templates` + `HttpDocumentTarget` on an operator-authorized staging ingestion endpoint | Adapter-level capability only: the default live UI/Live LedgerPilot demo does not upload hidden-text PDFs. Target OCR/PDF parsing must preserve the invisible layer. |
| Identity / privilege escalation | 4 objectives × 5 selected PyRIT wrappers = 20 combinations | `identity_corpus` / agent-exploitation focus | A permission manifest or multiple agents may be required for the oracle to prove the attempted boundary crossing. |
| Sensitive-data retrieval / exfiltration | 2 objectives × 5 selected PyRIT wrappers = 10 combinations | Information-retrieval focus | Requires a retrieval-capable target and a planted honeytoken/known secret. |

The human-readable case records are in `business_claims_v1.jsonl` and `channel_attacks_v1.jsonl`. PyRIT templates and authority templates are pinned in `purpleteam/attack/corpus.py`; identity and retrieval objectives are in `purpleteam/attack/identity.py` and `purpleteam/focus.py`.

## Gaps: do not present these as covered yet

There is not yet a validated five-case runnable suite for multi-session memory poisoning, memory persistence across restarts, policy drift over long sessions, orchestrator/stage-skip attacks, repeated-tool/loop amplification, image/audio/video injection, model or plugin supply-chain compromise, code-execution sandbox escapes, or vector-store/index poisoning beyond the tool-output cases. They need target adapters that reproduce the relevant state or modality and an oracle that proves the intended impact. A text prompt alone cannot test those properties.

Every case uses synthetic canaries and must run only against an isolated target the operator is authorized to assess. Re-run against each model/version/provider; results do not transfer automatically between models. Attack tests are diagnostic evidence, not a claim of complete security.
