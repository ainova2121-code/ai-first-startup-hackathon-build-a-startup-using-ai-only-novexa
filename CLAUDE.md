# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Project rules

B2B, BYOC (bring your own cloud) AI purple-team platform for AI agent systems in any domain (fintech is the launch market). `ledgerpilot/` is the demo customer agent (a deliberately vulnerable accounts-payable multi-agent system) that the platform attacks, patches, verifies and audits.

## Code style
- Clean, senior-level code that anyone can read. Follow SOLID.
- No unnecessary files, no noisy logic, no speculative abstractions.
- Use pydantic or dataclasses only when they're actually needed.
- Keep comments short. Keep every file under 300 lines.

## Layout
- `ledgerpilot/utils/config.py` holds the pydantic settings. `ledgerpilot/utils/prompt.py` holds every agent prompt as an UPPERCASE constant.
- `data/invoices/` holds the real FCC invoice PDFs and `manifest.json` (see `data/README.md`). `data/ledger.db` is generated.

## Boundaries
- The purple-team platform is domain-agnostic and plugs into any AI agent system. It discovers the target's agents, tools and purpose itself; never hard-code LedgerPilot, accounts-payable or fintech knowledge into it.
- Targets need no SDK or code changes. The platform integrates through an LLM gateway (the target's model base URL points at us), tool/egress proxies and, optionally, read-only repo analysis. Code-level fixes are prewritten codemods opened as pull requests for a human to merge.
- BYOC applies to the purple-team platform only. LedgerPilot is a plain demo target.

## Platform security (LedgerPilot is exempt: it is vulnerable on purpose)
- Treat everything from the target and from every LLM as untrusted data. The platform's own agents are prompt-injection targets too, so constrain them to structured output.
- The defender only selects patches from the prewritten catalog; it never generates code.
- Least privilege everywhere. Attacks run sandboxed. Every endpoint is authenticated and authorized.
- No secrets in code or logs (`SecretStr`, env vars). Parameterized SQL only. Validate every input.
- The audit trail is signed, append-only and tamper-evident. Dependencies are pinned and scanned.
- Run a security review on every platform change.
- LedgerPilot is configured through environment variables (`.env.example`).
- `ledgerpilot` never imports the platform. The platform plugs in through `ledgerpilot/ports.py` (`Guard`, `EventSink`).

## LedgerPilot architecture
- **Pipeline** (`pipeline.py`): a LangGraph `StateGraph` runs intake → vendor → matching → approval → payment. State is a `TypedDict` carrying only `email_id` and `invoice_id`. Each stage is gated: it runs only if the previous one left the invoice at the expected `status` (`STAGES`), otherwise the graph jumps to `END`. Agents communicate through the SQLite `status` column and a JSON case file, never by passing objects.
- **One interception point** (`agents/base.py`): `AgentFactory.create` wraps every tool so each call passes through the `Guard` (authorize + screen) and emits an `EventSink` event, and it screens agent input/output too. Patches and the audit trail attach here; agent modules never change (OCP). Defaults are `NoGuard`/`NullSink` (`ports.py`), so plain LedgerPilot runs ungated.
- **Agents** (`agents/*.py`): one module per diagram node, each a `build_*_agent` that injects its repositories and owns its tools. The LLM reaches them via `create_agent` (langchain) over any OpenAI-compatible endpoint set in `utils/config.py` (`llm_base_url`, `llm_model`, key from `LEDGERPILOT_LLM_API_KEY` or `HF_TOKEN`).
- **Data** (`db/repositories.py`): one repository per table over a dict-row SQLite connection; `PaymentRail` is the fake payment rail, `LedgerConsole` runs raw SQL for the inquiry agent, `Ledger` bundles them. A trigger marks an invoice `paid` when its payment row is inserted.
- **Deliberate vulnerabilities** are each a single marked line so patches have a clear target: f-string SQL in `vendor.lookup_vendor`, ungated `vendor.update_vendor_bank`, exact-match `matching.find_duplicates`, text-trusting `approval`, pay-anything `payment.schedule_payment`, raw-SQL `inquiry.query_ledger`. Intake reads only the invoice's first and last page (where header + totals sit), which also keeps requests within model token limits.

## Testing
- `tests/` submit the real FCC invoice PDFs through the API with a scripted fake LLM (`ScriptedChatModel` in `conftest.py`), so tool-call sequences are deterministic and no model credits are used. `test_pipeline.py` asserts the scripted turns are all consumed — a drift in the pipeline fails the test.
- Run one test: `uv run pytest tests/test_pipeline.py::test_duplicate_invoice_is_not_paid_twice`.

## Commands
- `uv sync`: install dependencies
- `uv run python -m ledgerpilot.db.seed`: create and seed `data/ledger.db`
- `uv run pytest`: run the tests
- `uv run uvicorn --factory ledgerpilot.main:create_app`: start the API
