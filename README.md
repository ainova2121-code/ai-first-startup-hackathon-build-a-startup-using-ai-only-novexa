# purpleteam

## Submission

- **Live demo:** https://aishwaryar24-hackathon-purple-teaming.hf.space. Click **Enter the demo**, then
  **Start run**; a full run takes about five minutes.
- **Demo video (watch online):** https://youtu.be/dz2Gy1rdgPE (4:56, captions burned in).
- **Demo video (download):** [demo/novexa-demo.mp4](demo/novexa-demo.mp4), captions also as
  [demo/novexa-demo.srt](demo/novexa-demo.srt).

[![Watch the Novexa demo video](https://img.youtube.com/vi/dz2Gy1rdgPE/hqdefault.jpg)](https://youtu.be/dz2Gy1rdgPE)

The hosted demo signs checkpoints with a software P-256 key, labelled "software" on the page, since a container
has no TPM; run the console locally to see the hardware TPM co-signature.

**License:** this code is Copyright (c) 2026 Aishwarya R, All Rights Reserved, as stated in [LICENSE](LICENSE). It is
submitted for hackathon judging only and is not offered under this template repository's MIT license.

**Note:** Claude appears as a co-author because this startup was built with AI, as the hackathon requires.

A BYOC AI purple-team platform: it discovers an AI agent system's own agents and tools, attacks it
with proof-based techniques (a breach must leave hard evidence — a canary value reaching a real tool
call — never a model's opinion), defends it, re-attacks with the exact payloads that got through to
prove the defense holds, and seals every step into a signed, tamper-evident audit trail mapped to
the compliance clauses it evidences (OWASP LLM Top 10, PCI SSC AI principles, EU AI Act, NIST AI RMF,
SOC 2, HIPAA, DORA, ISO 42001).

The defense has two parts. Runtime guards are only ever *selected* from a prewritten, reviewed
catalog. Source fixes are exact-match codemods: a model-drafted one is applied only when the scanner's
rescan and an independent invariant both pass, it is labelled everywhere as not human-reviewed, every
original is snapshotted first, and one click restores them all. The target is never called safe to
ship until the edited code has been reloaded and attacked again.

Everything runs in your own cloud. The target needs no SDK and no code change: point its model's
base URL at the gateway below, and traffic alone gives the platform everything it needs — which
framework built the agent (n8n, CrewAI, LangChain, a hand-rolled service) is never a question it
has to answer.

`ledgerpilot/` is the included demo target: a deliberately vulnerable accounts-payable multi-agent
system, used to prove the platform against a real, running agent rather than a toy.

## The live console

```bash
uv sync
cp .env.example .env    # set HF_TOKEN (or LEDGERPILOT_LLM_API_KEY)
uv run uvicorn --factory purpleteam.live_demo:app --port 8090
```

Open http://localhost:8090 and click "Enter the demo" (a passwordless session; every route sits behind it).
Pick a mode:

- **Static** (seconds): discovery, identity posture, the source scan and prompt rules. No attack runs, so
  it gives no release verdict.
- **Full** (about 3 minutes): every attack meets the *unpatched* agent, side by side, so the breach count
  is its real exposure. The attacker uses no model: plain claims written by rule from the discovered tool
  schema, the same claims hidden inside a document or a form field, and PyRIT's jailbreak,
  prompt-injection and social-engineering templates. The defender then checks legitimate work first
  (a patch that breaks it is dropped before any replay), re-attacks with every breaching payload until
  the release gate below is proven, applies verified source fixes, reloads the edited target and attacks it again.
- **Advanced**: Full, plus base64-disguised and document-buried variants and a tighter release gate.

Reverification sends each breaching question at most twice: once against the code patch alone (one per hole)
and once against the full defense. Advanced mode applies the platform's own release gate instead (at most a 20%
breach rate at 95% confidence: 16 replays per hole). `PURPLETEAM_RELEASE_GATE` sets the demo's gate; the evidence
always states the bound a run reached.

Measured on LedgerPilot (`openai/gpt-oss-120b` via Cerebras): 8–9 of 23 attacks breach across three
techniques — one planted bank account travels from the intake agent to the vendor and payment agents —
while all 8 jailbreak templates hold; every breach is held on re-attack; every agent reply is under 30 s. The demo
now defaults to the much cheaper `openai/gpt-oss-20b`, so expect different counts: results depend on the model.

The pages show it live: the **discovery** map builds as agents and tools are found; **Patched files** shows
the real diffs (and **Restore original files** undoes them); **Decision drift** compares each guard decision
with the last approved run; the **Audit ledger** draws each signature the moment it is made, grows the
Merkle tree (the inclusion proof is recomputed in your browser), and shows the checkpoint's TPM signature
and RFC 3161 timestamp. `PURPLETEAM_ONLY_STATIC=0` adds the model-driven attacks (targeted recon, TAP).

### Host the demo

The root `Dockerfile` packages this console with LedgerPilot for a hosted link (Hugging Face Spaces' free CPU tier,
or any host with 2 GB of memory); its header has the steps. A container has no TPM, so a hosted run signs checkpoints
with a software key, labelled as such. The login is passwordless and every run spends your model credit: keep the
link private and take it down afterwards.

## Assess another agent project

```bash
uv run python -m purpleteam.assess https://github.com/<owner>/<repo> --legit "a normal request it should handle"
```

Clones the project into its own environment, finds its entry point by reading its source, discovers its
agents and tools, and runs the same assessment. It executes that project's code on this machine in a
separate process, not a container: assess only code you would run yourself, or run it inside a VM.

## Additional attack channels

The default assessment also includes multilingual probes (Spanish, Hindi, Bengali and Arabic) and a
system-prompt extraction probe when discovery actually captured the agent prompt. Extraction is only
reported as a breach when the exact discovered prompt is found in a reply, tool output, or tool-call
arguments; prompt text
is used as an in-memory proof marker and is not added to the ledger.

For indirect/tool-output injection, `python -m purpleteam.demo_agentdojo` now includes payloads inserted
into AgentDojo's configured data injection vector, then judges the resulting observed tool calls with
the canary oracle. This demo currently exercises one AgentDojo workspace task, not the complete
AgentDojo or InjecAgent benchmark suites.

Unicode tag hiding is available as the `ascii_smuggler` disguise; the advanced disguise set also has
Caesar, Atbash, Vigenere and 5x5 ASCII-art encodings. Pass selected names through
`Assessment.run(disguise_with=[...])`. For a PDF ingestion endpoint, use
`purpleteam.targets.http_document.HttpDocumentTarget` with an operator-authorized staging URL: it
uploads a PDF whose instruction text is selectable by parsers but invisible when rendered, and takes
tool-call evidence from the gateway observer. The PDF fixture is ASCII-only; Unicode-tag attacks are
tested separately. This adapter provides the upload attack path; it does not automatically install a
defense into the customer application.

## Deploy the gateway (Docker Compose, one host)

```bash
cp .env.gateway.example .env.gateway              # fill in your model provider + a redactor secret
cp deploy/Caddyfile.example deploy/Caddyfile       # set your real domain, or "localhost" to try it locally
mkdir -p deploy/secrets && openssl rand -hex 32 > deploy/secrets/keyring_passphrase

docker compose up -d
docker compose logs gateway                        # prints the one-time bootstrap admin/target keys — save them
```

That's it for the gateway itself: Caddy terminates TLS automatically (Let's Encrypt for a real
domain, a self-signed certificate for `localhost`), and the gateway starts in **observe-only**
mode — it builds a profile of what calls your agent for; nothing is blocked yet.

Building the image yourself (as Compose does above) recompiles its proprietary modules with a
full C toolchain, which is slow and unnecessary on every machine. For production, pull the
signed image our CI publishes instead — set `GATEWAY_IMAGE` in `.env.gateway` to a pinned digest
and verify it before deploying:

```bash
cosign verify ghcr.io/<owner>/purpleteam-gateway@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/<owner>/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

See [Dockerfile.gateway](Dockerfile.gateway) for what the hardened run flags above actually protect
and what they don't.

## Watch your fleet (the console)

`docker compose up -d` above also starts the console (`docker compose logs console` for its
one-time bootstrap admin password). It watches every gateway you register into it — agents,
permissions, active keys, sealed-run verdicts, containment events — live, updated over SSE as
each one is polled.

Sign in, then **Targets → Register a gateway** with that gateway's own admin bearer key (from
`docker compose logs gateway`). Gateways are reached over https only. Every event the console reads is
verified against the gateway's pinned public keys -- paste its trust file at registration, or they are
pinned on first use -- so a tampered, forged or re-signed log shows as *untrusted*, never as a verdict;
**Re-pin keys** pins new ones after a gateway's signing keys change. Three roles: `admin` (manage the fleet and console users),
`analyst` (everything but fleet/user management), `auditor` (evidence-shaped views only — no raw
activity drill-down). The console only ever *reads* from a gateway over HTTP (`/ledger/export`,
admin-only, paginated) — it never touches the gateway's filesystem and nothing it does narrows or
widens a signed policy; that stays the gateway's own job.

### Turning enforcement on

Observe-only is the right place to start: let discovery and a first assessment run, review what
they found (`purpleteam.identity.posture`, the assessment report's findings), and only then have
the defender's selected patches signed into a policy file your own `GATEWAY_POLICY_TRUST_FILE`
pins — see `purpleteam/defender/policy.py`. Set `GATEWAY_ENFORCE=true` and the two
`GATEWAY_POLICY_*` paths in `.env.gateway` once that policy exists; the gateway refuses to enforce
an unsigned or edited one.

### Onboarding your own agent

There is no guided UI for *this* yet (the console above manages the fleet view, not discovery
itself) — today it's a short Python script against
`purpleteam.targets.endpoint.HttpTarget` (for anything that takes a message over HTTP: an n8n
webhook, a chat API) or `purpleteam.assessment.Assessment` directly. `purpleteam/demo.py` is a
complete, working example against the included LedgerPilot target — the same shape applies to
your own agent once its model traffic is pointed at the gateway.

## Run the LedgerPilot demo target

```bash
uv sync
uv run python -m ledgerpilot.db.seed
uv run uvicorn --factory ledgerpilot.main:create_app
```

Needs `LEDGERPILOT_LLM_API_KEY` or `HF_TOKEN` (see `.env.example`) for a real model endpoint.

> **Demo Data Disclaimer:** The invoice PDFs used in this application are real documents sourced unedited from the
> FCC political public file via Amazon's [ConfBench](https://huggingface.co/datasets/amazon/ConfBench) dataset (FCC
> Invoices Verified subset), licensed under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/).
>
> - **Purpose:** For non-commercial demonstration and security research only.
> - **Privacy:** All bank details and email addresses are synthetic.
> - **Affiliation:** This project is independent and is not affiliated with, sponsored by, or endorsed by Amazon, the
>   FCC, or any broadcast station named in the documents.
>
> The PDFs are not covered by this repository's LICENSE and must be replaced with synthetic invoices before any
> commercial use. See `NOTICE` and `data/README.md`.

## Run a full assessment end to end

```bash
uv run python -m purpleteam.demo
```

Discovers LedgerPilot's agents and tools, attacks it, patches and re-verifies any breach, seals
the signed audit trail, and prints a summary. See `purpleteam/demo.py`'s own docstring for the
model/network requirements and `ATTEMPT_TIMEOUT`.

## Tests

```bash
uv run pytest
```

See [CLAUDE.md](CLAUDE.md) for the full architecture, the project's security boundaries, and
everything else a contributor needs.
