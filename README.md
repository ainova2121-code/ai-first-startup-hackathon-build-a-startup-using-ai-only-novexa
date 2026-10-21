# purpleteam

A BYOC AI purple-team platform: it discovers an AI agent system's own agents and tools from the
traffic it generates, attacks it with proof-based techniques (a breach must leave hard evidence —
a canary value reaching a real tool call — never a model's opinion), patches it from a prewritten,
human-reviewed catalog (it never generates code), re-verifies the fix by attacking again, and seals
every step into a signed, tamper-evident audit trail mapped to the compliance clauses it evidences
(OWASP LLM Top 10, PCI SSC AI principles, EU AI Act, NIST AI RMF, SOC 2, HIPAA, DORA, ISO 42001).

Everything runs in your own cloud. The target needs no SDK and no code change: point its model's
base URL at the gateway below, and traffic alone gives the platform everything it needs — which
framework built the agent (n8n, CrewAI, LangChain, a hand-rolled service) is never a question it
has to answer.

`ledgerpilot/` is the included demo target: a deliberately vulnerable accounts-payable multi-agent
system, used to prove the platform against a real, running agent rather than a toy.

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

### Turning enforcement on

Observe-only is the right place to start: let discovery and a first assessment run, review what
they found (`purpleteam.identity.posture`, the assessment report's findings), and only then have
the defender's selected patches signed into a policy file your own `GATEWAY_POLICY_TRUST_FILE`
pins — see `purpleteam/defender/policy.py`. Set `GATEWAY_ENFORCE=true` and the two
`GATEWAY_POLICY_*` paths in `.env.gateway` once that policy exists; the gateway refuses to enforce
an unsigned or edited one.

### Onboarding your own agent

There is no guided UI for this yet — today it's a short Python script against
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
