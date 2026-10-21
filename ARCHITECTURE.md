# PurpleTeam system architecture

This describes the current repository implementation. It separates the deployable LLM gateway, the Python assessment engine, the LedgerPilot demo target, and release/audit trust. The gateway Compose stack is deployable on its own; the assessment engine is currently driven from Python rather than a packaged management UI.

## 1. Customer deployment and model traffic

```mermaid
flowchart LR
  subgraph BYOC[Customer cloud or host]
    Agent[Customer AI application\nagent framework and tools]
    Tools[Customer tools and data\nAPIs, databases, files, actions]
    Caddy[Caddy TLS ingress]
    Gateway[PurpleTeam LLM Gateway\nFastAPI proxy]
    Auth[GatewayKeys\nadmin and target bearer keys]
    Dialect[Provider dialect adapters\nOpenAI, Anthropic, Gemini]
    Observer[GatewayObserver\nprofiles, tools, calls, attribution]
    Decision[DecisionPoint]
    Guard[Optional signed policy guard\nobserve-only by default]
    Ledger[AuditLedger\nredaction, signed events, checkpoints]
    State[(Persistent gateway volume\nkeyring, keys, ledger, trust)]
    Signer[Optional checkpoint signer\nWindows TPM, PKCS#11, AWS KMS]
    Profile[/GET profile\nadmin-key protected/]
    Provider[Customer-selected model endpoint\ncloud API or local inference server]

    Agent -->|model requests using target key| Caddy
    Caddy -->|TLS terminated| Gateway
    Gateway --> Auth
    Gateway --> Dialect
    Dialect --> Observer
    Dialect -->|forward with gateway-held provider key| Provider
    Provider -->|model completion| Decision
    Decision --> Guard
    Guard -->|allow or remove a proposed tool call| Agent
    Agent -->|executes its own tool calls| Tools
    Agent -->|tool results in later model request| Caddy
    Observer --> Decision
    Decision -->|decision and tool-result evidence| Ledger
    Ledger --> State
    Ledger -. checkpoint signature .-> Signer
    Gateway --> Profile
    Profile --> Observer
  end
```

The gateway observes model requests and responses, including declared tools and model-proposed tool calls. It does not execute customer tools; the customer agent does. With a verified signed policy enabled, the gateway can withhold model-proposed calls before the agent receives them. Provider-executed native tools run upstream and cannot be stopped by the gateway, so enforcement rejects them by default.

## 2. Purple Team assessment and remediation loop

```mermaid
flowchart TD
  Inputs[Operator supplies target adapter, profile, oracle, scope and facts]
  Adapter[Target adapter\nLedgerPilotTarget, GenericAgentTarget, or HttpTarget]
  Assessment[Assessment orchestrator]
  Corpus[Seed attack corpus\nPyRIT templates, disguise and placement options]
  Adaptive[Separate adaptive runner\nPyRIT PAIR or TAP]
  Target[Target AI application]
  Obs[Observation\nreply, tool calls, evidence level, attribution]
  Oracle[Proof-based oracle\ncanary, secret leak, permission scope]
  Regress[Optional regression replay\nre-test prior exploits on current target]
  Identity[Agent IAM checks\nmanifest, credentials, baseline drift]
  SAST[Optional target-repository scan\nBandit or configured scanner]
  Blast[Optional blast-radius analysis\ncapability chains and declared handoffs]
  Findings[Consolidated findings]
  Defender[Defender\ndeterministic patch selection]
  Catalog[Prewritten runtime patch catalog\ninjection, tool gate, allowlist, SQL, egress, scope]
  Guard[Composite runtime guard]
  Verify[Verifier\nreplay attack and legitimate-use checks]
  Report[AssessmentReport\nfindings, verdict, identity, coverage, trust]
  Markdown[Markdown compliance evidence report]
  Ledger[(Signed tamper-evident audit ledger)]
  Compliance[Compliance mapping\nEU AI Act, NIST AI RMF, DORA, ISO 42001,\nOWASP LLM, SOC 2, HIPAA, PCI AI principles]

  Inputs --> Assessment
  Inputs --> Adapter
  Adapter --> Assessment
  Assessment --> Corpus
  Corpus --> Adapter
  Adaptive -. separately invoked attack mode .-> Adapter
  Adapter --> Target
  Target --> Adapter
  Adapter --> Obs
  Obs --> Oracle
  Oracle --> Assessment
  Assessment --> Regress
  Regress --> Adapter
  Assessment --> Identity
  Assessment --> SAST
  Assessment --> Blast
  Assessment --> Findings
  Oracle --> Findings
  Regress --> Findings
  Identity --> Findings
  SAST --> Findings
  Blast --> Findings
  Findings --> Defender
  Defender --> Catalog
  Catalog --> Guard
  Guard --> Verify
  Verify --> Adapter
  Verify --> Report
  Assessment --> Ledger
  Oracle --> Ledger
  Defender --> Ledger
  Verify --> Ledger
  Ledger --> Report
  Report --> Markdown
  Ledger --> Compliance
  Compliance --> Report
```

Default assessment runs use the seed corpus. PAIR/TAP is a separately callable adaptive attack runner, not automatically invoked by the default `Assessment.run`. Static repository scanning, baseline comparison, regression replay, blast-radius analysis, disguises, and placement variants are optional inputs or modes. The oracle—not the adaptive scorer—decides whether evidence proves a breach. A selected runtime guard is attached through the target adapter and then verified by replaying attacks and legitimate requests.

## 3. LedgerPilot demonstration target

```mermaid
flowchart LR
  Client[Demo or assessment client]
  API[LedgerPilot FastAPI]
  Invoice[POST invoices]
  Inquiry[POST inquiries]
  Pipeline[LangGraph invoice pipeline]
  Intake[Intake agent]
  Vendor[Vendor agent]
  Matching[Matching agent]
  Approval[Approval agent]
  Payment[Payment agent]
  InquiryAgent[Inquiry agent]
  Factory[AgentFactory\nLangChain agents and guarded tools]
  GuardPort[Guard port\nNoGuard by default; platform guard in assessment]
  SinkPort[EventSink port\nNullSink by default; recorder in assessment]
  LLM[Configured OpenAI-compatible model endpoint]
  Repos[SQLite repositories\nemails, invoices, vendors, orders, receipts, payments]
  Console[LedgerConsole\nraw-SQL query tool for demo inquiry agent]
  Rail[Fake payment rail]
  PDF[Seeded invoice PDFs and manifest]

  Client --> API
  API --> Invoice --> Pipeline
  API --> Inquiry --> InquiryAgent
  Pipeline --> Intake --> Vendor --> Matching --> Approval --> Payment
  InquiryAgent --> Factory
  Intake --> Factory
  Vendor --> Factory
  Matching --> Factory
  Approval --> Factory
  Payment --> Factory
  Factory --> GuardPort
  Factory --> SinkPort
  Factory <--> LLM
  Intake --> Repos
  Vendor --> Repos
  Matching --> Repos
  Approval --> Repos
  Payment --> Repos
  InquiryAgent --> Console --> Repos
  Payment --> Rail
  Invoice --> PDF
```

LedgerPilot is intentionally vulnerable and exists as a realistic demo target, not as part of the customer platform. Its `Guard` and `EventSink` ports let the assessment adapter attach runtime protection and capture tool activity without making LedgerPilot import the platform.

## 4. Evidence, hardware signing, timestamping, and release trust

```mermaid
flowchart LR
  Events[Assessment and gateway events]
  Redact[Optional privacy redactor\nkeyed commitments for sensitive values]
  Hybrid[Per-actor event signatures\nEd25519 plus ML-DSA-65]
  Chain[Per-actor hash chains]
  Merkle[Merkle root and signed checkpoint]
  Hardware[Optional additional P-256 checkpoint signature\nTPM, PKCS#11 HSM, or AWS KMS]
  Trust[Exported public trust bundle\nkept separate from the log]
  TSA[Optional RFC 3161 timestamp authorities\nhash of checkpoint only]
  Verify[Offline log/proof verification]
  CI[GitHub Actions release workflow]
  Image[Gateway container image]
  Cosign[Cosign keyless signature\nGitHub OIDC identity]
  Compose[Docker Compose deployment\nCaddy TLS, read-only gateway container, persistent volume]

  Events --> Redact --> Hybrid --> Chain --> Merkle
  Merkle -. additional signature .-> Hardware
  Merkle --> Trust
  Merkle -. checkpoint hash .-> TSA
  Trust --> Verify
  Chain --> Verify
  Hardware --> Verify
  TSA --> Verify
  CI --> Image --> Cosign --> Compose
```

The TPM/HSM/KMS key adds a signature to checkpoints; it does not attest the host, prove the container is unmodified, or sign every event. The gateway image’s Cosign signature is a separate release-integrity mechanism. Timestamp anchoring is optional and proves a checkpoint existed by the timestamp, not that the contents are truthful.

## Current boundaries

- The Compose deployment packages the gateway and Caddy. The assessment engine is Python-driven; there is no customer onboarding UI or one-click assessment console yet.
- External HTTP targets use `HttpTarget`; framework-neutral model observation depends on traffic routed through the gateway. The current repository does not include a packaged remote assessment client that automatically coordinates a separately deployed gateway’s `/profile` endpoint with the assessment runner.
- The current provider dialects are OpenAI-compatible, Anthropic, and Gemini. There is no dedicated RAG/vector-database or MCP security subsystem in this repository.
- The defender selects prewritten runtime guards. The separate codemod workflow may draft and verify a source change on a scratch copy, but it does not silently rewrite customer source code.
- The Windows TPM implementation signs ledger checkpoints. It is not TPM remote attestation. The hardware detector notes that WSL2 does not expose the host TPM to the Linux environment.
