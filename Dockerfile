# The live demo console (purpleteam.live_demo) with its LedgerPilot target, for a hosted demo link -- the root
# Dockerfile because Hugging Face Spaces builds the one at the repository root. The deployable products have their own
# images: Dockerfile.gateway and Dockerfile.console. This one is a demo: its login is passwordless and every run spends
# the model credit of the key you give it, so keep the link private and take it down after judging.
#
# No TPM exists in a container, so checkpoints are signed with a software P-256 key, labelled "software" on the page;
# every signature still verifies. Run the console on your own machine to show the hardware TPM signature.
#
# Hugging Face Spaces (Docker SDK, free CPU tier):
#   1. Create a Space with SDK "Docker". In its README.md front matter keep `sdk: docker` and set `app_port: 7860`.
#   2. Settings -> Variables and secrets: add the secret LEDGERPILOT_LLM_API_KEY (your Groq key) and the variable
#      PURPLETEAM_CONCURRENCY=4 (attacks and replays at once; a run is then bound by the model endpoint's own
#      throughput, so higher rarely helps). Optional: LEDGERPILOT_LLM_MODEL, LEDGERPILOT_LLM_BASE_URL.
#   3. Push this repository to the Space, after `git lfs track "*.pdf" "*.tsr" "screenshots/*"`: the Hub stores binary
#      files (the invoice PDFs, a test timestamp token, the architecture screenshot) in LFS.
#   4. Open the direct https://<user>-<space>.hf.space address, not the huggingface.co page: the demo's session
#      cookie is SameSite=Strict, which a browser does not send inside the Space page's frame.
#
# Anywhere else with Docker and at least 2 GB of memory:
#   docker build -t purpleteam-demo .
#   docker run --rm -p 7860:7860 -e LEDGERPILOT_LLM_API_KEY=... purpleteam-demo

FROM python:3.12-slim AS builder

RUN pip install --no-cache-dir uv==0.12.3
ENV UV_SYSTEM_CERTS=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev --group platform

FROM python:3.12-slim AS runtime

# Hugging Face Spaces runs the container as uid 1000; the demo writes its run evidence under /app/.purpleteam and
# applies its verified source fixes to /app/ledgerpilot, so the app directory belongs to that user.
RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin user && mkdir /app && chown user:user /app
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv

USER user
ENV PATH="/app/.venv/bin:${PATH}" PYTHONPATH=/app PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    HF_HOME=/home/user/.cache/huggingface PURPLETEAM_HARDWARE_SIGNING=software
# The prompt-injection classifier (P2), downloaded once at build time instead of on the first run -- and before the
# code is copied, so a code-only change reuses this layer. The stub mirrors purpleteam.patches.scanners._ensure_tf_stub.
RUN python - <<'EOF'
from transformers.utils.import_utils import _LazyModule
original = _LazyModule.__getattr__
_LazyModule.__getattr__ = lambda self, name: type(name, (), {}) if name == "TFPreTrainedModel" else original(self, name)
from llm_guard.input_scanners import PromptInjection
PromptInjection()
EOF

COPY --chown=user:user pyproject.toml ./
COPY --chown=user:user purpleteam ./purpleteam
COPY --chown=user:user ledgerpilot ./ledgerpilot
COPY --chown=user:user data/invoices ./data/invoices
COPY --chown=user:user config ./config
EXPOSE 7860
CMD ["uvicorn", "--factory", "purpleteam.live_demo:app", "--host", "0.0.0.0", "--port", "7860", "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
