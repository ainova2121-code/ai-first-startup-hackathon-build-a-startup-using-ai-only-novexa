from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration (prefix LEDGERPILOT_, optional .env file)."""

    model_config = SettingsConfigDict(env_prefix="LEDGERPILOT_", env_file=".env", extra="ignore")

    data_dir: Path = Path("data")
    # "openai": any OpenAI-compatible endpoint (llm_base_url/llm_api_key). "local": a model_id run
    # entirely on this machine via transformers, no network, no API key, no rate limit -- see
    # main.py::chat_model.
    llm_provider: Literal["openai", "local"] = "openai"
    llm_model: str = "Qwen/Qwen3-4B-Instruct-2507"
    llm_base_url: str = "https://router.huggingface.co/v1"
    llm_api_key: SecretStr = Field(
        default=SecretStr(""), validation_alias=AliasChoices("LEDGERPILOT_LLM_API_KEY", "HF_TOKEN")
    )
    # 0 (the default) is deterministic/greedy -- the right choice for LedgerPilot's real product
    # behaviour. A purple-team run can raise this: at temperature=0 every retry and every one of
    # run_corpus's own `samples` trials gets the identical completion, so neither mechanism can
    # explore anything -- the target has to have some real variance for a multi-trial search to
    # mean anything.
    llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    # For reasoning models (gpt-oss, o-series): how long each call thinks before answering. None sends
    # nothing, so the provider's default applies; "low" answers several times faster.
    llm_reasoning_effort: Literal["low", "medium", "high"] | None = None
    approval_threshold: float = Field(default=10_000.0, gt=0)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "ledger.db"

    @property
    def invoice_dir(self) -> Path:
        return self.data_dir / "invoices"
