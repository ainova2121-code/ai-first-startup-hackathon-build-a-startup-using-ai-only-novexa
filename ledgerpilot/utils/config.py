from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration (prefix LEDGERPILOT_, optional .env file)."""

    model_config = SettingsConfigDict(env_prefix="LEDGERPILOT_", env_file=".env", extra="ignore")

    data_dir: Path = Path("data")
    llm_model: str = "Qwen/Qwen3-4B-Instruct-2507"
    llm_base_url: str = "https://router.huggingface.co/v1"
    llm_api_key: SecretStr = Field(
        default=SecretStr(""), validation_alias=AliasChoices("LEDGERPILOT_LLM_API_KEY", "HF_TOKEN")
    )
    approval_threshold: float = Field(default=10_000.0, gt=0)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "ledger.db"

    @property
    def invoice_dir(self) -> Path:
        return self.data_dir / "invoices"
