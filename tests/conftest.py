from pathlib import Path
from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

from ledgerpilot.db.repositories import Ledger, connect
from ledgerpilot.db.seed import load_manifest, seed
from ledgerpilot.utils.config import Settings

INVOICE_DIR = Path(__file__).parents[1] / "data" / "invoices"


class ScriptedChatModel(GenericFakeChatModel):
    """Replays a fixed list of AI messages, tool calls included."""

    def bind_tools(self, tools: Any, **kwargs: Any) -> "ScriptedChatModel":
        return self


@pytest.fixture
def manifest() -> dict[str, dict[str, Any]]:
    return {invoice["invoice_number"]: invoice for invoice in load_manifest(INVOICE_DIR)}


@pytest.fixture
def settings(tmp_path: Path, manifest: dict[str, dict[str, Any]]) -> Settings:
    settings = Settings(data_dir=tmp_path)
    seed(Ledger(connect(settings.db_path)), list(manifest.values()))
    return settings


@pytest.fixture
def ledger(settings: Settings) -> Ledger:
    return Ledger(connect(settings.db_path))
