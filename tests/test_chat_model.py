"""chat_model's two providers: the default OpenAI-compatible endpoint, and a model run entirely
on this machine (llm_provider="local") -- no network, no API key, no rate limit. The local path's
heavy classes (HuggingFacePipeline/ChatHuggingFace, which would load real model weights) are
always faked here; nothing in this file touches a real model or the network.
"""

import pytest

from ledgerpilot.main import _local_chat_model, chat_model
from ledgerpilot.utils.config import Settings


def test_llm_provider_defaults_to_openai(tmp_path):
    assert Settings(data_dir=tmp_path).llm_provider == "openai"


def test_the_openai_path_still_refuses_without_a_key(tmp_path, monkeypatch):
    monkeypatch.setenv("LEDGERPILOT_LLM_API_KEY", "")
    monkeypatch.setenv("HF_TOKEN", "")
    settings = Settings(data_dir=tmp_path)
    with pytest.raises(RuntimeError, match="HF_TOKEN or LEDGERPILOT_LLM_API_KEY"):
        chat_model(settings)


def test_the_openai_path_builds_chat_openai_with_the_configured_model(tmp_path):
    settings = Settings(data_dir=tmp_path, llm_api_key="k", llm_model="some/model", llm_base_url="https://x/v1")
    model = chat_model(settings)
    assert model.model_name == "some/model" and str(model.openai_api_base) == "https://x/v1"


def test_the_local_provider_never_needs_an_api_key(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr("ledgerpilot.main._local_chat_model", lambda model_id: seen.setdefault("model_id", model_id))

    chat_model(Settings(data_dir=tmp_path, llm_provider="local", llm_model="tiny/model", llm_api_key=""))

    assert seen["model_id"] == "tiny/model"  # no RuntimeError despite no key -- local needs none


def test_local_chat_model_wraps_a_pipeline_for_the_configured_model_id(monkeypatch):
    calls = {}

    class _FakePipeline:
        pass

    def fake_from_model_id(*, model_id, task, pipeline_kwargs):
        calls["model_id"], calls["task"] = model_id, task
        return _FakePipeline()

    class _FakeChatHuggingFace:
        def __init__(self, *, llm):
            calls["llm"] = llm

    monkeypatch.setattr("langchain_huggingface.HuggingFacePipeline.from_model_id", fake_from_model_id)
    monkeypatch.setattr("langchain_huggingface.ChatHuggingFace", _FakeChatHuggingFace)

    _local_chat_model("Qwen/Qwen2.5-0.5B-Instruct")

    assert calls["model_id"] == "Qwen/Qwen2.5-0.5B-Instruct" and calls["task"] == "text-generation"
    assert isinstance(calls["llm"], _FakePipeline)
