"""chat_model's two providers: the default OpenAI-compatible endpoint, and a model run entirely
on this machine (llm_provider="local") -- no network, no API key, no rate limit. The local path's
heavy classes (HuggingFacePipeline/ChatHuggingFace, which would load real model weights) are
always faked here; nothing in this file touches a real model or the network.
"""

import httpx
import openai
import pytest
from langchain_openai import ChatOpenAI

from ledgerpilot.main import RETRY_TEMPERATURES, _local_chat_model, chat_model
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


def _status_error(status, code):
    response = httpx.Response(status, request=httpx.Request("POST", "https://model.invalid/v1/chat/completions"))
    return openai.APIStatusError(f"Error code: {status}", response=response, body={"code": code})


def _model_failing_with(monkeypatch, tmp_path, errors):
    """The wrapped model, whose real ChatOpenAI call raises each of ``errors`` in turn, then answers."""
    sent = []

    def fake_generate(self, messages, stop=None, run_manager=None, **kwargs):
        sent.append(kwargs.get("temperature"))
        if len(sent) <= len(errors):
            raise errors[len(sent) - 1]
        return "answered"

    monkeypatch.setattr(ChatOpenAI, "_generate", fake_generate)
    return chat_model(Settings(data_dir=tmp_path, llm_api_key="k")), sent


def test_a_generation_the_provider_rejected_is_asked_again_a_little_less_greedily(monkeypatch, tmp_path):
    errors = [_status_error(400, "output_parse_failed"), _status_error(400, "tool_use_failed")]
    model, sent = _model_failing_with(monkeypatch, tmp_path, errors)
    assert model._generate([]) == "answered"
    assert sent == [None, *RETRY_TEMPERATURES[:2]]  # the first call as configured, then rising temperatures


def test_every_other_model_error_is_raised_at_once(monkeypatch, tmp_path):
    model, sent = _model_failing_with(monkeypatch, tmp_path, [_status_error(400, "invalid_api_key")])
    with pytest.raises(openai.APIStatusError):
        model._generate([])
    assert len(sent) == 1


def test_a_generation_rejected_every_time_raises_after_the_last_retry(monkeypatch, tmp_path):
    errors = [_status_error(400, "output_parse_failed")] * (len(RETRY_TEMPERATURES) + 1)
    model, sent = _model_failing_with(monkeypatch, tmp_path, errors)
    with pytest.raises(openai.APIStatusError):
        model._generate([])
    assert len(sent) == len(RETRY_TEMPERATURES) + 1


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
