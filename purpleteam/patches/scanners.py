"""Text-screening patches backed by LLM Guard (Protect AI).

The injection scanner uses LLM Guard's ``PromptInjection`` scanner — a local transformer
classifier that runs offline after a one-time model download, so untrusted text is judged by a
real model, not keyword matching. The output redactor removes secrets found by the shared
``SecretFinder`` from tool results and replies.
"""

from __future__ import annotations

import threading
from functools import lru_cache
from typing import Callable

from purpleteam.patches.base import Blocked, Patch
from purpleteam.secrets import ScanTooLarge, SecretFinder


def _ensure_tf_stub() -> None:
    """llm_guard imports ``transformers.TFPreTrainedModel`` only as a type hint, never instantiating
    it on the PyTorch-only path used here; recent ``transformers`` dropped that TF-compat export
    entirely, which breaks the import regardless. A harmless placeholder lets it succeed without
    pulling in TensorFlow. Patched on the lazy-module class itself (not the instance): transformers'
    lazy loader re-resolves names through its own ``__getattr__`` deep in llm_guard's import chain,
    so a plain attribute assignment on the module object does not reliably survive to that point."""
    from transformers.utils.import_utils import _LazyModule

    if getattr(_LazyModule.__getattr__, "_tf_stub_patched", False):
        return
    original = _LazyModule.__getattr__

    def patched(self, name: str):
        if name == "TFPreTrainedModel":
            return type("TFPreTrainedModel", (), {})
        return original(self, name)

    patched._tf_stub_patched = True
    _LazyModule.__getattr__ = patched


_MODEL_LOCK = threading.Lock()  # one shared model object; parallel replays must not run it concurrently


@lru_cache(maxsize=1)
def _prompt_injection_scanner():
    _ensure_tf_stub()
    from llm_guard.input_scanners import PromptInjection
    from llm_guard.input_scanners.prompt_injection import MatchType

    return PromptInjection(threshold=0.5, match_type=MatchType.FULL)


def llm_guard_injection(text: str) -> bool:
    """True if LLM Guard flags the text as a prompt injection."""
    if not text.strip():
        return False
    with _MODEL_LOCK:  # inference takes milliseconds; serializing it costs nothing next to model calls
        _sanitized, is_valid, _risk = _prompt_injection_scanner().scan(text)
    return not is_valid


def warm_injection_backend() -> None:
    """Load the classifier ahead of the first patch (it is cached once loaded). Best effort: if it
    cannot load, the patch reports itself unavailable exactly as it would have without the warm-up."""
    try:
        if injection_backend_available():
            with _MODEL_LOCK:
                _prompt_injection_scanner()
    except Exception:
        pass


def injection_backend_available() -> bool:
    """Whether LLM Guard and its model backend can be loaded."""
    try:
        import torch

        _ensure_tf_stub()
        from llm_guard.input_scanners import PromptInjection  # noqa: F401

        return getattr(torch, "__file__", None) is not None
    except Exception:
        return False


class InjectionScanner(Patch):
    """Reject untrusted text that LLM Guard classifies as a prompt injection or jailbreak."""

    id, layer, answers = "P2", "input", ("prompt_injection", "jailbreak", "injection_action")

    def __init__(self, sources: tuple[str, ...] = ("input", "tool_result"),
                 detect: Callable[[str], bool] = llm_guard_injection) -> None:
        self._sources = sources
        self._detect = detect

    def screen(self, agent: str, text: str, source: str) -> str:
        if source in self._sources and self._detect(text):
            raise Blocked("prompt injection detected in untrusted text")
        return text


class OutputRedactor(Patch):
    """Redact secrets (known values, credential formats, encoded copies) from tool results and replies."""

    id, layer, answers = "P9", "output", ("exfiltration", "prompt_leak")

    def __init__(self, finder: SecretFinder, sources: tuple[str, ...] = ("tool_result", "output")) -> None:
        self._finder = finder
        self._sources = sources

    def screen(self, agent: str, text: str, source: str) -> str:
        if source not in self._sources:
            return text
        try:
            return self._finder.redact(text)
        except ScanTooLarge as error:  # fail closed: unscannable text is not passed through
            raise Blocked(f"{source} is too large to scan for secrets") from error
        except Exception as error:  # a scanner bug must stop the text, never crash the host or let it through
            raise Blocked(f"could not scan the {source} for secrets") from error
