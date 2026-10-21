"""Reasoning/thinking content, when a provider exposes it: extracted into Exchange.reasoning the
same way a tool call or the final answer already is — never guessed, never required."""

from purpleteam.gateway_dialects import ANTHROPIC, GEMINI, OPENAI


def test_openai_reads_reasoning_content_deepseeks_field_name():
    response = {"choices": [{"message": {"content": "Done.", "reasoning_content": "First I checked the vendor."}}]}
    exchange = OPENAI.parse({"messages": []}, response)
    assert exchange.reasoning == "First I checked the vendor." and exchange.answer == "Done."


def test_openai_reads_reasoning_openais_own_field_name():
    response = {"choices": [{"message": {"content": "Done.", "reasoning": "Weighing two options."}}]}
    assert OPENAI.parse({"messages": []}, response).reasoning == "Weighing two options."


def test_openai_with_neither_field_has_no_reasoning():
    response = {"choices": [{"message": {"content": "Done."}}]}
    exchange = OPENAI.parse({"messages": []}, response)
    assert exchange.reasoning == "" and not exchange.redacted_reasoning


def test_anthropic_reads_thinking_blocks_and_keeps_them_out_of_the_answer():
    response = {"content": [
        {"type": "thinking", "thinking": "The vendor name matches a known record.", "signature": "sig"},
        {"type": "text", "text": "Looked it up."}]}
    exchange = ANTHROPIC.parse({"messages": []}, response)
    assert exchange.reasoning == "The vendor name matches a known record."
    assert exchange.answer == "Looked it up."
    assert not exchange.redacted_reasoning


def test_anthropic_concatenates_multiple_interleaved_thinking_blocks():
    response = {"content": [
        {"type": "thinking", "thinking": "Step one."}, {"type": "text", "text": "..."},
        {"type": "thinking", "thinking": "Step two."}, {"type": "text", "text": "Done."}]}
    assert ANTHROPIC.parse({"messages": []}, response).reasoning == "Step one.\nStep two."


def test_anthropic_redacted_thinking_is_flagged_not_treated_as_text():
    response = {"content": [{"type": "redacted_thinking", "data": "opaque-ciphertext"},
                            {"type": "text", "text": "Looked it up."}]}
    exchange = ANTHROPIC.parse({"messages": []}, response)
    assert exchange.redacted_reasoning is True
    assert exchange.reasoning == ""  # the provider withheld it; nothing readable to show


def test_gemini_reads_thought_marked_parts_and_keeps_them_out_of_the_answer():
    response = {"candidates": [{"content": {"parts": [
        {"thought": True, "text": "Checking the vendor record first."},
        {"text": "Found it."}]}}]}
    exchange = GEMINI.parse({"contents": []}, response)
    assert exchange.reasoning == "Checking the vendor record first."
    assert exchange.answer == "Found it."


def test_gemini_with_no_thought_parts_has_no_reasoning():
    response = {"candidates": [{"content": {"parts": [{"text": "Found it."}]}}]}
    exchange = GEMINI.parse({"contents": []}, response)
    assert exchange.reasoning == "" and exchange.answer == "Found it."
