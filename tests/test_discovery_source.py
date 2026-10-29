"""A tool's reported source is where it is defined, not the shared wrapper a guard puts around it."""

import inspect

from langchain_core.tools import StructuredTool

from purpleteam.discovery import describe_tool


def update_vendor_bank(vendor_id: int, bank_account: str) -> str:
    """Replace the bank account on file for a vendor."""
    return "ok"


def _guarded(func):
    spec = StructuredTool.from_function(func)

    def call(**args):  # the one shared wrapper line every guarded tool would otherwise report
        return func(**args)

    return StructuredTool.from_function(call, name=spec.name, description=spec.description, args_schema=spec.args_schema)


def test_a_wrapped_tool_reports_its_own_definition_not_the_wrapper():
    described = describe_tool(_guarded(update_vendor_bank))
    assert described.source == f"test_discovery_source.py:{inspect.getsourcelines(update_vendor_bank)[1]}"


def test_an_unwrapped_tool_still_reports_its_definition():
    described = describe_tool(StructuredTool.from_function(update_vendor_bank))
    assert described.source.startswith("test_discovery_source.py:")
