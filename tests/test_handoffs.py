"""Handoff inference: a suggestion from text recurrence, never an assertion — short or coincidental
overlaps, and an agent "handing off" to itself, must never produce an edge."""

from purpleteam.handoffs import infer_handoffs

LONG_REPLY = "Invoice INV-2112-1 for ACME Corp totals $4,250.00 and is ready for approval by the finance team."


def test_a_clear_handoff_is_detected():
    exchanges = [
        ("intake", "Process this invoice email.", LONG_REPLY),
        ("approval", f"Please review: {LONG_REPLY}", "Approved."),
    ]
    assert infer_handoffs(exchanges) == [("intake", "approval")]


def test_unrelated_agents_produce_no_edge():
    exchanges = [
        ("intake", "Process this invoice email.", LONG_REPLY),
        ("payment", "Schedule the Q3 payroll run.", "Scheduled."),
    ]
    assert infer_handoffs(exchanges) == []


def test_an_overlap_shorter_than_the_threshold_is_not_enough():
    exchanges = [
        ("intake", "hi", "ok"),  # far too short to mean anything
        ("approval", "ok, approving now", "Approved."),
    ]
    assert infer_handoffs(exchanges) == []


def test_a_custom_min_overlap_is_respected():
    exchanges = [("a", "x", "short answer"), ("b", "the short answer arrived", "y")]
    assert infer_handoffs(exchanges) == []
    assert infer_handoffs(exchanges, min_overlap=5) == [("a", "b")]


def test_an_agent_is_never_reported_as_handing_off_to_itself():
    exchanges = [
        ("intake", LONG_REPLY, LONG_REPLY),  # degenerate: its own reply equals its own first_user
    ]
    assert infer_handoffs(exchanges) == []


def test_several_distinct_handoffs_are_all_found():
    vendor_reply = "Vendor verified, account on file and confirmed as legitimate for payment."
    exchanges = [
        ("intake", "start", LONG_REPLY),
        ("vendor", f"verify vendor for: {LONG_REPLY}", vendor_reply),
        ("payment", f"{vendor_reply} Pay now.", "Paid."),
    ]
    assert infer_handoffs(exchanges) == [("intake", "vendor"), ("vendor", "payment")]


def test_empty_input_produces_no_edges():
    assert infer_handoffs([]) == []
