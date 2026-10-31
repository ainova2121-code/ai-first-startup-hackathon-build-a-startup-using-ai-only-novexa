"""The human-approval gate: the scanner flags a dangerous tool's own definition -- pinned by where discovery saw it,
never by name alone -- and the deterministic codemod replaces its action with a marked hold, proven by the same
rescan + invariant as every other source fix."""

from purpleteam.codemods.context import source_statement
from purpleteam.codemods.gate import gate_candidate, gate_message
from purpleteam.codemods.invariants import action_is_gated
from purpleteam.codemods.verify import verify
from purpleteam.discovery import DiscoveredTool, TargetProfile
from purpleteam.gate_scan import GATE_KIND, GATE_TAG, UnguardedActionScanner, parse_location
from purpleteam.hardening_scan import CompositeScanner
from purpleteam.sast import BanditScanner, StaticFinding

TOOLS = '''def build(vendors):
    def update_vendor_bank(vendor_id, bank_account):
        """Replace the bank account on file for a vendor."""
        vendors.update_bank(vendor_id, bank_account)
        return "Bank account updated."

    return [update_vendor_bank]
'''
REPOSITORY = '''class VendorRepository:
    def update_vendor_bank(self, vendor_id, bank_account):
        self.rows[vendor_id] = bank_account
'''


def _target(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "vendor.py").write_text(TOOLS, encoding="utf-8")
    (repo / "repositories.py").write_text(REPOSITORY, encoding="utf-8")
    return repo, UnguardedActionScanner([("update_vendor_bank", "vendor.py", 2)])


def test_only_the_discovered_definition_is_flagged_never_a_same_named_helper(tmp_path):
    repo, scanner = _target(tmp_path)
    (finding,) = scanner.scan(repo)
    assert (finding.kind, finding.subject, finding.line) == (GATE_KIND, "update_vendor_bank", 4)
    assert finding.file.endswith("vendor.py") and not finding.blocking  # advisory unless the tool breached


def test_the_gate_is_verified_independently_holds_the_action_and_is_not_flagged_again(tmp_path):
    repo, scanner = _target(tmp_path)
    path = repo / "vendor.py"
    (finding,) = scanner.scan(repo)
    candidate = gate_candidate(finding, source_statement(path, finding.line))
    verified = verify(candidate, finding, path, CompositeScanner([BanditScanner(), scanner]))
    assert verified.verified_by == ("rescan", "invariant")
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace(candidate.original, candidate.replacement), encoding="utf-8")

    calls = []
    namespace: dict = {}
    exec(compile(path.read_text(encoding="utf-8"), "vendor", "exec"), namespace)  # noqa: S102 - test fixture only
    (tool,) = namespace["build"](type("Vendors", (), {"update_bank": lambda *args: calls.append(args)})())
    assert tool(1, "US00ATTACKER0666") == gate_message("update_vendor_bank") and calls == []
    assert scanner.scan(repo) == []


def test_a_tool_discovery_could_not_locate_is_never_matched_by_name(tmp_path):
    repo, _ = _target(tmp_path)
    tool = DiscoveredTool("update_vendor_bank", "", {}, "?", "write", "vendor")
    assert parse_location("update_vendor_bank", "?") is None
    assert UnguardedActionScanner.from_profile(TargetProfile("t", [tool])).scan(repo) == []


def test_from_profile_pins_only_dangerous_tools_at_their_discovered_definition(tmp_path):
    repo, _ = _target(tmp_path)
    tools = [DiscoveredTool("update_vendor_bank", "", {}, "vendor.py:2", "write", "vendor"),
             DiscoveredTool("build", "", {}, "vendor.py:1", "read", "vendor")]
    assert [f.subject for f in UnguardedActionScanner.from_profile(TargetProfile("t", tools)).scan(repo)] == [
        "update_vendor_bank"]


def test_a_decorated_tool_is_pinned_by_its_first_decorator_line(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "tools.py").write_text("@tool\ndef pay(to):\n    send(to)\n", encoding="utf-8")
    (finding,) = UnguardedActionScanner([("pay", "tools.py", 1)]).scan(repo)
    assert finding.line == 3


def test_no_gate_is_offered_for_a_compound_statement_or_another_kind():
    finding = StaticFinding(GATE_KIND, "vendor.py", 4, "x", "low", "pay")
    assert gate_candidate(finding, "    if ok:") is None
    assert gate_candidate(StaticFinding("sql_injection", "vendor.py", 4, "x", "low", "pay"), "    send(to)") is None
    assert gate_candidate(StaticFinding(GATE_KIND, "vendor.py", 4, "x", "low", ""), "    send(to)") is None


def test_a_tool_name_cannot_break_out_of_the_gate_string():
    finding = StaticFinding(GATE_KIND, "vendor.py", 4, "x", "low", 'pay"); import os; os.system("x')
    candidate = gate_candidate(finding, "    send(to)")
    assert action_is_gated(candidate.replacement.strip()) is None  # still one return of one literal, no call


def test_the_invariant_rejects_the_action_and_a_hold_that_still_acts():
    assert action_is_gated("vendors.update_bank(vendor_id, bank_account)") is not None
    assert action_is_gated(f"return {GATE_TAG!r} + send(to)") is not None
    assert action_is_gated("return 'Bank account updated.'") is not None
    assert action_is_gated(f"return {gate_message('pay')!r}") is None


def test_a_stale_catalog_gate_is_derived_again_instead_of_blocking_the_fix(tmp_path):
    """A catalog entry from an older transform no longer verifies: it is replaced, not left to skip the gate forever."""
    import asyncio

    from purpleteam.audit.ledger import AuditLedger
    from purpleteam.codemods.base import VerifiedCodemod
    from purpleteam.codemods.catalog import CodemodCatalog, pattern_key
    from purpleteam.codemods.restore import SourceSnapshots
    from purpleteam.source_fix import fix_sources

    repo, scanner = _target(tmp_path)
    (finding,) = scanner.scan(repo)
    original = source_statement(repo / "vendor.py", finding.line)
    catalog = CodemodCatalog(tmp_path / "catalog")
    stale = VerifiedCodemod(GATE_KIND, original, '        return "Held for approval."', "old", ("rescan",))
    catalog.approve(pattern_key(GATE_KIND, original), stale, approval="auto-approved")

    result = asyncio.run(fix_sources([finding], repo, scanner, catalog, complete=None,
                                     snapshots=SourceSnapshots(tmp_path / "snap.json"),
                                     ledger=AuditLedger(tmp_path / "audit.jsonl")))
    (change,) = result.changes
    assert GATE_TAG in (repo / "vendor.py").read_text(encoding="utf-8") and "invariant" in change["verified_by"]
