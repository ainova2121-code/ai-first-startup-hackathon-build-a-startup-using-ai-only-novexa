"""What the fix author sees: the whole flagged statement, its enclosing function, and the literal
values callers really pass -- all read from the target's own AST, nothing domain-specific."""

from purpleteam.codemods.context import fix_context, source_statement, statement

REPO_SOURCE = '''class Repo:
    def _get(self, table, row_id):
        row = self._one(f"SELECT * FROM {table} WHERE id = ?", row_id)
        return row

    def vendor(self, vendor_id):
        return self._get("vendors", vendor_id)

    def order(self, order_id):
        return self._get(table="orders", row_id=order_id)
'''


def test_a_finding_inside_a_multi_line_call_covers_the_whole_statement():
    text = "x = 1\nrows = conn.execute(\n    f'SELECT * FROM t WHERE id={x}'\n).fetchall()\n"
    assert statement(text, 3) == (2, 4)


def test_a_compound_statement_header_stays_one_line():
    assert statement("if x:\n    y = 1\n", 1) == (1, 1)


def test_the_context_lists_the_identifiers_callers_really_pass(tmp_path):
    (tmp_path / "repo.py").write_text(REPO_SOURCE, encoding="utf-8")
    context = fix_context(tmp_path, tmp_path / "repo.py", 3)
    assert context["call_site_values"] == {"table": ["orders", "vendors"]}
    assert context["enclosing_function"].startswith("    def _get(self, table, row_id):")
    assert source_statement(tmp_path / "repo.py", 3).strip().startswith("row = self._one(")


def test_an_interpolated_self_attribute_is_not_treated_as_a_caller_argument(tmp_path):
    """Found on a real project: f"{self.url}" made ``self`` look like a parameter callers pass."""
    source = "class C:\n    def go(self):\n        return f'SELECT {self.table} FROM t'\n\nC().go()\n"
    (tmp_path / "c.py").write_text(source, encoding="utf-8")
    assert "call_site_values" not in fix_context(tmp_path, tmp_path / "c.py", 3)


def test_no_values_are_claimed_when_any_caller_passes_a_non_literal(tmp_path):
    (tmp_path / "repo.py").write_text(REPO_SOURCE, encoding="utf-8")
    (tmp_path / "other.py").write_text("def f(repo, name):\n    return repo._get(name, 1)\n", encoding="utf-8")
    assert "call_site_values" not in fix_context(tmp_path, tmp_path / "repo.py", 3)
