"""Independent AST checks, distinct from any scanner, for whether a dynamically built string
still reaches a SQL execute call or a shell, and whether a secret is still a literal in source."""

import pytest

from purpleteam.codemods.invariants import (INVARIANTS, no_code_execution, no_dynamic_sql, no_hardcoded_secret,
                                            no_shell_injection, no_unsafe_deserialization, no_weak_hash,
                                            requests_have_timeout, tls_verification_on)
from purpleteam.sast import BANDIT_KINDS


def test_a_parameterized_query_passes():
    assert no_dynamic_sql("cursor.execute('SELECT * FROM t WHERE id=?', (x,))") is None


def test_parameters_passed_as_a_string_instead_of_a_tuple_fail():
    """A real model-drafted "fix": the comma sits inside the f-string, so it is not a tuple and the
    driver would bind it character by character -- scanner-clean, but broken."""
    problem = no_dynamic_sql('conn.execute("SELECT * FROM v WHERE name LIKE ?", (f"%{name}%,"))')
    assert problem is not None and "not a sequence" in problem
    assert no_dynamic_sql('conn.execute("SELECT * FROM v WHERE name LIKE ?", (f"%{name}%",))') is None


def test_an_f_string_query_fails():
    problem = no_dynamic_sql("cursor.execute(f'SELECT * FROM t WHERE id={x}')")
    assert problem is not None and "execute" in problem


def test_a_percent_formatted_query_fails():
    assert no_dynamic_sql("cursor.execute('SELECT * FROM t WHERE id=%s' % x)") is not None


def test_a_concatenated_query_fails():
    assert no_dynamic_sql("cursor.execute('SELECT * FROM t WHERE id=' + x)") is not None


def test_a_dot_format_query_fails():
    assert no_dynamic_sql("cursor.execute('SELECT * FROM t WHERE id={}'.format(x))") is not None


def test_executemany_and_executescript_are_also_checked():
    assert no_dynamic_sql("cursor.executemany(f'INSERT INTO t VALUES ({x})', rows)") is not None
    assert no_dynamic_sql("cursor.executescript(f'DROP TABLE {name}')") is not None


def test_a_dynamic_string_passed_to_an_unrelated_call_is_ignored():
    assert no_dynamic_sql("log.info(f'about to run for {x}')") is None


def test_code_unrelated_to_sql_entirely_passes():
    assert no_dynamic_sql("x = 1\ny = x + 2\n") is None


def test_unparseable_source_is_reported_not_raised():
    problem = no_dynamic_sql("cursor.execute(f'SELECT * FROM t WHERE id={x}")  # unterminated
    assert problem is not None and "could not parse" in problem


def test_every_mapped_bandit_kind_has_an_invariant():
    from purpleteam.hardening_scan import HARDENING_KINDS
    assert set(BANDIT_KINDS.values()) <= set(INVARIANTS)  # every scannable code-vuln kind has an independent check
    # the only invariants that are not for a bandit kind are the prompt / tool-description hardening ones
    assert set(INVARIANTS) - set(BANDIT_KINDS.values()) == set(HARDENING_KINDS)


def test_sql_built_for_a_query_helper_is_caught_not_only_direct_execute_calls():
    assert no_dynamic_sql('row = self._one(f"SELECT * FROM {table} WHERE id = ?", row_id)') is not None
    assert no_dynamic_sql('row = self._one({"vendors": "SELECT * FROM vendors WHERE id = ?"}[table], row_id)') is None
    assert no_dynamic_sql('raise ValueError(f"unknown table {table!r}")') is None  # not SQL-shaped


@pytest.mark.parametrize("source", [
    'q = "SELECT * FROM {} WHERE id = 1".format(table)',
    'q = "DELETE FROM t WHERE id = %s" % row',
    'q = "  (select a from t where b = " + b + ")"',
])
def test_every_way_of_building_a_query_is_caught(source):
    assert no_dynamic_sql(source) is not None


def test_prose_that_mentions_select_and_from_is_not_mistaken_for_sql():
    """Found on a real project: a scanner flagged this log line as SQL injection."""
    assert no_dynamic_sql('logger.info(f"Using LLM to select {n} most relevant tools from {len(tools)}")') is None


@pytest.mark.parametrize("checker, unsafe, safe", [
    (no_code_execution, "eval(text)", "ast.literal_eval(text)"),
    (no_unsafe_deserialization, "pickle.loads(blob)", "json.loads(blob)"),
    (no_unsafe_deserialization, "yaml.load(text)", "yaml.load(text, Loader=yaml.SafeLoader)"),
    (tls_verification_on, "requests.get(url, verify=False)", "requests.get(url, timeout=10)"),
    (no_weak_hash, "hashlib.md5(data)", "hashlib.sha256(data)"),
    (no_weak_hash, "hashlib.new('sha1', data)", "hashlib.sha1(data, usedforsecurity=False)"),
    (no_shell_injection, "os.system(f'ls {d}')", "subprocess.run(['ls', d])"),
    (requests_have_timeout, "requests.get(url)", "requests.get(url, timeout=30)"),
    (requests_have_timeout, "httpx.post(url, timeout=None)", "httpx.post(url, timeout=10)"),
])
def test_each_invariant_rejects_the_unsafe_shape_and_accepts_the_fix(checker, unsafe, safe):
    assert checker(unsafe) is not None
    assert checker(safe) is None


def test_a_literal_shell_true_command_passes():
    assert no_shell_injection("subprocess.run('ls -la', shell=True)") is None


def test_a_dynamically_built_shell_true_command_fails():
    problem = no_shell_injection("subprocess.run(f'ls {user_dir}', shell=True)")
    assert problem is not None and "shell=True" in problem


def test_shell_false_with_a_dynamic_command_is_not_this_findings_concern():
    assert no_shell_injection("subprocess.run([cmd, user_dir], shell=False)") is None


def test_percent_and_concat_and_format_shell_commands_all_fail():
    assert no_shell_injection("subprocess.call('rm ' + path, shell=True)") is not None
    assert no_shell_injection("subprocess.Popen('echo %s' % name, shell=True)") is not None
    assert no_shell_injection("subprocess.check_output('echo {}'.format(name), shell=True)") is not None


def test_a_dynamic_command_to_an_unrelated_call_is_ignored():
    assert no_shell_injection("log.info(f'about to run {cmd}')") is None


def test_shell_injection_unparseable_source_is_reported_not_raised():
    problem = no_shell_injection("subprocess.run(f'ls {x}', shell=True")  # unterminated
    assert problem is not None and "could not parse" in problem


def test_a_literal_secret_assignment_fails():
    problem = no_hardcoded_secret("password = 'super-secret-value'")
    assert problem is not None and "password" in problem


def test_an_env_or_config_backed_secret_passes():
    assert no_hardcoded_secret("password = os.environ['DB_PASSWORD']") is None
    assert no_hardcoded_secret("api_key = config.get('api_key')") is None


def test_a_literal_default_parameter_fails():
    problem = no_hardcoded_secret("def connect(user, password='literal-default'):\n    pass\n")
    assert problem is not None and "password" in problem


def test_a_literal_keyword_argument_fails():
    problem = no_hardcoded_secret("connect(host='db', password='literal-value')")
    assert problem is not None and "password" in problem


def test_a_non_secret_named_variable_with_a_literal_is_ignored():
    assert no_hardcoded_secret("greeting = 'hello world'") is None


def test_hardcoded_secret_unparseable_source_is_reported_not_raised():
    problem = no_hardcoded_secret("password = 'x")  # unterminated
    assert problem is not None and "could not parse" in problem
