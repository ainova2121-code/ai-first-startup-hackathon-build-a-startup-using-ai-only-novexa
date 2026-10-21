"""Independent AST checks, distinct from any scanner, for whether a dynamically built string
still reaches a SQL execute call or a shell, and whether a secret is still a literal in source."""

from purpleteam.codemods.invariants import INVARIANTS, no_dynamic_sql, no_hardcoded_secret, no_shell_injection


def test_a_parameterized_query_passes():
    assert no_dynamic_sql("cursor.execute('SELECT * FROM t WHERE id=?', (x,))") is None


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


def test_registered_invariants_cover_exactly_these_three_kinds_today():
    assert set(INVARIANTS) == {"sql_injection", "shell_injection", "hardcoded_secret"}


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
