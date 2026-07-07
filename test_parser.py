"""Tests for SPL tokenizer and parser."""

import pytest
from spl_parser import tokenize, parse_spl, TokenType


class TestTokenizer:
    def test_simple_words(self):
        tokens = tokenize("field1=value1 field2=value2")
        assert len(tokens) == 6  # WORD EQ WORD WORD EQ WORD
        assert tokens[0].type == TokenType.WORD
        assert tokens[0].value == "field1"

    def test_macro(self):
        tokens = tokenize("`my_macro` field=value")
        assert tokens[0].type == TokenType.MACRO
        assert tokens[0].value == "`my_macro`"

    def test_quoted_string(self):
        tokens = tokenize('field="quoted value"')
        assert tokens[2].type == TokenType.STRING
        assert tokens[2].value == '"quoted value"'

    def test_wildcard(self):
        tokens = tokenize("field=*wild*")
        assert tokens[2].type == TokenType.WILDCARD

    def test_number(self):
        tokens = tokenize("field=123 field2=-456 field3=0xABCD")
        assert tokens[2].type == TokenType.NUMBER
        assert tokens[5].type == TokenType.NUMBER

    def test_pipe(self):
        tokens = tokenize("search a=b | stats count")
        assert tokens[4].type == TokenType.PIPE

    def test_parentheses(self):
        tokens = tokenize("(a=b OR c=d)")
        assert tokens[0].type == TokenType.LPAREN
        assert tokens[-1].type == TokenType.RPAREN

    def test_comparison_operators(self):
        tokens = tokenize("a!=b c>d e<f g>=h i<=j")
        types = [t.type for t in tokens]
        assert TokenType.NEQ in types
        assert TokenType.GT in types
        assert TokenType.LT in types
        assert TokenType.GE in types
        assert TokenType.LE in types

    def test_bang_is_unary_not_and_tokenizer_advances(self):
        tokens = tokenize("!(a=b) !match(value, pattern)")
        assert [token.value for token in tokens].count("NOT") == 2
        assert all(token.value for token in tokens)


class TestParser:
    def test_simple_search(self):
        ast = parse_spl("`macro` field1=value1")
        assert ast["type"] == "pipeline"
        assert len(ast["stages"]) == 1
        stage = ast["stages"][0]
        assert stage["type"] == "search"

    def test_tstats(self):
        ast = parse_spl(
            "| tstats count FROM datamodel=Endpoint.Processes "
            "WHERE Processes.process_name=cmd.exe BY Processes.dest"
        )
        stage = ast["stages"][0]
        assert stage["type"] == "command"
        assert stage["command"] == "tstats"
        assert len(stage["from"]) == 1
        assert stage["from"][0]["name"] == "Endpoint.Processes"
        assert stage["where"] is not None

    def test_tstats_with_macros(self):
        ast = parse_spl(
            "| tstats `summariesonly` count FROM datamodel=Endpoint.Processes "
            "WHERE `process_cmd` Processes.process_name=cmd.exe BY Processes.dest Processes.user"
        )
        stage = ast["stages"][0]
        assert "`summariesonly`" in stage.get("macros", [])

    def test_in_operator(self):
        ast = parse_spl('field IN ("a", "b", "c")')
        stage = ast["stages"][0]
        cond = stage["condition"]
        assert cond["type"] == "in"

    def test_boolean_or(self):
        ast = parse_spl("a=1 OR b=2")
        stage = ast["stages"][0]
        cond = stage["condition"]
        assert cond["type"] == "or"

    def test_boolean_and(self):
        ast = parse_spl("a=1 b=2")
        stage = ast["stages"][0]
        cond = stage["condition"]
        assert cond["type"] == "and"

    def test_boolean_not(self):
        ast = parse_spl("NOT a=1")
        stage = ast["stages"][0]
        cond = stage["condition"]
        assert cond["type"] == "not"

    def test_bang_boolean_not(self):
        ast = parse_spl("!(a=1 OR b=2)")
        condition = ast["stages"][0]["condition"]
        assert condition["type"] == "not"
        assert condition["expr"]["type"] == "or"

    def test_bang_function_not(self):
        ast = parse_spl("!match(country, expected_country)")
        condition = ast["stages"][0]["condition"]
        assert condition["type"] == "not"
        assert condition["expr"]["type"] == "function_call"

    def test_parenthesized_group(self):
        ast = parse_spl("(a=1 OR b=2) AND c=3")
        stage = ast["stages"][0]
        cond = stage["condition"]
        # should parse as AND of (OR) and eq
        assert cond["type"] == "and"

    def test_multi_stage_pipeline(self):
        ast = parse_spl("`macro` a=1 | stats count BY dest | `filter`")
        assert len(ast["stages"]) == 3

    def test_complex_nested_function(self):
        ast = parse_spl('| stats values(eval(if(x="y",z))) as result by field')
        assert ast["stages"][0]["command"] == "stats"

    def test_dotted_field_names(self):
        ast = parse_spl("Processes.parent_process_name=spoolsv.exe")
        stage = ast["stages"][0]
        cond = stage["condition"]
        field = cond.get("field", {})
        assert "Processes.parent_process_name" in field.get("raw", "")

    def test_wildcard_values(self):
        ast = parse_spl('Web.url=*logoimagehandler.ashx*codes*')
        stage = ast["stages"][0]
        cond = stage["condition"]
        assert cond["type"] == "eq"

    def test_eval_case_parsing(self):
        ast = parse_spl(
            '| eval severity=case(message_id="302013","Built inbound",'
            'message_id="302014","Teardown")'
        )
        assert ast["stages"][0]["command"] == "eval"


class TestRealWorldQueries:
    """Test with actual SPL from Splunk security_content detections."""

    def test_basic_search_with_macro_and_in(self):
        query = ('`powershell` EventCode=4104 ScriptBlockText="*Get-DomainGroupMember*" '
                 'AND ScriptBlockText IN ("*Domain Admins*","*Enterprise Admins*")')
        ast = parse_spl(query)
        assert ast is not None

    def test_tstats_with_aggregations(self):
        query = (
            "| tstats `security_content_summariesonly` count "
            "min(_time) as firstTime max(_time) as lastTime "
            "FROM datamodel=Endpoint.Processes "
            "WHERE `process_cmd` Processes.process_name=cmd.exe "
            "BY Processes.dest Processes.user"
        )
        ast = parse_spl(query)
        stage = ast["stages"][0]
        assert stage["command"] == "tstats"
        assert len(stage["aggregations"]) >= 2

    def test_complex_pipeline(self):
        query = (
            "`cloudtrail` eventName=ConsoleLogin errorMessage=\"Failed authentication\" "
            "| rename user_name as user "
            "| stats count min(_time) as firstTime max(_time) as lastTime BY signature dest user "
            "| `security_content_ctime(firstTime)` "
            "| `filter_macro`"
        )
        ast = parse_spl(query)
        assert len(ast["stages"]) >= 3
