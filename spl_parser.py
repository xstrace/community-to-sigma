"""
SPL Tokenizer and Recursive Descent Parser.

Tokenizes SPL search strings into tokens, then parses them into an AST.
Handles SPL's context-sensitive nature (where keywords can be field names,
commands can be bare words, etc.) using lookahead and precedence rules.

No regex-based string replacement for parsing — proper token stream processing.
"""

import re
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# TOKEN TYPES
# ---------------------------------------------------------------------------
class TokenType:
    PIPE = "PIPE"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    COMMA = "COMMA"
    EQ = "EQ"
    NEQ = "NEQ"
    GT = "GT"
    LT = "LT"
    GE = "GE"
    LE = "LE"
    STRING = "STRING"
    WILDCARD = "WILDCARD"
    NUMBER = "NUMBER"
    MACRO = "MACRO"
    WORD = "WORD"


@dataclass
class Token:
    type: str
    value: str
    pos: int = 0


# Keywords that act as boolean operators in search context
BOOLEAN_KEYWORDS = {"AND", "OR", "NOT"}

# Keywords that start SPL clauses/commands
COMMAND_NAMES = {
    "tstats", "stats", "where", "eval", "rename", "table", "fields",
    "fillnull", "convert", "rex", "lookup", "inputlookup", "outputlookup",
    "sort", "dedup", "head", "tail", "mvexpand", "spath", "search",
    "transaction", "eventstats", "streamstats", "bin", "bucket",
    "makemv", "from", "top", "rare", "chart", "timechart",
}

# tstats structural keywords
TSTATS_KEYWORDS = {"from", "where", "by", "as", "prestats"}

# Stats structural keywords
STATS_KEYWORDS = {"by", "as"}

# Keywords that are structural (not field names) in specific contexts
STRUCTURAL_KEYWORDS = COMMAND_NAMES | TSTATS_KEYWORDS | STATS_KEYWORDS | {
    "datamodel", "count", "sum", "avg", "min", "max", "dc",
    "values", "latest", "earliest", "distinct_count", "null",
    "true", "false", "t", "f",
}


# ---------------------------------------------------------------------------
# TOKENIZER
# ---------------------------------------------------------------------------
def tokenize(text: str) -> list[Token]:
    """Tokenize an SPL string into a flat list of tokens."""
    tokens = []
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]

        # Whitespace
        if ch.isspace():
            i += 1
            continue

        # Pipe
        if ch == "|":
            tokens.append(Token(TokenType.PIPE, "|", i))
            i += 1
            continue

        # Parentheses and comma
        if ch == "(":
            tokens.append(Token(TokenType.LPAREN, "(", i))
            i += 1
            continue
        if ch == ")":
            tokens.append(Token(TokenType.RPAREN, ")", i))
            i += 1
            continue
        if ch == ",":
            tokens.append(Token(TokenType.COMMA, ",", i))
            i += 1
            continue

        # Comparison operators
        if text[i:i+2] == "!=":
            tokens.append(Token(TokenType.NEQ, "!=", i))
            i += 2
            continue
        if text[i:i+2] == ">=":
            tokens.append(Token(TokenType.GE, ">=", i))
            i += 2
            continue
        if text[i:i+2] == "<=":
            tokens.append(Token(TokenType.LE, "<=", i))
            i += 2
            continue
        if ch == "=":
            tokens.append(Token(TokenType.EQ, "=", i))
            i += 1
            continue
        if ch == ">":
            tokens.append(Token(TokenType.GT, ">", i))
            i += 1
            continue
        if ch == "<":
            tokens.append(Token(TokenType.LT, "<", i))
            i += 1
            continue

        # Quoted strings
        if ch in ('"', "'"):
            quote = ch
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2  # skip escaped char
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            tokens.append(Token(TokenType.STRING, text[i:j], i))
            i = j
            continue

        # Backtick macros
        if ch == "`":
            j = i + 1
            while j < n and text[j] != "`":
                j += 1
            if j < n:
                j += 1  # include closing backtick
            tokens.append(Token(TokenType.MACRO, text[i:j], i))
            i = j
            continue

        # Numbers (including hex, negative, scientific notation)
        num_match = re.match(
            r'-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)',
            text[i:]
        )
        if num_match:
            tokens.append(Token(TokenType.NUMBER, num_match.group(), i))
            i += len(num_match.group())
            continue

        # Wildcard patterns
        if ch == "*":
            j = i + 1
            # Consume until whitespace, pipe, paren, comma, operator, or another *
            while j < n and text[j] not in " \t\n|)(,=><`'\"":
                if text[j] == "*":
                    j += 1
                    break
                j += 1
            tokens.append(Token(TokenType.WILDCARD, text[i:j], i))
            i = j
            continue

        # Words (identifiers, keywords, field names)
        j = i
        while j < n and text[j] not in " \t\n|)(,=><`'\"":
            # Check for operators
            if j > i and text[j] in "=><":
                break
            j += 1
        word = text[i:j]
        # Check for trailing * (wildcard suffix like "foo*")
        if j < n and text[j] == "*":
            # This word ends at j, then * follows — make it a wildcard
            # Actually, let me handle this differently:
            # Words with internal * are WILDCARD tokens
            pass
        tokens.append(Token(TokenType.WORD, word, i))
        i = j

    return tokens


# ---------------------------------------------------------------------------
# PARSER
# ---------------------------------------------------------------------------
class SPLParser:
    """Recursive descent parser for SPL search strings."""

    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self) -> Token:
        if self.pos >= len(self.tokens):
            raise EOFError("Unexpected end of token stream")
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def expect(self, token_type: str) -> Token:
        token = self.consume()
        if token.type != token_type:
            raise SyntaxError(
                f"Expected {token_type}, got {token.type}({token.value}) at pos {token.pos}"
            )
        return token

    def match(self, token_type: str) -> bool:
        token = self.peek()
        return token is not None and token.type == token_type

    def match_word(self, *words: str) -> bool:
        token = self.peek()
        return (
            token is not None
            and token.type == TokenType.WORD
            and token.value.lower() in {w.lower() for w in words}
        )

    def parse(self) -> dict:
        """Parse the full pipeline and return an AST dict."""
        stages = []

        # Optional leading pipe
        if self.match(TokenType.PIPE):
            self.consume()

        # Parse first stage
        stages.append(self._parse_stage())

        # Parse remaining pipe-separated stages
        while self.match(TokenType.PIPE):
            self.consume()
            stages.append(self._parse_stage())

        return {
            "type": "pipeline",
            "stages": stages,
        }

    def _parse_stage(self) -> dict:
        """Parse one pipe stage."""
        # Check if this stage starts with a command name
        token = self.peek()
        if token and token.type == TokenType.WORD and token.value.lower() in COMMAND_NAMES:
            return self._parse_command_stage()
        else:
            return self._parse_search_stage()

    def _parse_command_stage(self) -> dict:
        """Parse a command stage: COMMAND_NAME arg*"""
        cmd_token = self.consume()
        cmd_name = cmd_token.value.lower()

        stage: dict[str, Any] = {
            "type": "command",
            "command": cmd_name,
        }

        # Parse command-specific structures
        if cmd_name == "tstats":
            stage.update(self._parse_tstats())
        elif cmd_name == "where":
            stage["condition"] = self._parse_boolean_expr()
        elif cmd_name == "stats":
            stage.update(self._parse_stats())
        elif cmd_name == "eval":
            stage.update(self._parse_eval())
        elif cmd_name == "search":
            stage["condition"] = self._parse_boolean_expr()
        else:
            # Generic command — collect remaining tokens as raw args
            args = []
            while self.peek() and self.peek().type != TokenType.PIPE:
                args.append(self._parse_token_value())
            stage["args"] = args

        return stage

    def _parse_search_stage(self) -> dict:
        """Parse a search stage (bare search terms before first pipe)."""
        condition = self._parse_boolean_expr()
        return {
            "type": "search",
            "condition": condition,
        }

    def _parse_boolean_expr(self) -> dict:
        """Parse boolean expression: OR > AND > NOT > comparison"""
        return self._parse_or()

    def _parse_or(self) -> dict:
        left = self._parse_and()
        while self.match_word("OR"):
            self.consume()
            right = self._parse_and()
            left = {"type": "or", "left": left, "right": right}
        return left

    def _parse_and(self) -> dict:
        left = self._parse_not()
        # Implicit AND: sequential expressions without explicit AND keyword
        while self.peek() and self.peek().type != TokenType.PIPE:
            token = self.peek()
            if token.type == TokenType.WORD and token.value.upper() == "OR":
                break
            if token.type == TokenType.RPAREN:
                break
            # Stop at structural keywords
            if token.type == TokenType.WORD and token.value.lower() in {"by", "from", "where", "as", "prestats"}:
                break
            # Check if it looks like a new comparison or atom
            if self._looks_like_atom_start():
                right = self._parse_not()
                left = {"type": "and", "left": left, "right": right}
            elif token.type == TokenType.WORD and token.value.upper() == "AND":
                self.consume()
                right = self._parse_not()
                left = {"type": "and", "left": left, "right": right}
            else:
                break
        return left

    def _parse_not(self) -> dict:
        if self.match_word("NOT"):
            self.consume()
            expr = self._parse_not()
            return {"type": "not", "expr": expr}
        return self._parse_primary()

    def _parse_primary(self) -> dict:
        """Parse a primary expression: comparison, IN, paren group, or bare atom."""
        # Parenthesized group
        if self.match(TokenType.LPAREN):
            self.consume()
            expr = self._parse_boolean_expr()
            self.expect(TokenType.RPAREN)
            return expr

        # Could be a comparison or a bare atom
        return self._parse_comparison_or_atom()

    def _parse_comparison_or_atom(self) -> dict:
        """Parse either a comparison (field OP value / field IN (...)) or a bare atom."""

        # Handle parenthesized group before trying field ref
        if self.match(TokenType.LPAREN):
            self.consume()
            expr = self._parse_boolean_expr()
            self.expect(TokenType.RPAREN)
            return expr

        # Handle macro as a bare atom
        if self.match(TokenType.MACRO):
            token = self.consume()
            return {"type": "macro", "value": token.value}

        # Try to parse field reference
        field_expr = self._try_parse_field_ref()
        if field_expr is None:
            # Must be a bare atom
            token = self.peek()
            if token:
                return {"type": "atom", "value": self._parse_token_value()}
            raise SyntaxError("Unexpected end of input")

        # Check if it's followed by an operator
        op_token = self.peek()
        if op_token is None:
            return field_expr  # bare field reference

        if op_token.type == TokenType.EQ:
            self.consume()
            return {"type": "eq", "field": field_expr, "value": self._parse_value()}
        elif op_token.type == TokenType.NEQ:
            self.consume()
            return {"type": "ne", "field": field_expr, "value": self._parse_value()}
        elif op_token.type == TokenType.GT:
            self.consume()
            return {"type": "gt", "field": field_expr, "value": self._parse_value()}
        elif op_token.type == TokenType.LT:
            self.consume()
            return {"type": "lt", "field": field_expr, "value": self._parse_value()}
        elif op_token.type == TokenType.GE:
            self.consume()
            return {"type": "ge", "field": field_expr, "value": self._parse_value()}
        elif op_token.type == TokenType.LE:
            self.consume()
            return {"type": "le", "field": field_expr, "value": self._parse_value()}
        elif op_token.type == TokenType.WORD and op_token.value.upper() == "IN":
            self.consume()  # consume IN
            return self._parse_in_list(field_expr)
        elif op_token.type == TokenType.LPAREN:
            # field followed by ( — this is a function call, treat field as function name
            # and everything inside parens as args
            self.consume()  # (
            args = []
            while self.peek() and self.peek().type != TokenType.RPAREN:
                if self.peek().type == TokenType.COMMA:
                    self.consume()  # skip comma
                    continue
                args.append(self._parse_boolean_expr())
            self.expect(TokenType.RPAREN)
            return {"type": "function_call", "name": field_expr, "args": args}
        else:
            # No operator follows — it's a bare field reference
            return field_expr

    def _parse_in_list(self, field_expr: dict) -> dict:
        """Parse field IN (value, value, ...)"""
        self.expect(TokenType.LPAREN)
        values = []
        while self.peek() and self.peek().type != TokenType.RPAREN:
            if self.peek().type == TokenType.COMMA:
                self.consume()
                continue
            values.append(self._parse_value())
        self.expect(TokenType.RPAREN)
        return {"type": "in", "field": field_expr, "values": values}

    def _try_parse_field_ref(self) -> dict | None:
        """Try to parse a field reference (simple name or dotted). Returns None if not possible."""
        token = self.peek()
        if token is None:
            return None

        # STRING as a field is only valid if followed by an operator (quoted field name)
        if token.type == TokenType.STRING:
            # Check if followed by an operator
            if self.pos + 1 < len(self.tokens):
                next_t = self.tokens[self.pos + 1]
                if next_t.type not in (TokenType.EQ, TokenType.NEQ, TokenType.GT,
                                       TokenType.LT, TokenType.GE, TokenType.LE,
                                       TokenType.LPAREN) and not (
                    next_t.type == TokenType.WORD and next_t.value.upper() == "IN"):
                    return None  # Bare string, not a field reference
            else:
                return None  # Last token, can't be a field

        # WILDCARD as a field is not valid
        if token.type == TokenType.WILDCARD:
            return None

        # Field can be a WORD or STRING (quoted field name). MACRO tokens are atoms, not fields.
        if token.type in (TokenType.WORD, TokenType.STRING):
            self.consume()
            parts = [token.value]

            # Handle dotted references: field.subfield.subfield
            saved_pos = self.pos
            while (
                self.match(TokenType.WORD) and self.tokens[self.pos].value == "."
            ):
                self.consume()  # consume the "." (tokenized as WORD since it's a single char)
                if self.peek() and self.peek().type in (TokenType.WORD, TokenType.STRING):
                    parts.append(self.consume().value)
                else:
                    # Put back the dot
                    self.pos = saved_pos
                    break
                saved_pos = self.pos

            return {"type": "field", "parts": parts, "raw": ".".join(parts)}

        return None

    def _parse_value(self) -> dict:
        """Parse a value (string, number, wildcard, macro, word)."""
        token = self.consume()
        return self._token_to_value(token)

    def _parse_token_value(self) -> dict:
        """Parse a single token as a value (without consuming if not appropriate)."""
        token = self.peek()
        if token is None:
            raise EOFError("Unexpected end of input")
        if token.type in (TokenType.PIPE, TokenType.RPAREN):
            raise SyntaxError(f"Unexpected token {token.type}")
        self.consume()
        return self._token_to_value(token)

    def _token_to_value(self, token: Token) -> dict:
        """Convert a token to a value AST node."""
        if token.type == TokenType.STRING:
            return {"type": "string", "value": token.value}
        elif token.type == TokenType.WILDCARD:
            return {"type": "wildcard", "value": token.value}
        elif token.type == TokenType.NUMBER:
            return {"type": "number", "value": token.value}
        elif token.type == TokenType.MACRO:
            return {"type": "macro", "value": token.value}
        elif token.type == TokenType.WORD:
            return {"type": "word", "value": token.value}
        elif token.type == TokenType.COMMA:
            return {"type": "word", "value": ","}
        else:
            # Operators, parens, etc. — return as raw string in generic contexts
            return {"type": "word", "value": token.value}

    def _looks_like_atom_start(self) -> bool:
        """Check if the current position looks like the start of a new atom."""
        token = self.peek()
        if token is None:
            return False
        if token.type in (
            TokenType.WORD, TokenType.STRING, TokenType.WILDCARD,
            TokenType.NUMBER, TokenType.MACRO, TokenType.LPAREN,
        ):
            # Don't treat structural keywords as atom starts
            if token.type == TokenType.WORD and token.value.lower() in {"by", "from", "where", "as", "prestats"}:
                return False
            return True
        return False

    def _parse_tstats(self) -> dict:
        """Parse tstats arguments: ... FROM datamodel=X WHERE ... BY ..."""
        result: dict[str, Any] = {
            "macros": [],
            "aggregations": [],
            "from": None,
            "where": None,
            "by": [],
        }

        # Parse until FROM, WHERE, BY, or end of stage
        while self.peek() and self.peek().type != TokenType.PIPE:
            token = self.peek()

            if token.type == TokenType.MACRO:
                result["macros"].append(self.consume().value)
                continue

            if token.type == TokenType.WORD:
                word = token.value.lower()

                if word == "from":
                    self.consume()
                    result["from"] = self._parse_datamodel_refs()
                    continue

                if word == "where":
                    self.consume()
                    result["where"] = self._parse_boolean_expr()
                    continue

                if word == "by":
                    self.consume()
                    result["by"] = self._parse_field_list()
                    continue

                if word == "prestats":
                    self.consume()
                    result["prestats"] = self.consume().value  # t or f
                    continue

                # Otherwise it might be an aggregation function
                agg = self._try_parse_agg()
                if agg:
                    result["aggregations"].append(agg)
                    continue

                # Or just a keyword argument — skip
                self.consume()
                continue

            # Skip other tokens in tstats preamble
            self.consume()

        return result

    def _parse_datamodel_refs(self) -> list[dict]:
        """Parse datamodel references: datamodel=X.Y, datamodel=Z"""
        refs = []
        while self.peek() and self.peek().type != TokenType.PIPE:
            if self.match_word("datamodel"):
                self.consume()
                self.expect(TokenType.EQ)
                name = self.consume().value  # e.g., Endpoint.Processes
                refs.append({"type": "datamodel", "name": name})
            elif self.match(TokenType.COMMA):
                self.consume()
                continue
            elif self.match_word("where", "by"):
                break
            else:
                self.consume()  # skip unknown
        return refs

    def _try_parse_agg(self) -> dict | None:
        """Try to parse an aggregation function: count, sum(field), min(field) as alias, etc."""
        token = self.peek()
        if token is None or token.type != TokenType.WORD:
            return None

        func_name = token.value.lower()
        agg_funcs = {"count", "sum", "avg", "min", "max", "dc",
                      "values", "latest", "earliest", "distinct_count"}

        if func_name not in agg_funcs:
            return None

        self.consume()  # consume function name
        func = {
            "type": "aggregation",
            "function": func_name,
            "field": None,
            "alias": None,
        }

        # Check for (field) — field may be complex (nested function calls)
        if self.match(TokenType.LPAREN):
            self.consume()
            if self.peek() and self.peek().type != TokenType.RPAREN:
                # Check if this is a complex expression (contains nested parens or keywords)
                if self._looks_like_complex_arg():
                    func["field"] = self._parse_boolean_expr()
                else:
                    func["field"] = self._parse_value()
            self.expect(TokenType.RPAREN)

        # Check for AS alias
        if self.match_word("as"):
            self.consume()
            if self.peek():
                func["alias"] = self._parse_value()

        return func

    def _parse_field_list(self) -> list[dict]:
        """Parse a list of field references: field1, field2, ..."""
        fields = []
        while self.peek() and self.peek().type != TokenType.PIPE:
            # Skip commas
            if self.match(TokenType.COMMA):
                self.consume()
                continue

            # Check if we hit the next structural keyword
            if self.match_word("from", "where", "by", "prestats"):
                break

            field = self._try_parse_field_ref()
            if field:
                fields.append(field)
            else:
                self.consume()  # skip unknown
        return fields

    def _parse_stats(self) -> dict:
        """Parse stats arguments."""
        result: dict[str, Any] = {
            "functions": [],
            "by": [],
        }

        while self.peek() and self.peek().type != TokenType.PIPE:
            token = self.peek()

            if token.type == TokenType.WORD:
                word = token.value.lower()

                if word == "by":
                    self.consume()
                    result["by"] = self._parse_field_list()
                    continue

                # Try aggregation
                agg = self._try_parse_agg()
                if agg:
                    result["functions"].append(agg)
                    continue

            # Try to parse a function call like values(eval(if(...)))
            if token.type == TokenType.WORD and self._peek_next_is(TokenType.LPAREN):
                func_name_token = self.consume()
                self.expect(TokenType.LPAREN)
                args = self._parse_function_args()
                self.expect(TokenType.RPAREN)
                func_node: dict[str, Any] = {
                    "type": "function_call",
                    "name": {"type": "field", "parts": [func_name_token.value],
                             "raw": func_name_token.value},
                    "args": args,
                }
                # Check for AS alias
                if self.match_word("as"):
                    self.consume()
                    func_node["alias"] = self._parse_value()
                result["functions"].append(func_node)
                continue

            self.consume()

        return result

    def _parse_function_args(self) -> list[dict]:
        """Parse function call arguments: expr, expr, expr"""
        args = []
        while self.peek() and self.peek().type != TokenType.RPAREN:
            if self.peek().type == TokenType.COMMA:
                self.consume()
                continue
            args.append(self._parse_boolean_expr())
        return args

    def _looks_like_complex_arg(self) -> bool:
        """Check if the current position looks like a complex expression
        (contains function calls, keywords like 'if', 'eval', etc.)"""
        if not self.peek():
            return False
        # Look ahead a few tokens for signs of complexity
        # Simple: just a field reference like _time, process_name
        # Complex: eval(...), if(...), OperatorType="...", etc.
        token = self.peek()

        # If it starts with a known evaluator keyword
        if token.type == TokenType.WORD and token.value.lower() in {
            "eval", "if", "case", "coalesce", "replace", "split", "mvjoin",
            "trim", "lower", "upper", "len", "match", "round", "tonumber",
            "tostring", "urldecode", "mvfilter", "mvindex",
        }:
            return True

        # If the next few tokens contain an operator, it's likely a comparison expr
        for i in range(min(5, len(self.tokens) - self.pos)):
            t = self.tokens[self.pos + i]
            if t.type in (TokenType.EQ, TokenType.NEQ, TokenType.GT,
                          TokenType.LT, TokenType.GE, TokenType.LE):
                return True
            if t.type == TokenType.RPAREN:
                break

        return False

    def _peek_next_is(self, token_type: str) -> bool:
        """Check if the next token (after current) is of given type."""
        if self.pos + 1 >= len(self.tokens):
            return False
        return self.tokens[self.pos + 1].type == token_type

    def _parse_eval(self) -> dict:
        """Parse eval arguments."""
        assignments = []
        while self.peek() and self.peek().type != TokenType.PIPE:
            field = self._try_parse_field_ref()
            if field and self.match(TokenType.EQ):
                self.consume()  # =
                value = self._parse_boolean_expr() if self.peek() else None
                assignments.append({"field": field, "value": value})
            elif self.match(TokenType.COMMA):
                self.consume()
            else:
                self.consume()  # skip
        return {"assignments": assignments}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def parse_spl(spl_text: str) -> dict:
    """Parse an SPL search string into an AST.

    Tries full parse first. If that fails and the query contains complex
    commands (eventstats, appendpipe, foreach, etc.), returns a minimal
    AST that marks it as unparseable but preserves macro names and
    complex-command indicators for the classifier.
    """
    tokens = tokenize(spl_text)

    try:
        parser = SPLParser(tokens)
        return parser.parse()
    except SyntaxError as e:
        # Check if this query contains patterns known to be complex
        complex_patterns = [
            "eventstats", "appendpipe", "foreach", "timechart",
            "streamstats", "| eval", "relative_time", "stdev",
        ]
        has_complex = any(p in spl_text.lower() for p in complex_patterns)

        if has_complex:
            # Return minimal AST so classifier can properly skip it
            macros = _extract_macros_from_text(spl_text)
            return {
                "type": "pipeline",
                "stages": [
                    {
                        "type": "command",
                        "command": "__unparseable_complex__",
                        "raw_search": spl_text[:200],
                    }
                ],
                "_macros": macros,
                "_parse_error": str(e),
            }

        # Re-raise for genuinely unexpected parse errors
        raise


def _extract_macros_from_text(text: str) -> list[str]:
    """Extract backtick macros from raw SPL text."""
    macros = []
    in_macro = False
    start = 0
    for i, ch in enumerate(text):
        if ch == "`":
            if not in_macro:
                start = i
                in_macro = True
            else:
                macros.append(text[start:i + 1])
                in_macro = False
    return macros


def ast_to_debug_string(ast: dict, indent: int = 0) -> str:
    """Pretty-print an SPL AST for debugging."""
    prefix = "  " * indent

    if not isinstance(ast, dict):
        return f"{prefix}{ast}"

    ast_type = ast.get("type", "unknown")
    lines = [f"{prefix}[{ast_type}]"]

    for key, value in ast.items():
        if key == "type":
            continue
        if isinstance(value, dict):
            lines.append(f"{prefix}  {key}:")
            lines.append(ast_to_debug_string(value, indent + 2))
        elif isinstance(value, list):
            lines.append(f"{prefix}  {key}:")
            for item in value:
                lines.append(ast_to_debug_string(item, indent + 2))
        else:
            lines.append(f"{prefix}  {key}: {value}")

    return "\n".join(lines)
