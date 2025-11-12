# mini_cfg_checker_nested.py

import re

# === TOKEN DEFINITIONS ===
token_spec = [
    ('IF',         r'if'),
    ('LPAREN',     r'\('),
    ('RPAREN',     r'\)'),
    ('LBRACE',     r'\{'),
    ('RBRACE',     r'\}'),
    ('EQ',         r'=='),
    ('GT',         r'>'),         # Adisionál: Greater Than (>)
    ('LT',         r'<'),         # Adisionál: Less Than (<)
    ('ASSIGN',     r'='),
    ('NUMBER',     r'\d+'),
    ('IDENTIFIER', r'[a-zA-Z_]\w*'),
    ('SEMICOLON',  r';'),
    ('SKIP',       r'[ \t\n]+'),
    ('MISMATCH',   r'.'),
]

token_regex = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in token_spec)

# === LEXER ===
def lexer(code):
    tokens = []
    for match in re.finditer(token_regex, code):
        kind = match.lastgroup
        value = match.group()
        if kind == 'SKIP':
            continue
        elif kind == 'MISMATCH':
            raise SyntaxError(f"Unexpected character: {value}")
        elif kind in ('NUMBER', 'IDENTIFIER'):
            tokens.append(f"[{kind}:{value}]")
        else:
            tokens.append(f"[{kind}]")
    return tokens

# A funsaun check_syntax ne'e la úniku ba Nested If, tanba ne'e ha'u husik hanesan uluk.
def check_syntax(code):
    errors = []
    if code.count("if") < 2:
        errors.append("Need at least two 'if' keywords for nested structure")
    # ... (ba cek kona-ba paréntezes no xave sira)
    if code.count("(") != code.count(")"):
        errors.append("Unmatched parentheses '()' count")
    if code.count("{") != code.count("}"):
        errors.append("Unmatched braces '{}' count")
    if code.count("=") < 1:
        errors.append("Assignment operator '=' is missing")
    if code.count(";") < 1:
        errors.append("Semicolon ';' is missing")
    return errors

# === MAIN ===
user_input = input("Enter your code: ").strip()

try:
    tokens = lexer(user_input)
    print("\nLexer Output (tokens):")
    print(' '.join(tokens))

    errors = check_syntax(user_input)

    if not errors:
        # CFG/Regex ne'e simu de'it estrutura Nested If espesífiku ne'e:
        # if (ID OP NUM) { if (ID OP NUM) { ID = NUM; } }
        nested_if_pattern = re.compile(
            r'^\s*if\s*\(\s*[a-zA-Z_]\w*\s*[<>]+\s*\d+\s*\)\s*\{\s*if\s*\(\s*[a-zA-Z_]\w*\s*[<>]+\s*\d+\s*\)\s*\{\s*[a-zA-Z_]\w*\s*=\s*\d+\s*;\s*\}\s*\}$'
        )
        
        if nested_if_pattern.match(user_input):
            print("\n✅ Syntax correct for the specific Nested If CFG!")
        else:
            print("\n❌ Syntax Error: Structure doesn't match the specific Nested If CFG.")
    else:
        print("\n❌ Syntax Error(s) Detected:")
        for e in errors:
            print(" -", e)

except SyntaxError as e:
    print("\n❌ Lexer Error:", e)