import ast
for fname in ['backend/main.py', 'backend/email_service.py']:
    path = r'C:\Users\Claw\.openclaw\workspace\quanby-legal\\' + fname
    try:
        with open(path, 'r', encoding='utf-8') as f:
            ast.parse(f.read())
        print(f'{fname}: OK')
    except SyntaxError as e:
        print(f'{fname}: SYNTAX ERROR at line {e.lineno}: {e.msg}')
