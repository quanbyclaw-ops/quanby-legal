"""patch_syntax.py — Fix JS syntax error in _renderTestUI."""

with open(r'C:\Users\Claw\.openclaw\workspace\quanby-legal\index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the broken onclick in _renderTestUI - unescaped single quotes
old = """            q.choices.map(c =>
                '<div class="ob-choice" onclick="_pickAnswer('' + q.id + '',this)">' + c + '</div>'
            ).join('') +"""

new = """            q.choices.map(c =>
                '<div class="ob-choice" onclick="_pickAnswer(\\'' + q.id + '\\',this)">' + c + '</div>'
            ).join('') +"""

if old in content:
    content = content.replace(old, new)
    print("Syntax fix applied")
else:
    print("Pattern not found - searching...")
    idx = content.find("_pickAnswer(''")
    print(f"Found at index: {idx}")
    if idx > 0:
        print(repr(content[idx-50:idx+100]))

with open(r'C:\Users\Claw\.openclaw\workspace\quanby-legal\index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print("Saved.")
