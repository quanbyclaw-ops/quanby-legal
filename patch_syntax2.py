"""patch_syntax2.py — Fix all JS onclick quote issues in template strings."""

with open(r'C:\Users\Claw\.openclaw\workspace\quanby-legal\index.html', 'r', encoding='utf-8') as f:
    content = f.read()

fixes = [
    # _renderTestResult liveness button
    (
        "? '<button class=\"onboard-btn\" onclick=\"_renderObStep('liveness')\">Continue to Liveness Check &#8594;</button>'",
        "? '<button class=\"onboard-btn\" onclick=\"_renderObStep(\\'liveness\\')\">Continue to Liveness Check &#8594;</button>'"
    ),
    # _renderTestResult retake button
    (
        ": '<button class=\"onboard-btn\" onclick=\"_loadTest()\">Retake Test</button>'",
        ": '<button class=\"onboard-btn\" onclick=\"_loadTest()\">Retake Test</button>'"  # this one is fine
    ),
]

count = 0
for old, new in fixes:
    if old in content and old != new:
        content = content.replace(old, new)
        count += 1
        print(f"Fixed: {old[:60]}...")

# Also scan for any remaining single-quoted onclick in string concatenation
import re
# Find patterns like onclick="someFunc('..." inside single-quoted strings
# Pattern: ' ... onclick="funcName('something')" ... '
# These need the inner quotes escaped

# Fix _renderObStep('liveness') pattern - use double quotes or escape
bad_pattern = r"""onclick="_renderObStep\('([^']+)'\)"""
matches = [(m.start(), m.group()) for m in re.finditer(bad_pattern, content)]
print(f"Found {len(matches)} _renderObStep onclick patterns")
for start, m in matches:
    ctx = content[start-20:start+80]
    print(f"  Context: {repr(ctx)}")

with open(r'C:\Users\Claw\.openclaw\workspace\quanby-legal\index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print(f"Applied {count} fixes. Saved.")
