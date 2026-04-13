"""patch_guards.py — Add null guards to openOnboard/closeOnboard."""

with open(r'C:\Users\Claw\.openclaw\workspace\quanby-legal\index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix openOnboard
old1 = """    function openOnboard(step, role) {
        _obRole = role || 'attorney';
        document.getElementById('onboard-overlay').classList.add('open');
        _renderObStep(step);
    }"""

new1 = """    function openOnboard(step, role) {
        _obRole = role || 'attorney';
        var overlay = document.getElementById('onboard-overlay');
        if (!overlay) { console.error('onboard-overlay missing from DOM'); return; }
        overlay.classList.add('open');
        document.body.style.overflow = 'hidden';
        _renderObStep(step);
    }"""

if old1 in content:
    content = content.replace(old1, new1)
    print("openOnboard patched")
else:
    print("WARNING: openOnboard pattern not found")

# Fix closeOnboard
old2 = """    function closeOnboard() {
        var overlay = document.getElementById('onboard-overlay');
        if (overlay) overlay.classList.remove('open');
        document.body.style.overflow = '';
    }"""

# Check if already patched
if 'if (overlay) overlay.classList.remove' in content:
    print("closeOnboard already patched")
else:
    old2b = """    function closeOnboard() {
        document.getElementById('onboard-overlay').classList.remove('open');
    }"""
    new2 = """    function closeOnboard() {
        var overlay = document.getElementById('onboard-overlay');
        if (overlay) overlay.classList.remove('open');
        document.body.style.overflow = '';
    }"""
    if old2b in content:
        content = content.replace(old2b, new2)
        print("closeOnboard patched")
    else:
        print("WARNING: closeOnboard pattern not found")

with open(r'C:\Users\Claw\.openclaw\workspace\quanby-legal\index.html', 'w', encoding='utf-8') as f:
    f.write(content)

# Final verify
assert 'onboard-overlay missing from DOM' in content, "Guard missing!"
assert 'id="onboard-overlay"' in content, "Modal div missing!"
print("Verified OK.")
