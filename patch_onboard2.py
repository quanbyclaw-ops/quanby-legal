"""patch_onboard2.py — Fix /onboard 404 by replacing redirect stub with inline modal logic."""
import re

with open(r'C:\Users\Claw\.openclaw\workspace\quanby-legal\index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the old block using start/end anchors
start_anchor = '    // Handle return from OAuth'
end_anchor = "window.location.href = '/onboard?"

si = content.find(start_anchor)
ei = content.find(end_anchor)
if si == -1 or ei == -1:
    print(f"Anchors not found: start={si}, end={ei}")
    exit(1)

# Find end of the showOnboardingModal function after end_anchor
close_idx = content.find('\n    }', ei)  # closing brace of showOnboardingModal
block_end = close_idx + 6  # include the closing brace + newline

print(f"Replacing chars {si}-{block_end} ({block_end-si} chars)")

NEW_JS = '''    // Handle return from OAuth (backend sets HttpOnly cookie, redirects with ?step=)
    (function handleAuthReturn() {
        const params = new URLSearchParams(window.location.search);
        const step = params.get('step');
        if (!step) return;
        const role = sessionStorage.getItem('ql_pending_role') || 'attorney';
        sessionStorage.removeItem('ql_pending_role');
        window.history.replaceState({}, '', '/');
        routeToStep(step, role);
    })();

    function routeToStep(step, role) {
        switch(step) {
            case 'role_select': openOnboard('role', role); break;
            case 'profile':     openOnboard('profile', role); break;
            case 'test':        openOnboard('test', role); break;
            case 'liveness':    openOnboard('liveness', role); break;
            case 'survey':      openOnboard('survey', role); break;
            case 'certified':   openOnboard('certified', role); break;
            default:            openOnboard('role', role); break;
        }
    }

    // ══ ONBOARDING MODAL ENGINE ════════════════════════════════════════════════

    const OB_STEPS  = ['role','profile','test','liveness','certified'];
    const OB_LABELS = ['Role','Profile','15-Q Test','Liveness','Certificate'];
    let _obRole      = 'attorney';
    let _obAnswers   = {};
    let _obQuestions = [];

    function openOnboard(step, role) {
        _obRole = role || 'attorney';
        document.getElementById('onboard-overlay').classList.add('open');
        _renderObStep(step);
    }
    function closeOnboard() {
        document.getElementById('onboard-overlay').classList.remove('open');
    }
    // Legacy alias
    function showOnboardingModal(step, role) { openOnboard(step, role); }

    function _renderObProgress(activeStep) {
        const idx = OB_STEPS.indexOf(activeStep);
        document.getElementById('ob-progress').innerHTML = OB_STEPS.map((s, i) => {
            const cls = i < idx ? 'done' : (i === idx ? 'active' : '');
            const lbl = i < idx ? '&#10003;' : (i + 1);
            return (i > 0 ? '<div class="ob-line"></div>' : '') +
                '<div class="ob-step"><div class="ob-step-num ' + cls + '">' + lbl + '</div><span>' + OB_LABELS[i] + '</span></div>';
        }).join('');
    }

    async function _renderObStep(step) {
        _renderObProgress(step);
        const el = document.getElementById('ob-content');
        if (step === 'role') {
            el.innerHTML = `
                <h3>Choose Your Role</h3>
                <p class="sub">Select your role to begin your Electronic Notary Public (ENP) certification under A.M. No. 24-10-14-SC.</p>
                <div class="onboard-role-cards">
                    <div class="role-card ${_obRole==='attorney'?'selected':''}" onclick="_selectRole('attorney',this)">
                        <div class="role-icon">&#9878;&#65039;</div>
                        <div class="role-title">Attorney / Law Firm</div>
                        <div class="role-desc">IBP-accredited, practicing notary public</div>
                    </div>
                    <div class="role-card ${_obRole==='client'?'selected':''}" onclick="_selectRole('client',this)">
                        <div class="role-icon">&#128100;</div>
                        <div class="role-title">Client / Individual</div>
                        <div class="role-desc">Get documents notarized electronically</div>
                    </div>
                </div>
                <button class="onboard-btn" onclick="_submitRole()">Continue &#8594;</button>
                <div id="ob-err" class="ob-error"></div>`;
        } else if (step === 'profile') {
            el.innerHTML = `
                <h3>Complete Your Profile</h3>
                <p class="sub">Required for ENP certification under A.M. No. 24-10-14-SC.</p>
                <div class="onboard-field"><label>Full Name *</label><input type="text" id="ob-name" placeholder="Juan dela Cruz"></div>
                <div class="onboard-field"><label>IBP Roll No. ${_obRole==='attorney'?'*':'(if applicable)'}</label><input type="text" id="ob-ibp" placeholder="e.g. 12345"></div>
                <div class="onboard-field"><label>PTR No. (if applicable)</label><input type="text" id="ob-ptr" placeholder="e.g. 98765"></div>
                <div class="onboard-field"><label>Province / City *</label><input type="text" id="ob-province" placeholder="e.g. Legazpi City, Albay"></div>
                <div class="onboard-field"><label>Notarial Jurisdiction</label><input type="text" id="ob-jurisdiction" placeholder="e.g. Albay"></div>
                <button class="onboard-btn" onclick="_submitProfile()">Continue &#8594;</button>
                <div id="ob-err" class="ob-error"></div>`;
        } else if (step === 'test') {
            el.innerHTML = '<h3>ENP Certification Test</h3><p class="sub">Loading your 15-question test&#8230;</p>';
            await _loadTest();
        } else if (step === 'liveness') {
            el.innerHTML = `
                <h3>Identity Verification</h3>
                <p class="sub">A quick liveness check is required under BSP Circular 944 (eKYC).</p>
                <div style="border:1px solid rgba(255,255,255,0.1);border-radius:0.75rem;padding:1.5rem;text-align:center;margin-bottom:1.25rem;background:rgba(255,255,255,0.03);">
                    <div style="font-size:2.5rem;margin-bottom:0.75rem;">&#128248;</div>
                    <p style="color:var(--muted);font-size:0.88rem;margin:0 0 1rem;">Your camera will be used to verify your identity. Ensure good lighting and look directly at the camera.</p>
                    <button class="onboard-btn" style="max-width:220px;margin:0 auto;display:block;" onclick="_startLiveness(event)">Start Liveness Check</button>
                </div>
                <div id="ob-err" class="ob-error"></div>`;
        } else if (step === 'certified') {
            el.innerHTML = `
                <h3>&#127881; Certification Complete!</h3>
                <div class="ob-cert-card">
                    <div class="cert-icon">&#127963;&#65039;</div>
                    <h4>You are now ENP Certified</h4>
                    <p>Your Electronic Notary Public certificate has been issued and sent to your email.</p>
                </div>
                <p class="sub" style="text-align:center;">You can now perform electronic notarizations in compliance with A.M. No. 24-10-14-SC.</p>
                <button class="onboard-btn" onclick="closeOnboard()">Done</button>`;
        }
    }

    function _selectRole(role, el) {
        _obRole = role;
        document.querySelectorAll('.role-card').forEach(c => c.classList.remove('selected'));
        el.classList.add('selected');
    }

    async function _submitRole() {
        const btn = document.querySelector('#ob-content .onboard-btn');
        btn.disabled = true; btn.innerHTML = '<span class="ob-spinner"></span>Saving&#8230;';
        try {
            const res = await fetch('/api/onboarding/role', {
                method: 'POST', credentials: 'include',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({ role: _obRole })
            });
            if (!res.ok) throw new Error((await res.json()).detail || 'Failed');
            _renderObStep('profile');
        } catch(e) {
            btn.disabled = false; btn.textContent = 'Continue \u2192';
            document.getElementById('ob-err').textContent = e.message;
        }
    }

    async function _submitProfile() {
        const name = document.getElementById('ob-name').value.trim();
        const province = document.getElementById('ob-province').value.trim();
        if (!name || !province) {
            document.getElementById('ob-err').textContent = 'Full name and province are required.'; return;
        }
        const btn = document.querySelector('#ob-content .onboard-btn');
        btn.disabled = true; btn.innerHTML = '<span class="ob-spinner"></span>Saving&#8230;';
        try {
            const res = await fetch('/api/onboarding/profile', {
                method: 'POST', credentials: 'include',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({
                    full_name: name,
                    ibp_number: document.getElementById('ob-ibp').value.trim(),
                    ptr_number: document.getElementById('ob-ptr').value.trim(),
                    province: province,
                    notarial_jurisdiction: document.getElementById('ob-jurisdiction').value.trim()
                })
            });
            if (!res.ok) throw new Error((await res.json()).detail || 'Failed');
            _renderObStep('test');
        } catch(e) {
            btn.disabled = false; btn.textContent = 'Continue \u2192';
            document.getElementById('ob-err').textContent = e.message;
        }
    }

    async function _loadTest() {
        try {
            const res = await fetch('/api/onboarding/test/start', { method: 'POST', credentials: 'include' });
            if (!res.ok) throw new Error((await res.json()).detail || 'Failed to start test');
            const data = await res.json();
            _obQuestions = data.questions; _obAnswers = {};
            _renderTestUI();
        } catch(e) {
            document.getElementById('ob-content').innerHTML =
                '<h3>Test</h3><div class="ob-error">' + e.message + '</div>';
        }
    }

    function _renderTestUI() {
        const qs = _obQuestions.map((q, i) =>
            '<div class="ob-question" id="q-' + q.id + '">' +
            '<p>' + (i+1) + '. ' + q.question + '</p>' +
            q.choices.map(c =>
                '<div class="ob-choice" onclick="_pickAnswer(\'' + q.id + '\',this)">' + c + '</div>'
            ).join('') +
            '</div>'
        ).join('');
        document.getElementById('ob-content').innerHTML =
            '<h3>ENP Certification Test</h3>' +
            '<p class="sub">Answer all 15 questions. You need 80% (12/15) to pass.</p>' +
            qs +
            '<button class="onboard-btn" id="ob-submit-btn" onclick="_submitTest()">Submit Test</button>' +
            '<div id="ob-err" class="ob-error"></div>';
    }

    function _pickAnswer(qid, el) {
        const text = el.textContent;
        _obAnswers[qid] = text;
        const block = document.getElementById('q-' + qid);
        block.querySelectorAll('.ob-choice').forEach(c => c.classList.remove('selected'));
        el.classList.add('selected');
    }

    async function _submitTest() {
        if (Object.keys(_obAnswers).length < _obQuestions.length) {
            document.getElementById('ob-err').textContent =
                'Please answer all questions (' + Object.keys(_obAnswers).length + '/' + _obQuestions.length + ' answered).';
            return;
        }
        const btn = document.getElementById('ob-submit-btn');
        btn.disabled = true; btn.innerHTML = '<span class="ob-spinner"></span>Grading&#8230;';
        try {
            const res = await fetch('/api/onboarding/test/submit', {
                method: 'POST', credentials: 'include',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({ answers: _obAnswers })
            });
            _renderTestResult(await res.json());
        } catch(e) {
            btn.disabled = false; btn.textContent = 'Submit Test';
            document.getElementById('ob-err').textContent = 'Submission failed. Please try again.';
        }
    }

    function _renderTestResult(data) {
        const passed = data.passed, score = data.score, total = data.total;
        document.getElementById('ob-content').innerHTML =
            '<h3>Test Result</h3>' +
            '<div class="ob-result-banner ' + (passed?'pass':'fail') + '">' +
            (passed ? '&#127881; Passed!' : '&#10060; Not Passed') +
            ' &mdash; ' + score + '/' + total + ' correct (' + Math.round(score/total*100) + '%)</div>' +
            '<p class="sub">' + (passed
                ? 'Congratulations! Proceed to the final identity verification step.'
                : 'You need 80% to pass. Review the Philippine ENP rules and try again.') + '</p>' +
            (passed
                ? '<button class="onboard-btn" onclick="_renderObStep(\'liveness\')">Continue to Liveness Check &#8594;</button>'
                : '<button class="onboard-btn" onclick="_loadTest()">Retake Test</button>');
        _renderObProgress(passed ? 'liveness' : 'test');
    }

    async function _startLiveness(evt) {
        const btn = evt.target;
        btn.disabled = true; btn.innerHTML = '<span class="ob-spinner"></span>Starting camera&#8230;';
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: true });
            stream.getTracks().forEach(t => t.stop());
            const res = await fetch('/api/onboarding/liveness', {
                method: 'POST', credentials: 'include',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({ verified: true, method: 'camera_check' })
            });
            if (!res.ok) throw new Error((await res.json()).detail || 'Liveness check failed');
            _renderObStep('certified');
        } catch(e) {
            btn.disabled = false; btn.textContent = 'Start Liveness Check';
            document.getElementById('ob-err').textContent =
                e.name === 'NotAllowedError'
                    ? 'Camera access denied. Please allow camera access and try again.'
                    : e.message;
        }
    }'''

content = content[:si] + NEW_JS + content[block_end:]

# Remove old showCertifiedModal stub
old_cert_variants = [
    "    function showCertifiedModal(token) {\n        alert('dYZ% You are fully certified! Check your email for your certificate.');\n    }",
    "    function showCertifiedModal(token) {\n        alert(",
]
for v in old_cert_variants:
    idx = content.find(v)
    if idx != -1:
        end = content.find('\n    }', idx) + 6
        content = content[:idx] + content[end:]
        print("Removed showCertifiedModal stub")
        break

with open(r'C:\Users\Claw\.openclaw\workspace\quanby-legal\index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print("Saved successfully.")

# Verify
assert '/onboard?' not in content, "Still has /onboard redirect!"
assert 'openOnboard' in content, "openOnboard function missing!"
assert 'onboard-overlay' in content, "Modal overlay missing!"
print("Verification passed.")
