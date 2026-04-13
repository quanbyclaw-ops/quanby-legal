"""Patch index.html and backend files for KYC + retake payment flow."""
import os
import re

BASE = r'C:\Users\Claw\.openclaw\workspace\quanby-legal'
INDEX = os.path.join(BASE, 'index.html')

# ─── Read index.html ────────────────────────────────────────────────────────
content = open(INDEX, 'r', encoding='utf-8').read()
original = content

# ── PART 1a: OB_STEPS + OB_LABELS ──────────────────────────────────────────
content = content.replace(
    "OB_STEPS  = ['role','profile','test','liveness','certified'];",
    "OB_STEPS  = ['role','profile','test','kyc','liveness','certified'];"
)
content = content.replace(
    "const OB_LABELS = ['Role','Profile','15-Q Test','Liveness','Certificate'];",
    "const OB_LABELS = ['Role','Profile','Exam','ID Upload','Liveness','Certificate'];"
)
print("OB_STEPS/LABELS patched:", "OB_STEPS  = ['role','profile','test','kyc'" in content)

# ── PART 1b: Replace liveness block and inject kyc block before it ──────────
OLD_LIVENESS = """        } else if (step === 'liveness') {
            el.innerHTML = `
                <h3>Identity Verification</h3>
                <p class="sub">A quick liveness check is required under BSP Circular 944 (eKYC).</p>
                <div style="border:1px solid rgba(255,255,255,0.1);border-radius:0.75rem;padding:1.5rem;text-align:center;margin-bottom:1.25rem;background:rgba(255,255,255,0.03);">
                    <div style="font-size:2.5rem;margin-bottom:0.75rem;">&#128248;</div>
                    <p style="color:var(--muted);font-size:0.88rem;margin:0 0 1rem;">Your camera will be used to verify your identity. Ensure good lighting and look directly at the camera.</p>
                    <button class="onboard-btn" style="max-width:220px;margin:0 auto;display:block;" onclick="_startLiveness(event)">Start Liveness Check</button>
                </div>
                <div id="ob-err" class="ob-error"></div>`;"""

NEW_KYC_AND_LIVENESS = """        } else if (step === 'kyc') {
            el.innerHTML = `
                <h3>&#128203; KYC &mdash; Identity Document Upload</h3>
                <p class="sub">Upload a valid Philippine government-issued ID. This will be used during the liveness verification step when meeting with your notary.</p>
                <div class="kyc-upload-box" id="kyc-upload-box">
                    <div style="font-size:2.5rem;margin-bottom:0.75rem;">&#129371;</div>
                    <p style="color:var(--muted);font-size:0.88rem;margin:0 0 1rem;">Accepted IDs: PhilSys (National ID), Passport, Driver&#39;s License, SSS/GSIS, PRC ID, Voter&#39;s ID</p>
                    <div style="background:rgba(255,255,255,0.05);border:2px dashed rgba(201,168,76,0.4);border-radius:0.75rem;padding:2rem;text-align:center;cursor:pointer;margin-bottom:1rem;" onclick="document.getElementById('kyc-file-input').click()">
                        <div id="kyc-preview" style="display:none;margin-bottom:0.75rem;">
                            <img id="kyc-img-preview" style="max-width:100%;max-height:200px;border-radius:0.5rem;" />
                        </div>
                        <div id="kyc-placeholder">
                            <div style="font-size:1.5rem;margin-bottom:0.5rem;">&#128228;</div>
                            <p style="color:var(--muted);margin:0;font-size:0.875rem;">Click to upload your ID photo</p>
                            <p style="color:var(--muted);margin:0.25rem 0 0;font-size:0.75rem;">JPG, PNG, or PDF &middot; Max 5MB</p>
                        </div>
                    </div>
                    <input type="file" id="kyc-file-input" accept="image/jpeg,image/png,application/pdf" style="display:none;" onchange="_kycFileSelected(this)">
                    <button class="onboard-btn" id="kyc-upload-btn" disabled style="opacity:0.5;" onclick="_submitKycId()">
                        Upload ID &amp; Continue &rarr;
                    </button>
                </div>
                <div id="ob-err" class="ob-error"></div>`;
        } else if (step === 'liveness') {
            el.innerHTML = `
                <h3>&#128248; Liveness Verification</h3>
                <p class="sub">BSP Circular 944 (eKYC) requires a live selfie verification. Please have your Philippine National ID ready.</p>
                <div style="border:1px solid rgba(255,255,255,0.1);border-radius:0.75rem;padding:1.5rem;text-align:center;margin-bottom:1.25rem;background:rgba(255,255,255,0.03);">
                    <div style="font-size:2.5rem;margin-bottom:0.75rem;">&#128248;</div>
                    <div style="background:rgba(201,168,76,0.08);border:1px solid rgba(201,168,76,0.3);border-radius:0.5rem;padding:1rem;margin-bottom:1rem;text-align:left;">
                        <p style="margin:0 0 0.5rem;font-weight:600;color:var(--gold, #c9a84c);">Before you begin:</p>
                        <ul style="margin:0;padding-left:1.25rem;color:var(--muted);font-size:0.875rem;line-height:1.7;">
                            <li>Ensure good lighting &mdash; face well-lit from the front</li>
                            <li>Hold your <strong>Philippine National ID</strong> (PhilSys) next to your face</li>
                            <li>Look directly at the camera</li>
                            <li>The ID photo will be compared with your uploaded KYC document</li>
                        </ul>
                    </div>
                    <button class="onboard-btn" style="max-width:240px;margin:0 auto;display:block;" onclick="_startLiveness(event)">
                        &#128248; Start Liveness Check
                    </button>
                </div>
                <div id="ob-err" class="ob-error"></div>`;"""

if OLD_LIVENESS in content:
    content = content.replace(OLD_LIVENESS, NEW_KYC_AND_LIVENESS)
    print("KYC + liveness step injected: YES")
else:
    print("ERROR: liveness block not found for replacement!")

# ── PART 3: Replace _renderTestResult and add helpers ───────────────────────
OLD_RENDER_RESULT = """    function _renderTestResult(data) {
        const passed = data.passed, score = data.score, total = data.total;
        document.getElementById('ob-content').innerHTML =
            '<h3>Test Result</h3>' +
            '<div class="ob-result-banner ' + (passed?'pass':'fail') + '">' +
            (passed ? '&#127881; Passed!' : '&#10060; Not Passed') +
            ' &mdash; ' + score + '/' + total + ' correct (' + Math.round(score/total*100) + '%)</div>' +
            '<p class="sub">' + (passed
                ? 'Congratulations! Proceed to the final identity verification step.'
                : 'You need 70% (35/50) to pass. Review the course module and try again.') + '</p>' +
            (passed
                ? '<button class="onboard-btn" onclick="_renderObStep(\\'liveness\\')">Continue to Liveness Check &#8594;</button>'
                : '<button class="onboard-btn" onclick="_loadTest()">Retake Test</button>');
        _renderObProgress(passed ? 'liveness' : 'test');
    }"""

NEW_RENDER_RESULT = r"""    function _renderTestResult(data) {
        const passed = data.passed;
        const score = data.score !== undefined ? data.score : data.correct;
        const total = data.total;
        const scorePct = data.score_pct || Math.round(score/total*100);
        const ob = document.getElementById('ob-content');
        if (passed) {
            ob.innerHTML =
                '<h3>Test Result</h3>' +
                '<div class="ob-result-banner pass">&#127881; Passed! &mdash; ' + score + '/' + total + ' correct (' + scorePct + '%)</div>' +
                '<p class="sub">Congratulations! Proceed to identity verification.</p>' +
                '<button class="onboard-btn" onclick="_renderObStep(\'kyc\')">Continue to ID Verification &rarr;</button>';
            _renderObProgress('kyc');
        } else {
            const safeData = JSON.stringify(data).replace(/'/g, "\\'");
            ob.innerHTML =
                '<h3>Test Result</h3>' +
                '<div class="ob-result-banner fail">&#10060; Not Passed &mdash; ' + score + '/' + total + ' correct (' + scorePct + '%)</div>' +
                '<p class="sub">You need 70% (35/50) to pass. A notification has been sent to your registered email with instructions on how to retake the exam.</p>' +
                '<div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);border-radius:0.5rem;padding:1rem;margin:1rem 0;font-size:0.875rem;color:var(--muted);">&#128231; Check your email for retake instructions and payment details.</div>' +
                '<button class="onboard-btn" onclick="_showRetakePayment(' + safeData + ')">Retake Test (&#8369;500 fee) &rarr;</button>';
            _renderObProgress('test');
        }
    }

    function _showRetakePayment(testData) {
        const ob = document.getElementById('ob-content');
        ob.innerHTML =
            '<h3>&#128179; Retake Fee Payment</h3>' +
            '<p class="sub">A &#8369;500 retake fee is required to attempt the exam again.</p>' +
            '<div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.1);border-radius:0.75rem;padding:1.5rem;margin-bottom:1.25rem;">' +
                '<div style="display:flex;gap:1rem;margin-bottom:1.25rem;">' +
                    '<button id="tab-gcash" onclick="_switchPayTab(\'gcash\')" style="flex:1;padding:0.75rem;border-radius:0.5rem;border:2px solid rgba(201,168,76,0.5);background:rgba(201,168,76,0.1);color:#c9a84c;font-weight:600;cursor:pointer;">&#128241; GCash</button>' +
                    '<button id="tab-bank" onclick="_switchPayTab(\'bank\')" style="flex:1;padding:0.75rem;border-radius:0.5rem;border:1px solid rgba(255,255,255,0.1);background:transparent;color:var(--muted);cursor:pointer;">&#127974; Bank Transfer</button>' +
                '</div>' +
                '<div id="payment-gcash">' +
                    '<div style="background:rgba(0,168,107,0.08);border:1px solid rgba(0,168,107,0.3);border-radius:0.5rem;padding:1.25rem;text-align:center;">' +
                        '<div style="font-size:2rem;margin-bottom:0.5rem;">&#128241;</div>' +
                        '<p style="margin:0 0 0.5rem;font-weight:600;color:#00a86b;">GCash</p>' +
                        '<p style="font-size:1.5rem;font-weight:700;margin:0 0 0.25rem;color:#fff;" id="gcash-number">Loading&hellip;</p>' +
                        '<p style="color:var(--muted);font-size:0.875rem;margin:0;">Account Name: Quanby Solutions, Inc.</p>' +
                        '<div style="margin-top:1rem;padding:0.75rem;background:rgba(255,255,255,0.05);border-radius:0.4rem;">' +
                            '<p style="margin:0;font-size:0.8rem;color:var(--muted);">Reference Number</p>' +
                            '<p style="margin:0.25rem 0 0;font-weight:700;color:#c9a84c;letter-spacing:0.05em;" id="pay-ref">Loading&hellip;</p>' +
                        '</div>' +
                    '</div>' +
                '</div>' +
                '<div id="payment-bank" style="display:none;">' +
                    '<div style="background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.3);border-radius:0.5rem;padding:1.25rem;">' +
                        '<div style="font-size:2rem;margin-bottom:0.5rem;text-align:center;">&#127974;</div>' +
                        '<table style="width:100%;font-size:0.875rem;border-collapse:collapse;">' +
                            '<tr><td style="padding:0.4rem 0;color:var(--muted);">Bank:</td><td style="padding:0.4rem 0;font-weight:600;" id="bank-name">Loading&hellip;</td></tr>' +
                            '<tr><td style="padding:0.4rem 0;color:var(--muted);">Account Number:</td><td style="padding:0.4rem 0;font-weight:600;" id="bank-account">Loading&hellip;</td></tr>' +
                            '<tr><td style="padding:0.4rem 0;color:var(--muted);">Account Name:</td><td style="padding:0.4rem 0;font-weight:600;" id="bank-name-2">Loading&hellip;</td></tr>' +
                            '<tr><td style="padding:0.4rem 0;color:var(--muted);">Amount:</td><td style="padding:0.4rem 0;font-weight:700;color:#c9a84c;">&#8369;500.00</td></tr>' +
                            '<tr><td style="padding:0.4rem 0;color:var(--muted);">Reference:</td><td style="padding:0.4rem 0;font-weight:600;color:#c9a84c;" id="pay-ref-bank">Loading&hellip;</td></tr>' +
                        '</table>' +
                    '</div>' +
                '</div>' +
            '</div>' +
            '<div style="background:rgba(255,255,255,0.03);border-radius:0.5rem;padding:1rem;margin-bottom:1rem;font-size:0.8rem;color:var(--muted);">' +
            '&#9888;&#65039; After sending payment, click "I\'ve Paid \u2014 Submit for Verification" below. Our team will verify and unlock your retake within 24 hours. You will receive a confirmation email.' +
            '</div>' +
            '<button class="onboard-btn" id="pay-confirm-btn" onclick="_submitRetakePayment()">&#9989; I\'ve Paid \u2014 Submit for Verification</button>' +
            '<div id="ob-err" class="ob-error"></div>';
        _loadPaymentDetails();
    }

    function _switchPayTab(tab) {
        document.getElementById('payment-gcash').style.display = tab === 'gcash' ? 'block' : 'none';
        document.getElementById('payment-bank').style.display = tab === 'bank' ? 'block' : 'none';
        document.getElementById('tab-gcash').style.cssText = tab === 'gcash'
            ? 'flex:1;padding:0.75rem;border-radius:0.5rem;border:2px solid rgba(201,168,76,0.5);background:rgba(201,168,76,0.1);color:#c9a84c;font-weight:600;cursor:pointer;'
            : 'flex:1;padding:0.75rem;border-radius:0.5rem;border:1px solid rgba(255,255,255,0.1);background:transparent;color:var(--muted);cursor:pointer;';
        document.getElementById('tab-bank').style.cssText = tab === 'bank'
            ? 'flex:1;padding:0.75rem;border-radius:0.5rem;border:2px solid rgba(201,168,76,0.5);background:rgba(201,168,76,0.1);color:#c9a84c;font-weight:600;cursor:pointer;'
            : 'flex:1;padding:0.75rem;border-radius:0.5rem;border:1px solid rgba(255,255,255,0.1);background:transparent;color:var(--muted);cursor:pointer;';
    }

    async function _loadPaymentDetails() {
        try {
            const res = await fetch('/api/onboarding/retake-payment', {
                method: 'POST', credentials: 'include',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({ payment_method: 'gcash' })
            });
            const d = await res.json();
            const ref = d.reference_number || ('RETAKE-' + Math.random().toString(36).substr(2,8).toUpperCase());
            if (document.getElementById('gcash-number')) document.getElementById('gcash-number').textContent = d.gcash_number || '09XX-XXX-XXXX';
            if (document.getElementById('pay-ref')) document.getElementById('pay-ref').textContent = ref;
            if (document.getElementById('pay-ref-bank')) document.getElementById('pay-ref-bank').textContent = ref;
            if (document.getElementById('bank-name')) document.getElementById('bank-name').textContent = d.bank_name || 'BDO';
            if (document.getElementById('bank-account')) document.getElementById('bank-account').textContent = d.bank_account || 'XXXX-XXXX-XXXX';
            if (document.getElementById('bank-name-2')) document.getElementById('bank-name-2').textContent = d.bank_account_name || 'Quanby Solutions, Inc.';
        } catch(e) {}
    }

    async function _submitRetakePayment() {
        const btn = document.getElementById('pay-confirm-btn');
        btn.disabled = true; btn.innerHTML = '<span class="ob-spinner"></span>Submitting&hellip;';
        try {
            const res = await fetch('/api/onboarding/retake-payment/verify', { method: 'POST', credentials: 'include' });
            const d = await res.json();
            document.getElementById('ob-content').innerHTML =
                '<h3>Payment Submitted</h3>' +
                '<div style="text-align:center;padding:2rem 0;">' +
                '<div style="font-size:3rem;margin-bottom:1rem;">&#9203;</div>' +
                '<p style="font-weight:600;color:#c9a84c;">Payment verification pending</p>' +
                '<p class="sub">Our team will verify your payment within 24 hours and send you a confirmation email with a link to retake the exam.</p>' +
                '<p class="sub">Reference: <strong style="color:#c9a84c;">' + (d.reference_number || '') + '</strong></p>' +
                '</div>';
        } catch(e) {
            btn.disabled = false; btn.textContent = "\u2705 I've Paid \u2014 Submit for Verification";
            document.getElementById('ob-err').textContent = 'Submission failed. Please try again.';
        }
    }

    function _kycFileSelected(input) {
        const file = input.files[0];
        if (!file) return;
        if (file.size > 5 * 1024 * 1024) {
            document.getElementById('ob-err').textContent = 'File too large. Max 5MB.'; return;
        }
        document.getElementById('ob-err').textContent = '';
        const btn = document.getElementById('kyc-upload-btn');
        btn.disabled = false; btn.style.opacity = '1';
        if (file.type.startsWith('image/')) {
            const reader = new FileReader();
            reader.onload = e => {
                document.getElementById('kyc-img-preview').src = e.target.result;
                document.getElementById('kyc-preview').style.display = 'block';
                document.getElementById('kyc-placeholder').style.display = 'none';
            };
            reader.readAsDataURL(file);
        } else {
            document.getElementById('kyc-placeholder').innerHTML = '<div style="font-size:1.5rem;">&#128196;</div><p style="color:var(--teal);margin:0;">' + file.name + '</p>';
        }
    }

    async function _submitKycId() {
        const input = document.getElementById('kyc-file-input');
        if (!input.files[0]) { document.getElementById('ob-err').textContent = 'Please select a file first.'; return; }
        const btn = document.getElementById('kyc-upload-btn');
        btn.disabled = true; btn.innerHTML = '<span class="ob-spinner"></span>Uploading&hellip;';
        try {
            const formData = new FormData();
            formData.append('national_id', input.files[0]);
            const res = await fetch('/api/onboarding/national-id', {
                method: 'POST', credentials: 'include', body: formData
            });
            if (!res.ok) throw new Error((await res.json()).detail || 'Upload failed');
            _renderObStep('liveness');
        } catch(e) {
            btn.disabled = false; btn.textContent = 'Upload ID & Continue \u2192';
            document.getElementById('ob-err').textContent = e.message;
        }
    }"""

if OLD_RENDER_RESULT in content:
    content = content.replace(OLD_RENDER_RESULT, NEW_RENDER_RESULT)
    print("_renderTestResult replaced: YES")
else:
    print("ERROR: _renderTestResult not found!")

open(INDEX, 'w', encoding='utf-8').write(content)
print("index.html saved. Size:", len(content))
