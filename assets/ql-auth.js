// Quanby Legal — Shared Auth Module v2.0
// Fixes: random logout, redirect on transient failure, session keepalive
(function(w) {
  'use strict';

  var _refreshTimer = null;
  var _refreshing = false;

  // Proactive refresh every 18 minutes (access token is 7 days, but keep session warm)
  function _startKeepalive() {
    if (_refreshTimer) return;
    _refreshTimer = setInterval(async function() {
      try { await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' }); } catch(e) {}
    }, 18 * 60 * 1000);
  }

  function _stopKeepalive() {
    if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null; }
  }

  // Single refresh — debounced so concurrent calls don't stack
  async function refresh() {
    if (_refreshing) {
      await new Promise(function(r){ setTimeout(r, 600); });
      return;
    }
    _refreshing = true;
    try { await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' }); } catch(e) {}
    _refreshing = false;
  }

  // Auth/me with retry — refresh first on each attempt, then check
  async function authMeWithRetry(max) {
    max = max || 6;
    for (var i = 0; i < max; i++) {
      if (i > 0) {
        // Wait before retry: 300ms, 600ms, 1200ms ... capped at 2s
        var delay = Math.min(300 * Math.pow(2, i - 1), 2000);
        await new Promise(function(r){ setTimeout(r, delay); });
      }
      // Always try refresh first
      try { await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' }); } catch(e) {}
      try {
        var res = await fetch('/api/auth/me', { credentials: 'include' });
        if (res.ok) return res;
      } catch(e) {}
    }
    return null;
  }

  // isAuthenticated — quick non-blocking check (no retry)
  async function isAuthenticated() {
    try {
      await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' });
      var r = await fetch('/api/auth/me', { credentials: 'include' });
      return r.ok;
    } catch(e) { return false; }
  }

  // requireAuth — calls onSuccess(user) or shows inline error (NEVER redirects to /)
  // onFail: optional custom handler. If not provided, shows a non-blocking error message.
  async function requireAuth(onSuccess, onFail) {
    try {
      var res = await authMeWithRetry(6);
      if (res && res.ok) {
        var user = await res.json();
        _startKeepalive();
        if (typeof onSuccess === 'function') onSuccess(user);
        return;
      }
      // Auth failed after all retries
      if (typeof onFail === 'function') {
        onFail();
      } else {
        // Default: show a non-blocking "session expired" banner instead of redirect
        _showSessionExpiredBanner();
      }
    } catch(e) {
      console.error('[QLAuth] requireAuth error:', e);
      if (typeof onFail === 'function') {
        onFail();
      } else {
        _showSessionExpiredBanner();
      }
    }
  }

  // requireAuthWithRedirect — same as requireAuth but DOES redirect if session truly gone
  // Use only when redirect is intentional (e.g. accessing a page that strictly requires login)
  async function requireAuthWithRedirect(onSuccess) {
    await requireAuth(onSuccess, function() {
      w.location.href = '/?sso=1';
    });
  }

  function _showSessionExpiredBanner() {
    // Don't show if already on landing page
    if (w.location.pathname === '/' || w.location.pathname === '/auth-complete') return;
    var existing = document.getElementById('ql-session-expired-banner');
    if (existing) return;
    var banner = document.createElement('div');
    banner.id = 'ql-session-expired-banner';
    banner.style.cssText = [
      'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:99999',
      'background:#1e3a5f', 'color:#fff', 'padding:12px 20px',
      'display:flex', 'align-items:center', 'gap:12px',
      'font-family:Inter,sans-serif', 'font-size:0.9rem',
      'border-bottom:2px solid #00d4c8', 'box-shadow:0 2px 16px rgba(0,0,0,0.4)'
    ].join(';');
    banner.innerHTML = [
      '<span>&#x26A0;&#xFE0F; Your session has expired.</span>',
      '<button onclick="QLAuth._handleReauth()" style="',
        'background:#00d4c8;color:#0a1628;border:none;border-radius:6px;',
        'padding:6px 16px;font-weight:700;cursor:pointer;font-size:0.85rem;',
      '">Sign Back In</button>',
      '<button onclick="document.getElementById(\'ql-session-expired-banner\').remove()" style="',
        'background:none;border:none;color:rgba(255,255,255,0.5);cursor:pointer;font-size:1.1rem;margin-left:auto;',
      '">&#x2715;</button>'
    ].join('');
    document.body.prepend(banner);
  }

  // Attempt re-auth inline without full page redirect
  async function _handleReauth() {
    var banner = document.getElementById('ql-session-expired-banner');
    if (banner) banner.innerHTML = '<span>&#x1F504; Restoring session&#x2026;</span>';
    try {
      await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' });
      var r = await fetch('/api/auth/me', { credentials: 'include' });
      if (r.ok) {
        if (banner) banner.remove();
        w.location.reload();
        return;
      }
    } catch(e) {}
    // Still failed — redirect to sign in
    w.location.href = '/?sso=1';
  }

  // authFetch — like fetch() but auto-refreshes on 401 and retries once
  async function authFetch(url, opts) {
    opts = opts || {};
    opts.credentials = 'include';
    var res = await fetch(url, opts);
    if (res.status === 401) {
      await refresh();
      res = await fetch(url, opts);
    }
    return res;
  }

  w.QLAuth = {
    requireAuth: requireAuth,
    requireAuthWithRedirect: requireAuthWithRedirect,
    authMeWithRetry: authMeWithRetry,
    isAuthenticated: isAuthenticated,
    refresh: refresh,
    authFetch: authFetch,
    _handleReauth: _handleReauth,
    _stopKeepalive: _stopKeepalive,
  };
})(window);
