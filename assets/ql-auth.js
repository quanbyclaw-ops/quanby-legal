// Quanby Legal — Shared Auth Module v1.0
(function(w) {
  'use strict';
  async function authMeWithRetry(max) {
    max = max || 4;
    for (var i = 0; i < max; i++) {
      if (i > 0) await new Promise(function(r){ setTimeout(r, 500 * Math.pow(2, i-1)); });
      try { await fetch('/api/auth/refresh',{method:'POST',credentials:'include'}); } catch(e){}
      try {
        var res = await fetch('/api/auth/me',{credentials:'include'});
        if (res.ok) return res;
      } catch(e){}
    }
    return null;
  }
  async function requireAuth(onSuccess, onFail) {
    if (!onFail) onFail = function(){ w.location.href='/'; };
    try {
      var res = await authMeWithRetry(4);
      if (!res || !res.ok) { onFail(); return; }
      var user = await res.json();
      if (typeof onSuccess === 'function') onSuccess(user);
    } catch(e) {
      console.error('[QLAuth] requireAuth error:', e);
      onFail();
    }
  }
  w.QLAuth = { authMeWithRetry: authMeWithRetry, requireAuth: requireAuth };
})(window);
