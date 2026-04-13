
# ══════════════════════════════════════════════════════════════════════════════
# ADMIN PANEL — Auth + API Endpoints
# ══════════════════════════════════════════════════════════════════════════════

import jwt as _pyjwt_admin
from fastapi.responses import FileResponse as _FileResponse
from datetime import datetime as _admin_dt, timezone as _admin_tz, timedelta as _admin_td

_ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Alyssa7719!!")
_ADMIN_SECRET   = os.getenv("SECRET_KEY", "change-me-in-production")
_ADMIN_COOKIE   = "ql_admin"
_ADMIN_HTML     = os.path.join(os.path.dirname(os.path.dirname(__file__)), "admin.html")


def _issue_admin_jwt() -> str:
    now = _admin_dt.now(_admin_tz.utc)
    payload = {
        "sub":  "admin",
        "role": "admin",
        "iat":  int(now.timestamp()),
        "exp":  int((now + _admin_td(hours=8)).timestamp()),
    }
    return _pyjwt_admin.encode(payload, _ADMIN_SECRET, algorithm="HS256")


def _get_admin_user(request: Request):
    token = request.cookies.get(_ADMIN_COOKIE)
    if not token:
        return None
    try:
        payload = _pyjwt_admin.decode(token, _ADMIN_SECRET, algorithms=["HS256"])
        if payload.get("role") == "admin":
            return {"role": "admin", "sub": payload.get("sub", "admin")}
    except Exception:
        pass
    return None


# ── Static: GET /admin → admin.html ──────────────────────────────────────────

@app.get("/admin")
async def admin_panel():
    return _FileResponse(_ADMIN_HTML)


# ── POST /api/admin/login ────────────────────────────────────────────────────

class _AdminLoginReq(BaseModel):
    username: str
    password: str


@app.post("/api/admin/login")
async def admin_login(req: _AdminLoginReq, response: Response):
    if req.username != _ADMIN_USERNAME or req.password != _ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid credentials")
    token = _issue_admin_jwt()
    response.set_cookie(
        key=_ADMIN_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=8 * 3600,
        path="/",
    )
    return {"ok": True}


# ── POST /api/admin/logout ───────────────────────────────────────────────────

@app.post("/api/admin/logout")
async def admin_logout(response: Response):
    response.delete_cookie(_ADMIN_COOKIE, path="/")
    return {"ok": True}


# ── GET /api/admin/me ────────────────────────────────────────────────────────

@app.get("/api/admin/me")
async def admin_me(request: Request):
    admin = _get_admin_user(request)
    if not admin:
        raise HTTPException(401, "Unauthorized")
    return {"ok": True, "role": "admin"}


# ── GET /api/admin/stats ─────────────────────────────────────────────────────

@app.get("/api/admin/stats")
async def admin_stats(request: Request):
    admin = _get_admin_user(request)
    if not admin:
        raise HTTPException(401, "Unauthorized")

    _users_path = os.path.join(os.path.dirname(__file__), "data", "users.json")
    try:
        with open(_users_path, "r", encoding="utf-8") as f:
            all_users: dict = json.load(f)
    except Exception:
        all_users = {}

    with _apts_lock:
        _reload_appointments()
        all_apts = dict(_appointments)

    with _registry_lock:
        reg = _load_registry()

    today = _admin_dt.now(_admin_tz.utc).date().isoformat()

    total_users = len(all_users)
    by_role = {"attorney": 0, "client": 0, "admin": 0}
    new_users_today = 0
    pending_enp_commission = 0

    for u in all_users.values():
        r = u.get("role", "")
        if r in by_role:
            by_role[r] += 1
        created = (u.get("created_at") or "")[:10]
        if created == today:
            new_users_today += 1
        if u.get("role") == "attorney" and u.get("sc_commission_status", "pending") == "pending":
            pending_enp_commission += 1

    total_apts = len(all_apts)
    ended_apts = sum(1 for a in all_apts.values() if a.get("session_status") == "ended")
    new_apts_today = sum(1 for a in all_apts.values() if (a.get("created_at") or "")[:10] == today)
    total_acts = len(reg.get("acts", []))

    return {
        "total_users": total_users,
        "users_by_role": by_role,
        "total_appointments": total_apts,
        "ended_appointments": ended_apts,
        "total_acts": total_acts,
        "pending_enp_commission": pending_enp_commission,
        "new_users_today": new_users_today,
        "new_appointments_today": new_apts_today,
    }


# ── GET /api/admin/users ─────────────────────────────────────────────────────

@app.get("/api/admin/users")
async def admin_list_users(
    request: Request,
    search: Optional[str] = None,
    role: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
):
    admin = _get_admin_user(request)
    if not admin:
        raise HTTPException(401, "Unauthorized")

    _users_path = os.path.join(os.path.dirname(__file__), "data", "users.json")
    try:
        with open(_users_path, "r", encoding="utf-8") as f:
            all_users: dict = json.load(f)
    except Exception:
        all_users = {}

    users = list(all_users.values())

    if role:
        users = [u for u in users if u.get("role") == role]
    if search:
        q = search.lower()
        users = [
            u for u in users
            if q in (u.get("email") or "").lower()
            or q in (u.get("first_name") or "").lower()
            or q in (u.get("last_name") or "").lower()
        ]

    users.sort(key=lambda u: u.get("created_at") or "", reverse=True)

    total = len(users)
    start = (page - 1) * per_page
    result = []
    for u in users[start:start + per_page]:
        result.append({
            "id":                 u.get("id"),
            "email":              u.get("email"),
            "first_name":         u.get("first_name"),
            "last_name":          u.get("last_name"),
            "role":               u.get("role"),
            "created_at":         u.get("created_at"),
            "onboarding_step":    u.get("onboarding_step"),
            "certificate_status": u.get("certificate_status"),
            "sc_commission_status": u.get("sc_commission_status"),
            "kyc_verified_at":    u.get("kyc_verified_at"),
        })

    return {
        "users": result,
        "total": total,
        "page":  page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }


# ── POST /api/admin/users/{user_id}/set-role ─────────────────────────────────

class _SetRoleReq(BaseModel):
    role: str


@app.post("/api/admin/users/{user_id}/set-role")
async def admin_set_role(user_id: str, req: _SetRoleReq, request: Request):
    admin = _get_admin_user(request)
    if not admin:
        raise HTTPException(401, "Unauthorized")
    if req.role not in ("attorney", "client", "admin"):
        raise HTTPException(400, "role must be attorney, client, or admin")

    _users_path = os.path.join(os.path.dirname(__file__), "data", "users.json")
    try:
        with open(_users_path, "r", encoding="utf-8") as f:
            all_users: dict = json.load(f)
    except Exception:
        all_users = {}

    if user_id not in all_users:
        raise HTTPException(404, "User not found")

    all_users[user_id]["role"] = req.role
    with open(_users_path, "w", encoding="utf-8") as f:
        json.dump(all_users, f, indent=2, ensure_ascii=False)

    return {"ok": True, "user_id": user_id, "role": req.role}


# ── GET /api/admin/appointments ──────────────────────────────────────────────

@app.get("/api/admin/appointments")
async def admin_list_appointments(
    request: Request,
    status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
):
    admin = _get_admin_user(request)
    if not admin:
        raise HTTPException(401, "Unauthorized")

    _users_path = os.path.join(os.path.dirname(__file__), "data", "users.json")
    try:
        with open(_users_path, "r", encoding="utf-8") as f:
            all_users: dict = json.load(f)
    except Exception:
        all_users = {}

    with _apts_lock:
        _reload_appointments()
        all_apts = list(_appointments.values())

    def _enp_name(enp_id: str) -> str:
        u = all_users.get(enp_id)
        if u:
            return f"{u.get('first_name','')} {u.get('last_name','')}".strip()
        return enp_id[:8] if enp_id else ""

    apts = all_apts
    if status:
        status_upper = status.upper()
        apts = [a for a in apts if a.get("status", "").upper() == status_upper
                or a.get("session_status", "").upper() == status_upper]
    if search:
        q = search.lower()
        apts = [
            a for a in apts
            if q in (a.get("client_email") or "").lower()
            or q in (a.get("enp_name") or "").lower()
            or q in (a.get("apt_id") or "").lower()
        ]

    apts.sort(key=lambda a: a.get("created_at") or "", reverse=True)

    total = len(apts)
    start = (page - 1) * per_page
    result = []
    for a in apts[start:start + per_page]:
        result.append({
            "id":              a.get("apt_id"),
            "enp_id":          a.get("enp_id"),
            "enp_name":        a.get("enp_name") or _enp_name(a.get("enp_id", "")),
            "client_email":    a.get("client_email"),
            "status":          a.get("status"),
            "session_status":  a.get("session_status"),
            "session_ended_at": a.get("session_ended_at"),
            "doc_count":       len(a.get("session_documents", [])),
            "created_at":      a.get("created_at"),
        })

    return {
        "appointments": result,
        "total": total,
        "page":  page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }


# ── GET /api/admin/registry ──────────────────────────────────────────────────

@app.get("/api/admin/registry")
async def admin_list_registry(
    request: Request,
    search: Optional[str] = None,
    act_type: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
):
    admin = _get_admin_user(request)
    if not admin:
        raise HTTPException(401, "Unauthorized")

    with _registry_lock:
        reg = _load_registry()

    acts = list(reg.get("acts", []))

    if act_type:
        acts = [a for a in acts if a.get("act_type", "").upper() == act_type.upper()]
    if search:
        q = search.lower()
        acts = [
            a for a in acts
            if q in (a.get("doc_name") or "").lower()
            or q in (a.get("enp_name") or "").lower()
            or q in (a.get("principal_name") or "").lower()
            or q in (a.get("dc_reference_number") or "").lower()
        ]

    acts.sort(key=lambda a: a.get("executed_at") or a.get("created_at") or "", reverse=True)

    total = len(acts)
    start = (page - 1) * per_page
    result = acts[start:start + per_page]

    return {
        "acts": result,
        "total": total,
        "page":  page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }
