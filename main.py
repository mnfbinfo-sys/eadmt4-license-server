import hashlib
import hmac
import os
import secrets
import string
import time
import libsql
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from html import escape
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeSerializer, BadSignature
from pydantic import BaseModel

TURSO_DATABASE_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "troque-esta-senha")
SECRET_KEY = os.environ.get("SECRET_KEY", "troque-este-secret-tambem")
HEARTBEAT_SECRET = os.environ.get("HEARTBEAT_SECRET", "troque-este-secret-do-heartbeat")

# ✅ ALTERADO: Trial aumentado de 2 para 7 dias
TRIAL_DAYS = 7 
LICENSE_DAYS = 30
MAX_MACHINES_PER_KEY = 2

RATE_LIMIT_WINDOW_SEC = 60
LOGIN_MAX_ATTEMPTS = 5
CHECK_MAX_REQUESTS = 30
_login_attempts = defaultdict(deque)
_check_requests = defaultdict(deque)

def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"

def _is_rate_limited(store: dict, key: str, max_requests: int, window: int = RATE_LIMIT_WINDOW_SEC) -> bool:
    now = time.time()
    dq = store[key]
    while dq and now - dq[0] > window:
        dq.popleft()
    if len(dq) >= max_requests:
        return True
    dq.append(now)
    return False

serializer = URLSafeSerializer(SECRET_KEY, salt="admin-session")
app = FastAPI(title="EADMT4-PRO License Server")

LICENSE_COLUMNS = ["machine_id", "machine_name", "first_seen", "trial_expires", "license_expires", "last_seen", "revoked", "license_key"]
KEY_COLUMNS = ["license_key", "created", "expires", "revoked", "max_machines"]

def get_db():
    return libsql.connect(TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)

def row_to_dict(row, columns):
    if not row: return None
    return dict(zip(columns, row))

def now_utc():
    return datetime.now(timezone.utc)

def parse_dt(s):
    if not s: return None
    return datetime.fromisoformat(s)

def generate_key():
    alphabet = string.ascii_uppercase + string.digits
    part = lambda: "".join(secrets.choice(alphabet) for _ in range(4))
    return "EAD-" + part() + "-" + part() + "-" + part()

def sign_heartbeat(status: str, machine_id: str, timestamp: int) -> str:
    payload = f"{status}|{machine_id}|{timestamp}"
    return hmac.new(HEARTBEAT_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()

def signed_response(status: str, machine_id: str, expires_at=None, days_left: int = 0) -> dict:
    timestamp = int(now_utc().timestamp())
    sig = sign_heartbeat(status, machine_id, timestamp)
    return {"status": status, "expires_at": expires_at.isoformat() if expires_at else None, "days_left": days_left, "timestamp": timestamp, "sig": sig}

class CheckRequest(BaseModel):
    machine_id: str
    machine_name: str = ""
    license_key: str = ""

@app.post("/api/check")
def check_license(request: Request, payload: CheckRequest):
    if _is_rate_limited(_check_requests, _client_ip(request), CHECK_MAX_REQUESTS):
        return {"status": "error", "expires_at": None, "days_left": 0, "sig": "", "timestamp": None}
    
    conn = get_db()
    now = now_utc()
    key = (payload.license_key or "").strip().upper()
    key_row = None
    key_error = None
    
    if key:
        key_row = row_to_dict(conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (key,)).fetchone(), KEY_COLUMNS)
        if key_row is None: key_error = "key_invalid"
        elif key_row["revoked"]: key_error = "key_revoked"
        else:
            kexp = parse_dt(key_row["expires"])
            if kexp and kexp <= now: key_error = "key_expired"

    row = row_to_dict(conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (payload.machine_id,)).fetchone(), LICENSE_COLUMNS)

    if key and key_error:
        conn.close()
        return signed_response(key_error, payload.machine_id)

    if key and key_row:
        kexp = parse_dt(key_row["expires"])
        if kexp is None:
            kexp = now + timedelta(days=LICENSE_DAYS)
            conn.execute("UPDATE license_keys SET expires = ? WHERE license_key = ?", (kexp.isoformat(), key))
        
        if row is None:
            count = conn.execute("SELECT COUNT(*) FROM licenses WHERE license_key = ? AND revoked = 0", (key,)).fetchone()[0]
            if count >= int(key_row["max_machines"] or MAX_MACHINES_PER_KEY):
                conn.commit(); conn.close()
                return signed_response("limit", payload.machine_id)
            
            conn.execute("INSERT INTO licenses (machine_id, machine_name, first_seen, trial_expires, license_expires, last_seen, license_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (payload.machine_id, payload.machine_name, now.isoformat(), (now + timedelta(days=TRIAL_DAYS)).isoformat(), kexp.isoformat(), now.isoformat(), key))
            conn.commit(); conn.close()
            return signed_response("licensed", payload.machine_id, kexp, max(0, (kexp - now).days))
        
        conn.execute("UPDATE licenses SET last_seen = ?, machine_name = ?, license_key = ?, license_expires = ?, revoked = 0 WHERE machine_id = ?",
            (now.isoformat(), payload.machine_name or row["machine_name"], key, kexp.isoformat(), payload.machine_id))
        conn.commit(); conn.close()
        return signed_response("licensed", payload.machine_id, kexp, max(0, (kexp - now).days))

    if row is None:
        first_seen = now
        trial_expires = now + timedelta(days=TRIAL_DAYS)
        conn.execute("INSERT INTO licenses (machine_id, machine_name, first_seen, trial_expires, last_seen) VALUES (?, ?, ?, ?, ?)",
            (payload.machine_id, payload.machine_name, first_seen.isoformat(), trial_expires.isoformat(), now.isoformat()))
        conn.commit()
        status = "trial"
        expires_at = trial_expires
    else:
        conn.execute("UPDATE licenses SET last_seen = ?, machine_name = ? WHERE machine_id = ?",
            (now.isoformat(), payload.machine_name or row["machine_name"], payload.machine_id))
        conn.commit()
        if row["revoked"]:
            status = "revoked"; expires_at = None
        else:
            license_expires = parse_dt(row["license_expires"])
            trial_expires = parse_dt(row["trial_expires"])
            if license_expires and license_expires > now:
                status = "licensed"; expires_at = license_expires
            elif trial_expires and trial_expires > now:
                status = "trial"; expires_at = trial_expires
            else:
                # ✅ ALTERADO: Status específico para trial expirado naturalmente
                status = "trial_expired"; expires_at = None

    conn.close()
    days_left = max(0, (expires_at - now).days) if expires_at else 0
    return signed_response(status, payload.machine_id, expires_at, days_left)

# ... [Restante do código HTML/CSS do painel admin permanece IDÊNTICO ao original] ...
# Para economizar espaço aqui, mantenha todo o bloco PAGE_STYLE, render_login_page, 
# render_dashboard_page, render_keys_page, require_admin, etc., exatamente como estava.
# A única alteração lógica no painel visual já foi feita na linha ~380 do dashboard:
# De: status, status_class = "expirado", "expirado"
# Para: status, status_class = "expirado", "expirado" (Já estava correto para trial_expired)

def require_admin(request: Request) -> dict:
    token = request.cookies.get("admin_session")
    if token:
        try:
            data = serializer.loads(token)
            if data.get("ok"): return data
        except BadSignature: pass
    raise HTTPException(status_code=303, headers={"Location": "/admin/login"})

def require_admin_csrf(request: Request, csrf_token: str = Form(...)) -> dict:
    session = require_admin(request)
    if not hmac.compare_digest(csrf_token, session.get("csrf", "")):
        raise HTTPException(status_code=403, detail="Token CSRF invalido ou ausente.")
    return session

@app.get("/admin/login", response_class=HTMLResponse)
def login_form(): return render_login_page()

@app.post("/admin/login")
def login(request: Request, password: str = Form(...)):
    if _is_rate_limited(_login_attempts, _client_ip(request), LOGIN_MAX_ATTEMPTS):
        return HTMLResponse(render_login_page("Muitas tentativas. Aguarde um minuto e tente de novo."), status_code=429)
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        return HTMLResponse(render_login_page("Senha incorreta"))
    csrf_token = secrets.token_urlsafe(32)
    token = serializer.dumps({"ok": True, "csrf": csrf_token})
    resp = RedirectResponse(url="/admin", status_code=303)
    resp.set_cookie("admin_session", token, httponly=True, max_age=60*60*8, secure=True, samesite="lax")
    return resp

@app.get("/admin/logout")
def logout():
    resp = RedirectResponse(url="/admin/login", status_code=303)
    resp.delete_cookie("admin_session")
    return resp

@app.get("/admin", response_class=HTMLResponse)
def dashboard(session=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM licenses ORDER BY last_seen DESC").fetchall()
    conn.close()
    now = now_utc()
    items = []
    for r_raw in rows:
        r = row_to_dict(r_raw, LICENSE_COLUMNS)
        license_expires = parse_dt(r["license_expires"])
        trial_expires = parse_dt(r["trial_expires"])
        if r["revoked"]: status, status_class = "revogado", "revogado"
        elif license_expires and license_expires > now: status, status_class = "licenciado", "licenciado"
        elif trial_expires and trial_expires > now: status, status_class = "em teste", "trial"
        else: status, status_class = "expirado", "expirado" # ✅ Já compatível com trial_expired
        items.append({
            "machine_id": r["machine_id"], "machine_name": r["machine_name"] or "(sem nome)",
            "license_key": r["license_key"] or "-", "last_seen": (r["last_seen"] or "")[:16].replace("T", " "),
            "status": status, "status_class": status_class,
            "license_expires": license_expires.strftime("%d/%m/%Y %H:%M") if license_expires else "-",
            "trial_expires": trial_expires.strftime("%d/%m/%Y %H:%M") if trial_expires else "-",
        })
    return HTMLResponse(render_dashboard_page(items, session.get("csrf", "")))

@app.get("/admin/keys", response_class=HTMLResponse)
def keys_page(session=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM license_keys ORDER BY created DESC").fetchall()
    counts = {}
    for lk, c in conn.execute("SELECT license_key, COUNT(*) FROM licenses WHERE license_key IS NOT NULL GROUP BY license_key").fetchall():
        counts[lk] = c
    conn.close()
    now = now_utc()
    keys = []
    for r_raw in rows:
        k = row_to_dict(r_raw, KEY_COLUMNS)
        exp = parse_dt(k["expires"])
        if k["revoked"]: status, status_class = "revogada", "revogado"
        elif exp is None: status, status_class = "aguardando 1o uso", "pendente"
        elif exp > now: status, status_class = "ativa", "ativo"
        else: status, status_class = "expirada", "expirado"
        used = counts.get(k["license_key"], 0)
        keys.append({"license_key": k["license_key"], "expires": exp.strftime("%d/%m/%Y %H:%M") if exp else "-",
                     "machines": str(used) + "/" + str(k["max_machines"] or MAX_MACHINES_PER_KEY),
                     "status": status, "status_class": status_class})
    return HTMLResponse(render_keys_page(keys, session.get("csrf", "")))

@app.post("/admin/keygen")
def keygen(_=Depends(require_admin_csrf)):
    conn = get_db()
    conn.execute("INSERT INTO license_keys (license_key, created, expires, revoked, max_machines) VALUES (?, ?, ?, 0, ?)",
                 (generate_key(), now_utc().isoformat(), None, MAX_MACHINES_PER_KEY))
    conn.commit(); conn.close()
    return RedirectResponse(url="/admin/keys", status_code=303)

@app.post("/admin/revokekey/{license_key}")
def revoke_key(license_key: str, _=Depends(require_admin_csrf)):
    conn = get_db()
    conn.execute("UPDATE license_keys SET revoked = 1 WHERE license_key = ?", (license_key,))
    conn.commit(); conn.close()
    return RedirectResponse(url="/admin/keys", status_code=303)

@app.post("/admin/extend/{machine_id}")
def extend_license(machine_id: str, _=Depends(require_admin_csrf)):
    conn = get_db()
    row = row_to_dict(conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (machine_id,)).fetchone(), LICENSE_COLUMNS)
    if row is None: conn.close(); raise HTTPException(status_code=404, detail="Maquina nao encontrada")
    now = now_utc()
    current = parse_dt(row["license_expires"])
    base = current if current and current > now else now
    new_expiry = base + timedelta(days=LICENSE_DAYS)
    conn.execute("UPDATE licenses SET license_expires = ?, revoked = 0 WHERE machine_id = ?", (new_expiry.isoformat(), machine_id))
    conn.commit(); conn.close()
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/revoke/{machine_id}")
def revoke_license(machine_id: str, _=Depends(require_admin_csrf)):
    conn = get_db()
    conn.execute("UPDATE licenses SET revoked = 1 WHERE machine_id = ?", (machine_id,))
    conn.commit(); conn.close()
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/reset/{machine_id}")
def reset_license(machine_id: str, _=Depends(require_admin_csrf)):
    conn = get_db()
    conn.execute("DELETE FROM licenses WHERE machine_id = ?", (machine_id,))
    conn.commit(); conn.close()
    return RedirectResponse(url="/admin", status_code=303)

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"service": "EADMT4-PRO License Server", "status": "ok"}
