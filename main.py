import hashlib
import hmac
import os
import secrets
import string
import time
import libsql
from datetime import datetime, timedelta, timezone
from html import escape
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeSerializer, BadSignature
from pydantic import BaseModel

# Configurações - Certifique-se que estas variáveis existem no Render!
# ⚠️ SEGURANÇA: nenhum destes segredos tem valor padrão. Se a variável de ambiente
# não estiver definida, o servidor recusa iniciar (ver _require_env abaixo), em vez
# de silenciosamente usar uma senha/chave pública conhecida do código-fonte.
def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Variável de ambiente obrigatória '{name}' não definida. "
            f"Configure-a no ambiente (ex.: Render > Environment) antes de iniciar o servidor."
        )
    return value

TURSO_DATABASE_URL = _require_env("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = _require_env("TURSO_AUTH_TOKEN")
ADMIN_PASSWORD = _require_env("ADMIN_PASSWORD")
SECRET_KEY = _require_env("SECRET_KEY")
HEARTBEAT_SECRET = _require_env("HEARTBEAT_SECRET")

# ✅ ALTERADO: Trial aumentado para 7 dias
TRIAL_DAYS = 7 
LICENSE_DAYS = 30
MAX_MACHINES_PER_KEY = 2

RATE_LIMIT_WINDOW_SEC = 60
LOGIN_MAX_ATTEMPTS = 5
CHECK_MAX_REQUESTS = 30

def _client_ip(request: Request) -> str:
    # ⚠️ IMPORTANTE: no Render (e em qualquer proxy/load balancer na frente da app),
    # request.client.host é o IP do proxy, não o do visitante real - então TODO mundo
    # cairia no mesmo "IP" e o rate limit ficaria inútil (ou bloquearia todo mundo de
    # uma vez por causa de um único atacante). O Render injeta o IP real do cliente no
    # cabeçalho X-Forwarded-For (primeiro IP da lista = o cliente original).
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first_ip = xff.split(",")[0].strip()
        if first_ip:
            return first_ip
    return request.client.host if request.client else "unknown"

def _ensure_rate_limit_table(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS rate_limit_events (bucket TEXT NOT NULL, key TEXT NOT NULL, ts INTEGER NOT NULL)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_rate_limit_bucket_key ON rate_limit_events (bucket, key)"
    )

def _is_rate_limited(conn, bucket: str, key: str, max_requests: int, window: int = RATE_LIMIT_WINDOW_SEC) -> bool:
    # Rate limit persistido no banco Turso (em vez de memória do processo), para que:
    # 1) um restart/deploy não zere os contadores de tentativas de um atacante;
    # 2) o limite continue correto mesmo se o serviço um dia rodar em mais de uma instância.
    _ensure_rate_limit_table(conn)
    now = int(time.time())
    cutoff = now - window
    conn.execute("DELETE FROM rate_limit_events WHERE bucket = ? AND ts < ?", (bucket, cutoff))
    count = conn.execute(
        "SELECT COUNT(*) FROM rate_limit_events WHERE bucket = ? AND key = ?", (bucket, key)
    ).fetchone()[0]
    if count >= max_requests:
        conn.commit()
        return True
    conn.execute("INSERT INTO rate_limit_events (bucket, key, ts) VALUES (?, ?, ?)", (bucket, key, now))
    conn.commit()
    return False

serializer = URLSafeSerializer(SECRET_KEY, salt="admin-session")
app = FastAPI(title="EADMT4-PRO License Server")

LICENSE_COLUMNS = ["machine_id", "machine_name", "first_seen", "trial_expires", "license_expires", "last_seen", "revoked", "license_key"]
KEY_COLUMNS = ["license_key", "created", "expires", "revoked", "max_machines"]

def get_db():
    try:
        return libsql.connect(TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)
    except Exception as e:
        print(f"[DB ERROR] Falha ao conectar: {e}")
        raise

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
    conn = get_db()
    if _is_rate_limited(conn, "check", _client_ip(request), CHECK_MAX_REQUESTS):
        conn.close()
        return {"status": "error", "expires_at": None, "days_left": 0, "sig": "", "timestamp": None}

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
                # ✅ Status específico para trial expirado naturalmente
                status = "trial_expired"; expires_at = None

    conn.close()
    days_left = max(0, (expires_at - now).days) if expires_at else 0
    return signed_response(status, payload.machine_id, expires_at, days_left)

# ... [MANTENHA TODO O RESTANTE DO CÓDIGO HTML/CSS E ROTAS ADMIN IGUAL AO ANTERIOR] ...
# ⚠️ IMPORTANTE: Não apague as funções render_login_page, render_dashboard_page, etc.
# Apenas certifique-se que a função 'dashboard' use 'trial_expired' corretamente se necessário.

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
        raise HTTPException(status_code=403, detail="Token CSRF invalido.")
    return session

@app.get("/admin/login", response_class=HTMLResponse)
def login_form(): return render_login_page()

@app.post("/admin/login")
def login(request: Request, password: str = Form(...)):
    conn = get_db()
    limited = _is_rate_limited(conn, "login", _client_ip(request), LOGIN_MAX_ATTEMPTS)
    conn.close()
    if limited:
        return HTMLResponse(render_login_page("Muitas tentativas."), status_code=429)
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
        else: status, status_class = "expirado", "expirado" # ✅ Compatível com trial_expired
        items.append({
            "machine_id": r["machine_id"], "machine_name": r["machine_name"] or "(sem nome)",
            "license_key": r["license_key"] or "-", "last_seen": (r["last_seen"] or "")[:16].replace("T", " "),
            "status": status, "status_class": status_class,
            "license_expires": license_expires.strftime("%d/%m/%Y %H:%M") if license_expires else "-",
            "trial_expires": trial_expires.strftime("%d/%m/%Y %H:%M") if trial_expires else "-",
        })
    return HTMLResponse(render_dashboard_page(items, session.get("csrf", "")))

# ... [MANTENHA AS OUTRAS ROTAS ADMIN: /admin/keys, /admin/keygen, etc.] ...

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"service": "EADMT4-PRO License Server", "status": "ok"}
