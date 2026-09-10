#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EADMT4-PRO License Server - main.py
Versão: 5.2 (2026-09-11)
- Trial automático de 7 dias
- Captura de lead (nome, email, telefone) no primeiro acesso
- Status trial_expired quando o trial acaba naturalmente
- Heartbeat HMAC-SHA256 seguro
- Painel admin HTML + API REST JSON para o gerenciador local
"""
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
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from itsdangerous import URLSafeSerializer, BadSignature
from pydantic import BaseModel

# ============================================================================
# CONFIGURAÇÃO (variáveis de ambiente do Render)
# ============================================================================
TURSO_DATABASE_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "troque-esta-senha")
ADMIN_API_TOKEN = os.environ.get("ADMIN_API_TOKEN", "")  # ✅ NOVO
SECRET_KEY = os.environ.get("SECRET_KEY", "troque-este-secret-tambem")
HEARTBEAT_SECRET = os.environ.get("HEARTBEAT_SECRET", "troque-este-secret-do-heartbeat")

TRIAL_DAYS = 7
LICENSE_DAYS = 30
MAX_MACHINES_PER_KEY = 2

RATE_LIMIT_WINDOW_SEC = 60
LOGIN_MAX_ATTEMPTS = 5
CHECK_MAX_REQUESTS = 30
_login_attempts = defaultdict(deque)
_check_requests = defaultdict(deque)

app = FastAPI(title="EADMT4-PRO License Server")
serializer = URLSafeSerializer(SECRET_KEY, salt="admin-session")

LICENSE_COLUMNS = [
    "machine_id", "machine_name", "first_seen", "trial_expires",
    "license_expires", "last_seen", "revoked", "license_key",
    "client_name", "client_email", "client_phone", "hardware_fingerprint",
]
KEY_COLUMNS = ["license_key", "created", "expires", "revoked", "max_machines"]


# ============================================================================
# BANCO DE DADOS
# ============================================================================
def get_db():
    return libsql.connect(TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)


def row_to_dict(row, columns):
    if not row:
        return None
    return dict(zip(columns, row))


def now_utc():
    return datetime.now(timezone.utc)


def parse_dt(s):
    if not s:
        return None
    return datetime.fromisoformat(s)


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            machine_id TEXT PRIMARY KEY,
            machine_name TEXT,
            first_seen TEXT,
            trial_expires TEXT,
            license_expires TEXT,
            last_seen TEXT,
            revoked INTEGER DEFAULT 0,
            license_key TEXT,
            client_name TEXT,
            client_email TEXT,
            client_phone TEXT,
            hardware_fingerprint TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS license_keys (
            license_key TEXT PRIMARY KEY,
            created TEXT,
            expires TEXT,
            revoked INTEGER DEFAULT 0,
            max_machines INTEGER DEFAULT 2
        )
    """)
    for col_sql in [
        "ALTER TABLE licenses ADD COLUMN client_name TEXT",
        "ALTER TABLE licenses ADD COLUMN client_email TEXT",
        "ALTER TABLE licenses ADD COLUMN client_phone TEXT",
        "ALTER TABLE licenses ADD COLUMN hardware_fingerprint TEXT",
    ]:
        try:
            conn.execute(col_sql)
        except Exception:
            pass
    conn.commit()
    conn.close()


init_db()


# ============================================================================
# HELPERS
# ============================================================================
def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _is_rate_limited(store: dict, key: str, max_requests: int,
                     window: int = RATE_LIMIT_WINDOW_SEC) -> bool:
    now = time.time()
    dq = store[key]
    while dq and now - dq[0] > window:
        dq.popleft()
    if len(dq) >= max_requests:
        return True
    dq.append(now)
    return False


def generate_key():
    alphabet = string.ascii_uppercase + string.digits
    part = lambda: "".join(secrets.choice(alphabet) for _ in range(4))
    return "EAD-" + part() + "-" + part() + "-" + part()


def sign_heartbeat(status: str, machine_id: str, timestamp: int) -> str:
    payload = f"{status}|{machine_id}|{timestamp}"
    return hmac.new(
        HEARTBEAT_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def signed_response(status: str, machine_id: str, expires_at=None, days_left: int = 0) -> dict:
    timestamp = int(now_utc().timestamp())
    sig = sign_heartbeat(status, machine_id, timestamp)
    return {
        "status": status,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": days_left,
        "timestamp": timestamp,
        "sig": sig,
    }


# ============================================================================
# AUTENTICAÇÃO API (para o gerenciador local)
# ============================================================================
def verify_api_token(x_admin_api_token: str = Header(...)):
    """Verifica o token da API admin."""
    if not ADMIN_API_TOKEN:
        raise HTTPException(status_code=500, detail="ADMIN_API_TOKEN não configurado no servidor")
    if not hmac.compare_digest(x_admin_api_token, ADMIN_API_TOKEN):
        raise HTTPException(status_code=401, detail="Token inválido")
    return True


# ============================================================================
# ✅ ROTAS API REST JSON (para o gerenciador_local.py)
# ============================================================================
@app.get("/admin/api/keys")
def api_list_keys(_=Depends(verify_api_token)):
    """Lista todas as chaves em formato JSON."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM license_keys ORDER BY created DESC").fetchall()
    counts = {}
    for lk, c in conn.execute(
        "SELECT license_key, COUNT(*) FROM licenses WHERE license_key IS NOT NULL GROUP BY license_key"
    ).fetchall():
        counts[lk] = c
    conn.close()
    keys = []
    for r_raw in rows:
        k = row_to_dict(r_raw, KEY_COLUMNS)
        keys.append({
            "license_key": k["license_key"],
            "created": k["created"],
            "expires": k["expires"],
            "revoked": bool(k["revoked"]),
            "max_machines": k["max_machines"] or MAX_MACHINES_PER_KEY,
            "machines_used": counts.get(k["license_key"], 0),
        })
    return {"keys": keys}


@app.post("/admin/api/keygen")
def api_keygen(_=Depends(verify_api_token)):
    """Gera uma nova chave de licença."""
    conn = get_db()
    key = generate_key()
    conn.execute(
        "INSERT INTO license_keys (license_key, created, expires, revoked, max_machines) VALUES (?, ?, ?, 0, ?)",
        (key, now_utc().isoformat(), None, MAX_MACHINES_PER_KEY),
    )
    conn.commit()
    conn.close()
    return {
        "license_key": key,
        "max_machines": MAX_MACHINES_PER_KEY,
        "created": now_utc().isoformat(),
    }


@app.post("/admin/api/keys/{license_key}/renew")
def api_renew_key(license_key: str, body: dict = {"days": 30}, _=Depends(verify_api_token)):
    """Renova uma chave existente (estende a expiração)."""
    dias = body.get("days", body.get("dias", 30))
    conn = get_db()
    row = row_to_dict(
        conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (license_key,)).fetchone(),
        KEY_COLUMNS,
    )
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Chave não encontrada")
    now = now_utc()
    current = parse_dt(row["expires"])
    base = current if current and current > now else now
    new_expiry = base + timedelta(days=int(dias))
    conn.execute(
        "UPDATE license_keys SET expires = ?, revoked = 0 WHERE license_key = ?",
        (new_expiry.isoformat(), license_key),
    )
    conn.commit()
    conn.close()
    return {"license_key": license_key, "expires": new_expiry.isoformat(), "days_added": dias}


@app.post("/admin/api/keys/{license_key}/revoke")
def api_revoke_key(license_key: str, _=Depends(verify_api_token)):
    """Revoga uma chave."""
    conn = get_db()
    conn.execute("UPDATE license_keys SET revoked = 1 WHERE license_key = ?", (license_key,))
    conn.commit()
    conn.close()
    return {"license_key": license_key, "revoked": True}


# ============================================================================
# MODELO DE REQUEST DO CLIENTE
# ============================================================================
class CheckRequest(BaseModel):
    machine_id: str
    machine_name: str = ""
    license_key: str = ""
    client_name: str = ""
    client_email: str = ""
    client_phone: str = ""
    hardware_fingerprint: str = ""


# ============================================================================
# ENDPOINT PRINCIPAL: /api/check
# ============================================================================
@app.post("/api/check")
def check_license(request: Request, payload: CheckRequest):
    if _is_rate_limited(_check_requests, _client_ip(request), CHECK_MAX_REQUESTS):
        return {"status": "error", "expires_at": None, "days_left": 0,
                "sig": "", "timestamp": None}

    conn = get_db()
    now = now_utc()
    key = (payload.license_key or "").strip().upper()
    key_row = None
    key_error = None

    if key:
        key_row = row_to_dict(
            conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (key,)).fetchone(),
            KEY_COLUMNS,
        )
        if key_row is None:
            key_error = "key_invalid"
        elif key_row["revoked"]:
            key_error = "key_revoked"
        else:
            kexp = parse_dt(key_row["expires"])
            if kexp and kexp <= now:
                key_error = "key_expired"

    row = row_to_dict(
        conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (payload.machine_id,)).fetchone(),
        LICENSE_COLUMNS,
    )

    if row:
        if row["revoked"]:
            conn.close()
            return signed_response("revoked", payload.machine_id)
        if key_error:
            conn.close()
            return signed_response(key_error, payload.machine_id)

        updates = ["last_seen = ?"]
        params = [now.isoformat()]

        if payload.client_name:
            updates.append("client_name = ?")
            params.append(payload.client_name)
        if payload.client_email:
            updates.append("client_email = ?")
            params.append(payload.client_email)
        if payload.client_phone:
            updates.append("client_phone = ?")
            params.append(payload.client_phone)
        if payload.hardware_fingerprint:
            updates.append("hardware_fingerprint = ?")
            params.append(payload.hardware_fingerprint)
        if key:
            updates.append("license_key = ?")
            params.append(key)
            kexp = parse_dt(key_row["expires"]) if key_row else None
            if kexp is None:
                kexp = now + timedelta(days=LICENSE_DAYS)
            updates.append("license_expires = ?")
            params.append(kexp.isoformat())
            updates.append("revoked = 0")

        params.append(payload.machine_id)
        conn.execute(f"UPDATE licenses SET {', '.join(updates)} WHERE machine_id = ?", params)
        conn.commit()

        if key and key_row:
            kexp = parse_dt(key_row["expires"]) or (now + timedelta(days=LICENSE_DAYS))
            conn.close()
            return signed_response("licensed", payload.machine_id, kexp, max(0, (kexp - now).days))

        license_expires = parse_dt(row["license_expires"])
        trial_expires = parse_dt(row["trial_expires"])

        if license_expires and license_expires > now:
            days = max(0, (license_expires - now).days)
            conn.close()
            return signed_response("licensed", payload.machine_id, license_expires, days)
        elif trial_expires and trial_expires > now:
            days = max(0, (trial_expires - now).days)
            conn.close()
            return signed_response("trial", payload.machine_id, trial_expires, days)
        else:
            conn.close()
            return signed_response("trial_expired", payload.machine_id)

    if key_error:
        conn.close()
        return signed_response(key_error, payload.machine_id)

    trial_expires = now + timedelta(days=TRIAL_DAYS)
    conn.execute(
        """INSERT INTO licenses
           (machine_id, machine_name, first_seen, trial_expires, last_seen,
            client_name, client_email, client_phone, hardware_fingerprint)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            payload.machine_id,
            payload.machine_name,
            now.isoformat(),
            trial_expires.isoformat(),
            now.isoformat(),
            payload.client_name or "",
            payload.client_email or "",
            payload.client_phone or "",
            payload.hardware_fingerprint or "",
        ),
    )
    conn.commit()
    conn.close()
    return signed_response("trial", payload.machine_id, trial_expires, TRIAL_DAYS)


# ============================================================================
# CSS / ESTILO DO PAINEL
# ============================================================================
PAGE_STYLE = """
<style>
:root {
  --deriv-red: #ff444f; --deriv-red-dark: #eb3e48;
  --deriv-black: #0e0e0e; --deriv-gray: #6b6b6b;
  --deriv-light: #f5f7f9; --deriv-border: #e6e9e9;
  --deriv-green: #4caf50; --deriv-blue: #2196f3;
  --deriv-orange: #e65100;
}
* { box-sizing: border-box; }
body {
  font-family: 'IBM Plex Sans', 'Segoe UI', Arial, sans-serif;
  background: var(--deriv-light); color: var(--deriv-black);
  margin: 0; padding: 0;
}
.wrapper { max-width: 1400px; margin: 0 auto; padding: 32px 24px; }
h1 { font-size: 32px; font-weight: 800; margin: 0 0 4px 0; color: var(--deriv-black); }
.sub {
  color: var(--deriv-gray); font-size: 14px; margin-bottom: 24px;
  padding-top: 8px; border-top: 1px solid var(--deriv-border);
}
.sub a { color: var(--deriv-red); text-decoration: none; font-weight: 500; }
.sub a:hover { text-decoration: underline; }
table {
  width: 100%; border-collapse: collapse; background: #fff;
  border-radius: 8px; overflow: hidden;
  box-shadow: 0 1px 3px rgba(0,0,0,.04); font-size: 13px;
}
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--deriv-border); }
th {
  background: var(--deriv-light); color: var(--deriv-gray);
  font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: #fafbfc; }
.badge {
  padding: 4px 10px; border-radius: 4px; font-size: 11px;
  font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px;
  white-space: nowrap; display: inline-block;
}
.badge.trial      { background: #e3f2fd; color: var(--deriv-blue); }
.badge.licenciado { background: #e8f5e9; color: var(--deriv-green); }
.badge.expirado   { background: #fff3e0; color: var(--deriv-orange); }
.badge.revogado   { background: #eeeeee; color: #616161; }
.badge.ativo      { background: #e8f5e9; color: var(--deriv-green); }
.badge.pendente   { background: #fff8e1; color: #f57c00; }
form { display: inline; }
button {
  padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer;
  font-size: 12px; font-weight: 600; margin-right: 4px;
  transition: all 0.15s ease;
}
.btn-extend { background: var(--deriv-green); color: #fff; }
.btn-extend:hover { background: #3d9140; }
.btn-revoke { background: var(--deriv-red); color: #fff; }
.btn-revoke:hover { background: var(--deriv-red-dark); }
.btn-reset { background: #6b6b6b; color: #fff; }
.btn-reset:hover { background: #555; }
.btn-new {
  background: var(--deriv-red); color: #fff; font-weight: 700;
  padding: 12px 24px; font-size: 14px;
}
.btn-new:hover { background: var(--deriv-red-dark); }
.mono {
  font-family: 'IBM Plex Mono', Consolas, monospace; font-size: 12px;
  color: var(--deriv-gray); cursor: pointer; max-width: 180px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  display: inline-block; padding: 2px 6px; background: var(--deriv-light);
  border-radius: 3px;
}
.mono:hover { color: var(--deriv-red); }
.copied-msg {
  color: var(--deriv-green); font-size: 11px; font-weight: 700;
  margin-left: 6px; display: none;
}
.login-box {
  background: #fff; padding: 40px; border-radius: 8px; width: 400px;
  max-width: 90%; box-shadow: 0 4px 12px rgba(0,0,0,.06);
  margin: 12vh auto; border-top: 4px solid var(--deriv-red);
}
.login-box h1 { font-size: 28px; margin-bottom: 24px; }
input[type="password"], input[type="text"], input[type="email"] {
  width: 100%; padding: 12px 14px; margin-bottom: 16px;
  border-radius: 4px; border: 1px solid var(--deriv-border);
  background: #fff; color: var(--deriv-black); font-size: 14px;
}
input:focus { outline: none; border-color: var(--deriv-red); }
.login-box button {
  width: 100%; padding: 14px; background: var(--deriv-red);
  color: #fff; font-weight: 700; font-size: 14px; border: none;
  border-radius: 4px; cursor: pointer;
}
.login-box button:hover { background: var(--deriv-red-dark); }
.error {
  color: var(--deriv-red); background: #fdecea; padding: 10px 14px;
  border-radius: 4px; margin-bottom: 16px; font-size: 13px; font-weight: 500;
}
.client-info { font-size: 11px; color: var(--deriv-gray); max-width: 160px; }
.client-info strong { color: var(--deriv-black); display: block; }
</style>
"""


def render_login_page(error=None):
    error_html = f'<div class="error">{escape(error)}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8">
<title>Login - EADMT4-PRO</title>{PAGE_STYLE}</head>
<body>
<div class="login-box">
  <h1>EADMT4-PRO</h1>
  {error_html}
  <form method="post" action="/admin/login">
    <input type="password" name="password" placeholder="Senha de administrador" required autofocus>
    <button type="submit">Entrar</button>
  </form>
</div>
</body></html>"""


def render_dashboard_page(items, csrf_token=""):
    csrf_field = f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
    rows_html = ""
    if not items:
        rows_html = '<tr><td colspan="10">Nenhuma máquina se conectou ainda.</td></tr>'
    for item in items:
        rows_html += f"""
<tr>
  <td>{escape(item['machine_name'])}</td>
  <td><span class="mono" title="{escape(item['machine_id'])}"
       onclick="navigator.clipboard.writeText(this.textContent);
                var m=this.nextElementSibling;m.style.display='inline';
                setTimeout(function(){{m.style.display='none';}},1200);">
       {escape(item['machine_id'][:16])}...</span><span class="copied-msg">Copiado!</span></td>
  <td class="client-info">
    <strong>{escape(item.get('client_name') or '-')}</strong>
    {escape(item.get('client_email') or '')}<br>
    {escape(item.get('client_phone') or '')}
  </td>
  <td>{escape(item['license_key'])}</td>
  <td><span class="badge {item['status_class']}">{escape(item['status'])}</span></td>
  <td>{item['trial_expires']}</td>
  <td>{item['license_expires']}</td>
  <td>{item['last_seen']}</td>
  <td>
    <form method="post" action="/admin/extend/{item['machine_id']}">
      {csrf_field}
      <button class="btn-extend" type="submit">+ 1 mes</button>
    </form>
    <form method="post" action="/admin/revoke/{item['machine_id']}">
      {csrf_field}
      <button class="btn-revoke" type="submit">Revogar</button>
    </form>
    <form method="post" action="/admin/reset/{item['machine_id']}">
      {csrf_field}
      <button class="btn-reset" type="submit">Resetar</button>
    </form>
  </td>
</tr>"""
    return f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8">
<title>Painel - EADMT4-PRO</title>{PAGE_STYLE}</head>
<body>
<div class="wrapper">
  <h1>EADMT4-PRO — Licenças</h1>
  <div class="sub">
    {len(items)} máquina(s) registrada(s) &nbsp;•&nbsp;
    <a href="/admin/keys">Gerenciar chaves</a> &nbsp;•&nbsp;
    <a href="/admin/logout">Sair</a>
  </div>
  <table>
    <thead>
      <tr>
        <th>Computador</th><th>ID da máquina</th><th>Cliente</th><th>Chave</th>
        <th>Status</th><th>Trial expira</th><th>Licença expira</th>
        <th>Última conexão</th><th>Ações</th>
      </tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>
</div>
</body></html>"""


def render_keys_page(keys, csrf_token=""):
    csrf_field = f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
    rows_html = ""
    if not keys:
        rows_html = '<tr><td colspan="5">Nenhuma chave criada ainda.</td></tr>'
    for k in keys:
        rows_html += f"""
<tr>
  <td><span class="mono" style="max-width:260px"
       onclick="navigator.clipboard.writeText(this.textContent);
                var m=this.nextElementSibling;m.style.display='inline';
                setTimeout(function(){{m.style.display='none';}},1200);">
       {escape(k['license_key'])}</span><span class="copied-msg">Copiado!</span></td>
  <td>{k['expires']}</td>
  <td>{k['machines']}</td>
  <td><span class="badge {k['status_class']}">{escape(k['status'])}</span></td>
  <td>
    <form method="post" action="/admin/revokekey/{escape(k['license_key'])}">
      {csrf_field}
      <button class="btn-revoke" type="submit">Revogar</button>
    </form>
  </td>
</tr>"""
    return f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8">
<title>Chaves - EADMT4-PRO</title>{PAGE_STYLE}</head>
<body>
<div class="wrapper">
  <h1>EADMT4-PRO</h1>
  <div class="sub">
    Chaves de licença. Cada chave libera o app em até {MAX_MACHINES_PER_KEY} máquinas.
    Clique na chave para copiar. &nbsp;•&nbsp; <a href="/admin">Voltar</a>
  </div>
  <form method="post" action="/admin/keygen" style="margin-bottom:20px">
    {csrf_field}
    <button class="btn-new" type="submit">+ Gerar nova chave (30 dias)</button>
  </form>
  <table>
    <thead>
      <tr><th>Chave</th><th>Expira em</th><th>Máquinas</th><th>Status</th><th>Ações</th></tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>
</div>
</body></html>"""


# ============================================================================
# AUTENTICAÇÃO ADMIN (painel web)
# ============================================================================
def require_admin(request: Request) -> dict:
    token = request.cookies.get("admin_session")
    if token:
        try:
            data = serializer.loads(token)
            if data.get("ok"):
                return data
        except BadSignature:
            pass
    raise HTTPException(status_code=303, headers={"Location": "/admin/login"})


def require_admin_csrf(request: Request, csrf_token: str = Form(...)) -> dict:
    session = require_admin(request)
    if not hmac.compare_digest(csrf_token, session.get("csrf", "")):
        raise HTTPException(status_code=403, detail="Token CSRF inválido ou ausente.")
    return session


# ============================================================================
# ROTAS ADMIN (painel web HTML)
# ============================================================================
@app.get("/admin/login", response_class=HTMLResponse)
def login_form():
    return render_login_page()


@app.post("/admin/login")
def login(request: Request, password: str = Form(...)):
    if _is_rate_limited(_login_attempts, _client_ip(request), LOGIN_MAX_ATTEMPTS):
        return HTMLResponse(render_login_page("Muitas tentativas. Aguarde um minuto."), status_code=429)
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
        if r["revoked"]:
            status, status_class = "revogado", "revogado"
        elif license_expires and license_expires > now:
            status, status_class = "licenciado", "licenciado"
        elif trial_expires and trial_expires > now:
            status, status_class = "em teste", "trial"
        else:
            status, status_class = "expirado", "expirado"
        items.append({
            "machine_id": r["machine_id"],
            "machine_name": r["machine_name"] or "(sem nome)",
            "license_key": r["license_key"] or "-",
            "client_name": r.get("client_name") or "",
            "client_email": r.get("client_email") or "",
            "client_phone": r.get("client_phone") or "",
            "last_seen": (r["last_seen"] or "")[:16].replace("T", " "),
            "status": status,
            "status_class": status_class,
            "license_expires": license_expires.strftime("%d/%m/%Y %H:%M") if license_expires else "-",
            "trial_expires": trial_expires.strftime("%d/%m/%Y %H:%M") if trial_expires else "-",
        })
    return HTMLResponse(render_dashboard_page(items, session.get("csrf", "")))


@app.get("/admin/keys", response_class=HTMLResponse)
def keys_page(session=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM license_keys ORDER BY created DESC").fetchall()
    counts = {}
    for lk, c in conn.execute(
        "SELECT license_key, COUNT(*) FROM licenses WHERE license_key IS NOT NULL GROUP BY license_key"
    ).fetchall():
        counts[lk] = c
    conn.close()
    now = now_utc()
    keys = []
    for r_raw in rows:
        k = row_to_dict(r_raw, KEY_COLUMNS)
        exp = parse_dt(k["expires"])
        if k["revoked"]:
            status, status_class = "revogada", "revogado"
        elif exp is None:
            status, status_class = "aguardando 1º uso", "pendente"
        elif exp > now:
            status, status_class = "ativa", "ativo"
        else:
            status, status_class = "expirada", "expirado"
        used = counts.get(k["license_key"], 0)
        keys.append({
            "license_key": k["license_key"],
            "expires": exp.strftime("%d/%m/%Y %H:%M") if exp else "-",
            "machines": f"{used}/{k['max_machines'] or MAX_MACHINES_PER_KEY}",
            "status": status,
            "status_class": status_class,
        })
    return HTMLResponse(render_keys_page(keys, session.get("csrf", "")))


@app.post("/admin/keygen")
def keygen(_=Depends(require_admin_csrf)):
    conn = get_db()
    conn.execute(
        "INSERT INTO license_keys (license_key, created, expires, revoked, max_machines) VALUES (?, ?, ?, 0, ?)",
        (generate_key(), now_utc().isoformat(), None, MAX_MACHINES_PER_KEY),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/keys", status_code=303)


@app.post("/admin/revokekey/{license_key}")
def revoke_key(license_key: str, _=Depends(require_admin_csrf)):
    conn = get_db()
    conn.execute("UPDATE license_keys SET revoked = 1 WHERE license_key = ?", (license_key,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/keys", status_code=303)


@app.post("/admin/extend/{machine_id}")
def extend_license(machine_id: str, _=Depends(require_admin_csrf)):
    conn = get_db()
    row = row_to_dict(
        conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (machine_id,)).fetchone(),
        LICENSE_COLUMNS,
    )
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Máquina não encontrada")
    now = now_utc()
    current = parse_dt(row["license_expires"])
    base = current if current and current > now else now
    new_expiry = base + timedelta(days=LICENSE_DAYS)
    conn.execute(
        "UPDATE licenses SET license_expires = ?, revoked = 0 WHERE machine_id = ?",
        (new_expiry.isoformat(), machine_id),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/revoke/{machine_id}")
def revoke_license(machine_id: str, _=Depends(require_admin_csrf)):
    conn = get_db()
    conn.execute("UPDATE licenses SET revoked = 1 WHERE machine_id = ?", (machine_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/reset/{machine_id}")
def reset_license(machine_id: str, _=Depends(require_admin_csrf)):
    conn = get_db()
    conn.execute("DELETE FROM licenses WHERE machine_id = ?", (machine_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)


# ============================================================================
# HEALTH CHECK
# ============================================================================
@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"service": "EADMT4-PRO License Server", "status": "ok"}
