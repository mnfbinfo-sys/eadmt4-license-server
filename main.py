#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EADMT4-PRO License Server v2.5 (Edição Profissional 2026)
Melhorias:
 - Garantia absoluta de Trial de 3 dias para novos clientes (Bug fix no schema)
 - Interface Web Admin Dark High-Tech moderna
 - Botão de Reset Completo do Banco com Proteção por Senha de Administrador
 - Rate-limit em memória (Zero custos extras no Turso)
"""
import asyncio
import hashlib
import hmac
import os
import secrets
import string
import time
import libsql
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Optional, Dict, List
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeSerializer, BadSignature
from pydantic import BaseModel, Field

# ============================================================================
# CONFIGURAÇÕES
# ============================================================================
def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Variável de ambiente obrigatória '{name}' não definida.")
    return value

TURSO_DATABASE_URL = _require_env("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = _require_env("TURSO_AUTH_TOKEN")
ADMIN_PASSWORD = _require_env("ADMIN_PASSWORD")
SECRET_KEY = _require_env("SECRET_KEY")
HEARTBEAT_SECRET = _require_env("HEARTBEAT_SECRET")

ADMIN_API_TOKEN = os.environ.get("ADMIN_API_TOKEN") or ADMIN_PASSWORD

TRIAL_DAYS = 3
LICENSE_DAYS = 30
MAX_MACHINES_PER_KEY = 2
LOGIN_MAX_ATTEMPTS = 5
CHECK_MAX_REQUESTS = 60
RATE_LIMIT_WINDOW_SEC = 60

# ============================================================================
# RATE-LIMIT EM MEMÓRIA
# ============================================================================
class InMemoryRateLimiter:
    def __init__(self):
        self.requests: Dict[str, List[int]] = {}
    
    def is_limited(self, bucket: str, key: str, max_requests: int, window: int = RATE_LIMIT_WINDOW_SEC) -> bool:
        now = int(time.time())
        cutoff = now - window
        composite_key = f"{bucket}:{key}"
        
        if composite_key in self.requests:
            self.requests[composite_key] = [ts for ts in self.requests[composite_key] if ts > cutoff]
        
        if len(self.requests.get(composite_key, [])) >= max_requests:
            return True
        
        if composite_key not in self.requests:
            self.requests[composite_key] = []
        self.requests[composite_key].append(now)
        return False
    
    def cleanup(self):
        now = int(time.time())
        cutoff = now - RATE_LIMIT_WINDOW_SEC
        keys_to_remove = []
        for key, timestamps in self.requests.items():
            self.requests[key] = [ts for ts in timestamps if ts > cutoff]
            if not self.requests[key]:
                keys_to_remove.append(key)
        for key in keys_to_remove:
            del self.requests[key]

rate_limiter = InMemoryRateLimiter()

def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first_ip = xff.split(",")[0].strip()
        if first_ip: return first_ip
    return request.client.host if request.client else "unknown"

# ============================================================================
# APP FASTAPI E INICIALIZAÇÃO
# ============================================================================
serializer = URLSafeSerializer(SECRET_KEY, salt="admin-session")
app = FastAPI(title="EADMT4-PRO License Server")

@app.middleware("http")
async def _security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response

@app.on_event("startup")
async def _on_startup():
    async def cleanup_loop():
        while True:
            await asyncio.sleep(6 * 60 * 60)
            rate_limiter.cleanup()
    asyncio.create_task(cleanup_loop())

# ============================================================================
# BANCO DE DADOS (TURSO)
# ============================================================================
LICENSE_COLUMNS = ["machine_id", "machine_name", "first_seen", "license_expires", "last_seen", "revoked", "license_key", "hardware_fingerprint"]
KEY_COLUMNS = ["license_key", "created", "expires", "revoked", "max_machines"]

def _ensure_core_tables(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        machine_id TEXT PRIMARY KEY,
        machine_name TEXT,
        first_seen TEXT,
        license_expires TEXT,
        last_seen TEXT,
        revoked INTEGER DEFAULT 0,
        license_key TEXT,
        hardware_fingerprint TEXT
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS license_keys (
        license_key TEXT PRIMARY KEY,
        created TEXT,
        expires TEXT,
        revoked INTEGER DEFAULT 0,
        max_machines INTEGER
    )
    """)
    try:
        conn.execute("ALTER TABLE licenses ADD COLUMN hardware_fingerprint TEXT")
        conn.commit()
    except Exception:
        pass

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
    return {
        "status": status,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": days_left,
        "timestamp": timestamp,
        "sig": sig
    }

# ============================================================================
# API PÚBLICA DE LICENÇAS - /api/check
# ============================================================================
class CheckRequest(BaseModel):
    machine_id: str = Field(..., min_length=1, max_length=128)
    machine_name: str = Field("", max_length=128)
    license_key: str = Field("", max_length=64)
    hardware_fingerprint: str = Field("", max_length=128)

@app.post("/api/check")
def check_license(request: Request, payload: CheckRequest):
    if rate_limiter.is_limited("check", _client_ip(request), CHECK_MAX_REQUESTS):
        return {"status": "error", "expires_at": None, "days_left": 0, "sig": "", "timestamp": None}

    conn = get_db()
    _ensure_core_tables(conn)
    now = now_utc()
    key = (payload.license_key or "").strip().upper()
    key_row = None
    key_error = None

    # Validação se o usuário enviou uma chave PRO
    if key:
        key_row = row_to_dict(conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (key,)).fetchone(), KEY_COLUMNS)
        if key_row is None: key_error = "key_invalid"
        elif key_row["revoked"]: key_error = "key_revoked"
        else:
            kexp = parse_dt(key_row["expires"])
            if kexp and kexp <= now: key_error = "key_expired"

    row = row_to_dict(conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (payload.machine_id,)).fetchone(), LICENSE_COLUMNS)

    # 1. Chave enviada porém inválida/expirada
    if key and key_error:
        conn.close()
        return signed_response(key_error, payload.machine_id)

    # 2. Chave PRO válida
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

            conn.execute("""
                INSERT INTO licenses (machine_id, machine_name, first_seen, license_expires, last_seen, revoked, license_key, hardware_fingerprint)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?)
            """, (payload.machine_id, payload.machine_name, now.isoformat(), kexp.isoformat(), now.isoformat(), key, payload.hardware_fingerprint))
            conn.commit(); conn.close()
            return signed_response("licensed", payload.machine_id, kexp, max(0, (kexp - now).days))

        conn.execute("""
            UPDATE licenses SET last_seen = ?, machine_name = ?, license_key = ?, license_expires = ?, revoked = 0,
            hardware_fingerprint = COALESCE(NULLIF(?, ''), hardware_fingerprint) WHERE machine_id = ?
        """, (now.isoformat(), payload.machine_name or row["machine_name"], key, kexp.isoformat(), payload.hardware_fingerprint, payload.machine_id))
        conn.commit(); conn.close()
        return signed_response("licensed", payload.machine_id, kexp, max(0, (kexp - now).days))

    # 3. NOVO CLIENTE: CRIAÇÃO AUTOMÁTICA E GARANTIDA DO TRIAL DE 3 DIAS
    trial_expires = now + timedelta(days=TRIAL_DAYS)
    
    if row is None:
        # Primeiro acesso desta máquina: CRIA O TRIAL IMEDIATAMENTE
        conn.execute("""
            INSERT INTO licenses (machine_id, machine_name, first_seen, license_expires, last_seen, revoked, license_key, hardware_fingerprint)
            VALUES (?, ?, ?, ?, ?, 0, NULL, ?)
        """, (payload.machine_id, payload.machine_name, now.isoformat(), trial_expires.isoformat(), now.isoformat(), payload.hardware_fingerprint))
        conn.commit()
        conn.close()
        return signed_response("trial", payload.machine_id, trial_expires, TRIAL_DAYS)
    
    # 4. CLIENTE EXISTENTE (TRIAL EM ANDAMENTO OU EXPIRADO)
    if row.get("revoked", 0) == 1:
        conn.close()
        return signed_response("revoked", payload.machine_id)
        
    existing_expires = parse_dt(row["license_expires"])
    if existing_expires and existing_expires > now and not row.get("license_key"):
        days_left = max(0, (existing_expires - now).days)
        conn.execute("""
            UPDATE licenses SET last_seen = ?, machine_name = ?, hardware_fingerprint = COALESCE(NULLIF(?, ''), hardware_fingerprint)
            WHERE machine_id = ?
        """, (now.isoformat(), payload.machine_name or row["machine_name"], payload.hardware_fingerprint, payload.machine_id))
        conn.commit()
        conn.close()
        return signed_response("trial", payload.machine_id, existing_expires, days_left)
    
    # Trial expirou
    conn.execute("UPDATE licenses SET last_seen = ? WHERE machine_id = ?", (now.isoformat(), payload.machine_id))
    conn.commit()
    conn.close()
    return signed_response("trial_expired", payload.machine_id)

# ============================================================================
# ESTILO CSS DARK PRO PARA O PAINEL WEB
# ============================================================================
_PAGE_STYLE = """
<style>
* { box-sizing: border-box; }
body { background: #0b121e; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; }
.wrap { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
.card { background: #131d2e; border: 1px solid #1e2c42; border-radius: 12px; padding: 24px; box-shadow: 0 8px 30px rgba(0,0,0,0.4); margin-bottom: 24px; }
h1 { font-size: 20px; font-weight: 700; color: #fff; margin: 0 0 16px 0; display: flex; align-items: center; gap: 8px; }
input[type=password], input[type=text], input[type=number] {
  width: 100%; padding: 10px 14px; border-radius: 6px; border: 1px solid #22354d;
  background: #090e17; color: #fff; font-size: 14px; outline: none; transition: border-color 0.2s;
}
input:focus { border-color: #00b0ff; }
button, .btn {
  background: #00b0ff; color: #fff; border: none; padding: 9px 16px; border-radius: 6px;
  font-size: 13px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; transition: 0.2s;
}
button:hover, .btn:hover { opacity: 0.9; transform: translateY(-1px); }
.btn-danger { background: #ff3b56; }
.btn-ok { background: #00e676; color: #000; }
.btn-reset { background: #ef4444; padding: 10px 18px; font-size: 13px; }
.topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #1e2c42; padding-bottom: 14px; }
.topbar a { color: #8e9eb5; text-decoration: none; font-size: 14px; margin-left: 18px; font-weight: 500; }
.topbar a:hover { color: #00e676; }
table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #1c2a3f; }
th { color: #8e9eb5; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
tr:hover { background: #162438; }
.tag { padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
.tag.licenciado { background: #064e3b; color: #34d399; }
.tag.trial { background: #1e3a8a; color: #60a5fa; }
.tag.revogado { background: #7f1d1d; color: #f87171; }
.tag.expirado { background: #374151; color: #9ca3af; }
.mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; color: #cbd5e1; }
.err { background: #450a0a; color: #fca5a5; padding: 12px; border-radius: 6px; margin-bottom: 16px; font-size: 13px; border: 1px solid #7f1d1d; }
.modal-bg { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.75); z-index: 999; align-items: center; justify-content: center; }
.modal-box { background: #131d2e; border: 1px solid #ff3b56; border-radius: 12px; padding: 28px; width: 440px; box-shadow: 0 10px 40px rgba(0,0,0,0.8); }
</style>
"""

# ============================================================================
# PÁGINAS DO PAINEL ADMIN
# ============================================================================
def render_login_page(error: str = "") -> str:
    err_html = f'<div class="err">{escape(error)}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="utf-8"><title>Login - EADMT4 Pro Server</title>{_PAGE_STYLE}</head>
<body>
<div class="wrap" style="max-width:400px; margin-top:100px;">
<div class="card">
<h1>⚡ EADMT4-PRO Admin</h1>
<p style="color:#8e9eb5; font-size:13px; margin-bottom:20px;">Digite a senha mestra para gerenciar o servidor.</p>
{err_html}
<form method="post" action="/admin/login">
<input type="password" name="password" placeholder="Senha do Administrador" autofocus required style="margin-bottom:14px;">
<button type="submit" style="width:100%; justify-content:center; padding:12px;">Entrar no Painel</button>
</form>
</div>
</div>
</body></html>"""

def render_dashboard_page(items: list, csrf_token: str, message: str = "") -> str:
    msg_html = f'<div class="err" style="background:#064e3b;color:#34d399;border-color:#059669;">{escape(message)}</div>' if message else ""
    rows_html = ""
    if not items:
        rows_html = '<tr><td colspan="8" style="color:#64748b; text-align:center; padding:30px;">Nenhum cliente conectado ainda.</td></tr>'

    for it in items:
        toggle_label = "Revogar" if it["status_class"] != "revogado" else "Reativar"
        toggle_class = "btn-danger" if it["status_class"] != "revogado" else "btn-ok"

        rows_html += f"""
<tr>
<td class="mono">{escape(it['machine_id'])}</td>
<td style="font-weight:600;">{escape(it['machine_name'])}</td>
<td class="mono">{escape(it['license_key'])}</td>
<td class="mono">{escape(it['hw_fingerprint'])}</td>
<td style="color:#94a3b8;">{escape(it['last_seen'])}</td>
<td><span class="tag {escape(it['status_class'])}">{escape(it['status'])}</span></td>
<td style="color:#94a3b8;">{escape(it['license_expires'])}</td>
<td>
<form method="post" action="/admin/license/toggle-revoke" style="margin:0;">
<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
<input type="hidden" name="machine_id" value="{escape(it['machine_id'])}">
<button type="submit" class="{toggle_class}">{toggle_label}</button>
</form>
</td>
</tr>"""

    return f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="utf-8"><title>Dashboard - EADMT4 Pro Server</title>{_PAGE_STYLE}</head>
<body>
<div class="wrap">
<div class="card">
<div class="topbar">
<h1>⚡ EADMT4-PRO &mdash; Licenças dos Clientes</h1>
<div>
<a href="/admin/keys">🔑 Gerenciar Chaves PRO</a>
<a href="/admin/logout" style="color:#ff3b56;">🚪 Sair</a>
</div>
</div>
{msg_html}
<table>
<thead><tr>
<th>Machine ID</th><th>Nome do Trader</th><th>Chave Ativa</th><th>HW Fingerprint</th>
<th>Último Ping</th><th>Status</th><th>Expira em</th><th>Ação</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div>

<!-- BLOCO DE SEGURANÇA: RESET GERAL DO BANCO -->
<div class="card" style="border-color:#7f1d1d; background:#181017;">
<div style="display:flex; justify-content:space-between; align-items:center;">
<div>
<h3 style="color:#f87171; margin:0 0 4px 0;">🚨 Zona Perigosa: Reset Geral do Sistema</h3>
<p style="color:#94a3b8; font-size:13px; margin:0;">Apaga todos os clientes cadastrados e todas as chaves geradas. Requer confirmação por senha.</p>
</div>
<button onclick="document.getElementById('resetModal').style.display='flex'" class="btn-danger btn-reset">🗑️ Resetar e Limpar Tudo</button>
</div>
</div>

</div>

<!-- MODAL DE CONFIRMAÇÃO POR SENHA -->
<div id="resetModal" class="modal-bg">
<div class="modal-box">
<h3 style="color:#ff3b56; margin-top:0;">⚠️ Confirmar Exclusão Geral</h3>
<p style="color:#cbd5e1; font-size:13px;">Tem certeza absoluta? Essa ação não pode ser desfeita e vai apagar todos os registros de licença.</p>
<form method="post" action="/admin/reset-database">
<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
<input type="password" name="admin_pwd" placeholder="Digite sua senha de Administrador" required style="margin-bottom:16px;">
<div style="display:flex; justify-content:flex-end; gap:10px;">
<button type="button" onclick="document.getElementById('resetModal').style.display='none'" style="background:#374151;">Cancelar</button>
<button type="submit" class="btn-danger">Confirmar e Limpar</button>
</div>
</form>
</div>
</div>

</body></html>"""

def render_keys_page(keys: list, csrf_token: str, message: str = "") -> str:
    msg_html = f'<div class="err" style="background:#064e3b;color:#34d399;border-color:#059669;">{escape(message)}</div>' if message else ""
    rows_html = ""
    if not keys:
        rows_html = '<tr><td colspan="6" style="color:#64748b; text-align:center; padding:25px;">Nenhuma chave gerada ainda.</td></tr>'

    for k in keys:
        status = "revogada" if k["revoked"] else "ativa"
        tag_class = "revogado" if k["revoked"] else "licenciado"
        toggle_label = "Revogar" if not k["revoked"] else "Reativar"
        toggle_class = "btn-danger" if not k["revoked"] else "btn-ok"

        rows_html += f"""
<tr>
<td class="mono" style="font-size:14px; font-weight:bold; color:#38bdf8;">{escape(k['license_key'])}</td>
<td style="color:#94a3b8;">{escape(k['created'] or '-')}</td>
<td style="color:#94a3b8;">{escape(k['expires'] or 'Sem prazo (Vitalício)')}</td>
<td><span class="tag {tag_class}">{status}</span></td>
<td>{escape(str(k['max_machines'] or 2))} máq.</td>
<td>
<form method="post" action="/admin/keys/toggle-revoke" style="margin:0;">
<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
<input type="hidden" name="license_key" value="{escape(k['license_key'])}">
<button type="submit" class="{toggle_class}">{toggle_label}</button>
</form>
</td>
</tr>"""

    return f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="utf-8"><title>Chaves - EADMT4 Pro Server</title>{_PAGE_STYLE}</head>
<body>
<div class="wrap">
<div class="card">
<div class="topbar">
<h1>🔑 EADMT4-PRO &mdash; Gerador de Chaves de Licença</h1>
<div>
<a href="/admin">👥 Ver Clientes / Licenças</a>
<a href="/admin/logout" style="color:#ff3b56;">🚪 Sair</a>
</div>
</div>
{msg_html}
<form method="post" action="/admin/keygen" style="display:flex; gap:10px; align-items:center; margin-bottom:20px; background:#090e17; padding:14px; border-radius:8px; border:1px solid #1c2a3f;">
<span style="font-size:13px; font-weight:600; color:#8e9eb5;">GERAR NOVA CHAVE:</span>
<input type="number" name="days" min="1" placeholder="Validade em dias (Ex: 30) ou vazio para vitalícia" style="max-width:380px;">
<button type="submit" class="btn-ok">⚡ Gerar Chave Agora</button>
</form>

<table>
<thead><tr><th>Chave da Licença</th><th>Criada em</th><th>Expira em</th><th>Status</th><th>Limite</th><th>Ação</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div>
</div>
</body></html>"""

# ============================================================================
# AUTENTICAÇÃO E SESSÃO ADMIN
# ============================================================================
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
        raise HTTPException(status_code=403, detail="Token CSRF inválido.")
    return session

# ============================================================================
# ROTAS DO PAINEL ADMIN
# ============================================================================
@app.get("/admin/login", response_class=HTMLResponse)
def login_form(): return render_login_page()

@app.post("/admin/login")
def login(request: Request, password: str = Form(...)):
    limited = rate_limiter.is_limited("login", _client_ip(request), LOGIN_MAX_ATTEMPTS)
    if limited:
        return HTMLResponse(render_login_page("Muitas tentativas. Aguarde 1 minuto."), status_code=429)
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        return HTMLResponse(render_login_page("Senha incorreta."))
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
    _ensure_core_tables(conn)
    rows = conn.execute("SELECT * FROM licenses ORDER BY last_seen DESC").fetchall()
    conn.close()
    now = now_utc()

    items = []
    for r_raw in rows:
        r = row_to_dict(r_raw, LICENSE_COLUMNS)
        license_expires = parse_dt(r["license_expires"])

        if r.get("revoked", 0) == 1:
            status, status_class = "revogado", "revogado"
        elif not r.get("license_key"):
            if license_expires and license_expires > now:
                status, status_class = "trial (ativo)", "trial"
            else:
                status, status_class = "trial expirado", "expirado"
        elif license_expires and license_expires > now:
            status, status_class = "pro licenciado", "licenciado"
        else:
            status, status_class = "expirado", "expirado"

        fp = (r.get("hardware_fingerprint") or "").strip()
        items.append({
            "machine_id": r["machine_id"],
            "machine_name": r["machine_name"] or "(sem nome)",
            "license_key": r["license_key"] or "(trial gratuito)",
            "last_seen": (r["last_seen"] or "")[:16].replace("T", " "),
            "status": status,
            "status_class": status_class,
            "license_expires": license_expires.strftime("%d/%m/%Y %H:%M") if license_expires else "-",
            "hw_fingerprint": fp[:12] + "…" if fp else "-",
        })

    return HTMLResponse(render_dashboard_page(items, session.get("csrf", "")))

@app.post("/admin/license/toggle-revoke")
def toggle_license_revoke(machine_id: str = Form(...), session=Depends(require_admin_csrf)):
    conn = get_db()
    row = row_to_dict(conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (machine_id,)).fetchone(), LICENSE_COLUMNS)
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Máquina não encontrada.")
    new_value = 0 if row["revoked"] else 1
    conn.execute("UPDATE licenses SET revoked = ? WHERE machine_id = ?", (new_value, machine_id))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)

@app.get("/admin/keys", response_class=HTMLResponse)
def list_keys(nova: str = "", session=Depends(require_admin)):
    conn = get_db()
    _ensure_core_tables(conn)
    rows = conn.execute("SELECT * FROM license_keys ORDER BY created DESC").fetchall()
    conn.close()
    keys = [row_to_dict(r, KEY_COLUMNS) for r in rows]
    message = f"✅ Nova chave PRO gerada com sucesso: {nova}" if nova else ""
    return HTMLResponse(render_keys_page(keys, session.get("csrf", ""), message=message))

@app.post("/admin/keygen")
def keygen(days: Optional[int] = Form(None), session=Depends(require_admin_csrf)):
    conn = get_db()
    _ensure_core_tables(conn)
    new_key = generate_key()
    for _ in range(5):
        exists = conn.execute("SELECT 1 FROM license_keys WHERE license_key = ?", (new_key,)).fetchone()
        if not exists: break
        new_key = generate_key()

    expires_iso = None
    if days and days > 0:
        expires_iso = (now_utc() + timedelta(days=days)).isoformat()

    conn.execute("""
        INSERT INTO license_keys (license_key, created, expires, revoked, max_machines) VALUES (?, ?, ?, 0, ?)
    """, (new_key, now_utc().isoformat(), expires_iso, MAX_MACHINES_PER_KEY))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/admin/keys?nova={new_key}", status_code=303)

@app.post("/admin/keys/toggle-revoke")
def toggle_key_revoke(license_key: str = Form(...), session=Depends(require_admin_csrf)):
    conn = get_db()
    row = row_to_dict(conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (license_key,)).fetchone(), KEY_COLUMNS)
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Chave não encontrada.")
    new_value = 0 if row["revoked"] else 1
    conn.execute("UPDATE license_keys SET revoked = ? WHERE license_key = ?", (new_value, license_key))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/keys", status_code=303)

# ============================================================================
# BOTÃO DE RESET TOTAL DO BANCO (COM CONFIRMAÇÃO POR SENHA)
# ============================================================================
@app.post("/admin/reset-database")
def reset_database(admin_pwd: str = Form(...), session=Depends(require_admin_csrf)):
    # Valida se a senha digitada no modal bate com a senha do Admin
    if not hmac.compare_digest(admin_pwd, ADMIN_PASSWORD):
        return HTMLResponse(render_dashboard_page([], session.get("csrf", ""), "❌ Senha incorreta! O banco não foi alterado."), status_code=403)
    
    conn = get_db()
    _ensure_core_tables(conn)
    try:
        conn.execute("DELETE FROM licenses")
        conn.execute("DELETE FROM license_keys")
        conn.commit()
        conn.close()
        return RedirectResponse(url="/admin", status_code=303)
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"service": "EADMT4-PRO License Server", "status": "online", "trial_days": TRIAL_DAYS}
