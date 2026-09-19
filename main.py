#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EADMT4-PRO License Server v3.1 (Correção Datetime Timezone + LibSQL Turso
                                 + restauração da migração defensiva de colunas)
"""
import asyncio
import hashlib
import hmac
import os
import secrets
import string
import time
import traceback
import libsql
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Optional, Dict, List
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from itsdangerous import URLSafeSerializer, BadSignature
from pydantic import BaseModel, Field

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

serializer = URLSafeSerializer(SECRET_KEY, salt="admin-session")
app = FastAPI(title="EADMT4-PRO License Server")

@app.middleware("http")
async def _security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

@app.on_event("startup")
async def _on_startup():
    async def cleanup_loop():
        while True:
            await asyncio.sleep(6 * 60 * 60)
            rate_limiter.cleanup()
    asyncio.create_task(cleanup_loop())
    try:
        conn = get_db()
        _ensure_core_tables(conn)
        conn.close()
        print("[DATABASE] Tabelas verificadas/migradas com sucesso na inicialização.")
    except Exception as e:
        print(f"[DATABASE INIT ERROR] {e}")

LICENSE_COLUMNS = ["machine_id", "machine_name", "first_seen", "license_expires", "last_seen", "revoked", "license_key", "hardware_fingerprint"]
KEY_COLUMNS = ["license_key", "created", "expires", "revoked", "max_machines"]

def _safe_add_column(conn, table: str, column: str, coltype: str):
    """Adiciona uma coluna a uma tabela já existente, se ela ainda não existir.
    Necessário porque 'CREATE TABLE IF NOT EXISTS' NUNCA altera uma tabela que
    já existe - então um banco criado por uma versão antiga deste script, sem
    uma coluna nova (ex.: hardware_fingerprint ou max_machines), continuaria
    sem ela para sempre, e todo INSERT/UPDATE que citasse essa coluna quebraria
    a rota /api/check com um 500 - que o app cliente confunde com licença
    expirada/inválida em vez de mostrar o erro real.
    """
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
        try:
            conn.commit()
        except Exception:
            pass
        print(f"[DATABASE] Coluna '{column}' adicionada à tabela '{table}'.")
    except Exception:
        # Coluna já existe (caso mais comum) ou outro erro não crítico - ignora.
        pass

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
        conn.commit()
    except Exception:
        pass

    # Migração defensiva: garante que bancos criados por versões antigas
    # ganhem as colunas novas em vez de quebrar o /api/check silenciosamente.
    _safe_add_column(conn, "licenses", "hardware_fingerprint", "TEXT")
    _safe_add_column(conn, "license_keys", "max_machines", "INTEGER DEFAULT 2")

def get_db():
    return libsql.connect(TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)

def row_to_dict(row, columns):
    if not row: return None
    return dict(zip(columns, row))

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def parse_dt(s) -> Optional[datetime]:
    if not s: return None
    try:
        clean = str(s).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def generate_key() -> str:
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

class CheckRequest(BaseModel):
    machine_id: str = Field(..., min_length=1, max_length=128)
    machine_name: str = Field("", max_length=128)
    license_key: str = Field("", max_length=64)
    hardware_fingerprint: str = Field("", max_length=128)

@app.post("/api/check")
def check_license(request: Request, payload: CheckRequest):
    try:
        if rate_limiter.is_limited("check", _client_ip(request), CHECK_MAX_REQUESTS):
            return signed_response("error", payload.machine_id)

        conn = get_db()
        _ensure_core_tables(conn)
        now = now_utc()
        key = (payload.license_key or "").strip().upper()
        key_row = None

        if key:
            try:
                res = conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (key,)).fetchone()
                key_row = row_to_dict(res, KEY_COLUMNS)
            except Exception as e:
                print(f"[SQL ERROR KEY] {e}")

        row = None
        try:
            res_m = conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (payload.machine_id,)).fetchone()
            row = row_to_dict(res_m, LICENSE_COLUMNS)
        except Exception as e:
            print(f"[SQL ERROR LICENSE] {e}")

        # 1. Chave PRO Válida
        if key and key_row and not key_row.get("revoked", 0):
            kexp = parse_dt(key_row.get("expires"))
            
            is_valid = False
            days_left = 9999
            if kexp is None:
                is_valid = True
            else:
                diff_seconds = (kexp - now).total_seconds()
                if diff_seconds > 0:
                    is_valid = True
                    days_left = max(0, int(diff_seconds // 86400))

            if is_valid:
                if row is None:
                    count = conn.execute("SELECT COUNT(*) FROM licenses WHERE license_key = ? AND revoked = 0", (key,)).fetchone()[0]
                    if count >= int(key_row.get("max_machines") or MAX_MACHINES_PER_KEY):
                        conn.close()
                        return signed_response("limit", payload.machine_id)

                    conn.execute("""
                        INSERT INTO licenses (machine_id, machine_name, first_seen, license_expires, last_seen, revoked, license_key, hardware_fingerprint)
                        VALUES (?, ?, ?, ?, ?, 0, ?, ?)
                    """, (payload.machine_id, payload.machine_name, now.isoformat(), kexp.isoformat() if kexp else None, now.isoformat(), key, payload.hardware_fingerprint))
                    try: conn.commit()
                    except Exception: pass
                    conn.close()
                    return signed_response("licensed", payload.machine_id, kexp, days_left)

                conn.execute("""
                    UPDATE licenses SET last_seen = ?, machine_name = ?, license_key = ?, license_expires = ?, revoked = 0,
                    hardware_fingerprint = COALESCE(NULLIF(?, ''), hardware_fingerprint) WHERE machine_id = ?
                """, (now.isoformat(), payload.machine_name or row.get("machine_name"), key, kexp.isoformat() if kexp else None, payload.hardware_fingerprint, payload.machine_id))
                try: conn.commit()
                except Exception: pass
                conn.close()
                return signed_response("licensed", payload.machine_id, kexp, days_left)

        # 2. NOVO CLIENTE -> CRIA TRIAL DE 3 DIAS
        trial_expires = now + timedelta(days=TRIAL_DAYS)

        if row is None:
            conn.execute("""
                INSERT INTO licenses (machine_id, machine_name, first_seen, license_expires, last_seen, revoked, license_key, hardware_fingerprint)
                VALUES (?, ?, ?, ?, ?, 0, NULL, ?)
            """, (payload.machine_id, payload.machine_name, now.isoformat(), trial_expires.isoformat(), now.isoformat(), payload.hardware_fingerprint))
            try: conn.commit()
            except Exception: pass
            conn.close()
            return signed_response("trial", payload.machine_id, trial_expires, TRIAL_DAYS)

        # 3. MÁQUINA JÁ EXISTE
        if row.get("revoked", 0) == 1:
            conn.close()
            return signed_response("revoked", payload.machine_id)

        existing_expires = parse_dt(row.get("license_expires"))
        if existing_expires and (existing_expires - now).total_seconds() > 0 and not row.get("license_key"):
            days_left = max(0, int((existing_expires - now).total_seconds() // 86400))
            conn.execute("""
                UPDATE licenses SET last_seen = ?, machine_name = ?, hardware_fingerprint = COALESCE(NULLIF(?, ''), hardware_fingerprint)
                WHERE machine_id = ?
            """, (now.isoformat(), payload.machine_name or row.get("machine_name"), payload.hardware_fingerprint, payload.machine_id))
            try: conn.commit()
            except Exception: pass
            conn.close()
            return signed_response("trial", payload.machine_id, existing_expires, days_left)

        # Se tiver chave vinculada na máquina, mas expirou
        if row.get("license_key"):
            conn.close()
            return signed_response("expired", payload.machine_id)

        # Trial expirou
        conn.execute("UPDATE licenses SET last_seen = ? WHERE machine_id = ?", (now.isoformat(), payload.machine_id))
        try: conn.commit()
        except Exception: pass
        conn.close()
        return signed_response("trial_expired", payload.machine_id)

    except Exception as e:
        print("[ERRO FATAL NA ROTA /api/check]:")
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"status": "error", "error": str(e), "trace": traceback.format_exc()})

# ============================================================================
# ESTILOS E INTERFACE DO PAINEL WEB
# ============================================================================
_PAGE_STYLE = """
<style>
* { box-sizing: border-box; }
body { background: #0b121e; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 0; }
.wrap { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
.card { background: #131d2e; border: 1px solid #1e2c42; border-radius: 12px; padding: 24px; box-shadow: 0 8px 30px rgba(0,0,0,0.4); margin-bottom: 24px; }
h1 { font-size: 20px; font-weight: 700; color: #fff; margin: 0 0 16px 0; display: flex; align-items: center; gap: 8px; }
input[type=password], input[type=text], input[type=number] {
  width: 100%; padding: 10px 14px; border-radius: 6px; border: 1px solid #22354d;
  background: #090e17; color: #fff; font-size: 14px; outline: none;
}
button, .btn {
  background: #00b0ff; color: #fff; border: none; padding: 9px 16px; border-radius: 6px;
  font-size: 13px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px;
}
button:hover, .btn:hover { opacity: 0.9; }
.btn-danger { background: #ff3b56; }
.btn-ok { background: #00e676; color: #000; }
.topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #1e2c42; padding-bottom: 14px; }
.topbar a { color: #8e9eb5; text-decoration: none; font-size: 14px; margin-left: 18px; font-weight: 500; }
table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #1c2a3f; }
th { color: #8e9eb5; font-weight: 600; text-transform: uppercase; font-size: 11px; }
tr:hover { background: #162438; }
.tag { padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
.tag.licenciado { background: #064e3b; color: #34d399; }
.tag.trial { background: #1e3a8a; color: #60a5fa; }
.tag.revogado { background: #7f1d1d; color: #f87171; }
.tag.expirado { background: #374151; color: #9ca3af; }
.mono { font-family: Consolas, monospace; font-size: 12px; color: #cbd5e1; }
.err { background: #450a0a; color: #fca5a5; padding: 12px; border-radius: 6px; margin-bottom: 16px; }
.modal-bg { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.75); z-index: 999; align-items: center; justify-content: center; }
.modal-box { background: #131d2e; border: 1px solid #ff3b56; border-radius: 12px; padding: 28px; width: 440px; }
</style>
"""

def render_login_page(error: str = "") -> str:
    err_html = f'<div class="err">{escape(error)}</div>' if error else ""
    return f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="utf-8"><title>Login - EADMT4 Pro</title>{_PAGE_STYLE}</head>
<body><div class="wrap" style="max-width:400px; margin-top:100px;"><div class="card">
<h1>⚡ EADMT4-PRO Admin</h1><p style="color:#8e9eb5; font-size:13px;">Digite a senha mestra de administração:</p>
{err_html}
<form method="post" action="/admin/login">
<input type="password" name="password" placeholder="Senha do Administrador" autofocus required style="margin-bottom:14px;">
<button type="submit" style="width:100%; justify-content:center; padding:12px;">Entrar no Painel</button>
</form></div></div></body></html>"""

def render_dashboard_page(items: list, message: str = "") -> str:
    msg_html = f'<div class="err" style="background:#064e3b;color:#34d399;">{escape(message)}</div>' if message else ""
    rows_html = ""
    if not items:
        rows_html = '<tr><td colspan="8" style="color:#64748b; text-align:center; padding:30px;">Nenhum cliente conectado ainda.</td></tr>'

    for it in items:
        toggle_label = "Revogar" if it["status_class"] != "revogado" else "Reativar"
        toggle_class = "btn-danger" if it["status_class"] != "revogado" else "btn-ok"
        rows_html += f"""<tr>
<td class="mono">{escape(it['machine_id'])}</td><td>{escape(it['machine_name'])}</td>
<td class="mono">{escape(it['license_key'])}</td><td class="mono">{escape(it['hw_fingerprint'])}</td>
<td style="color:#94a3b8;">{escape(it['last_seen'])}</td><td><span class="tag {escape(it['status_class'])}">{escape(it['status'])}</span></td>
<td style="color:#94a3b8;">{escape(it['license_expires'])}</td>
<td><form method="post" action="/admin/license/toggle-revoke" style="margin:0;">
<input type="hidden" name="machine_id" value="{escape(it['machine_id'])}">
<button type="submit" class="{toggle_class}">{toggle_label}</button></form></td></tr>"""

    return f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="utf-8"><title>Dashboard - EADMT4 Pro</title>{_PAGE_STYLE}</head>
<body><div class="wrap"><div class="card"><div class="topbar">
<h1>⚡ EADMT4-PRO &mdash; Licenças dos Clientes</h1>
<div><a href="/admin/keys">🔑 Gerenciar Chaves PRO</a><a href="/admin/logout" style="color:#ff3b56;">🚪 Sair</a></div>
</div>{msg_html}
<table><thead><tr><th>Machine ID</th><th>Nome do Trader</th><th>Chave Ativa</th><th>HW Fingerprint</th><th>Último Ping</th><th>Status</th><th>Expira em</th><th>Ação</th></tr></thead>
<tbody>{rows_html}</tbody></table></div>

<div class="card" style="border-color:#7f1d1d; background:#181017; display:flex; justify-content:space-between; align-items:center;">
<div><h3 style="color:#f87171; margin:0 0 4px 0;">🚨 Zona Perigosa: Reset Geral</h3><p style="color:#94a3b8; font-size:13px; margin:0;">Apaga todas as licenças e chaves do banco de dados.</p></div>
<button onclick="document.getElementById('resetModal').style.display='flex'" class="btn-danger">🗑️ Resetar Tudo</button>
</div></div>

<div id="resetModal" class="modal-bg"><div class="modal-box">
<h3 style="color:#ff3b56; margin-top:0;">⚠️ Confirmar Reset Geral</h3>
<p style="color:#cbd5e1; font-size:13px;">Digite sua senha de administrador para confirmar a limpeza total:</p>
<form method="post" action="/admin/reset-database">
<input type="password" name="admin_pwd" placeholder="Senha do Administrador" required style="margin-bottom:16px;">
<div style="display:flex; justify-content:flex-end; gap:10px;">
<button type="button" onclick="document.getElementById('resetModal').style.display='none'" style="background:#374151;">Cancelar</button>
<button type="submit" class="btn-danger">Confirmar</button>
</div></form></div></div></body></html>"""

def render_keys_page(keys: list, message: str = "") -> str:
    msg_html = f'<div class="err" style="background:#064e3b;color:#34d399;">{escape(message)}</div>' if message else ""
    rows_html = ""
    if not keys:
        rows_html = '<tr><td colspan="6" style="color:#64748b; text-align:center; padding:25px;">Nenhuma chave gerada ainda.</td></tr>'

    for k in keys:
        status = "revogada" if k["revoked"] else "ativa"
        tag_class = "revogado" if k["revoked"] else "licenciado"
        toggle_label = "Revogar" if not k["revoked"] else "Reativar"
        toggle_class = "btn-danger" if not k["revoked"] else "btn-ok"
        rows_html += f"""<tr>
<td class="mono" style="font-size:14px; font-weight:bold; color:#38bdf8;">{escape(k['license_key'])}</td>
<td style="color:#94a3b8;">{escape(k['created'] or '-')}</td><td style="color:#94a3b8;">{escape(k['expires'] or 'Vitalício')}</td>
<td><span class="tag {tag_class}">{status}</span></td><td>{escape(str(k['max_machines'] or 2))} máq.</td>
<td><form method="post" action="/admin/keys/toggle-revoke" style="margin:0;">
<input type="hidden" name="license_key" value="{escape(k['license_key'])}">
<button type="submit" class="{toggle_class}">{toggle_label}</button></form></td></tr>"""

    return f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="utf-8"><title>Chaves - EADMT4 Pro</title>{_PAGE_STYLE}</head>
<body><div class="wrap"><div class="card"><div class="topbar">
<h1>🔑 EADMT4-PRO &mdash; Gerador de Chaves de Licença</h1>
<div><a href="/admin">👥 Ver Clientes</a><a href="/admin/logout" style="color:#ff3b56;">🚪 Sair</a></div>
</div>{msg_html}
<form method="post" action="/admin/keygen" style="display:flex; gap:10px; align-items:center; margin-bottom:20px; background:#090e17; padding:14px; border-radius:8px;">
<span style="font-size:13px; font-weight:600; color:#8e9eb5;">GERAR NOVA CHAVE:</span>
<input type="number" name="days" min="1" placeholder="Validade em dias (Ex: 30) ou vazio para vitalícia" style="max-width:380px;">
<button type="submit" class="btn-ok">⚡ Gerar Chave Agora</button>
</form>
<table><thead><tr><th>Chave da Licença</th><th>Criada em</th><th>Expira em</th><th>Status</th><th>Limite</th><th>Ação</th></tr></thead>
<tbody>{rows_html}</tbody></table></div></div></body></html>"""

def require_admin(request: Request) -> dict:
    token = request.cookies.get("admin_session")
    if token:
        try:
            data = serializer.loads(token)
            if data.get("ok"): return data
        except BadSignature: pass
    raise HTTPException(status_code=303, headers={"Location": "/admin/login"})

@app.get("/admin/login", response_class=HTMLResponse)
def login_form(): return render_login_page()

@app.post("/admin/login")
def login(request: Request, password: str = Form(...)):
    limited = rate_limiter.is_limited("login", _client_ip(request), LOGIN_MAX_ATTEMPTS)
    if limited:
        return HTMLResponse(render_login_page("Muitas tentativas. Aguarde 1 minuto."), status_code=429)
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        return HTMLResponse(render_login_page("Senha incorreta."))
    token = serializer.dumps({"ok": True})
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
        license_expires = parse_dt(r.get("license_expires"))

        if r.get("revoked", 0) == 1:
            status, status_class = "revogado", "revogado"
        elif not r.get("license_key"):
            if license_expires and (license_expires - now).total_seconds() > 0:
                status, status_class = "trial (ativo)", "trial"
            else:
                status, status_class = "trial expirado", "expirado"
        elif license_expires and (license_expires - now).total_seconds() > 0:
            status, status_class = "pro licenciado", "licenciado"
        elif license_expires is None and r.get("license_key"):
            status, status_class = "pro vitalício", "licenciado"
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
            "license_expires": license_expires.strftime("%d/%m/%Y %H:%M") if license_expires else "Vitalício",
            "hw_fingerprint": fp[:12] + "…" if fp else "-",
        })

    return HTMLResponse(render_dashboard_page(items))

@app.post("/admin/license/toggle-revoke")
def toggle_license_revoke(machine_id: str = Form(...), session=Depends(require_admin)):
    conn = get_db()
    row = row_to_dict(conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (machine_id,)).fetchone(), LICENSE_COLUMNS)
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Máquina não encontrada.")
    new_value = 0 if row["revoked"] else 1
    conn.execute("UPDATE licenses SET revoked = ? WHERE machine_id = ?", (new_value, machine_id))
    try: conn.commit()
    except Exception: pass
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)

@app.get("/admin/keys", response_class=HTMLResponse)
def list_keys(nova: str = "", session=Depends(require_admin)):
    conn = get_db()
    _ensure_core_tables(conn)
    rows = conn.execute("SELECT * FROM license_keys ORDER BY created DESC").fetchall()
    conn.close()
    keys = [row_to_dict(r, KEY_COLUMNS) for r in rows]
    message = f"✅ Nova chave PRO gerada: {nova}" if nova else ""
    return HTMLResponse(render_keys_page(keys, message=message))

@app.post("/admin/keygen")
def keygen(days: Optional[int] = Form(None), session=Depends(require_admin)):
    conn = get_db()
    _ensure_core_tables(conn)
    new_key = generate_key()
    expires_iso = (now_utc() + timedelta(days=days)).isoformat() if days and days > 0 else None
    conn.execute("""
        INSERT INTO license_keys (license_key, created, expires, revoked, max_machines) VALUES (?, ?, ?, 0, ?)
    """, (new_key, now_utc().isoformat(), expires_iso, MAX_MACHINES_PER_KEY))
    try: conn.commit()
    except Exception: pass
    conn.close()
    return RedirectResponse(url=f"/admin/keys?nova={new_key}", status_code=303)

@app.post("/admin/keys/toggle-revoke")
def toggle_key_revoke(license_key: str = Form(...), session=Depends(require_admin)):
    conn = get_db()
    row = row_to_dict(conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (license_key,)).fetchone(), KEY_COLUMNS)
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Chave não encontrada.")
    new_value = 0 if row["revoked"] else 1
    conn.execute("UPDATE license_keys SET revoked = ? WHERE license_key = ?", (new_value, license_key))
    try: conn.commit()
    except Exception: pass
    conn.close()
    return RedirectResponse(url="/admin/keys", status_code=303)

@app.post("/admin/reset-database")
def reset_database(admin_pwd: str = Form(...), session=Depends(require_admin)):
    if not hmac.compare_digest(admin_pwd, ADMIN_PASSWORD):
        return HTMLResponse(render_dashboard_page([], "❌ Senha incorreta!"), status_code=403)
    conn = get_db()
    _ensure_core_tables(conn)
    try:
        conn.execute("DELETE FROM licenses")
        conn.execute("DELETE FROM license_keys")
        try: conn.commit()
        except Exception: pass
        conn.close()
        return RedirectResponse(url="/admin", status_code=303)
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"service": "EADMT4-PRO License Server", "status": "online", "trial_days": TRIAL_DAYS}
