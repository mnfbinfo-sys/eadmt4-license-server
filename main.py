#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EADMT4-PRO License Server v3.5 (Recuperação e Ativação Estável)
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
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Variável {name} não definida.")
    return val

TURSO_DATABASE_URL = _require_env("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = _require_env("TURSO_AUTH_TOKEN")
ADMIN_PASSWORD = _require_env("ADMIN_PASSWORD")
SECRET_KEY = _require_env("SECRET_KEY")
HEARTBEAT_SECRET = _require_env("HEARTBEAT_SECRET")

TRIAL_DAYS = 3
LICENSE_DAYS = 30
MAX_MACHINES_PER_KEY = 2

app = FastAPI(title="EADMT4-PRO License Server")
serializer = URLSafeSerializer(SECRET_KEY, salt="admin-session")

def get_db():
    return libsql.connect(TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def generate_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    part = lambda: "".join(secrets.choice(alphabet) for _ in range(4))
    return f"EAD-{part()}-{part()}-{part()}"

def sign_heartbeat(status: str, machine_id: str, timestamp: int) -> str:
    payload = f"{status}|{machine_id}|{timestamp}"
    return hmac.new(HEARTBEAT_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()

def make_response(status: str, machine_id: str, days_left: int = 0, expires_at: str = None) -> dict:
    ts = int(time.time())
    sig = sign_heartbeat(status, machine_id, ts)
    return {
        "status": status,
        "expires_at": expires_at,
        "days_left": days_left,
        "timestamp": ts,
        "sig": sig
    }

@app.on_event("startup")
def init_tables():
    try:
        conn = get_db()
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
                max_machines INTEGER DEFAULT 2
            )
        """)
        try: conn.commit()
        except: pass
        conn.close()
        print("[DB] Tabelas prontas.")
    except Exception as e:
        print(f"[DB INIT ERROR] {e}")

class CheckPayload(BaseModel):
    machine_id: str
    machine_name: Optional[str] = ""
    license_key: Optional[str] = ""
    hardware_fingerprint: Optional[str] = ""

@app.post("/api/check")
def check_license(payload: CheckPayload):
    conn = None
    try:
        conn = get_db()
        m_id = str(payload.machine_id).strip()
        m_name = str(payload.machine_name or "PC-Trader").strip()
        hw_fp = str(payload.hardware_fingerprint or "").strip()
        key = str(payload.license_key or "").strip().upper()
        now_ts = int(time.time())

        # 1. VERIFICAR SE O CLIENTE JÁ EXISTE NO BANCO
        row = conn.execute("SELECT machine_id, revoked, license_key, license_expires FROM licenses WHERE machine_id = ?", (m_id,)).fetchone()
        
        # 2. SE ENVIOU UMA CHAVE PRO PARA ATIVAR
        if key:
            key_data = conn.execute("SELECT license_key, expires, revoked, max_machines FROM license_keys WHERE license_key = ?", (key,)).fetchone()
            
            if not key_data:
                conn.close()
                return make_response("key_invalid", m_id)
            
            if key_data[2] == 1:
                conn.close()
                return make_response("key_revoked", m_id)

            # Verifica limite de máquinas
            usage = conn.execute("SELECT COUNT(*) FROM licenses WHERE license_key = ? AND machine_id != ? AND revoked = 0", (key, m_id)).fetchone()[0]
            max_m = key_data[3] or MAX_MACHINES_PER_KEY
            if usage >= max_m:
                conn.close()
                return make_response("limit", m_id)

            # Define expiração da chave
            exp_str = key_data[1] or "2099-12-31T23:59:59+00:00"
            days_left = 9999
            if key_data[1]:
                try:
                    dt = datetime.fromisoformat(key_data[1].replace("Z", "+00:00"))
                    diff = (dt - datetime.now(timezone.utc)).total_seconds()
                    days_left = max(0, int(diff // 86400))
                except:
                    pass

            # Salva / Atualiza o cliente como PRO
            if row:
                conn.execute("""
                    UPDATE licenses 
                    SET last_seen = ?, machine_name = ?, license_key = ?, license_expires = ?, revoked = 0, hardware_fingerprint = ?
                    WHERE machine_id = ?
                """, (now_utc_iso(), m_name, key, exp_str, hw_fp, m_id))
            else:
                conn.execute("""
                    INSERT INTO licenses (machine_id, machine_name, first_seen, license_expires, last_seen, revoked, license_key, hardware_fingerprint)
                    VALUES (?, ?, ?, ?, ?, 0, ?, ?)
                """, (m_id, m_name, now_utc_iso(), exp_str, now_utc_iso(), key, hw_fp))

            try: conn.commit()
            except: pass
            conn.close()
            return make_response("licensed", m_id, days_left=days_left, expires_at=exp_str)

        # 3. CONSULTA SEM CHAVE (TRIAL OU JÁ ATIVADO ANTERIORMENTE)
        if row:
            is_revoked = row[1]
            saved_key = row[2]
            saved_exp = row[3]

            if is_revoked == 1:
                conn.close()
                return make_response("revoked", m_id)

            # Se já tem chave PRO salva no banco
            if saved_key:
                conn.execute("UPDATE licenses SET last_seen = ? WHERE machine_id = ?", (now_utc_iso(), m_id))
                try: conn.commit()
                except: pass
                conn.close()
                return make_response("licensed", m_id, days_left=9999, expires_at=saved_exp)

            # Se está em Trial
            conn.execute("UPDATE licenses SET last_seen = ? WHERE machine_id = ?", (now_utc_iso(), m_id))
            try: conn.commit()
            except: pass
            conn.close()

            # Checa se o trial venceu
            days_left = 0
            if saved_exp:
                try:
                    dt = datetime.fromisoformat(saved_exp.replace("Z", "+00:00"))
                    diff = (dt - datetime.now(timezone.utc)).total_seconds()
                    days_left = max(0, int(diff // 86400))
                    if diff > 0:
                        return make_response("trial", m_id, days_left=days_left, expires_at=saved_exp)
                except:
                    pass

            return make_response("trial_expired", m_id)

        # 4. PRIMEIRO ACESSO (CRIA NOVO TRIAL DE 3 DIAS)
        trial_dt = datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)
        trial_iso = trial_dt.isoformat()
        
        conn.execute("""
            INSERT INTO licenses (machine_id, machine_name, first_seen, license_expires, last_seen, revoked, license_key, hardware_fingerprint)
            VALUES (?, ?, ?, ?, ?, 0, '', ?)
        """, (m_id, m_name, now_utc_iso(), trial_iso, now_utc_iso(), hw_fp))
        
        try: conn.commit()
        except: pass
        conn.close()
        return make_response("trial", m_id, days_left=TRIAL_DAYS, expires_at=trial_iso)

    except Exception as e:
        traceback.print_exc()
        if conn:
            try: conn.close()
            except: pass
        return JSONResponse(status_code=200, content={
            "status": "error",
            "error": str(e),
            "machine_id": payload.machine_id
        })

# ============================================================================
# PAINEL ADMINISTRATIVO
# ============================================================================
_STYLE = """<style>
body{background:#0b121e;color:#fff;font-family:sans-serif;margin:30px;}
.card{background:#131d2e;padding:24px;border-radius:10px;border:1px solid #1e2c42;max-width:1100px;margin:auto;}
table{width:100%;border-collapse:collapse;margin-top:16px;font-size:13px;}
th,td{padding:10px;border-bottom:1px solid #1e2c42;text-align:left;}
th{color:#8e9eb5;}
input{background:#090e17;color:#fff;border:1px solid #1e2c42;padding:8px 12px;border-radius:6px;}
button,.btn{background:#00b0ff;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;text-decoration:none;font-weight:600;}
.btn-ok{background:#00e676;color:#000;}
.btn-danger{background:#ff3b56;}
.tag{padding:3px 8px;border-radius:12px;font-size:11px;font-weight:700;}
.tag-ok{background:#064e3b;color:#34d399;}
.tag-trial{background:#1e3a8a;color:#60a5fa;}
.tag-rev{background:#7f1d1d;color:#f87171;}
</style>"""

def require_admin(request: Request):
    tok = request.cookies.get("admin_session")
    if tok:
        try:
            if serializer.loads(tok).get("ok"): return True
        except: pass
    raise HTTPException(status_code=303, headers={"Location": "/admin/login"})

@app.get("/admin/login", response_class=HTMLResponse)
def login_page():
    return f"""<html><head>{_STYLE}</head><body><div class="card" style="max-width:350px;margin-top:100px;">
    <h2>⚡ Login EADMT4 Pro</h2>
    <form method="post" action="/admin/login">
    <input type="password" name="pwd" placeholder="Senha Mestra" style="width:100%;margin-bottom:12px;" required>
    <button type="submit" style="width:100%;">Entrar</button>
    </form></div></body></html>"""

@app.post("/admin/login")
def do_login(pwd: str = Form(...)):
    if not hmac.compare_digest(pwd, ADMIN_PASSWORD):
        return HTMLResponse("Senha incorreta!", status_code=403)
    resp = RedirectResponse(url="/admin", status_code=303)
    resp.set_cookie("admin_session", serializer.dumps({"ok": True}), httponly=True, max_age=3600*12)
    return resp

@app.get("/admin/logout")
def logout():
    r = RedirectResponse("/admin/login", status_code=303)
    r.delete_cookie("admin_session")
    return r

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(auth=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute("SELECT machine_id, machine_name, license_key, last_seen, revoked, license_expires FROM licenses ORDER BY last_seen DESC").fetchall()
    conn.close()

    tr = ""
    for r in rows:
        tag = '<span class="tag tag-rev">REVOGADO</span>' if r[4] else ('<span class="tag tag-ok">PRO</span>' if r[2] else '<span class="tag tag-trial">TRIAL</span>')
        tr += f"<tr><td><code>{r[0][:16]}...</code></td><td>{escape(r[1] or '-')}</td><td><b>{escape(r[2] or '-')}</b></td><td>{r[3][:16]}</td><td>{tag}</td><td>{r[5][:16] if r[5] else 'Vitalício'}</td></tr>"

    return f"""<html><head>{_STYLE}</head><body><div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;">
    <h2>⚡ Clientes Conectados</h2>
    <div><a href="/admin/keys" class="btn">🔑 Chaves de Licença</a> <a href="/admin/logout" style="color:#ff3b56;margin-left:14px;">Sair</a></div>
    </div>
    <table><tr><th>Machine ID</th><th>Nome</th><th>Chave</th><th>Último Visto</th><th>Status</th><th>Expira</th></tr>{tr}</table>
    </div></body></html>"""

@app.get("/admin/keys", response_class=HTMLResponse)
def admin_keys(nova: str = "", auth=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute("SELECT license_key, created, expires, revoked FROM license_keys ORDER BY created DESC").fetchall()
    conn.close()

    tr = ""
    for r in rows:
        status = '<span class="tag tag-rev">REVOGADA</span>' if r[3] else '<span class="tag tag-ok">ATIVA</span>'
        tr += f"<tr><td><b>{r[0]}</b></td><td>{r[1][:16] if r[1] else '-'}</td><td>{r[2][:16] if r[2] else 'Vitalício'}</td><td>{status}</td></tr>"

    msg = f'<div style="background:#064e3b;padding:10px;border-radius:6px;margin-bottom:12px;">✅ Nova Chave: <b>{nova}</b></div>' if nova else ""
    return f"""<html><head>{_STYLE}</head><body><div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;">
    <h2>🔑 Gerador de Chaves de Licença</h2>
    <div><a href="/admin" class="btn">👥 Ver Clientes</a> <a href="/admin/logout" style="color:#ff3b56;margin-left:14px;">Sair</a></div>
    </div>
    {msg}
    <form method="post" action="/admin/keygen" style="display:flex;gap:10px;margin:16px 0;">
    <input type="number" name="days" placeholder="Dias de validade (vazio = vitalícia)" style="width:300px;">
    <button type="submit" class="btn-ok">⚡ Gerar Chave</button>
    </form>
    <table><tr><th>Chave</th><th>Criada em</th><th>Expira</th><th>Status</th></tr>{tr}</table>
    </div></body></html>"""

@app.post("/admin/keygen")
def admin_keygen(days: Optional[int] = Form(None), auth=Depends(require_admin)):
    conn = get_db()
    k = generate_key()
    exp = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat() if days and days > 0 else None
    conn.execute("INSERT INTO license_keys (license_key, created, expires, revoked, max_machines) VALUES (?, ?, ?, 0, 2)",
                 (k, now_utc_iso(), exp))
    try: conn.commit()
    except: pass
    conn.close()
    return RedirectResponse(f"/admin/keys?nova={k}", status_code=303)

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"service": "EADMT4-PRO", "status": "online"}
