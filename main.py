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

# ️ CRÍTICO: Verifique se estas variáveis existem nas configurações do Render
TURSO_DATABASE_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "troque-esta-senha")
SECRET_KEY = os.environ.get("SECRET_KEY", "troque-este-secret-tambem")
HEARTBEAT_SECRET = os.environ.get("HEARTBEAT_SECRET", "troque-este-secret-do-heartbeat")

# ✅ Trial aumentado para 7 dias
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
# ✅ NOVOS CAMPOS PARA CLIENTES
CLIENT_COLUMNS = ["id", "nome", "telefone", "email", "obs", "created"]

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

    if row:
        if row["revoked"]:
            conn.close()
            return signed_response("revoked", payload.machine_id)
        if key_error:
            conn.close()
            return signed_response(key_error, payload.machine_id)
        
        conn.execute("UPDATE licenses SET last_seen = ? WHERE machine_id = ?", (now.isoformat(), payload.machine_id))
        conn.commit()
        
        trial_exp = parse_dt(row["trial_expires"])
        lic_exp = parse_dt(row["license_expires"])
        
        if lic_exp and lic_exp > now:
            days = (lic_exp - now).days
            conn.close()
            return signed_response("licensed", payload.machine_id, lic_exp, days)
        elif trial_exp and trial_exp > now:
            days = (trial_exp - now).days
            conn.close()
            return signed_response("trial", payload.machine_id, trial_exp, days)
        else:
            # ✅ Trial expirou naturalmente
            conn.close()
            return signed_response("trial_expired", payload.machine_id)
    else:
        if key_error:
            conn.close()
            return signed_response(key_error, payload.machine_id)
        
        # ✅ NOVO REGISTRO: Ativa trial de 7 dias automaticamente
        trial_exp = now + timedelta(days=TRIAL_DAYS)
        conn.execute(
            "INSERT INTO licenses (machine_id, machine_name, first_seen, trial_expires, last_seen) VALUES (?, ?, ?, ?, ?)",
            (payload.machine_id, payload.machine_name, now.isoformat(), trial_exp.isoformat(), now.isoformat())
        )
        conn.commit()
        conn.close()
        return signed_response("trial", payload.machine_id, trial_exp, TRIAL_DAYS)

@app.get("/", response_class=HTMLResponse)
def root():
    return {"service": "EADMT4-PRO License Server", "status": "ok"}

PAGE_STYLE = """
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f8; color: #1f2733; }
.header { background: #1f2733; color: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 20px; }
.header .user { font-size: 14px; }
.container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
.card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.card h2 { margin-bottom: 15px; color: #1f2733; font-size: 18px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e4e8ec; }
th { background: #1f2733; color: white; font-weight: 600; }
tr:hover { background: #f9fafb; }
.badge { padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.badge.ativo { background: #d4edda; color: #155724; }
.badge.expirando { background: #fff3cd; color: #856404; }
.badge.expirado { background: #fff3e0; color: #e65100; }
.badge.revogado { background: #f8d7da; color: #721c24; }
.btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-block; margin: 2px; }
.btn-primary { background: #28a745; color: white; }
.btn-danger { background: #dc3545; color: white; }
.btn-warning { background: #ffc107; color: #333; }
.btn-secondary { background: #6c757d; color: white; }
.btn:hover { opacity: 0.9; }
.form-group { margin-bottom: 15px; }
.form-group label { display: block; margin-bottom: 5px; font-weight: 600; }
.form-group input, .form-group select, .form-group textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
.form-group textarea { resize: vertical; min-height: 80px; }
.login-box { max-width: 400px; margin: 100px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
.login-box h2 { margin-bottom: 20px; text-align: center; }
.alert { padding: 12px; border-radius: 4px; margin-bottom: 15px; }
.alert-error { background: #f8d7da; color: #721c24; }
.alert-success { background: #d4edda; color: #155724; }
</style>
"""

def render_login_page(error=""):
    return f"""<!DOCTYPE html>
<html><head><title>Login - EADMT4 Admin</title>{PAGE_STYLE}</head>
<body><div class="login-box">
<h2>🔐 Admin Login</h2>
{f'<div class="alert alert-error">{escape(error)}</div>' if error else ''}
<form method="post" action="/admin/login">
<div class="form-group"><label>Senha</label><input type="password" name="password" required></div>
<button type="submit" class="btn btn-primary" style="width:100%">Entrar</button>
</form></div></body></html>"""

def render_dashboard_page(machines, csrf_token):
    rows = ""
    for i, m in enumerate(machines):
        rows += f"""<tr class="{'even' if i % 2 == 0 else 'odd'}">
<td>{escape(m['machine_id'][:16])}...</td>
<td>{escape(m.get('machine_name', '-'))}</td>
<td>{m['license_expires']}</td>
<td>{m['trial_expires']}</td>
<td><span class="badge {m['status_class']}">{escape(m['status'])}</span></td>
<td>
<form method="post" action="/admin/extend/{escape(m['machine_id'])}" style="display:inline">
<input type="hidden" name="csrf" value="{csrf_token}">
<button type="submit" class="btn btn-primary">+30 dias</button>
</form>
<form method="post" action="/admin/revoke/{escape(m['machine_id'])}" style="display:inline" onsubmit="return confirm('Revogar?')">
<input type="hidden" name="csrf" value="{csrf_token}">
<button type="submit" class="btn btn-danger">Revogar</button>
</form>
</td>
</tr>"""
    
    return f"""<!DOCTYPE html>
<html><head><title>Dashboard - EADMT4 Admin</title>{PAGE_STYLE}</head>
<body>
<div class="header"><h1> EADMT4-PRO Admin Dashboard</h1><div class="user"><a href="/admin/logout" class="btn btn-secondary">Sair</a></div></div>
<div class="container">
<div class="card">
<h2>🖥️ Máquinas Ativas</h2>
<table><thead><tr><th>Machine ID</th><th>Nome</th><th>Licença Expira</th><th>Trial Expira</th><th>Status</th><th>Ações</th></tr></thead>
<tbody>{rows}</tbody></table>
</div>
<div class="card">
<h2>🔑 Gerenciar Chaves</h2>
<a href="/admin/keys" class="btn btn-primary">Ver Chaves</a>
<a href="/admin/clients" class="btn btn-secondary">👥 Clientes</a>
</div>
</div></body></html>"""

def render_keys_page(keys, csrf_token):
    rows = ""
    for i, k in enumerate(keys):
        rows += f"""<tr class="{'even' if i % 2 == 0 else 'odd'}">
<td>{escape(k['license_key'])}</td>
<td>{k['expires']}</td>
<td>{k['machines']}</td>
<td><span class="badge {k['status_class']}">{escape(k['status'])}</span></td>
<td>
<form method="post" action="/admin/revokekey/{escape(k['license_key'])}" style="display:inline" onsubmit="return confirm('Revogar chave?')">
<input type="hidden" name="csrf" value="{csrf_token}">
<button type="submit" class="btn btn-danger">Revogar</button>
</form>
</td>
</tr>"""
    
    return f"""<!DOCTYPE html>
<html><head><title>Chaves - EADMT4 Admin</title>{PAGE_STYLE}</head>
<body>
<div class="header"><h1>🔑 Chaves de Licença</h1><div class="user"><a href="/admin" class="btn btn-secondary">Voltar</a></div></div>
<div class="container">
<div class="card">
<h2>Gerar Nova Chave</h2>
<form method="post" action="/admin/keygen">
<input type="hidden" name="csrf" value="{csrf_token}">
<button type="submit" class="btn btn-primary">Gerar Chave</button>
</form>
</div>
<div class="card">
<h2>Chaves Existentes</h2>
<table><thead><tr><th>Chave</th><th>Expira</th><th>Máquinas</th><th>Status</th><th>Ações</th></tr></thead>
<tbody>{rows}</tbody></table>
</div>
</div></body></html>"""

# ✅ NOVO: Página de Cadastro de Clientes
def render_clients_page(clients, csrf_token):
    rows = ""
    for i, c in enumerate(clients):
        rows += f"""<tr class="{'even' if i % 2 == 0 else 'odd'}">
<td>{escape(c.get('nome', '-'))}</td>
<td>{escape(c.get('telefone', '-'))}</td>
<td>{escape(c.get('email', '-'))}</td>
<td>{escape(c.get('obs', '-')[:50])}</td>
<td>{c['created']}</td>
<td>
<form method="post" action="/admin/deleteclient/{c['id']}" style="display:inline" onsubmit="return confirm('Excluir cliente?')">
<input type="hidden" name="csrf" value="{csrf_token}">
<button type="submit" class="btn btn-danger">Excluir</button>
</form>
</td>
</tr>"""
    
    return f"""<!DOCTYPE html>
<html><head><title>Clientes - EADMT4 Admin</title>{PAGE_STYLE}</head>
<body>
<div class="header"><h1>👥 Cadastro de Clientes</h1><div class="user"><a href="/admin" class="btn btn-secondary">Voltar</a></div></div>
<div class="container">
<div class="card">
<h2>Novo Cliente</h2>
<form method="post" action="/admin/addclient">
<input type="hidden" name="csrf" value="{csrf_token}">
<div class="form-group"><label>Nome *</label><input type="text" name="nome" required></div>
<div class="form-group"><label>Telefone</label><input type="text" name="telefone"></div>
<div class="form-group"><label>Email</label><input type="email" name="email"></div>
<div class="form-group"><label>Observações</label><textarea name="obs"></textarea></div>
<button type="submit" class="btn btn-primary">Cadastrar Cliente</button>
</form>
</div>
<div class="card">
<h2>Clientes Cadastrados</h2>
<table><thead><tr><th>Nome</th><th>Telefone</th><th>Email</th><th>Observações</th><th>Criado</th><th>Ações</th></tr></thead>
<tbody>{rows}</tbody></table>
</div>
</div></body></html>"""

def require_admin(request: Request):
    try:
        data = serializer.loads(request.cookies.get("admin_session", ""))
        if data.get("logged") and data.get("ts", 0) > time.time() - 3600:
            return data
    except:
        pass
    raise HTTPException(status_code=401, detail="Não autenticado")

def require_admin_csrf(request: Request, session=Depends(require_admin)):
    form_data = request.form()
    csrf = form_data.get("csrf", "")
    if csrf != session.get("csrf"):
        raise HTTPException(status_code=403, detail="CSRF inválido")
    return session

@app.get("/admin/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse(render_login_page())

@app.post("/admin/login", response_class=HTMLResponse)
def login_submit(request: Request, password: Form = Form(...)):
    ip = _client_ip(request)
    if _is_rate_limited(_login_attempts, ip, LOGIN_MAX_ATTEMPTS):
        return HTMLResponse(render_login_page("Muitas tentativas. Aguarde."))
    
    if password == ADMIN_PASSWORD:
        session = {"logged": True, "ts": time.time(), "csrf": secrets.token_hex(16)}
        resp = RedirectResponse(url="/admin", status_code=303)
        resp.set_cookie("admin_session", serializer.dumps(session), httponly=True, max_age=3600)
        return resp
    return HTMLResponse(render_login_page("Senha incorreta"))

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
    machines = []
    for r_raw in rows:
        r = row_to_dict(r_raw, LICENSE_COLUMNS)
        trial_expires = parse_dt(r["trial_expires"])
        license_expires = parse_dt(r["license_expires"])
        if r["revoked"]: status, status_class = "revogado", "revogado"
        elif license_expires and license_expires > now: status, status_class = "ativo", "ativo"
        elif trial_expires and trial_expires > now: status, status_class = "trial", "expirando"
        else: status, status_class = "expirado", "expirado"
        machines.append({
            "machine_id": r["machine_id"], "machine_name": r["machine_name"] or "(sem nome)",
            "license_key": r["license_key"] or "-", "last_seen": (r["last_seen"] or "")[:16].replace("T", " "),
            "status": status, "status_class": status_class,
            "license_expires": license_expires.strftime("%d/%m/%Y %H:%M") if license_expires else "-",
            "trial_expires": trial_expires.strftime("%d/%m/%Y %H:%M") if trial_expires else "-",
        })
    return HTMLResponse(render_dashboard_page(machines, session.get("csrf", "")))

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

# ✅ NOVO: Página de Clientes
@app.get("/admin/clients", response_class=HTMLResponse)
def clients_page(session=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM clients ORDER BY created DESC").fetchall()
    conn.close()
    clients = []
    for r_raw in rows:
        c = row_to_dict(r_raw, CLIENT_COLUMNS)
        clients.append({
            "id": c["id"],
            "nome": c["nome"],
            "telefone": c["telefone"] or "-",
            "email": c["email"] or "-",
            "obs": c["obs"] or "-",
            "created": (c["created"] or "")[:16].replace("T", " "),
        })
    return HTMLResponse(render_clients_page(clients, session.get("csrf", "")))

@app.post("/admin/addclient")
def add_client(_=Depends(require_admin_csrf), nome: Form = Form(...), telefone: Form = Form(""), email: Form = Form(""), obs: Form = Form("")):
    conn = get_db()
    conn.execute("INSERT INTO clients (nome, telefone, email, obs, created) VALUES (?, ?, ?, ?, ?)",
                 (nome, telefone, email, obs, now_utc().isoformat()))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/clients", status_code=303)

@app.post("/admin/deleteclient/{client_id}")
def delete_client(client_id: int, _=Depends(require_admin_csrf)):
    conn = get_db()
    conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/clients", status_code=303)

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
