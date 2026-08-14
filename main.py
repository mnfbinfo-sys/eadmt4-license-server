import os
import libsql
from datetime import datetime, timedelta, timezone
from html import escape

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeSerializer, BadSignature
from pydantic import BaseModel

# ----------------------------------------------------------------------
# Configuração (via variáveis de ambiente no Render)
# ----------------------------------------------------------------------
TURSO_DATABASE_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "troque-esta-senha")
SECRET_KEY = os.environ.get("SECRET_KEY", "troque-este-secret-tambem")

TRIAL_DAYS = 2
LICENSE_DAYS = 30

serializer = URLSafeSerializer(SECRET_KEY, salt="admin-session")

app = FastAPI(title="EADMT4-PRO License Server")

# Mapeamento das colunas para garantir compatibilidade com qualquer driver SQL
LICENSE_COLUMNS = [
    "machine_id", "machine_name", "first_seen",
    "trial_expires", "license_expires", "last_seen", "revoked"
]

def get_db():
    conn = libsql.connect(
        TURSO_DATABASE_URL,
        auth_token=TURSO_AUTH_TOKEN,
    )
    return conn

def row_to_dict(row):
    """Converte tupla do banco em dicionário para facilitar o acesso por nome."""
    if not row:
        return None
    return dict(zip(LICENSE_COLUMNS, row))

def now_utc():
    return datetime.now(timezone.utc)

def parse_dt(s):
    if not s: return None
    return datetime.fromisoformat(s)

class CheckRequest(BaseModel):
    machine_id: str
    machine_name: str = ""

# ----------------------------------------------------------------------
# API usada pelo aplicativo (cliente)
# ----------------------------------------------------------------------
@app.post("/api/check")
def check_license(payload: CheckRequest):
    conn = get_db()
    cursor = conn.execute(
        "SELECT * FROM licenses WHERE machine_id = ?", (payload.machine_id,)
    )
    row = row_to_dict(cursor.fetchone())
    now = now_utc()

    if row is None:
        first_seen = now
        trial_expires = now + timedelta(days=TRIAL_DAYS)
        conn.execute(
            "INSERT INTO licenses (machine_id, machine_name, first_seen, trial_expires, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                payload.machine_id,
                payload.machine_name,
                first_seen.isoformat(),
                trial_expires.isoformat(),
                now.isoformat(),
            ),
        )
        conn.commit()
        status = "trial"
        expires_at = trial_expires
    else:
        conn.execute(
            "UPDATE licenses SET last_seen = ?, machine_name = ? WHERE machine_id = ?",
            (now.isoformat(), payload.machine_name or row["machine_name"], payload.machine_id),
        )
        conn.commit()

        if row["revoked"]:
            status = "revoked"
            expires_at = None
        else:
            license_expires = parse_dt(row["license_expires"])
            trial_expires = parse_dt(row["trial_expires"])

            if license_expires and license_expires > now:
                status = "licensed"
                expires_at = license_expires
            elif trial_expires and trial_expires > now:
                status = "trial"
                expires_at = trial_expires
            else:
                status = "expired"
                expires_at = None

    conn.close()
    return {
        "status": status,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": max(0, (expires_at - now).days) if expires_at else 0,
    }

# ----------------------------------------------------------------------
# Painel administrativo
# ----------------------------------------------------------------------
PAGE_STYLE = """
<style>
  body { font-family: Arial, sans-serif; background:#0f172a; color:#e5e7eb; margin:0; padding:24px; }
  h1 { font-size:20px; margin-bottom:4px; }
  .sub { color:#94a3b8; margin-bottom:20px; font-size:13px; }
  table { width:100%; border-collapse: collapse; background:#1e293b; border-radius:8px; overflow:hidden; }
  th, td { padding:10px 12px; text-align:left; font-size:13px; border-bottom:1px solid #334155; }
  th { background:#111827; color:#94a3b8; font-weight:600; }
  tr:hover { background:#243043; }
  .badge { padding:3px 8px; border-radius:12px; font-size:11px; font-weight:bold; white-space:nowrap; }
  .badge.trial { background:#3b82f6; color:#fff; }
  .badge.licenciado { background:#22c55e; color:#052e14; }
  .badge.expirado { background:#ef4444; color:#fff; }
  .badge.revogado { background:#6b7280; color:#fff; }
  form { display:inline; }
  button { padding:6px 10px; border:none; border-radius:6px; cursor:pointer; font-size:12px; margin-right:4px; }
  .btn-extend { background:#22c55e; color:#052e14; font-weight:bold; }
  .btn-extend:hover { background:#16a34a; }
  .btn-revoke { background:#ef4444; color:#fff; }
  .btn-revoke:hover { background:#dc2626; }
  .mono { font-family: monospace; font-size:11px; color:#94a3b8; cursor:pointer;
          max-width: 140px; overflow:hidden; text-overflow: ellipsis; white-space: nowrap;
          display:inline-block; vertical-align:middle; }
  .mono:hover { color:#e5e7eb; text-decoration: underline dotted; }
  .copied-msg { color:#22c55e; font-size:10px; margin-left:6px; display:none; }
  a.logout { color:#94a3b8; font-size:12px; }
  .login-box { background:#1f2937; padding:32px; border-radius:10px; width:300px;
               box-shadow:0 4px 20px rgba(0,0,0,.4); margin: 10vh auto; }
  input { width:100%; padding:10px; margin-bottom:14px; border-radius:6px; border:1px solid #374151;
          background:#111827; color:#e5e7eb; box-sizing:border-box; }
  .login-box button { width:100%; padding:10px; background:#22c55e; color:#fff; font-weight:bold; }
  .error { color:#f87171; margin-bottom:12px; font-size:14px; }
</style>
"""

def render_login_page(error=None):
    error_html = '<div class="error">' + escape(error) + '</div>' if error else ""
    return """<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8"><title>Login - Painel de Licencas</title>""" + PAGE_STYLE + """</head>
<body>
  <div class="login-box">
    <h1>Painel de Licencas<br>EADMT4-PRO</h1>
    """ + error_html + """
    <form method="post" action="/admin/login">
      <input type="password" name="password" placeholder="Senha de administrador" required autofocus>
      <button type="submit">Entrar</button>
    </form>
  </div>
</body></html>"""

def render_dashboard_page(items):
    rows_html = ""
    if not items:
        rows_html = '<tr><td colspan="7">Nenhuma maquina se conectou ainda.</td></tr>'
    for item in items:
        badge_class = item["status_class"]
        rows_html += """
        <tr>
          <td>""" + escape(item['machine_name']) + """</td>
          <td><span class="mono" title=\"""" + escape(item['machine_id']) + """\" onclick="navigator.clipboard.writeText(this.textContent);var m=this.nextElementSibling;m.style.display='inline';setTimeout(function(){m.style.display='none';},1200);">""" + escape(item['machine_id']) + """</span><span class="copied-msg">Copiado!</span></td>
          <td><span class="badge """ + badge_class + """">""" + escape(item['status']) + """</span></td>
          <td>""" + item['trial_expires'] + """</td>
          <td>""" + item['license_expires'] + """</td>
          <td>""" + item['last_seen'] + """</td>
          <td>
            <form method="post" action="/admin/extend/""" + item['machine_id'] + """">
              <button class="btn-extend" type="submit">Liberar 1 mes</button>
            </form>
            <form method="post" action="/admin/revoke/""" + item['machine_id'] + """">
              <button class="btn-revoke" type="submit">Revogar</button>
            </form>
          </td>
        </tr>"""
    return """<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8"><title>Painel de Licencas</title>""" + PAGE_STYLE + """</head>
<body>
  <h1>Painel de Licencas &mdash; EADMT4-PRO</h1>
  <div class="sub">""" + str(len(items)) + """ maquina(s) registrada(s) &nbsp;&bull;&nbsp; <a class="logout" href="/admin/logout">Sair</a></div>
  <table>
    <thead>
      <tr><th>Computador</th><th>ID da maquina</th><th>Status</th><th>Teste expira</th>
          <th>Licenca expira</th><th>Ultima conexao</th><th>Acoes</th></tr>
    </thead>
    <tbody>""" + rows_html + """</tbody>
  </table>
</body></html>"""

def require_admin(request: Request):
    token = request.cookies.get("admin_session")
    if token:
        try:
            data = serializer.loads(token)
            if data.get("ok"):
                return True
        except BadSignature:
            pass
    raise HTTPException(status_code=303, headers={"Location": "/admin/login"})

@app.get("/admin/login", response_class=HTMLResponse)
def login_form():
    return render_login_page()

@app.post("/admin/login")
def login(password: str = Form(...)):
    if password != ADMIN_PASSWORD:
        return HTMLResponse(render_login_page("Senha incorreta"))
    token = serializer.dumps({"ok": True})
    resp = RedirectResponse(url="/admin", status_code=303)
    resp.set_cookie("admin_session", token, httponly=True, max_age=60 * 60 * 8)
    return resp

@app.get("/admin/logout")
def logout():
    resp = RedirectResponse(url="/admin/login", status_code=303)
    resp.delete_cookie("admin_session")
    return resp

@app.get("/admin", response_class=HTMLResponse)
def dashboard(_=Depends(require_admin)):
    conn = get_db()
    cursor = conn.execute("SELECT * FROM licenses ORDER BY last_seen DESC")
    rows_raw = cursor.fetchall()
    conn.close()
    
    now = now_utc()
    items = []
    for r_raw in rows_raw:
        r = row_to_dict(r_raw)
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
            
        items.append(
            {
                "machine_id": r["machine_id"],
                "machine_name": r["machine_name"] or "(sem nome)",
                "last_seen": (r["last_seen"] or "")[:16].replace("T", " "),
                "status": status,
                "status_class": status_class,
                "license_expires": license_expires.strftime("%d/%m/%Y %H:%M") if license_expires else "-",
                "trial_expires": trial_expires.strftime("%d/%m/%Y %H:%M") if trial_expires else "-",
            }
        )
    return HTMLResponse(render_dashboard_page(items))

@app.post("/admin/extend/{machine_id}")
def extend_license(machine_id: str, _=Depends(require_admin)):
    conn = get_db()
    cursor = conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (machine_id,))
    row = row_to_dict(cursor.fetchone())
    
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Maquina nao encontrada")
        
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
def revoke_license(machine_id: str, _=Depends(require_admin)):
    conn = get_db()
    conn.execute("UPDATE licenses SET revoked = 1 WHERE machine_id = ?", (machine_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"service": "EADMT4-PRO License Server", "status": "ok"}
