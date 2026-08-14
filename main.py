import os
import secrets
import string
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
MAX_MACHINES_PER_KEY = 2

serializer = URLSafeSerializer(SECRET_KEY, salt="admin-session")

app = FastAPI(title="EADMT4-PRO License Server")

LICENSE_COLUMNS = [
    "machine_id", "machine_name", "first_seen",
    "trial_expires", "license_expires", "last_seen", "revoked", "license_key"
]
KEY_COLUMNS = ["license_key", "created", "expires", "revoked", "max_machines"]


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


def generate_key():
    alphabet = string.ascii_uppercase + string.digits
    part = lambda: "".join(secrets.choice(alphabet) for _ in range(4))
    return "EAD-" + part() + "-" + part() + "-" + part()


class CheckRequest(BaseModel):
    machine_id: str
    machine_name: str = ""
    license_key: str = ""


# ----------------------------------------------------------------------
# API usada pelo aplicativo (cliente)
# ----------------------------------------------------------------------
@app.post("/api/check")
def check_license(payload: CheckRequest):
    conn = get_db()
    now = now_utc()
    key = (payload.license_key or "").strip().upper()

    # Valida a chave, se enviada
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

    # ---------- FLUXO COM CHAVE ----------
    if key and key_error:
        conn.close()
        return {"status": key_error, "expires_at": None, "days_left": 0}

    if key and key_row:
        kexp = parse_dt(key_row["expires"])
        if kexp is None:
            # chave nunca usada: comeca a contar 30 dias agora
            kexp = now + timedelta(days=LICENSE_DAYS)
            conn.execute(
                "UPDATE license_keys SET expires = ? WHERE license_key = ?",
                (kexp.isoformat(), key),
            )

        if row is None:
            count = conn.execute(
                "SELECT COUNT(*) FROM licenses WHERE license_key = ? AND revoked = 0", (key,)
            ).fetchone()[0]
            if count >= int(key_row["max_machines"] or MAX_MACHINES_PER_KEY):
                conn.commit()
                conn.close()
                return {"status": "limit", "expires_at": None, "days_left": 0}
            conn.execute(
                "INSERT INTO licenses (machine_id, machine_name, first_seen, trial_expires, license_expires, last_seen, license_key) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    payload.machine_id,
                    payload.machine_name,
                    now.isoformat(),
                    (now + timedelta(days=TRIAL_DAYS)).isoformat(),
                    kexp.isoformat(),
                    now.isoformat(),
                    key,
                ),
            )
            conn.commit()
            conn.close()
            return {
                "status": "licensed",
                "expires_at": kexp.isoformat(),
                "days_left": max(0, (kexp - now).days),
            }

        # maquina ja existe: atualiza e vincula a chave
        conn.execute(
            "UPDATE licenses SET last_seen = ?, machine_name = ?, license_key = ?, license_expires = ?, revoked = 0 "
            "WHERE machine_id = ?",
            (now.isoformat(), payload.machine_name or row["machine_name"], key, kexp.isoformat(), payload.machine_id),
        )
        conn.commit()
        conn.close()
        return {
            "status": "licensed",
            "expires_at": kexp.isoformat(),
            "days_left": max(0, (kexp - now).days),
        }

    # ---------- FLUXO ANTIGO (sem chave) ----------
    if row is None:
        first_seen = now
        trial_expires = now + timedelta(days=TRIAL_DAYS)
        conn.execute(
            "INSERT INTO licenses (machine_id, machine_name, first_seen, trial_expires, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (payload.machine_id, payload.machine_name, first_seen.isoformat(), trial_expires.isoformat(), now.isoformat()),
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
  .badge.ativo { background:#22c55e; color:#052e14; }
  .badge.pendente { background:#eab308; color:#422006; }
  form { display:inline; }
  button { padding:6px 10px; border:none; border-radius:6px; cursor:pointer; font-size:12px; margin-right:4px; }
  .btn-extend { background:#22c55e; color:#052e14; font-weight:bold; }
  .btn-extend:hover { background:#16a34a; }
  .btn-revoke { background:#ef4444; color:#fff; }
  .btn-revoke:hover { background:#dc2626; }
  .btn-reset { background:#64748b; color:#fff; }
  .btn-reset:hover { background:#475569; }
  .btn-new { background:#22c55e; color:#052e14; font-weight:bold; padding:10px 16px; }
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
        rows_html = '<tr><td colspan="8">Nenhuma maquina se conectou ainda.</td></tr>'
    for item in items:
        rows_html += """
        <tr>
          <td>""" + escape(item['machine_name']) + """</td>
          <td><span class="mono" title=\"""" + escape(item['machine_id']) + """\" onclick="navigator.clipboard.writeText(this.textContent);var m=this.nextElementSibling;m.style.display='inline';setTimeout(function(){m.style.display='none';},1200);">""" + escape(item['machine_id']) + """</span><span class="copied-msg">Copiado!</span></td>
          <td>""" + escape(item['license_key']) + """</td>
          <td><span class="badge """ + item['status_class'] + """">""" + escape(item['status']) + """</span></td>
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
            <form method="post" action="/admin/reset/""" + item['machine_id'] + """">
              <button class="btn-reset" type="submit">Resetar</button>
            </form>
          </td>
        </tr>"""
    return """<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8"><title>Painel de Licencas</title>""" + PAGE_STYLE + """</head>
<body>
  <h1>Painel de Licencas &mdash; EADMT4-PRO</h1>
  <div class="sub">""" + str(len(items)) + """ maquina(s) registrada(s) &nbsp;&bull;&nbsp; <a class="logout" href="/admin/keys">Gerenciar chaves</a> &nbsp;&bull;&nbsp; <a class="logout" href="/admin/logout">Sair</a></div>
  <table>
    <thead>
      <tr><th>Computador</th><th>ID da maquina</th><th>Chave</th><th>Status</th><th>Teste expira</th>
          <th>Licenca expira</th><th>Ultima conexao</th><th>Acoes</th></tr>
    </thead>
    <tbody>""" + rows_html + """</tbody>
  </table>
</body></html>"""


def render_keys_page(keys):
    rows_html = ""
    if not keys:
        rows_html = '<tr><td colspan="5">Nenhuma chave criada ainda. Clique em "Gerar nova chave".</td></tr>'
    for k in keys:
        rows_html += """
        <tr>
          <td><span class="mono" style="max-width:220px" onclick="navigator.clipboard.writeText(this.textContent);var m=this.nextElementSibling;m.style.display='inline';setTimeout(function(){m.style.display='none';},1200);">""" + escape(k['license_key']) + """</span><span class="copied-msg">Copiado!</span></td>
          <td>""" + k['expires'] + """</td>
          <td>""" + k['machines'] + """</td>
          <td><span class="badge """ + k['status_class'] + """">""" + escape(k['status']) + """</span></td>
          <td>
            <form method="post" action="/admin/revokekey/""" + escape(k['license_key']) + """">
              <button class="btn-revoke" type="submit">Revogar</button>
            </form>
          </td>
        </tr>"""
    return """<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8"><title>Chaves - Painel de Licencas</title>""" + PAGE_STYLE + """</head>
<body>
  <h1>Chaves de Licenca &mdash; EADMT4-PRO</h1>
  <div class="sub">Cada chave libera o app em ate """ + str(MAX_MACHINES_PER_KEY) + """ maquinas. Clique na chave para copiar. &nbsp;&bull;&nbsp; <a class="logout" href="/admin">Voltar</a></div>
  <form method="post" action="/admin/keygen" style="margin-bottom:16px">
    <button class="btn-new" type="submit">+ Gerar nova chave (30 dias)</button>
  </form>
  <table>
    <thead>
      <tr><th>Chave</th><th>Expira em</th><th>Maquinas</th><th>Status</th><th>Acoes</th></tr>
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
        items.append(
            {
                "machine_id": r["machine_id"],
                "machine_name": r["machine_name"] or "(sem nome)",
                "license_key": r["license_key"] or "-",
                "last_seen": (r["last_seen"] or "")[:16].replace("T", " "),
                "status": status,
                "status_class": status_class,
                "license_expires": license_expires.strftime("%d/%m/%Y %H:%M") if license_expires else "-",
                "trial_expires": trial_expires.strftime("%d/%m/%Y %H:%M") if trial_expires else "-",
            }
        )
    return HTMLResponse(render_dashboard_page(items))


@app.get("/admin/keys", response_class=HTMLResponse
