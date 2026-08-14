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


@app.post("/api/check")
def check_license(payload: CheckRequest):
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

    if key and key_error:
        conn.close()
        return {"status": key_error, "expires_at": None, "days_left": 0}

    if key and key_row:
        kexp = parse_dt(key_row["expires"])
        if kexp is None:
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
# NOVO VISUAL — CORES DA DERIV
# Vermelho #ff444f, fundo claro #f5f7f9, cards brancos, tipografia moderna
# ----------------------------------------------------------------------
PAGE_STYLE = """
<style>
  :root {
    --deriv-red: #ff444f;
    --deriv-red-dark: #eb3e48;
    --deriv-black: #0e0e0e;
    --deriv-gray: #6b6b6b;
    --deriv-light: #f5f7f9;
    --deriv-border: #e6e9e9;
    --deriv-green: #4caf50;
    --deriv-blue: #2196f3;
  }
  * { box-sizing: border-box; }
  body {
    font-family: 'IBM Plex Sans', 'Segoe UI', Arial, sans-serif;
    background: var(--deriv-light);
    color: var(--deriv-black);
    margin: 0;
    padding: 0;
  }
  .wrapper {
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px 24px;
  }
  h1 {
    font-size: 32px;
    font-weight: 800;
    margin: 0 0 4px 0;
    color: var(--deriv-black);
    letter-spacing: -0.5px;
  }
  .sub {
    color: var(--deriv-gray);
    font-size: 14px;
    margin-bottom: 24px;
    padding-top: 8px;
    border-top: 1px solid var(--deriv-border);
  }
  .sub a {
    color: var(--deriv-red);
    text-decoration: none;
    font-weight: 500;
  }
  .sub a:hover { text-decoration: underline; }
  table {
    width: 100%;
    border-collapse: collapse;
    background: #fff;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,.04);
    font-size: 14px;
  }
  th, td {
    padding: 12px 16px;
    text-align: left;
    border-bottom: 1px solid var(--deriv-border);
  }
  th {
    background: var(--deriv-light);
    color: var(--deriv-gray);
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #fafbfc; }
  .badge {
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    white-space: nowrap;
    display: inline-block;
  }
  .badge.trial      { background: #e3f2fd; color: var(--deriv-blue); }
  .badge.licenciado { background: #e8f5e9; color: var(--deriv-green); }
  .badge.expirado   { background: #fff3e0; color: #e65100; }
  .badge.revogado   { background: #eeeeee; color: #616161; }
  .badge.ativo      { background: #e8f5e9; color: var(--deriv-green); }
  .badge.pendente   { background: #fff8e1; color: #f57c00; }
  form { display: inline; }
  button {
    padding: 7px 14px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
    margin-right: 4px;
    transition: all 0.15s ease;
  }
  .btn-extend { background: var(--deriv-green); color: #fff; }
  .btn-extend:hover { background: #3d9140; }
  .btn-revoke { background: var(--deriv-red); color: #fff; }
  .btn-revoke:hover { background: var(--deriv-red-dark); }
  .btn-reset { background: #6b6b6b; color: #fff; }
  .btn-reset:hover { background: #555; }
  .btn-new {
    background: var(--deriv-red);
    color: #fff;
    font-weight: 700;
    padding: 12px 24px;
    font-size: 14px;
  }
  .btn-new:hover { background: var(--deriv-red-dark); }
  .mono {
    font-family: 'IBM Plex Mono', Consolas, monospace;
    font-size: 12px;
    color: var(--deriv-gray);
    cursor: pointer;
    max-width: 180px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: inline-block;
    vertical-align: middle;
    padding: 2px 6px;
    background: var(--deriv-light);
    border-radius: 3px;
  }
  .mono:hover { color: var(--deriv-red); }
  .copied-msg {
    color: var(--deriv-green);
    font-size: 11px;
    font-weight: 700;
    margin-left: 6px;
    display: none;
  }
  .login-box {
    background: #fff;
    padding: 40px;
    border-radius: 8px;
    width: 400px;
    max-width: 90%;
    box-shadow: 0 4px 12px rgba(0,0,0,.06);
    margin: 12vh auto;
    border-top: 4px solid var(--deriv-red);
  }
  .login-box h1 {
    font-size: 28px;
    margin-bottom: 24px;
    color: var(--deriv-black);
  }
  input {
    width: 100%;
    padding: 12px 14px;
    margin-bottom: 16px;
    border-radius: 4px;
    border: 1px solid var(--deriv-border);
    background: #fff;
    color: var(--deriv-black);
    font-size: 14px;
    transition: border-color 0.15s;
  }
  input:focus {
    outline: none;
    border-color: var(--deriv-red);
  }
  .login-box button {
    width: 100%;
    padding: 14px;
    background: var(--deriv-red);
    color: #fff;
    font-weight: 700;
    font-size: 14px;
  }
  .login-box button:hover { background: var(--deriv-red-dark); }
  .error {
    color: var(--deriv-red);
    background: #fdecea;
    padding: 10px 14px;
    border-radius: 4px;
    margin-bottom: 16px;
    font-size: 13px;
    font-weight: 500;
  }
</style>
"""


def render_login_page(error=None):
    error_html = '<div class="error">' + escape(error) + '</div>' if error else ""
    return """<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8"><title>Login - EADMT4-PRO</title>""" + PAGE_STYLE + """</head>
<body>
  <div class="login-box">
    <h1>EADMT4-PRO</h1>
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
              <button class="btn-extend" type="submit">+ 1 mes</button>
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
<html lang="pt-br"><head><meta charset="UTF-8"><title>Painel - EADMT4-PRO</title>""" + PAGE_STYLE + """</head>
<body>
  <div class="wrapper">
    <h1>EADMT4-PRO</h1>
    <div class="sub">""" + str(len(items)) + """ maquina(s) registrada(s) &nbsp;&bull;&nbsp; <a href="/admin/keys">Gerenciar chaves</a> &nbsp;&bull;&nbsp; <a href="/admin/logout">Sair</a></div>
    <table>
      <thead>
        <tr><th>Computador</th><th>ID da maquina</th><th>Chave</th><th>Status</th><th>Teste expira</th>
            <th>Licenca expira</th><th>Ultima conexao</th><th>Acoes</th></tr>
      </thead>
      <tbody>""" + rows_html + """</tbody>
    </table>
  </div>
</body></html>"""


def render_keys_page(keys):
    rows_html = ""
    if not keys:
        rows_html = '<tr><td colspan="5">Nenhuma chave criada ainda. Clique em "Gerar nova chave".</td></tr>'
    for k in keys:
        rows_html += """
        <tr>
          <td><span class="mono" style="max-width:260px" onclick="navigator.clipboard.writeText(this.textContent);var m=this.nextElementSibling;m.style.display='inline';setTimeout(function(){m.style.display='none';},1200);">""" + escape(k['license_key']) + """</span><span class="copied-msg">Copiado!</span></td>
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
<html lang="pt-br"><head><meta charset="UTF-8"><title>Chaves - EADMT4-PRO</title>""" + PAGE_STYLE + """</head>
<body>
  <div class="wrapper">
    <h1>EADMT4-PRO</h1>
    <div class="sub">Chaves de licenca. Cada chave libera o app em ate """ + str(MAX_MACHINES_PER_KEY) + """ maquinas. Clique na chave para copiar. &nbsp;&bull;&nbsp; <a href="/admin">Voltar</a></div>
    <form method="post" action="/admin/keygen" style="margin-bottom:20px">
      <button class="btn-new" type="submit">+ Gerar nova chave (30 dias)</button>
    </form>
    <table>
      <thead>
        <tr><th>Chave</th><th>Expira em</th><th>Maquinas</th><th>Status</th><th>Acoes</th></tr>
      </thead>
      <tbody>""" + rows_html + """</tbody>
    </table>
  </div>
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


@app.get("/admin/keys", response_class=HTMLResponse)
def keys_page(_=Depends(require_admin)):
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
            status, status_class = "aguardando 1o uso", "pendente"
        elif exp > now:
            status, status_class = "ativa", "ativo"
        else:
            status, status_class = "expirada", "expirado"
        used = counts.get(k["license_key"], 0)
        keys.append(
            {
                "license_key": k["license_key"],
                "expires": exp.strftime("%d/%m/%Y %H:%M") if exp else "-",
                "machines": str(used) + "/" + str(k["max_machines"] or MAX_MACHINES_PER_KEY),
                "status": status,
                "status_class": status_class,
            }
        )
    return HTMLResponse(render_keys_page(keys))


@app.post("/admin/keygen")
def keygen(_=Depends(require_admin)):
    conn = get_db()
    conn.execute(
        "INSERT INTO license_keys (license_key, created, expires, revoked, max_machines) VALUES (?, ?, ?, 0, ?)",
        (generate_key(), now_utc().isoformat(), None, MAX_MACHINES_PER_KEY),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/keys", status_code=303)


@app.post("/admin/revokekey/{license_key}")
def revoke_key(license_key: str, _=Depends(require_admin)):
    conn = get_db()
    conn.execute("UPDATE license_keys SET revoked = 1 WHERE license_key = ?", (license_key,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/keys", status_code=303)


@app.post("/admin/extend/{machine_id}")
def extend_license(machine_id: str, _=Depends(require_admin)):
    conn = get_db()
    row = row_to_dict(
        conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (machine_id,)).fetchone(),
        LICENSE_COLUMNS,
    )
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


@app.post("/admin/reset/{machine_id}")
def reset_license(machine_id: str, _=Depends(require_admin)):
    conn = get_db()
    conn.execute("DELETE FROM licenses WHERE machine_id = ?", (machine_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)


@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"service": "EADMT4-PRO License Server", "status": "ok"}
