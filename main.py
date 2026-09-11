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
from typing import Optional
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeSerializer, BadSignature
from pydantic import BaseModel, Field

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

# Token separado para o script local (gerenciador_local.py) chamar a API
# administrativa sem precisar de sessão de navegador/cookie/CSRF. É OPCIONAL:
# se ADMIN_API_TOKEN não for definido, cai de volta para ADMIN_PASSWORD (não
# quebra deploys existentes). Mas o ideal é configurar um valor próprio no
# Render - assim, se o computador que roda o script local for comprometido,
# quem vazar é só um token com escopo de API, não a senha do painel inteiro.
ADMIN_API_TOKEN = os.environ.get("ADMIN_API_TOKEN") or ADMIN_PASSWORD

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

RATE_LIMIT_CLEANUP_INTERVAL_SEC = 6 * 60 * 60   # roda a cada 6 horas
RATE_LIMIT_RETENTION_SEC = 24 * 60 * 60         # nao guarda mais que 24h de eventos

def _cleanup_rate_limit_events():
    # Diferente da limpeza "de passagem" dentro de _is_rate_limited (que só apaga
    # linhas do bucket que está sendo consultado naquele instante), esta função
    # limpa a TABELA INTEIRA, incluindo buckets que ficaram sem tráfego por um
    # tempo - é o que evita o crescimento indefinido mencionado no diagnóstico.
    try:
        conn = get_db()
        _ensure_rate_limit_table(conn)
        cutoff = int(time.time()) - RATE_LIMIT_RETENTION_SEC
        conn.execute("DELETE FROM rate_limit_events WHERE ts < ?", (cutoff,))
        conn.commit()
        conn.close()
        print(f"[CLEANUP] rate_limit_events: linhas com ts < {cutoff} removidas.")
    except Exception as e:
        # Falha na limpeza nunca deve derrubar o servidor.
        print(f"[CLEANUP ERROR] {e}")

async def _rate_limit_cleanup_loop():
    while True:
        await asyncio.sleep(RATE_LIMIT_CLEANUP_INTERVAL_SEC)
        _cleanup_rate_limit_events()

def _ensure_audit_log_table(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS admin_audit_log (ts INTEGER NOT NULL, ip TEXT, action TEXT NOT NULL, detail TEXT, success INTEGER NOT NULL)"
    )

def log_admin_action(conn, request: Request, action: str, detail: str = "", success: bool = True):
    # Registra quem fez o quê e quando no painel admin: se ADMIN_PASSWORD algum dia vazar,
    # isso é o que permite reconstruir o que foi feito (logins, geração/revogação de chaves, etc.).
    try:
        _ensure_audit_log_table(conn)
        conn.execute(
            "INSERT INTO admin_audit_log (ts, ip, action, detail, success) VALUES (?, ?, ?, ?, ?)",
            (int(time.time()), _client_ip(request), action, detail, 1 if success else 0),
        )
        conn.commit()
    except Exception as e:
        # Falha ao logar nunca deve derrubar a ação administrativa em si.
        print(f"[AUDIT LOG ERROR] {e}")

serializer = URLSafeSerializer(SECRET_KEY, salt="admin-session")
app = FastAPI(title="EADMT4-PRO License Server")

@app.middleware("http")
async def _security_headers_middleware(request: Request, call_next):
    # Headers de segurança HTTP que o FastAPI não adiciona por padrão.
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # HSTS só faz sentido se o serviço é sempre servido via HTTPS (é o caso no Render).
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response

@app.on_event("startup")
async def _on_startup():
    # Limpa uma vez já na subida do serviço (cobre o caso comum no Render de a
    # instância reiniciar/dormir com frequência) e depois segue limpando sozinho
    # em loop enquanto o processo estiver de pé.
    _cleanup_rate_limit_events()
    asyncio.create_task(_rate_limit_cleanup_loop())

LICENSE_COLUMNS = ["machine_id", "machine_name", "first_seen", "trial_expires", "license_expires", "last_seen", "revoked", "license_key", "hardware_fingerprint"]
KEY_COLUMNS = ["license_key", "created", "expires", "revoked", "max_machines"]

def _ensure_hardware_fingerprint_column(conn):
    # SQLite/libsql não tem "ADD COLUMN IF NOT EXISTS" - a forma segura é tentar
    # adicionar e ignorar o erro se a coluna já existir (não apaga dado nenhum).
    try:
        conn.execute("ALTER TABLE licenses ADD COLUMN hardware_fingerprint TEXT")
        conn.commit()
    except Exception:
        pass

def _ensure_core_tables(conn):
    # CREATE TABLE IF NOT EXISTS é seguro mesmo que as tabelas já existam com dados -
    # não apaga nem altera nada, só evita erro caso alguma nunca tenha sido criada.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            machine_id TEXT PRIMARY KEY,
            machine_name TEXT,
            first_seen TEXT,
            trial_expires TEXT,
            license_expires TEXT,
            last_seen TEXT,
            revoked INTEGER DEFAULT 0,
            license_key TEXT
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
    _ensure_hardware_fingerprint_column(conn)

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
    # Limites de tamanho evitam que alguém envie payloads muito grandes repetidamente
    # (machine_id é um hash SHA-256 truncado em 32 chars; license_key segue o formato
    # EAD-XXXX-XXXX-XXXX, então 64 chars já dá folga de sobra para ambos).
    machine_id: str = Field(..., min_length=1, max_length=128)
    machine_name: str = Field("", max_length=128)
    license_key: str = Field("", max_length=64)
    # Sinal EXTRA de hardware (hash de disco+BIOS+CPU quando disponível), enviado
    # pelo license_client.py só para detecção/auditoria - NUNCA usado para decidir
    # status de licença nem para contar contra o limite de máquinas.
    hardware_fingerprint: str = Field("", max_length=128)

@app.post("/api/check")
def check_license(request: Request, payload: CheckRequest):
    conn = get_db()
    _ensure_core_tables(conn)
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
            
            conn.execute("INSERT INTO licenses (machine_id, machine_name, first_seen, trial_expires, license_expires, last_seen, license_key, hardware_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (payload.machine_id, payload.machine_name, now.isoformat(), (now + timedelta(days=TRIAL_DAYS)).isoformat(), kexp.isoformat(), now.isoformat(), key, payload.hardware_fingerprint))
            conn.commit(); conn.close()
            return signed_response("licensed", payload.machine_id, kexp, max(0, (kexp - now).days))
        
        # COALESCE(NULLIF(?, ''), hardware_fingerprint): se o cliente não conseguiu
        # coletar o sinal extra desta vez (string vazia), mantém o valor já salvo
        # em vez de apagar um fingerprint bom que já tínhamos.
        conn.execute("UPDATE licenses SET last_seen = ?, machine_name = ?, license_key = ?, license_expires = ?, revoked = 0, hardware_fingerprint = COALESCE(NULLIF(?, ''), hardware_fingerprint) WHERE machine_id = ?",
            (now.isoformat(), payload.machine_name or row["machine_name"], key, kexp.isoformat(), payload.hardware_fingerprint, payload.machine_id))
        conn.commit(); conn.close()
        return signed_response("licensed", payload.machine_id, kexp, max(0, (kexp - now).days))

    if row is None:
        first_seen = now
        trial_expires = now + timedelta(days=TRIAL_DAYS)
        conn.execute("INSERT INTO licenses (machine_id, machine_name, first_seen, trial_expires, last_seen, hardware_fingerprint) VALUES (?, ?, ?, ?, ?, ?)",
            (payload.machine_id, payload.machine_name, first_seen.isoformat(), trial_expires.isoformat(), now.isoformat(), payload.hardware_fingerprint))
        conn.commit()
        status = "trial"
        expires_at = trial_expires
    else:
        conn.execute("UPDATE licenses SET last_seen = ?, machine_name = ?, hardware_fingerprint = COALESCE(NULLIF(?, ''), hardware_fingerprint) WHERE machine_id = ?",
            (now.isoformat(), payload.machine_name or row["machine_name"], payload.hardware_fingerprint, payload.machine_id))
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

# ============================================================================
# RENDERIZAÇÃO HTML DO PAINEL ADMIN
# Estas duas funções faltavam no arquivo em produção (render_login_page e
# render_dashboard_page) - era a causa do "Internal Server Error" em /admin.
# Todo dado que vem de fora (machine_name, license_key, etc.) passa por escape()
# antes de entrar no HTML, para evitar XSS via campos preenchidos pelo cliente MT4/EA.
# ============================================================================

_PAGE_STYLE = """
<style>
  body { background:#0d1626; color:#e6e9ef; font-family: Arial, Helvetica, sans-serif; margin:0; padding:0; }
  .wrap { max-width: 1100px; margin: 40px auto; padding: 0 20px; }
  .card { background:#1f2733; border-radius:10px; padding:28px; box-shadow:0 4px 18px rgba(0,0,0,.35); }
  h1 { font-size:20px; margin:0 0 18px 0; color:#fff; }
  input[type=password], input[type=text], input[type=number] {
    width:100%; box-sizing:border-box; padding:10px 12px; border-radius:6px;
    border:1px solid #3a4553; background:#0d1626; color:#e6e9ef; margin-bottom:14px; font-size:14px;
  }
  button, .btn {
    background:#2f6fed; color:#fff; border:none; padding:10px 16px; border-radius:6px;
    font-size:14px; cursor:pointer; text-decoration:none; display:inline-block;
  }
  button:hover, .btn:hover { background:#255ac9; }
  .btn-danger { background:#c0392b; } .btn-danger:hover { background:#992d21; }
  .btn-ok { background:#1f9d55; } .btn-ok:hover { background:#187d44; }
  .err { background:#3a1f24; color:#ff9b9b; padding:10px 12px; border-radius:6px; margin-bottom:14px; font-size:13.5px; }
  table { width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #2c3646; }
  th { color:#9aa5b5; font-weight:600; text-transform:uppercase; font-size:11px; }
  .tag { padding:3px 8px; border-radius:20px; font-size:11.5px; font-weight:600; }
  .tag.trial { background:#3a3520; color:#e8d477; }
  .tag.licenciado { background:#1c3a2a; color:#5fd68c; }
  .tag.revogado { background:#3a1f24; color:#ff9b9b; }
  .tag.expirado { background:#33291d; color:#e8a15f; }
  .topbar { display:flex; justify-content:space-between; align-items:center; margin-bottom:18px; }
  .topbar a { color:#9aa5b5; font-size:13px; text-decoration:none; margin-left:14px; }
  .topbar a:hover { color:#fff; }
  form.inline { display:inline; }
  .mono { font-family: 'Courier New', monospace; font-size:12.5px; }
  .tag.suspeito { background:#3a1f24; color:#ff9b9b; }
</style>
"""

def render_login_page(error: str = "") -> str:
    err_html = f'<div class="err">{escape(error)}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="utf-8"><title>EADMT4-PRO - Login</title>{_PAGE_STYLE}</head>
<body>
  <div class="wrap" style="max-width:400px;">
    <div class="card">
      <h1>EADMT4-PRO &mdash; Painel Admin</h1>
      {err_html}
      <form method="post" action="/admin/login">
        <input type="password" name="password" placeholder="Senha do painel" autofocus required>
        <button type="submit" style="width:100%;">Entrar</button>
      </form>
    </div>
  </div>
</body></html>"""

def render_dashboard_page(items: list, csrf_token: str) -> str:
    rows_html = ""
    if not items:
        rows_html = '<tr><td colspan="8" style="color:#777;">Nenhuma licença registrada ainda.</td></tr>'
    for it in items:
        toggle_label = "Revogar" if it["status_class"] != "revogado" else "Reativar"
        toggle_class = "btn-danger" if it["status_class"] != "revogado" else "btn-ok"
        hw_badge = ' <span class="tag suspeito" title="Este fingerprint de hardware aparece em outro machine_id tambem">⚠ dup.</span>' if it["hw_suspect"] else ""
        rows_html += f"""
        <tr>
          <td class="mono">{escape(it['machine_id'])}</td>
          <td>{escape(it['machine_name'])}</td>
          <td class="mono">{escape(it['license_key'])}</td>
          <td class="mono">{escape(it['hw_fingerprint'])}{hw_badge}</td>
          <td>{escape(it['last_seen'])}</td>
          <td><span class="tag {escape(it['status_class'])}">{escape(it['status'])}</span></td>
          <td>{escape(it['license_expires'])}</td>
          <td>{escape(it['trial_expires'])}</td>
          <td>
            <form class="inline" method="post" action="/admin/license/toggle-revoke">
              <input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
              <input type="hidden" name="machine_id" value="{escape(it['machine_id'])}">
              <button type="submit" class="{toggle_class}">{toggle_label}</button>
            </form>
          </td>
        </tr>"""
    return f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="utf-8"><title>EADMT4-PRO - Dashboard</title>{_PAGE_STYLE}</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="topbar">
        <h1 style="margin:0;">EADMT4-PRO &mdash; Licenças</h1>
        <div>
          <a href="/admin/keys">Gerenciar chaves</a>
          <a href="/admin/logout">Sair</a>
        </div>
      </div>
      <table>
        <thead><tr>
          <th>Machine ID</th><th>Nome</th><th>Chave</th><th>HW Fingerprint</th><th>Última atividade</th>
          <th>Status</th><th>Licença expira</th><th>Trial expira</th><th>Ação</th>
        </tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </div>
</body></html>"""

def render_keys_page(keys: list, csrf_token: str, message: str = "") -> str:
    msg_html = f'<div class="err" style="background:#1c3a2a;color:#5fd68c;">{escape(message)}</div>' if message else ""
    rows_html = ""
    if not keys:
        rows_html = '<tr><td colspan="5" style="color:#777;">Nenhuma chave gerada ainda.</td></tr>'
    for k in keys:
        status = "revogada" if k["revoked"] else "ativa"
        tag_class = "revogado" if k["revoked"] else "licenciado"
        toggle_label = "Revogar" if not k["revoked"] else "Reativar"
        toggle_class = "btn-danger" if not k["revoked"] else "btn-ok"
        rows_html += f"""
        <tr>
          <td class="mono">{escape(k['license_key'])}</td>
          <td>{escape(k['created'] or '-')}</td>
          <td>{escape(k['expires'] or '-')}</td>
          <td><span class="tag {tag_class}">{status}</span></td>
          <td>
            <form class="inline" method="post" action="/admin/keys/toggle-revoke">
              <input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
              <input type="hidden" name="license_key" value="{escape(k['license_key'])}">
              <button type="submit" class="{toggle_class}">{toggle_label}</button>
            </form>
          </td>
        </tr>"""
    return f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="utf-8"><title>EADMT4-PRO - Chaves</title>{_PAGE_STYLE}</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="topbar">
        <h1 style="margin:0;">EADMT4-PRO &mdash; Chaves de Licença</h1>
        <div>
          <a href="/admin">Licenças</a>
          <a href="/admin/logout">Sair</a>
        </div>
      </div>
      {msg_html}
      <form method="post" action="/admin/keygen" style="margin-bottom:18px;">
        <input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
        <button type="submit" class="btn-ok">+ Gerar nova chave</button>
      </form>
      <table>
        <thead><tr><th>Chave</th><th>Criada em</th><th>Expira em</th><th>Status</th><th>Ação</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </div>
</body></html>"""

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
    if limited:
        log_admin_action(conn, request, "login", detail="rate_limited", success=False)
        conn.close()
        return HTMLResponse(render_login_page("Muitas tentativas."), status_code=429)
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        log_admin_action(conn, request, "login", detail="senha_incorreta", success=False)
        conn.close()
        return HTMLResponse(render_login_page("Senha incorreta"))
    log_admin_action(conn, request, "login", success=True)
    conn.close()
    csrf_token = secrets.token_urlsafe(32)
    token = serializer.dumps({"ok": True, "csrf": csrf_token})
    resp = RedirectResponse(url="/admin", status_code=303)
    resp.set_cookie("admin_session", token, httponly=True, max_age=60*60*8, secure=True, samesite="lax")
    return resp

@app.get("/admin/logout")
def logout(request: Request):
    conn = get_db()
    token = request.cookies.get("admin_session")
    if token:
        try:
            if serializer.loads(token).get("ok"):
                log_admin_action(conn, request, "logout", success=True)
        except BadSignature:
            pass
    conn.close()
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

    # Conta quantos machine_id distintos compartilham cada hardware_fingerprint.
    # Se um fingerprint aparece em 2+ machine_id diferentes (e não vazio), é sinal
    # de que a MESMA máquina física está gerando "novos" machine_id - possível
    # tentativa de burlar o limite de MAX_MACHINES_PER_KEY trocando MAC/VM.
    fingerprint_counts = {}
    for r_raw in rows:
        r = row_to_dict(r_raw, LICENSE_COLUMNS)
        fp = (r.get("hardware_fingerprint") or "").strip()
        if fp:
            fingerprint_counts[fp] = fingerprint_counts.get(fp, 0) + 1

    items = []
    for r_raw in rows:
        r = row_to_dict(r_raw, LICENSE_COLUMNS)
        license_expires = parse_dt(r["license_expires"])
        trial_expires = parse_dt(r["trial_expires"])
        if r["revoked"]: status, status_class = "revogado", "revogado"
        elif license_expires and license_expires > now: status, status_class = "licenciado", "licenciado"
        elif trial_expires and trial_expires > now: status, status_class = "em teste", "trial"
        else: status, status_class = "expirado", "expirado" # ✅ Compatível com trial_expired
        fp = (r.get("hardware_fingerprint") or "").strip()
        items.append({
            "machine_id": r["machine_id"], "machine_name": r["machine_name"] or "(sem nome)",
            "license_key": r["license_key"] or "-", "last_seen": (r["last_seen"] or "")[:16].replace("T", " "),
            "status": status, "status_class": status_class,
            "license_expires": license_expires.strftime("%d/%m/%Y %H:%M") if license_expires else "-",
            "trial_expires": trial_expires.strftime("%d/%m/%Y %H:%M") if trial_expires else "-",
            "hw_fingerprint": fp[:12] + "…" if fp else "-",
            "hw_suspect": fingerprint_counts.get(fp, 0) >= 2,
        })
    return HTMLResponse(render_dashboard_page(items, session.get("csrf", "")))

@app.post("/admin/license/toggle-revoke")
def toggle_license_revoke(request: Request, machine_id: str = Form(...), session=Depends(require_admin_csrf)):
    conn = get_db()
    row = row_to_dict(conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (machine_id,)).fetchone(), LICENSE_COLUMNS)
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Máquina não encontrada.")
    new_value = 0 if row["revoked"] else 1
    conn.execute("UPDATE licenses SET revoked = ? WHERE machine_id = ?", (new_value, machine_id))
    conn.commit()
    log_admin_action(conn, request, "revoke_licenca" if new_value else "reativar_licenca", detail=machine_id, success=True)
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)

@app.get("/admin/keys", response_class=HTMLResponse)
def list_keys(nova: str = "", session=Depends(require_admin)):
    conn = get_db()
    _ensure_core_tables(conn)
    rows = conn.execute("SELECT * FROM license_keys ORDER BY created DESC").fetchall()
    conn.close()
    keys = [row_to_dict(r, KEY_COLUMNS) for r in rows]
    message = f"Nova chave gerada: {nova}" if nova else ""
    return HTMLResponse(render_keys_page(keys, session.get("csrf", ""), message=message))

@app.post("/admin/keygen")
def keygen(request: Request, session=Depends(require_admin_csrf)):
    conn = get_db()
    _ensure_core_tables(conn)
    # Colisão de chave é praticamente impossível (3 blocos de 4 chars alfanuméricos),
    # mas o loop garante uma nova tentativa no caso extremamente improvável de já existir.
    new_key = generate_key()
    for _ in range(5):
        exists = conn.execute("SELECT 1 FROM license_keys WHERE license_key = ?", (new_key,)).fetchone()
        if not exists:
            break
        new_key = generate_key()
    conn.execute(
        "INSERT INTO license_keys (license_key, created, expires, revoked, max_machines) VALUES (?, ?, ?, 0, ?)",
        (new_key, now_utc().isoformat(), None, MAX_MACHINES_PER_KEY),
    )
    conn.commit()
    log_admin_action(conn, request, "gerar_chave", detail=new_key, success=True)
    conn.close()
    return RedirectResponse(url=f"/admin/keys?nova={new_key}", status_code=303)

@app.post("/admin/keys/toggle-revoke")
def toggle_key_revoke(request: Request, license_key: str = Form(...), session=Depends(require_admin_csrf)):
    conn = get_db()
    row = row_to_dict(conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (license_key,)).fetchone(), KEY_COLUMNS)
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Chave não encontrada.")
    new_value = 0 if row["revoked"] else 1
    conn.execute("UPDATE license_keys SET revoked = ? WHERE license_key = ?", (new_value, license_key))
    conn.commit()
    log_admin_action(conn, request, "revoke_chave" if new_value else "reativar_chave", detail=license_key, success=True)
    conn.close()
    return RedirectResponse(url="/admin/keys", status_code=303)

# ============================================================================
# API ADMINISTRATIVA (JSON) - para o script gerenciador_local.py
# Autenticação por header (X-Admin-Api-Token), não por cookie/CSRF, porque é
# chamada máquina-a-máquina, não por navegador. Usa o mesmo rate limit e o
# mesmo log de auditoria do painel web.
# ============================================================================

def require_admin_api(request: Request) -> None:
    conn = get_db()
    if _is_rate_limited(conn, "admin_api", _client_ip(request), LOGIN_MAX_ATTEMPTS):
        log_admin_action(conn, request, "admin_api", detail="rate_limited", success=False)
        conn.close()
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde um minuto.")
    token = request.headers.get("x-admin-api-token", "")
    if not token or not hmac.compare_digest(token, ADMIN_API_TOKEN):
        log_admin_action(conn, request, "admin_api", detail="token_invalido", success=False)
        conn.close()
        raise HTTPException(status_code=401, detail="Token invalido ou ausente.")
    conn.close()

@app.get("/admin/api/keys")
def api_list_keys(_=Depends(require_admin_api)):
    conn = get_db()
    _ensure_core_tables(conn)
    rows = conn.execute("SELECT * FROM license_keys ORDER BY created DESC").fetchall()
    conn.close()
    return {"keys": [row_to_dict(r, KEY_COLUMNS) for r in rows]}

@app.post("/admin/api/keygen")
def api_keygen(request: Request, _=Depends(require_admin_api)):
    conn = get_db()
    _ensure_core_tables(conn)
    new_key = generate_key()
    for _ in range(5):
        exists = conn.execute("SELECT 1 FROM license_keys WHERE license_key = ?", (new_key,)).fetchone()
        if not exists:
            break
        new_key = generate_key()
    conn.execute(
        "INSERT INTO license_keys (license_key, created, expires, revoked, max_machines) VALUES (?, ?, ?, 0, ?)",
        (new_key, now_utc().isoformat(), None, MAX_MACHINES_PER_KEY),
    )
    conn.commit()
    log_admin_action(conn, request, "gerar_chave_api", detail=new_key, success=True)
    conn.close()
    return {"license_key": new_key, "created": now_utc().isoformat(), "max_machines": MAX_MACHINES_PER_KEY}

# ✅ NOVO: rotas que o gerenciador_local.py já esperava (ADMIN_RENEW_PATH /
# ADMIN_REVOKE_PATH) mas que ainda não existiam no servidor - por isso
# "Renovar" e "Cancelar" sempre davam 404. Usam a mesma autenticação por
# token (require_admin_api) e o mesmo log de auditoria das demais rotas /admin/api/*.

class RenewKeyRequest(BaseModel):
    # O cliente manda os dois nomes (dias/days) só por compatibilidade; qualquer
    # um dos dois que vier preenchido é usado.
    dias: Optional[int] = None
    days: Optional[int] = None

@app.post("/admin/api/keys/{key}/renew")
def api_renew_key(key: str, body: RenewKeyRequest, request: Request, _=Depends(require_admin_api)):
    dias = body.dias or body.days
    if not dias or dias <= 0:
        raise HTTPException(status_code=422, detail="Informe 'dias' (ou 'days') maior que zero.")
    conn = get_db()
    _ensure_core_tables(conn)
    row = row_to_dict(conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (key,)).fetchone(), KEY_COLUMNS)
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Chave não encontrada.")
    now = now_utc()
    current_expires = parse_dt(row["expires"])
    # Se a chave ainda não venceu, soma a partir do vencimento atual (não perde
    # os dias que já restavam); se já venceu (ou nunca teve data), conta a
    # partir de agora.
    base = current_expires if (current_expires and current_expires > now) else now
    new_expires = base + timedelta(days=dias)
    # Renovar uma chave revogada também a reativa - é o comportamento esperado
    # de "renovar assinatura" no botão do gerenciador local.
    conn.execute("UPDATE license_keys SET expires = ?, revoked = 0 WHERE license_key = ?",
                 (new_expires.isoformat(), key))
    conn.commit()
    log_admin_action(conn, request, "renovar_chave_api", detail=f"{key} +{dias}d", success=True)
    conn.close()
    return {"license_key": key, "expires": new_expires.isoformat(), "dias_adicionados": dias}

@app.post("/admin/api/keys/{key}/revoke")
def api_revoke_key(key: str, request: Request, _=Depends(require_admin_api)):
    conn = get_db()
    _ensure_core_tables(conn)
    row = row_to_dict(conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (key,)).fetchone(), KEY_COLUMNS)
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Chave não encontrada.")
    conn.execute("UPDATE license_keys SET revoked = 1 WHERE license_key = ?", (key,))
    conn.commit()
    log_admin_action(conn, request, "revoke_chave_api", detail=key, success=True)
    conn.close()
    return {"license_key": key, "revoked": True}

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"service": "EADMT4-PRO License Server", "status": "ok"}
