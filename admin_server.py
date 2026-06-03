"""
Hermes WebUI User Admin Panel

A standalone management site for multi-user WebUI instances.
Reads/writes the same users.json that the WebUI uses, so changes
are effective immediately without restarting the WebUI server.

Usage:
    HERMES_WEBUI_STATE_DIR=/path/to/.webui_state \
    python3 admin_server.py [--port 8790]

Configuration:
    HERMES_WEBUI_STATE_DIR  — path to the WebUI state directory
                               (contains users.json)
    ADMIN_PASSWORD           — password to access this admin panel itself
                               (defaults to "admin")
"""

import argparse
import hashlib
import hmac
import html
import http.server
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────

STATE_DIR = Path(os.environ.get('YML_AGENT_STATE_DIR', '/data/project/yml/hermes-webui/.webui_state')).expanduser().resolve()
# Workspaces are created under the parent of STATE_DIR (the WebUI root),
# not inside .webui_state itself.
WORKSPACE_ROOT = STATE_DIR.parent
USERS_FILE = STATE_DIR / 'users.json'
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin')
DEFAULT_PORT = 8790

# ── Password hashing (same scheme as WebUI) ─────────────────────────────

def _signing_key():
    """Return the signing key, shared with the WebUI server."""
    import secrets
    key_file = STATE_DIR / '.signing_key'
    try:
        if key_file.exists():
            raw = key_file.read_bytes()
            if len(raw) >= 32:
                return raw[:32]
    except Exception:
        pass
    # Generate if missing
    key = secrets.token_bytes(32)
    try:
        key_file.write_bytes(key)
    except Exception:
        pass
    return key


def _hash_user_password(username: str, password: str) -> str:
    """PBKDF2 hash — identical to api/auth.py _hash_user_password()."""
    salt = _signing_key()
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        f'{username}:{password}'.encode(),
        salt,
        600_000,
    )
    return dk.hex()


# ── User data store ──────────────────────────────────────────────────────

_users_lock = threading.Lock()


def _load_users() -> dict:
    """Load users.json, creating it from webui_users.json + config.yaml if needed."""
    if USERS_FILE.exists():
        try:
            return json.loads(USERS_FILE.read_text(encoding='utf-8'))
        except Exception as e:
            logger.error("Failed to read users.json: %s", e)
            return {"users": []}

    # ── Migration: merge webui_users.json + config.yaml ──────────────────
    # webui_users.json may have redacted passwords (***).  config.yaml has
    # the original plaintext or stored hashes.  Merge both sources, preferring
    # config.yaml for passwords.

    # 1. Load config.yaml webui_users (source of truth for passwords)
    cfg_users_map = {}  # username -> full user dict from config.yaml
    try:
        import yaml
        cfg_path = Path(os.environ.get('HERMES_HOME', str(STATE_DIR.parent))) / 'config.yaml'
        if cfg_path.exists():
            cfg = yaml.safe_load(cfg_path.read_text(encoding='utf-8')) or {}
            for u in (cfg.get('webui_users') or []):
                uname = u.get('username', '')
                if uname:
                    cfg_users_map[uname.lower()] = u
    except Exception as e:
        logger.debug("Failed to load config.yaml for migration: %s", e)

    # 2. Load webui_users.json (has workspace + profile info)
    legacy = STATE_DIR / 'webui_users.json'
    if not legacy.exists() and not cfg_users_map:
        return {"users": []}

    now = datetime.now(timezone.utc).isoformat()
    data = {"users": []}

    # Merge: iterate legacy first, then add any config.yaml-only users
    seen_usernames = set()
    if legacy.exists():
        try:
            legacy_users = json.loads(legacy.read_text(encoding='utf-8'))
            for u in legacy_users:
                uname = u.get('username', '')
                if not uname:
                    continue
                key = uname.lower()
                if key in seen_usernames:
                    continue
                seen_usernames.add(key)

                # Prefer config.yaml password hash (it may have plaintext → we'll hash it)
                cfg_u = cfg_users_map.get(key)
                if cfg_u:
                    pw_hash = cfg_u.get('password_hash', '')
                    raw_pw = cfg_u.get('password', '')
                    if raw_pw and not pw_hash:
                        pw_hash = _hash_user_password(uname, raw_pw)
                else:
                    pw_hash = u.get('password_hash', '')

                data["users"].append({
                    "username": uname,
                    "password_hash": pw_hash,
                    "profile": u.get("profile", uname),
                    "workspaces": u.get("workspace") and [u["workspace"]] or [],
                    "created_at": now,
                })
        except Exception as e:
            logger.error("Failed to migrate webui_users.json: %s", e)

    # 3. Add config.yaml-only users (not in legacy file)
    for key, cfg_u in cfg_users_map.items():
        if key in seen_usernames:
            continue
        uname = cfg_u.get('username', '')
        if not uname:
            continue
        seen_usernames.add(key)

        pw_hash = cfg_u.get('password_hash', '')
        raw_pw = cfg_u.get('password', '')
        if raw_pw and not pw_hash:
            pw_hash = _hash_user_password(uname, raw_pw)

        ws = cfg_u.get('workspace')
        data["users"].append({
            "username": uname,
            "password_hash": pw_hash,
            "profile": cfg_u.get('profile', uname),
            "workspaces": [ws] if ws else [],
            "created_at": now,
        })

    if data["users"]:
        _save_users(data)
        logger.info("Migrated %d users from webui_users.json + config.yaml", len(data["users"]))

    return data


def _save_users(data: dict) -> None:
    """Persist users.json atomically."""
    tmp = USERS_FILE.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    tmp.rename(USERS_FILE)


def find_user(username: str) -> dict | None:
    with _users_lock:
        data = _load_users()
    for u in data.get("users", []):
        if u.get("username", "").lower() == username.lower():
            return u
    return None


def create_user(username: str, password: str, workspaces: list[str], profile: str = None) -> dict | None:
    """Create a user. Returns error dict on failure, None on success."""
    if not username or not password:
        return {"error": "Username and password are required"}

    if find_user(username):
        return {"error": f"User '{username}' already exists"}

    profile = profile or username
    now = datetime.now(timezone.utc).isoformat()

    # Auto-default workspace if none specified
    if not workspaces or (isinstance(workspaces, list) and not workspaces[0].strip()):
        workspaces = [str(WORKSPACE_ROOT / f"workspace_{username}")]

    # Auto-create workspace directories
    created = []
    for ws in workspaces:
        try:
            ws_path = Path(ws).expanduser().resolve()
            ws_path.mkdir(parents=True, exist_ok=True)
            created.append(str(ws_path))
        except Exception as e:
            return {"error": f"Failed to create workspace '{ws}': {e}"}

    user = {
        "username": username,
        "password_hash": _hash_user_password(username, password),
        "profile": profile,
        "workspaces": created,
        "created_at": now,
    }

    # Also symlink base config.yaml into the profile directory so
    # resolve_runtime_provider (which reads HERMES_HOME/config.yaml) can
    # find provider/model settings for this profile.
    try:
        profile_cfg_dir = STATE_DIR.parent / '.hermes_test' / 'profiles' / profile
        profile_cfg_dir.mkdir(parents=True, exist_ok=True)
        profile_cfg = profile_cfg_dir / 'config.yaml'
        base_cfg = STATE_DIR.parent / '.hermes_test' / 'config.yaml'
        if base_cfg.exists() and not profile_cfg.exists():
            profile_cfg.symlink_to(base_cfg.resolve())
    except Exception:
        pass

    with _users_lock:
        data = _load_users()
        data["users"].append(user)
        _save_users(data)

    # Also update config.yaml for WebUI compatibility
    _update_config_yaml()

    logger.info("User created: %s with workspaces %s", username, created)
    return None


def delete_user(username: str) -> dict | None:
    with _users_lock:
        data = _load_users()
        new_users = [u for u in data["users"] if u.get("username", "").lower() != username.lower()]
        if len(new_users) == len(data["users"]):
            return {"error": f"User '{username}' not found"}
        if len(new_users) == 0:
            return {"error": "Cannot delete the last user"}
        data["users"] = new_users
        _save_users(data)
    _update_config_yaml()
    logger.info("User deleted: %s", username)
    return None


def change_password(username: str, new_password: str) -> dict | None:
    if not new_password:
        return {"error": "New password is required"}

    with _users_lock:
        data = _load_users()
        for u in data["users"]:
            if u.get("username", "").lower() == username.lower():
                u["password_hash"] = _hash_user_password(username, new_password)
                _save_users(data)
                break
        else:
            return {"error": f"User '{username}' not found"}
    _update_config_yaml()
    logger.info("Password changed for user: %s", username)
    return None


def update_workspaces(username: str, workspaces: list[str]) -> dict | None:
    with _users_lock:
        data = _load_users()
        for u in data["users"]:
            if u.get("username", "").lower() == username.lower():
                # Create directories for new workspaces
                resolved = []
                for ws in workspaces:
                    try:
                        ws_path = Path(ws).expanduser().resolve()
                        ws_path.mkdir(parents=True, exist_ok=True)
                        resolved.append(str(ws_path))
                    except Exception as e:
                        return {"error": f"Failed to create workspace '{ws}': {e}"}
                u["workspaces"] = resolved
                _save_users(data)
                break
        else:
            return {"error": f"User '{username}' not found"}
    _update_config_yaml()
    logger.info("Workspaces updated for user: %s -> %s", username, resolved)
    return None


def list_users() -> list[dict]:
    """Return user list without password hashes."""
    data = _load_users()
    result = []
    for u in data.get("users", []):
        result.append({
            "username": u.get("username"),
            "profile": u.get("profile"),
            "workspaces": u.get("workspaces", []),
            "created_at": u.get("created_at"),
        })
    return result


def _update_config_yaml() -> None:
    """Sync users.json back to config.yaml webui_users for WebUI compatibility.

    Config path is fixed relative to STATE_DIR:
        STATE_DIR.parent / '.hermes_test' / 'config.yaml'
    This avoids env-var conflicts with other WebUI instances (e.g. port 8082).
    """
    cfg_path = STATE_DIR.parent / '.hermes_test' / 'config.yaml'
    if not cfg_path.exists():
        logger.warning("config.yaml not found at %s — skipping sync", cfg_path)
        return

    try:
        import yaml
        data = _load_users()
        users_section = []
        for u in data.get("users", []):
            entry = {
                "username": u["username"],
                "password_hash": u.get("password_hash", ""),
                "profile": u.get("profile", u["username"]),
            }
            ws_list = u.get("workspaces", [])
            if ws_list:
                entry["workspace"] = ws_list[0]  # Primary workspace
            users_section.append(entry)

        cfg_text = cfg_path.read_text(encoding='utf-8')
        cfg = yaml.safe_load(cfg_text) or {}
        # Merge: preserve config-only users not managed by users.json
        existing = cfg.get("webui_users") or []
        json_usernames = {u["username"].lower() for u in users_section}
        preserved = [u for u in existing if u.get("username", "").lower() not in json_usernames]
        cfg["webui_users"] = preserved + users_section
        cfg_path.write_text(yaml.dump(cfg, default_flow_style=False, allow_unicode=True), encoding='utf-8')
        logger.debug("Synced %d users to config.yaml (%s)", len(cfg["webui_users"]), cfg_path)
    except Exception as e:
        logger.error("Failed to sync config.yaml: %s", e)


# ── Admin authentication ─────────────────────────────────────────────────

_admin_sessions: dict[str, float] = {}
_ADMIN_TOKEN_TTL = 3600 * 24  # 24 hours


def _generate_admin_token() -> str:
    import secrets
    token = secrets.token_hex(16)
    _admin_sessions[token] = time.time()
    return token


def _validate_admin_token(cookie_val: str | None) -> bool:
    if not cookie_val:
        return False
    if cookie_val not in _admin_sessions:
        return False
    # Clean expired sessions
    if time.time() - _admin_sessions.get(cookie_val, 0) > _ADMIN_TOKEN_TTL:
        del _admin_sessions[cookie_val]
        return False
    _admin_sessions[cookie_val] = time.time()
    return True


def _parse_admin_cookie(handler) -> str | None:
    cookie_header = handler.headers.get('Cookie', '')
    if not cookie_header:
        return None
    import http.cookies
    cookie = http.cookies.SimpleCookie()
    try:
        cookie.load(cookie_header)
    except http.cookies.CookieError:
        return None
    m = cookie.get('admin_token')
    return m.value if m else None


# ── HTTP Handler ─────────────────────────────────────────────────────────

ADMIN_PAGE = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hermes User Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f172a;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;min-height:100vh}
.header{background:#1e293b;padding:16px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #334155}
.header h1{font-size:18px;font-weight:600;color:#f1f5f9}
.header .logout{color:#f472b6;background:#1e293b;border:1px solid #475569;cursor:pointer;font-size:13px;font-weight:500;padding:6px 14px;border-radius:6px;display:inline-flex;align-items:center;gap:6px;transition:all 0.15s}
.header .logout:hover{background:#334155;color:#f9a8d4;border-color:#f472b6}
.container{max-width:960px;margin:0 auto;padding:24px}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:60vh}
.login-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:32px;width:340px;text-align:center}
.login-card h2{margin-bottom:20px;font-size:16px}
.login-card input{width:100%;padding:10px 14px;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#e2e8f0;font-size:14px;outline:none;margin-bottom:14px}
.login-card button{width:100%;padding:10px;border-radius:8px;border:none;background:#3b82f6;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
.login-card button:hover{background:#2563eb}
.login-card .err{color:#f87171;font-size:12px;margin-top:8px;display:none}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}
.stat-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;text-align:center}
.stat-card .num{font-size:28px;font-weight:700;color:#3b82f6}
.stat-card .label{font-size:12px;color:#94a3b8;margin-top:4px}
.toolbar{display:flex;gap:12px;margin-bottom:16px;align-items:center}
.toolbar button{padding:8px 16px;border-radius:8px;border:none;background:#3b82f6;color:#fff;font-size:13px;font-weight:600;cursor:pointer}
.toolbar button:hover{background:#2563eb}
.toolbar input{padding:8px 14px;border-radius:8px;border:1px solid #475569;background:#1e293b;color:#e2e8f0;font-size:13px;outline:none;flex:1}
table{width:100%;border-collapse:collapse;background:#1e293b;border:1px solid #334155;border-radius:8px;overflow:hidden}
th{background:#334155;padding:10px 14px;text-align:left;font-size:12px;color:#94a3b8;font-weight:600}
td{padding:10px 14px;font-size:13px;border-top:1px solid #334155}
tr:hover td{background:#1e293bee}
.ws-tags{display:flex;flex-wrap:wrap;gap:4px}
.ws-tag{background:#1e3a5f;color:#7dd3fc;padding:2px 8px;border-radius:4px;font-size:11px;word-break:break-all}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge-blue{background:#1e3a5f;color:#7dd3fc}
.badge-gray{background:#334155;color:#94a3b8}
.actions{display:flex;gap:6px}
.actions button{padding:4px 10px;border-radius:6px;border:none;font-size:12px;cursor:pointer;font-weight:500}
.btn-edit{background:#1e3a5f;color:#7dd3fc}
.btn-edit:hover{background:#1e4a7f}
.btn-del{background:#450a0a;color:#fca5a5}
.btn-del:hover{background:#7f1d1d}
.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:100}
.modal{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;width:480px;max-width:90vw}
.modal h3{margin-bottom:16px;font-size:16px}
.modal label{display:block;font-size:12px;color:#94a3b8;margin-bottom:4px;margin-top:12px}
.modal input,.modal textarea{width:100%;padding:8px 12px;border-radius:6px;border:1px solid #475569;background:#0f172a;color:#e2e8f0;font-size:13px;outline:none;font-family:monospace}
.modal textarea{min-height:60px;resize:vertical}
.modal .modal-actions{display:flex;gap:8px;margin-top:16px;justify-content:flex-end}
.modal .modal-actions button{padding:8px 16px;border-radius:6px;border:none;font-size:13px;cursor:pointer;font-weight:600}
.modal .btn-primary{background:#3b82f6;color:#fff}
.modal .btn-primary:hover{background:#2563eb}
.modal .btn-cancel{background:#334155;color:#94a3b8}
.modal .btn-cancel:hover{background:#475569}
.toast{position:fixed;top:16px;right:16px;padding:12px 20px;border-radius:8px;font-size:13px;z-index:200;opacity:0;transition:opacity .2s}
.toast.show{opacity:1}
.toast-ok{background:#065f46;color:#6ee7b7;border:1px solid #059669}
.toast-err{background:#7f1d1d;color:#fca5a5;border:1px solid #dc2626}
</style></head><body>
<div id="app"></div>
<div class="toast" id="toast"></div>
<script>
""" + r"""
var API = ''; // base URL

function toast(msg, ok) {
  var el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast show ' + (ok ? 'toast-ok' : 'toast-err');
  setTimeout(function() { el.className = 'toast'; }, 3000);
}

function api(method, path, body) {
  var opts = { method: method, headers: {'Content-Type':'application/json'}, credentials:'include' };
  if (body) opts.body = JSON.stringify(body);
  return fetch(API + path, opts).then(function(r) { return r.json().then(function(d) { return {ok:r.ok, data:d}; }); });
}

function isAdmin() {
  return document.cookie.includes('admin_token=');
}

function renderLogin() {
  var h = '<div class="login-wrap"><div class="login-card">';
  h += '<h2>Hermes User Admin</h2>';
  h += '<input type="password" id="lpw" placeholder="Admin Password" autofocus>';
  h += '<button onclick="doLogin()">Sign in</button>';
  h += '<div class="err" id="lerr"></div>';
  h += '</div></div>';
  document.getElementById('app').innerHTML = h;
  document.getElementById('lpw').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') doLogin();
  });
}

async function doLogin() {
  var pw = document.getElementById('lpw').value;
  var r = await api('POST', '/api/admin/login', {password: pw});
  if (r.ok) { init(); }
  else { var el = document.getElementById('lerr'); el.textContent = r.data.error || 'Wrong password'; el.style.display = 'block'; }
}

function logout() {
  api('POST', '/api/admin/logout');
  renderLogin();
}

async function init() {
  if (!isAdmin()) { renderLogin(); return; }
  var r = await api('GET', '/api/users');
  if (!r.ok) { logout(); return; }
  renderDashboard(r.data.users || []);
}

function esc(s) { return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function renderDashboard(users) {
  var totalWs = users.reduce(function(s,u){ return s + (u.workspaces||[]).length; }, 0);
  var h = '<div class="header"><h1>Hermes User Admin</h1><button class="logout" onclick="logout()">&#x1f6aa; Logout</button></div>';
  h += '<div class="container">';
  h += '<div class="stats">';
  h += '<div class="stat-card"><div class="num">'+users.length+'</div><div class="label">Total Users</div></div>';
  h += '<div class="stat-card"><div class="num">'+totalWs+'</div><div class="label">Workspaces</div></div>';
  h += '<div class="stat-card"><div class="num">STATE_DIR_PLACEHOLDER</div><div class="label">State Dir</div></div>';
  h += '</div>';
  h += '<div class="toolbar">';
  h += '<button onclick="showCreate()">+ Create User</button>';
  h += '<input type="text" id="search" placeholder="Search users..." oninput="filterUsers()">';
  h += '</div>';
  h += '<table><thead><tr><th>Username</th><th>Profile</th><th>Workspaces</th><th>Created</th><th>Actions</th></tr></thead><tbody>';
  users.forEach(function(u) {
    var wsHtml = (u.workspaces||[]).map(function(w){return '<span class="ws-tag">'+esc(w)+'</span>';}).join('');
    var created = u.created_at ? new Date(u.created_at).toLocaleDateString() : '-';
    h += '<tr data-name="'+esc(u.username).toLowerCase()+'">';
    h += '<td><span class="badge badge-blue">'+esc(u.username)+'</span></td>';
    h += '<td><span class="badge badge-gray">'+esc(u.profile)+'</span></td>';
    h += '<td><div class="ws-tags">'+wsHtml+'</div></td>';
    h += '<td>'+created+'</td>';
    h += '<td class="actions">';
    h += '<button class="btn-edit" onclick="showEdit(\''+esc(u.username)+'\')">Edit</button>';
    h += '<button class="btn-del" onclick="showDelete(\''+esc(u.username)+'\')">Delete</button>';
    h += '</td></tr>';
  });
  h += '</tbody></table></div>';
  document.getElementById('app').innerHTML = h;
}

function filterUsers() {
  var q = (document.getElementById('search').value || '').toLowerCase();
  document.querySelectorAll('tbody tr').forEach(function(tr) {
    tr.style.display = tr.getAttribute('data-name').includes(q) ? '' : 'none';
  });
}

function showModal(html) {
  var overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.id = 'modalOverlay';
  overlay.innerHTML = '<div class="modal">'+html+'</div>';
  overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });
  document.body.appendChild(overlay);
}

function showCreate() {
  var h = '<h3>Create User</h3>';
  h += '<label>Username</label><input id="m_user" placeholder="e.g. charlie">';
  h += '<label>Password</label><input id="m_pass" type="password" placeholder="Set password">';
  h += '<label>Profile (default = username)</label><input id="m_profile" placeholder="Leave empty for default">';
  h += '<p style="color:#94a3b8;font-size:0.85em;margin-top:8px">Workspace will be auto-created as <code>workspace_&lt;username&gt;</code>.</p>';
  h += '<div class="modal-actions"><button class="btn-cancel" onclick="document.getElementById(\'modalOverlay\').remove()">Cancel</button>';
  h += '<button class="btn-primary" onclick="doCreate()">Create</button></div>';
  showModal(h);
}

async function doCreate() {
  var username = document.getElementById('m_user').value.trim();
  var password = document.getElementById('m_pass').value;
  var profile = document.getElementById('m_profile').value.trim() || null;
  // Workspace auto-generated as workspace_<username>
  var r = await api('POST', '/api/users/create', {username:username, password:password, workspaces:[], profile:profile});
  if (r.ok) { toast('User created: '+username, true); }
  else { toast(r.data.error || 'Failed', false); return; }
  document.getElementById('modalOverlay').remove();
  init();
}

function showEdit(username) {
  var h = '<h3>Edit User: '+esc(username)+'</h3>';
  h += '<label>Change Password (leave empty to keep)</label><input id="m_epass" type="password" placeholder="New password">';
  h += '<label>Workspace (auto-managed)</label><input id="m_ews" readonly style="background:#f1f5f9;color:#64748b;cursor:not-allowed">';
  h += '<div class="modal-actions"><button class="btn-cancel" onclick="document.getElementById(\'modalOverlay\').remove()">Cancel</button>';
  h += '<button class="btn-primary" onclick="doEdit(\''+esc(username)+'\')">Save</button></div>';
  showModal(h);
  // Load current workspaces
  api('GET', '/api/users').then(function(r) {
    r.data.users.forEach(function(u) {
      if (u.username === username) {
        document.getElementById('m_ews').value = (u.workspaces||[]).join('\n');
      }
    });
  });
}

async function doEdit(username) {
  var newPass = document.getElementById('m_epass').value;
  var err = null;
  if (newPass) {
    var r = await api('POST', '/api/users/change_password', {username:username, new_password:newPass});
    if (!r.ok) err = r.data.error;
  }
  if (err) { toast(err, false); return; }
  toast('Updated: '+username, true);
  document.getElementById('modalOverlay').remove();
  init();
}

function showDelete(username) {
  var h = '<h3>Delete User</h3>';
  h += '<p style="color:#94a3b8;margin-bottom:8px">Are you sure you want to delete <b style="color:#f472b6">'+esc(username)+'</b>? This cannot be undone.</p>';
  h += '<div class="modal-actions"><button class="btn-cancel" onclick="document.getElementById(\'modalOverlay\').remove()">Cancel</button>';
  h += '<button class="btn-primary" style="background:#dc2626" onclick="doDelete(\''+esc(username)+'\')">Delete</button></div>';
  showModal(h);
}

async function doDelete(username) {
  var r = await api('POST', '/api/users/delete', {username:username});
  if (r.ok) { toast('Deleted: '+username, true); }
  else { toast(r.data.error || 'Failed', false); return; }
  document.getElementById('modalOverlay').remove();
  init();
}

// Boot
if (!isAdmin()) renderLogin();
else init();
</script></body></html>"""


class JSONHandler(http.server.BaseHTTPRequestHandler):
    """Simple JSON response helper."""

    def log_message(self, format, *args):
        logger.info(format, *args)

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, text, status=200):
        body = text.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self) -> dict:
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode('utf-8'))

    def do_GET(self):
        parsed = self.path.split('?', 1)
        path = parsed[0]

        if path == '/' or path == '/index.html':
            page = ADMIN_PAGE.replace('STATE_DIR_PLACEHOLDER', html.escape(str(STATE_DIR.parent)))
            self.send_html(page)
            return

        if path == '/api/users':
            if not _validate_admin_token(_parse_admin_cookie(self)):
                return self.send_json({"error": "Unauthorized"}, 401)
            return self.send_json({"users": list_users()})

        return self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = self.path.split('?', 1)[0]

        if path == '/api/admin/login':
            body = self.read_body()
            if body.get('password') == ADMIN_PASSWORD:
                token = _generate_admin_token()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Set-Cookie', f'admin_token={token}; Path=/; Max-Age=86400; SameSite=Lax')
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            else:
                self.send_json({"error": "Wrong password"}, 401)
            return

        if path == '/api/admin/logout':
            token = _parse_admin_cookie(self)
            if token and token in _admin_sessions:
                del _admin_sessions[token]
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Set-Cookie', 'admin_token=; Path=/; Max-Age=0; SameSite=Lax')
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
            return

        if not _validate_admin_token(_parse_admin_cookie(self)):
            return self.send_json({"error": "Unauthorized"}, 401)

        body = self.read_body()

        if path == '/api/users/create':
            err = create_user(
                body.get('username', ''),
                body.get('password', ''),
                body.get('workspaces', []),
                body.get('profile'),
            )
            if err:
                return self.send_json(err, 400)
            return self.send_json({"ok": True})

        if path == '/api/users/delete':
            err = delete_user(body.get('username', ''))
            if err:
                return self.send_json(err, 400)
            return self.send_json({"ok": True})

        if path == '/api/users/change_password':
            err = change_password(body.get('username', ''), body.get('new_password', ''))
            if err:
                return self.send_json(err, 400)
            return self.send_json({"ok": True})

        if path == '/api/users/update_workspaces':
            err = update_workspaces(body.get('username', ''), body.get('workspaces', []))
            if err:
                return self.send_json(err, 400)
            return self.send_json({"ok": True})

        return self.send_json({"error": "Not found"}, 404)


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Hermes WebUI User Admin Panel')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port to listen on (default: 8790)')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
    parser.add_argument('--admin-password', default=None, help='Admin password (default: from ADMIN_PASSWORD env or "admin")')
    args = parser.parse_args()

    global ADMIN_PASSWORD
    if args.admin_password:
        ADMIN_PASSWORD = args.admin_password

    print(f"\n  Hermes User Admin Panel")
    print(f"  -----------------------")
    print(f"  State dir  : {STATE_DIR}")
    print(f"  Users file : {USERS_FILE}")
    print(f"  Port       : {args.port}")
    print(f"  Admin PW   : {'*' * len(ADMIN_PASSWORD)}")
    print()

    # Ensure users.json exists (triggers migration from webui_users.json or config.yaml)
    try:
        _load_users()
        logger.info("Loaded users.json (%d users)", len(_load_users().get("users", [])))
    except Exception as e:
        logger.error("Failed to load/migrate users: %s — creating empty", e)
        _save_users({"users": []})

    server = http.server.HTTPServer((args.host, args.port), JSONHandler)
    print(f"  Admin panel: http://localhost:{args.port}", flush=True)
    print(f"  Admin password: {ADMIN_PASSWORD}", flush=True)
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()


if __name__ == '__main__':
    main()
