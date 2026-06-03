"""
Hermes Web UI -- Optional password authentication.
Off by default. Enable by setting HERMES_WEBUI_PASSWORD env var
or configuring a password in the Settings panel.
"""
import hashlib
import hmac
import http.cookies
import json
import logging
import os
import secrets
import tempfile
import time

from api.config import STATE_DIR, load_settings

logger = logging.getLogger(__name__)


# Default session TTL — 30 days. Kept as a module-level constant for backwards
# compatibility with downstream code and regression tests that import it.
# At runtime, prefer ``_resolve_session_ttl()`` which honours the env var and
# settings.json overrides; this constant is the floor / fallback.
SESSION_TTL = 86400 * 30  # 30 days


def _resolve_session_ttl() -> int:
    """Resolve session TTL from env > settings > default.

    Priority mirrors get_password_hash(): HERMES_WEBUI_SESSION_TTL env var
    first, then settings.json, falling back to ``SESSION_TTL`` (30 days).
    Clamped to [60s, 1 year] to prevent runaway cookies or self-lockout.
    """
    env_v = os.getenv('HERMES_WEBUI_SESSION_TTL', '').strip()
    if env_v.isdigit():
        val = int(env_v)
        if 60 <= val <= 86400 * 365:
            return val
    s = load_settings()
    v = s.get('session_ttl_seconds')
    if isinstance(v, int) and 60 <= v <= 86400 * 365:
        return v
    return SESSION_TTL


# ── Public paths (no auth required) ─────────────────────────────────────────
PUBLIC_PATHS = frozenset({
    '/login', '/health', '/favicon.ico', '/sw.js',
    '/api/auth/login', '/api/auth/status',
    '/manifest.json', '/manifest.webmanifest',
})

# Cookie names are scoped per-instance using the first 4 hex chars of
# MD5(STATE_DIR). This guarantees that two WebUI instances served from the
# same hostname (e.g. 8082 and 8789) never fight over the same cookie —
# each instance writes its own cookie bucket in the browser.
def _resolve_cookie_name(name_suffix: str = '') -> str:
    """Return an instance-scoped cookie name so multi-instance setups don't clash."""
    import hashlib
    from api.config import STATE_DIR
    prefix = hashlib.md5(str(STATE_DIR).encode()).hexdigest()[:4]
    base = f'hermes_{prefix}'
    if name_suffix:
        base += f'_{name_suffix}'
    return base


COOKIE_NAME = _resolve_cookie_name('session')
PROFILE_COOKIE_NAME = _resolve_cookie_name('profile')

_SESSIONS_FILE = STATE_DIR / '.sessions.json'


def _load_sessions() -> dict[str, dict | float]:
    """Load persisted sessions from STATE_DIR, pruning expired entries.

    Supports both the old format (token -> expiry float) and the new format
    (token -> {"exp": float, "username": str, ...}). Old entries are preserved
    as-is; new multi-user sessions carry rich metadata.
    """
    try:
        if _SESSIONS_FILE.exists():
            data = json.loads(_SESSIONS_FILE.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                raise ValueError('malformed sessions file — expected dict')
            now = time.time()
            result = {}
            for t, v in data.items():
                if not isinstance(t, str):
                    continue
                if isinstance(v, (int, float)) and v > now:
                    # Old format — keep as-is
                    result[t] = v
                elif isinstance(v, dict):
                    exp = v.get('exp')
                    if isinstance(exp, (int, float)) and exp > now:
                        result[t] = v
            return result
    except Exception as e:
        logger.debug("Failed to load sessions file, starting fresh: %s", e)
    return {}


def _save_sessions(sessions: dict[str, dict | float]) -> None:
    """Atomically persist sessions to STATE_DIR/.sessions.json (0600).

    Uses a temp file + os.replace() so a crash mid-write never leaves a
    truncated file.  Mirrors the same pattern as .signing_key persistence.
    """
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=STATE_DIR, suffix='.sessions.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(sessions, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, _SESSIONS_FILE)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        logger.debug("Failed to persist sessions: %s", e)


# Active sessions: token -> expiry timestamp (persisted across restarts via STATE_DIR)
_sessions = _load_sessions()

# ── Login rate limiter ──────────────────────────────────────────────────────
_LOGIN_ATTEMPTS_FILE = STATE_DIR / '.login_attempts.json'
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW = 60  # seconds


def _load_login_attempts() -> dict[str, list[float]]:
    """Load persisted login attempts from STATE_DIR, pruning expired entries."""
    try:
        if _LOGIN_ATTEMPTS_FILE.exists():
            data = json.loads(_LOGIN_ATTEMPTS_FILE.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                raise ValueError('malformed login-attempts file — expected dict')
            now = time.time()
            attempts: dict[str, list[float]] = {}
            for ip, raw_times in data.items():
                if not isinstance(ip, str) or not isinstance(raw_times, list):
                    continue
                fresh = [
                    float(t)
                    for t in raw_times
                    if isinstance(t, (int, float)) and now - float(t) < _LOGIN_WINDOW
                ]
                if fresh:
                    attempts[ip] = fresh
            return attempts
    except Exception as e:
        logger.debug("Failed to load login attempts file, starting fresh: %s", e)
    return {}


def _save_login_attempts(attempts: dict[str, list[float]]) -> None:
    """Atomically persist login attempts to STATE_DIR/.login_attempts.json (0600)."""
    try:
        _LOGIN_ATTEMPTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=_LOGIN_ATTEMPTS_FILE.parent, suffix='.login_attempts.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(attempts, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, _LOGIN_ATTEMPTS_FILE)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        logger.debug("Failed to persist login attempts: %s", e)


_login_attempts = _load_login_attempts()  # ip -> [timestamp, ...]


def _check_login_rate(ip: str) -> bool:
    """Return True if the IP is allowed to attempt login."""
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    # Prune old attempts
    attempts = [t for t in attempts if now - t < _LOGIN_WINDOW]
    if attempts:
        _login_attempts[ip] = attempts
    else:
        _login_attempts.pop(ip, None)
    _save_login_attempts(_login_attempts)
    return len(attempts) < _LOGIN_MAX_ATTEMPTS


def _record_login_attempt(ip: str) -> None:
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    attempts.append(now)
    _login_attempts[ip] = attempts
    _save_login_attempts(_login_attempts)


def _signing_key():
    """Return a random signing key, generating and persisting one on first call."""
    key_file = STATE_DIR / '.signing_key'
    try:
        if key_file.exists():
            raw = key_file.read_bytes()
            if len(raw) >= 32:
                return raw[:32]
    except Exception:
        logger.debug("Failed to read or access signing key file, using in-memory key")
    # Generate a new random key
    key = secrets.token_bytes(32)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(key)
        key_file.chmod(0o600)
    except Exception:
        logger.debug("Failed to persist signing key, using in-memory key only")
    return key


def _hash_password(password):
    """PBKDF2-SHA256 with 600k iterations (OWASP recommendation).
    Salt is the persisted random signing key, which is secret and unique per
    installation. This keeps the stored hash format a plain hex string
    (no format change to settings.json) while replacing the predictable
    STATE_DIR-derived salt from the original implementation."""
    salt = _signing_key()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
    return dk.hex()


def get_password_hash() -> str | None:
    """Return the active password hash, or None if auth is disabled.
    Priority: env var > settings.json."""
    env_pw = os.getenv('HERMES_WEBUI_PASSWORD', '').strip()
    if env_pw:
        return _hash_password(env_pw)
    settings = load_settings()
    return settings.get('password_hash') or None


def is_auth_enabled() -> bool:
    """True if a password is configured (env var or settings) or multi-user mode is active."""
    if get_password_hash() is not None:
        return True
    try:
        from api.config import is_multi_user_mode
        if is_multi_user_mode():
            return True
    except Exception:
        pass
    return False


def verify_password(plain) -> bool:
    """Verify a plaintext password against the stored hash."""
    expected = get_password_hash()
    if not expected:
        return False
    return hmac.compare_digest(_hash_password(plain), expected)


# ── Multi-user authentication ────────────────────────────────────────────────


def _hash_user_password(username: str, password: str) -> str:
    """PBKDF2 hash that includes the username as an additional salt component.

    This prevents hash collisions between users who happen to share a password.
    """
    salt = _signing_key()
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        f'{username}:{password}'.encode(),
        salt,
        600_000,
    )
    return dk.hex()


def find_user(username: str) -> dict | None:
    """Look up a user entry from the configured webui_users list.

    Returns None if not found or any error occurs during loading.
    Username matching is case-insensitive.
    """
    try:
        from api.config import load_webui_users
        for u in load_webui_users():
            if u.get('username', '').lower() == username.lower():
                return u
    except Exception:
        pass
    return None


def verify_multi_user_login(username: str, password: str) -> dict | None:
    """Authenticate a multi-user login attempt.

    Returns a dict with ``username``, ``profile``, ``workspace`` on success,
    or ``None`` on failure (wrong credentials or user not found).

    On first login with a plaintext ``password`` field the hash is
    computed and persisted so subsequent comparisons are fast and salted.
    """
    user = find_user(username)
    if user is None:
        return None

    # Prefer stored hash
    stored_hash = user.get('password_hash')
    if stored_hash:
        if not hmac.compare_digest(_hash_user_password(username, password), stored_hash):
            return None
    else:
        # Plaintext in config.yaml — compare and upgrade
        raw_pw = user.get('password', '')
        if not raw_pw or password != raw_pw:
            return None
        # Upgrade: compute hash and persist back
        new_hash = _hash_user_password(username, password)
        user['password_hash'] = new_hash
        user.pop('password', None)
        try:
            from api.config import load_webui_users, _save_webui_users
            all_users = load_webui_users()
            for u in all_users:
                if u.get('username', '').lower() == username.lower():
                    u['password_hash'] = new_hash
                    u.pop('password', None)
                    break
            _save_webui_users(all_users)
        except Exception:
            logger.debug("Failed to persist upgraded password hash for %s", username)

    return {
        'username': username,
        'profile': user.get('profile', username),
        'workspace': user.get('workspace'),
        'workspaces': user.get('workspaces', []),
    }


def set_multi_user_cookie(handler, cookie_value: str, profile_name: str) -> None:
    """Set both the auth session cookie and the profile cookie.

    The profile cookie tells every subsequent request which profile (and
    therefore which HERMES_HOME sub-directory) to use, giving per-user
    isolation of memory, sessions, skills, cron, and workspace.
    """
    set_auth_cookie(handler, cookie_value)
    from api.helpers import build_profile_cookie
    handler.send_header('Set-Cookie', build_profile_cookie(profile_name))


def create_session() -> str:
    """Create a new auth session. Returns signed cookie value."""
    token = secrets.token_hex(32)
    _sessions[token] = time.time() + _resolve_session_ttl()
    _save_sessions(_sessions)
    sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{token}.{sig}"


def create_session_with_user_info(
    *,
    username: str,
    profile: str,
    workspaces: list[str],
) -> str:
    """Create a multi-user auth session with user metadata.

    Returns signed cookie value.  The session store carries the username,
    profile, and workspace list so subsequent requests can derive the
    current user without a second config lookup.

    Persists the session both globally and in a per-user file so that
    sessions are scoped per-instance (via COOKIE_NAME which already uses
    MD5(STATE_DIR)) and per-user (via per-user session files).
    """
    token = secrets.token_hex(32)
    session_data = {
        'exp': time.time() + _resolve_session_ttl(),
        'username': username,
        'profile': profile,
        'workspaces': workspaces,
    }
    _sessions[token] = session_data
    _save_sessions(_sessions)
    # Also persist in per-user session file for user-scoped isolation
    try:
        _user_sessions_dir = STATE_DIR / '.user_sessions'
        _user_sessions_dir.mkdir(exist_ok=True)
        user_file = _user_sessions_dir / f'{username}.json'
        user_sessions = {}
        try:
            if user_file.exists():
                user_sessions = json.loads(user_file.read_text(encoding='utf-8'))
        except Exception:
            pass
        user_sessions[token] = session_data
        fd, tmp = tempfile.mkstemp(dir=_user_sessions_dir, suffix='.tmp')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(user_sessions, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, user_file)
    except Exception as e:
        logger.debug("Failed to persist per-user session for %s: %s", username, e)
    sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{token}.{sig}"


def get_session_user_info(cookie_value: str | None) -> dict | None:
    """Return the user metadata attached to a session cookie, or None.

    Returns ``None`` if the cookie is missing, invalid, expired, or from a
    single-password session that carries no user metadata.
    """
    if not cookie_value or '.' not in cookie_value:
        return None
    token, sig = cookie_value.rsplit('.', 1)
    expected_sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected_sig):
        return None
    entry = _sessions.get(token)
    if entry is None:
        return None
    # Handle old format (token -> float) — no metadata
    if isinstance(entry, (int, float)):
        return None
    if isinstance(entry, dict):
        exp = entry.get('exp')
        if exp is None or time.time() > exp:
            _sessions.pop(token, None)
            return None
        return {
            'username': entry.get('username'),
            'profile': entry.get('profile'),
            'workspaces': entry.get('workspaces', []),
        }
    return None


def _get_session_expiry(token: str) -> float | None:
    """Extract expiry timestamp from a session entry (handles old/new format)."""
    v = _sessions.get(token)
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, dict):
        return v.get('exp')
    return None


def _prune_expired_sessions():
    """Remove all expired session entries to prevent unbounded memory growth."""
    now = time.time()
    expired = [t for t in _sessions if now > _get_session_expiry(t)]
    if expired:
        for token in expired:
            _sessions.pop(token, None)
        _save_sessions(_sessions)


def verify_session(cookie_value) -> bool:
    """Verify a signed session cookie. Returns True if valid and not expired."""
    if not cookie_value or '.' not in cookie_value:
        return False
    _prune_expired_sessions()  # lazy cleanup on every verification attempt
    token, sig = cookie_value.rsplit('.', 1)
    expected_sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected_sig):
        return False
    expiry = _get_session_expiry(token)
    if not expiry or time.time() > expiry:
        _sessions.pop(token, None)
        return False
    return True


def invalidate_session(cookie_value) -> None:
    """Remove a session token."""
    if cookie_value and '.' in cookie_value:
        token = cookie_value.rsplit('.', 1)[0]
        if token in _sessions:
            _sessions.pop(token, None)
            _save_sessions(_sessions)


def parse_cookie(handler) -> str | None:
    """Extract the auth cookie from the request headers."""
    cookie_header = handler.headers.get('Cookie', '')
    if not cookie_header:
        return None
    cookie = http.cookies.SimpleCookie()
    try:
        cookie.load(cookie_header)
    except http.cookies.CookieError:
        return None
    morsel = cookie.get(COOKIE_NAME)
    return morsel.value if morsel else None


def check_auth(handler, parsed) -> bool:
    """Check if request is authorized. Returns True if OK.
    If not authorized, sends 401 (API) or 302 redirect (page) and returns False."""
    if not is_auth_enabled():
        return True
    # Public paths don't require auth
    if parsed.path in PUBLIC_PATHS or parsed.path.startswith('/static/') or parsed.path.startswith('/session/static/'):
        return True
    # Check session cookie
    cookie_val = parse_cookie(handler)
    if cookie_val and verify_session(cookie_val):
        return True
    # Not authorized
    if parsed.path.startswith('/api/'):
        handler.send_response(401)
        handler.send_header('Content-Type', 'application/json')
        handler.end_headers()
        handler.wfile.write(b'{"error":"Authentication required"}')
    else:
        handler.send_response(302)
        # Pass the original path as ?next= so login.js redirects back after auth.
        # SECURITY/CORRECTNESS: the inner `?` and `&` MUST be percent-encoded
        # when stuffed into the outer `?next=` parameter, otherwise:
        #   (a) multi-param query strings get truncated at the first inner `&`
        #       (e.g. `/api/sessions?limit=50&offset=0` would round-trip as
        #       just `/api/sessions?limit=50` after the browser parses the
        #       outer URL — `offset=0` becomes a separate top-level query
        #       parameter that the login page ignores).
        #   (b) attacker-controlled paths could inject a second `next=`
        #       parameter; per RFC 3986 the duplicate behaviour is undefined
        #       and parsers diverge (Python's parse_qs returns last-match,
        #       URLSearchParams returns first-match), opening a query-pollution
        #       footgun even though _safeNextPath() rejects most malicious
        #       shapes downstream.
        # Encoding the entire `path?query` blob with quote(safe='/') turns
        # `?` → `%3F` and `&` → `%26`, so the outer parameter holds exactly
        # one path-with-query string and `searchParams.get('next')` returns
        # the full original URL (the browser auto-decodes once).
        # (Opus pre-release advisor finding for v0.50.258.)
        import urllib.parse as _urlparse
        _path_with_query = parsed.path or '/'
        if parsed.query:
            _path_with_query += '?' + parsed.query
        # safe='/' keeps path separators readable; everything else (including
        # `?`, `&`, `=`) gets percent-encoded.
        _next = _urlparse.quote(_path_with_query, safe='/')
        handler.send_header('Location', 'login?next=' + _next)
        handler.end_headers()
    return False


def set_auth_cookie(handler, cookie_value) -> None:
    """Set the auth cookie on the response."""
    cookie = http.cookies.SimpleCookie()
    cookie[COOKIE_NAME] = cookie_value
    cookie[COOKIE_NAME]['httponly'] = True
    cookie[COOKIE_NAME]['samesite'] = 'Lax'
    cookie[COOKIE_NAME]['path'] = '/'
    cookie[COOKIE_NAME]['max-age'] = str(_resolve_session_ttl())
    # Set Secure flag when connection is HTTPS
    if getattr(handler.request, 'getpeercert', None) is not None or handler.headers.get('X-Forwarded-Proto', '') == 'https':
        cookie[COOKIE_NAME]['secure'] = True
    handler.send_header('Set-Cookie', cookie[COOKIE_NAME].OutputString())


def clear_auth_cookie(handler) -> None:
    """Clear the auth cookie on the response."""
    cookie = http.cookies.SimpleCookie()
    cookie[COOKIE_NAME] = ''
    cookie[COOKIE_NAME]['httponly'] = True
    cookie[COOKIE_NAME]['path'] = '/'
    cookie[COOKIE_NAME]['max-age'] = '0'
    handler.send_header('Set-Cookie', cookie[COOKIE_NAME].OutputString())
