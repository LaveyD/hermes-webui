"""
Access control for multi-user WebUI mode.

Provides workspace whitelist checks, session ownership checks,
and profile-switch interception.  In single-password mode every
function is a no-op, so routes.py can call these unconditionally.
"""

import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)


def _get_current_user(handler) -> dict | None:
    """Get current user info from the session store (NOT from cookie directly).

    Returns ``None`` if not multi-user mode, not authenticated, or no user metadata.
    """
    try:
        from api.auth import parse_cookie, get_session_user_info
        from api.config import is_multi_user_mode
    except ImportError:
        return None

    if not is_multi_user_mode():
        return None

    cookie_val = parse_cookie(handler)
    if not cookie_val:
        return None

    # Verify session is valid first
    if not cookie_val or '.' not in cookie_val:
        return None

    import hmac
    import hashlib
    import secrets
    from api.auth import _signing_key
    token, sig = cookie_val.rsplit('.', 1)
    expected_sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected_sig):
        return None

    info = get_session_user_info(cookie_val)
    if info and info.get('username'):
        return info

    return None


def send_json_response(handler, data: dict, status: int = 200):
    """Send a JSON response helper."""
    body = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Cache-Control', 'no-store')
    handler.end_headers()
    handler.wfile.write(body)


def get_user_allowed_workspaces(handler) -> list[Path]:
    """Return the current user's allowed workspace paths, or empty list."""
    user = _get_current_user(handler)
    if not user:
        return []
    return [Path(w).expanduser().resolve() for w in user.get('workspaces', [])]


def _is_workspace_allowed(candidate: Path, allowed: list[Path]) -> bool:
    """Check if a workspace path is within any of the allowed workspaces."""
    for root in allowed:
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            pass
    return False


def check_workspace_access(handler, workspace_path: str) -> Path | None:
    """Check if a workspace path is within the user's allowed workspaces.

    Returns the resolved Path on success, or None on failure (sends 403 response).
    """
    candidate = Path(workspace_path).expanduser().resolve()
    allowed = get_user_allowed_workspaces(handler)
    if _is_workspace_allowed(candidate, allowed):
        return candidate

    send_json_response(handler, {
        'error': f'Workspace access denied: {workspace_path} is not in your allowed workspaces'
    }, 403)
    return None


def check_session_ownership(handler, session_profile: str) -> bool:
    """Check if a session belongs to the current user.

    Returns True if allowed, or False (sends 403 response) if not.
    """
    user = _get_current_user(handler)
    if not user:
        return False

    user_profile = user.get('profile')
    if user_profile != session_profile:
        send_json_response(handler, {
            'error': 'Session access denied: this session belongs to another user'
        }, 403)
        return False

    return True


def block_terminal(handler):
    """Block terminal access in multi-user mode. Returns True if blocked."""
    try:
        from api.config import is_multi_user_mode
    except ImportError:
        return False

    if is_multi_user_mode():
        send_json_response(handler, {
            'error': 'Terminal access is disabled in multi-user mode'
        }, 403)
        return True
    return False


def block_profile_switch(handler):
    """Block profile switching in multi-user mode. Returns True if blocked."""
    try:
        from api.config import is_multi_user_mode
    except ImportError:
        return False

    if is_multi_user_mode():
        send_json_response(handler, {
            'error': 'Profile switching is disabled in multi-user mode'
        }, 403)
        return True
    return False


def check_workspace_ownership(handler, workspace_path: Path) -> Path:
    """Verify that the given workspace path belongs to the current user.

    In multi-user mode, raises PermissionError if the workspace is not in
    the user's allowed list.  In single-password mode returns the resolved
    path unconditionally (no-op).

    Returns the resolved workspace Path on success.
    """
    resolved = workspace_path.expanduser().resolve()
    allowed = get_user_allowed_workspaces(handler)
    if not allowed:
        # Not multi-user mode or not authenticated — pass through
        return resolved

    for root in allowed:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            pass

    raise PermissionError(
        f"Workspace '{workspace_path}' is not in your allowed workspaces"
    )


def safe_resolve_with_auth(root: Path, requested: str, handler) -> Path:
    """Resolve a relative path inside root with workspace ownership check.

    Combines path-traversal protection (safe_resolve) with multi-user
    workspace ownership validation.  Drop-in replacement for safe_resolve()
    in request handlers.

    Raises:
        ValueError: if path escapes root (.. traversal or symlink escape)
        PermissionError: if root is not owned by the current user (multi-user)
    """
    # 1. Validate workspace ownership first (short-circuit in multi-user)
    check_workspace_ownership(handler, root)

    # 2. Resolve and block traversal
    resolved = (root / requested).resolve()
    resolved.relative_to(root.resolve())
    return resolved


def safe_resolve_ws_with_auth(root: Path, requested: str, handler) -> Path:
    """Like workspace.py:safe_resolve_ws but with workspace ownership check.

    Full symlink-aware path resolution + traversal protection + multi-user
    ownership validation.  Use this in handlers that currently call
    safe_resolve_ws() (list_dir, read_file_content, upload).

    Raises:
        ValueError: on path traversal or blocked system dirs
        PermissionError: if root is not owned by the current user
    """
    import os
    from api.workspace import safe_resolve_ws

    # 1. Validate workspace ownership first
    check_workspace_ownership(handler, root)

    # 2. Resolve with full workspace.py logic (symlink + normpath checks)
    return safe_resolve_ws(root, requested)
