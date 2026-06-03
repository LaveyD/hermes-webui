"""Hermes Web UI -- API modules."""

import threading

# Per-request handler reference — set at the top of do_POST, read by
# workspace isolation checks that need to look up the current user from
# the session cookie.
_current_request_handler = threading.local()
