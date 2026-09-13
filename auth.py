"""Role-based access control for owner/admin-only areas.

How it works
------------
The source of truth for a user's role is Clerk's *public metadata*
(`publicMetadata.role`), set from the Clerk Dashboard on the account(s)
that should have elevated access. We keep a local cache of that role in the
`clerk_users` table (see app.init_db) so we don't call the Clerk API on
every single request. The cache is refreshed automatically (see
CLERK_ROLE_CACHE_TTL below) whenever someone tries to reach a
role-protected route.

As a defense-in-depth measure (explicitly requested), access is also
restricted to a small allowlist of emails (OWNER_ALLOWED_EMAILS). A user
must satisfy BOTH conditions -- the right Clerk role AND an allowed email --
to be granted access. This means:
  * Flipping someone's role in Clerk alone isn't enough unless their email
    is also allowlisted.
  * An allowlisted email with no role set in Clerk metadata is still denied.

Setup required in Clerk
------------------------
1. Go to the Clerk Dashboard -> Users -> (the owner's account).
2. Under "Metadata" -> "Public metadata", add:
       { "role": "owner" }
3. Make sure CLERK_SECRET_KEY in your environment is valid (it's used to
   call the Clerk Backend API to read that metadata).
4. Sign out and back in (or just wait up to CLERK_ROLE_CACHE_TTL seconds) --
   the next request to a protected route will pull the fresh role.

Local (email/password) accounts can never satisfy this check: owner/admin
access requires signing in through Clerk, since that's where the role
metadata lives.
"""
import os
import time
from functools import wraps

from flask import current_app, g, jsonify, redirect, render_template, request, url_for

from db import get_db

try:
    from clerk_backend_api import Clerk

    CLERK_SDK_AVAILABLE = True
except ImportError:
    CLERK_SDK_AVAILABLE = False


def _parse_emails(value):
    return {email.strip().lower() for email in (value or "").split(",") if email.strip()}


# Restrict owner-only pages to a small allowlist, configurable via env.
OWNER_ALLOWED_EMAILS = _parse_emails(
    os.environ.get("OWNER_ALLOWED_EMAILS")
    or os.environ.get("ADMIN_ALLOWED_EMAIL")
    or "ayman.benkardoud@gmail.com"
)

# How long we trust the locally cached role before re-checking Clerk.
CLERK_ROLE_CACHE_TTL = int(os.environ.get("CLERK_ROLE_CACHE_TTL", "300"))

CLERK_SECRET_KEY = os.environ.get(
    "CLERK_SECRET_KEY",
    "sk_test_m4HZ56o1sqXkgvSkDhcVMXTLcGzXwCiPJdump1IjO2",
)

_clerk_client = None


def _get_clerk_client():
    global _clerk_client
    if _clerk_client is None and CLERK_SDK_AVAILABLE and CLERK_SECRET_KEY:
        _clerk_client = Clerk(bearer_auth=CLERK_SECRET_KEY)
    return _clerk_client


def sync_clerk_role(clerk_user_id):
    """Pull the authoritative role from Clerk's publicMetadata and cache it.

    Returns the fresh role string on success, or None if the sync could not
    be completed (missing SDK/key, network error, user not found, etc.).
    On failure we deliberately do NOT touch the cached value, so a
    transient Clerk outage doesn't silently downgrade -- or upgrade --
    anyone's access.
    """
    client = _get_clerk_client()
    if client is None:
        return None
    try:
        clerk_user = client.users.get(user_id=clerk_user_id)
        metadata = clerk_user.public_metadata or {}
        role = str(metadata.get("role") or "user").strip().lower()
    except Exception as exc:  # noqa: BLE001 - external API, keep the app alive
        current_app.logger.warning("Clerk role sync failed for %s: %s", clerk_user_id, exc)
        return None

    db = get_db()
    db.execute(
        "UPDATE clerk_users SET role = ?, role_synced_at = ? WHERE clerk_user_id = ?",
        (role, time.time(), clerk_user_id),
    )
    db.commit()
    return role


def _resolve_role():
    """Return the current user's role, refreshing from Clerk if stale."""
    if g.user is None:
        return None
    if g.user.get("type") != "clerk":
        # Local email/password accounts never carry a Clerk-verified role.
        return "user"

    db = get_db()
    row = db.execute(
        "SELECT role, role_synced_at FROM clerk_users WHERE clerk_user_id = ?",
        (g.user["id"],),
    ).fetchone()
    cached_role = (row["role"] if row and row["role"] else None) or g.user.get("role", "user")
    synced_at = row["role_synced_at"] if row else None

    is_stale = synced_at is None or (time.time() - synced_at) > CLERK_ROLE_CACHE_TTL
    if is_stale:
        fresh_role = sync_clerk_role(g.user["id"])
        if fresh_role is not None:
            return fresh_role
    return cached_role


def is_owner():
    """True if the current request's user passes the owner/admin gate."""
    if g.user is None or g.user.get("type") != "clerk":
        return False
    email = (g.user.get("email") or "").strip().lower()
    if OWNER_ALLOWED_EMAILS and email not in OWNER_ALLOWED_EMAILS:
        return False

    role = (_resolve_role() or "user").lower()
    return role in {"owner", "admin"}


def require_role(allowed_roles):
    """Reusable route decorator: @require_role(['owner']).

    Grants access only when ALL of the following hold:
      1. The user is signed in through Clerk.
      2. Their Clerk publicMetadata role is one of `allowed_roles`.
      3. Their email is on the OWNER_ALLOWED_EMAILS allowlist (if set).

    Anyone else gets a 401 (not authenticated) or 403 (authenticated but
    not authorized) on API routes, or a redirect / access_denied page on
    normal pages.
    """
    allowed = {role.strip().lower() for role in allowed_roles}

    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            is_api = request.path.startswith("/api/")

            if g.user is None:
                if is_api:
                    return jsonify({"success": False, "message": "Authentication required."}), 401
                return redirect(url_for("signin"))

            email = (g.user.get("email") or "").strip().lower()
            role = (_resolve_role() or "user").lower()
            is_clerk = g.user.get("type") == "clerk"
            email_ok = (not OWNER_ALLOWED_EMAILS) or (email in OWNER_ALLOWED_EMAILS)
            role_ok = role in allowed
            granted = is_clerk and email_ok and role_ok

            if not granted:
                current_app.logger.warning(
                    "Access denied: %s %s user=%s role=%s clerk=%s ip=%s",
                    request.method,
                    request.path,
                    email or "anonymous",
                    role,
                    is_clerk,
                    request.remote_addr,
                )
                if is_api:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "message": "Vous n'avez pas la permission d'accéder à cette ressource.",
                            }
                        ),
                        403,
                    )
                return render_template("access_denied.html", user_email=email), 403

            return view(*args, **kwargs)

        return wrapped_view

    return decorator
