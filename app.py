from flask import Flask, jsonify, request
from flask_cors import CORS
from groq import Groq
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import quote
import os
import re
import time
import requests
import secrets
import string
from argon2 import PasswordHasher
from datetime import datetime, timedelta, timezone

# ── ENV ──────────────────────────────────────────────────────────────
SUPABASE_URL         = os.environ.get("SUPABASE_URL")
SUPABASE_KEY         = os.environ.get("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_KEY")  # service role — same key, used for admin writes
ADMIN_SECRET         = os.environ.get("ADMIN_SECRET")  # Legacy — index.html panel
SETUP_SECRET  = os.environ.get("SETUP_SECRET")  # Unlocks setup.html

TOKEN_EXPIRY_DAYS = 3

# ── SUPABASE HELPER ──────────────────────────────────────────────────
SB_TIMEOUT = 10  # seconds — prevents cold-start hangs that cause silent 401s

def sb(table, method="GET", data=None, query=""):
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json"
    }
    url = f"{SUPABASE_URL}/rest/v1/{table}{query}"
    if method == "GET":
        return requests.get(url, headers=headers, timeout=SB_TIMEOUT)
    elif method == "POST":
        headers["Prefer"] = "return=representation"
        return requests.post(url, headers=headers, json=data, timeout=SB_TIMEOUT)
    elif method == "PATCH":
        headers["Prefer"] = "return=representation"
        return requests.patch(url, headers=headers, json=data, timeout=SB_TIMEOUT)
    elif method == "DELETE":
        return requests.delete(url, headers=headers, timeout=SB_TIMEOUT)

# ── SUPABASE ADMIN HELPER (bypasses RLS for admin writes) ────────────
def sb_admin(table, method="GET", data=None, query=""):
    headers = {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json"
    }
    url = f"{SUPABASE_URL}/rest/v1/{table}{query}"
    if method == "GET":
        return requests.get(url, headers=headers, timeout=SB_TIMEOUT)
    elif method == "POST":
        headers["Prefer"] = "return=representation"
        return requests.post(url, headers=headers, json=data, timeout=SB_TIMEOUT)
    elif method == "PATCH":
        headers["Prefer"] = "return=representation"
        return requests.patch(url, headers=headers, json=data, timeout=SB_TIMEOUT)
    elif method == "DELETE":
        return requests.delete(url, headers=headers, timeout=SB_TIMEOUT)

# ── VALIDATORS ───────────────────────────────────────────────────────
def is_valid_email(email):
    return bool(re.match(r'^[\w\.\-\+]+@[\w\-]+\.[a-zA-Z]{2,}$', email))

def is_valid_username(username):
    return bool(re.match(r'^[\w]{3,20}$', username))

# ── TOKEN HELPERS ────────────────────────────────────────────────────
def make_token():
    return secrets.token_hex(32)

def token_expiry():
    dt = datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRY_DAYS)
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

def is_token_expired(expires_at):
    if not expires_at:
        return True
    try:
        exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp
    except Exception:
        return False  # If we can't parse it, assume valid — never wipe token on parse error

# ── ADMIN TOKEN AUTH ─────────────────────────────────────────────────
def get_admin_from_token():
    """Verify Bearer token against admins table — retries on Supabase hiccup."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return None

    for attempt in range(3):
        try:
            result = sb_admin("admins", query=f"?token=eq.{quote(token, safe='')}&select=*")
            admins = result.json()
            if isinstance(admins, list) and admins:
                admin = admins[0]
                if is_token_expired(admin.get("token_expires")):
                    sb_admin("admins", method="PATCH",
                       data={"token": None, "token_expires": None},
                       query=f"?id=eq.{admin['id']}")
                    return None
                return admin
            elif isinstance(admins, list) and not admins:
                return None  # Token not found — genuine auth failure, don't retry
        except Exception as e:
            print(f"get_admin_from_token attempt {attempt + 1} failed: {e}", flush=True)
            if attempt < 2:
                time.sleep(2)
    return None

# ── MEMBER TOKEN AUTH ────────────────────────────────────────────────
def get_user_from_token():
    """Verify Bearer token against users table — retries on Supabase hiccup."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return None

    for attempt in range(3):
        try:
            result = sb("users", query=f"?token=eq.{quote(token, safe='')}&select=*")
            users = result.json()
            if isinstance(users, list) and users:
                user = users[0]
                if is_token_expired(user.get("token_expires")):
                    sb("users", method="PATCH",
                       data={"token": None, "token_expires": None},
                       query=f"?id=eq.{user['id']}")
                    return None
                return user
            elif isinstance(users, list) and not users:
                return None  # Token not found — genuine auth failure, don't retry
        except Exception as e:
            print(f"get_user_from_token attempt {attempt + 1} failed: {e}", flush=True)
            if attempt < 2:
                time.sleep(2)
    return None

# ── EMAIL (SILENCED) ─────────────────────────────────────────────────
def send_vault_invite(target_email, invite_code):
    print("!!! MANUAL APPROVAL REQUIRED !!!")
    print(f"TARGET: {target_email}")
    print(f"INVITE CODE: {invite_code}")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    return True

# ── APP ───────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, origins=["https://genesisvault8-beep.github.io"])

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

ph = PasswordHasher()
groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# ═══════════════════════════════════════════════════════════════════════
# BASIC ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.route("/")
def home():
    return jsonify({"status": "online", "message": "Genesis Vault API", "version": "2.0"})

@app.route("/ping")
@app.route("/api/ping")  # alias so frontend can ping via either URL
def ping():
    return jsonify({"status": "alive", "message": "VAULT ONLINE"})

# ═══════════════════════════════════════════════════════════════════════
# MEMBER AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/auth/request-access", methods=["POST"])
@limiter.limit("3 per hour")
def request_access():
    try:
        data = request.json or {}
        email = data.get("email", "").strip().lower()
        if not email:
            return jsonify({"status": "error", "message": "EMAIL_REQUIRED"}), 400
        if not is_valid_email(email):
            return jsonify({"status": "error", "message": "INVALID_EMAIL"}), 400

        check = sb("access_requests", query=f"?email=eq.{email}&select=id,status")
        existing = check.json()
        if existing:
            status = existing[0].get("status", "pending")
            if status == "approved":
                return jsonify({"status": "error", "message": "ALREADY_APPROVED"}), 400
            return jsonify({"status": "error", "message": "ALREADY_REQUESTED"}), 400

        response = sb("access_requests", method="POST", data={"email": email, "status": "pending"})
        if response.status_code in [200, 201]:
            return jsonify({"status": "success", "message": "REQUEST_RECEIVED"}), 200
        return jsonify({"status": "error", "message": "DATABASE_ERROR"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    try:
        data = request.json or {}
        email       = data.get("email", "").strip().lower()
        password    = data.get("password", "")
        username    = data.get("username", "").strip()
        invite_code = data.get("referral_code", "").strip().upper()

        if not email or not password or not username:
            return jsonify({"status": "error", "message": "ALL_FIELDS_REQUIRED"}), 400
        if not is_valid_username(username):
            return jsonify({"status": "error", "message": "INVALID_USERNAME"}), 400
        if not is_valid_email(email):
            return jsonify({"status": "error", "message": "INVALID_EMAIL"}), 400
        if len(password) < 8:
            return jsonify({"status": "error", "message": "PASSWORD_TOO_SHORT"}), 400
        if not invite_code:
            return jsonify({"status": "error", "message": "INVITE_CODE_REQUIRED"}), 400

        code_check = sb(
            "access_requests",
            query=f"?email=eq.{email}&invite_code=eq.{invite_code}&status=eq.approved&select=id"
        )
        if not code_check.json():
            return jsonify({"status": "error", "message": "INVALID_INVITE_CODE"}), 403

        password_hash = ph.hash(password)
        token   = make_token()
        expires = token_expiry()

        result = sb("users", method="POST", data={
            "email": email,
            "username": username,
            "password_hash": password_hash,
            "token": token,
            "token_expires": expires,
            "rank": "Ghost"
        })

        if result.status_code in [200, 201]:
            sb("access_requests", method="PATCH",
               data={"invite_code": None, "status": "used"},
               query=f"?email=eq.{email}")
            return jsonify({"status": "success", "token": token, "rank": "Ghost", "email": email})
        return jsonify({"status": "error", "message": "REGISTRATION_FAILED"}), 400
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.json or {}
        email    = data.get("email", "").strip().lower()
        password = data.get("password", "")

        result = sb("users", query=f"?email=eq.{email}&select=*")
        users = result.json()
        if not users:
            return jsonify({"status": "error", "message": "AUTH_FAILED"}), 401

        user = users[0]
        if user.get("is_banned"):
            return jsonify({"status": "error", "message": "ACCOUNT_BANNED"}), 403

        ph.verify(user.get("password_hash"), password)

        new_token = make_token()
        expires   = token_expiry()
        sb("users", method="PATCH",
           data={"token": new_token, "token_expires": expires},
           query=f"?email=eq.{email}")

        return jsonify({
            "status": "success",
            "token": new_token,
            "rank": user.get("rank"),
            "email": email
        })
    except Exception:
        return jsonify({"status": "error", "message": "AUTH_FAILED"}), 401

# ═══════════════════════════════════════════════════════════════════════
# LEGACY ADMIN ROUTES — ADMIN_SECRET (index.html — DO NOT CHANGE)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/admin/approve-request", methods=["POST"])
@limiter.limit("10 per hour")
def approve_request():
    data = request.json or {}
    admin_key = data.get("admin_key", "")
    if admin_key != ADMIN_SECRET:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 403

    target_email = data.get("email", "").strip().lower()
    if not target_email:
        return jsonify({"status": "error", "message": "EMAIL_REQUIRED"}), 400

    invite_code = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)
    )

    patch = sb("access_requests", method="PATCH",
               data={"status": "approved", "invite_code": invite_code},
               query=f"?email=eq.{target_email}")

    if patch.status_code in [200, 201]:
        send_vault_invite(target_email, invite_code)
        return jsonify({"status": "success", "code": invite_code, "email_sent": False}), 200
    return jsonify({"status": "error", "message": "DB_UPDATE_FAILED"}), 500


@app.route("/api/admin/list-requests", methods=["GET"])
@limiter.limit("30 per hour")
def list_requests():
    admin_key = request.headers.get("Authorization", "")
    if admin_key != ADMIN_SECRET:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 403

    result = sb("access_requests", query="?status=eq.pending&select=email,id,status")
    return jsonify(result.json())

# ═══════════════════════════════════════════════════════════════════════
# NEW ADMIN SYSTEM — TOKEN BASED (admin.html only)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/admin/setup", methods=["POST"])
@limiter.limit("10 per hour")
def admin_setup():
    """
    Create an admin. Allowed only when total admins < 3.
    Protected by SETUP_SECRET.
    When 2 admins exist and one is revoked, count drops to 2
    and this endpoint automatically unlocks again.
    """
    try:
        data = request.json or {}

        setup_key = data.get("setup_secret", "")
        if setup_key != SETUP_SECRET:
            return jsonify({"status": "error", "message": "INVALID_SETUP_SECRET"}), 403

        # Block if already at 3 admins
        count_res = sb("admins", query="?select=id")
        existing  = count_res.json()
        if not isinstance(existing, list):
            return jsonify({"status": "error", "message": "DB_ERROR"}), 500
        if len(existing) >= 3:
            return jsonify({"status": "error", "message": "MAX_ADMINS_REACHED"}), 403

        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username or not password:
            return jsonify({"status": "error", "message": "ALL_FIELDS_REQUIRED"}), 400
        if not is_valid_username(username):
            return jsonify({"status": "error", "message": "INVALID_USERNAME"}), 400
        if len(password) < 8:
            return jsonify({"status": "error", "message": "PASSWORD_TOO_SHORT"}), 400

        dup = sb("admins", query=f"?username=eq.{username}&select=id")
        if dup.json():
            return jsonify({"status": "error", "message": "USERNAME_TAKEN"}), 400

        password_hash = ph.hash(password)

        result = sb("admins", method="POST", data={
            "username": username,
            "password_hash": password_hash,
            "token": None,
            "token_expires": None
        })

        if result.status_code in [200, 201]:
            remaining = 3 - (len(existing) + 1)
            return jsonify({
                "status": "success",
                "message": f"Admin '{username}' created. {remaining} slot(s) remaining."
            }), 201
        return jsonify({"status": "error", "message": "CREATION_FAILED"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/admin/auth", methods=["POST"])
@limiter.limit("5 per minute")
def admin_auth():
    try:
        from urllib.parse import quote
        data     = request.json or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")

        result = sb("admins", query=f"?username=eq.{quote(username, safe='')}&select=*")
        admins = result.json()
        if not isinstance(admins, list) or not admins:
            return jsonify({"status": "error", "message": "AUTH_FAILED"}), 401

        admin = admins[0]
        ph.verify(admin.get("password_hash"), password)

        new_token = make_token()
        expires   = token_expiry()

        # Direct PATCH — bypass RPC entirely, retry up to 3 times
        saved = False
        for attempt in range(3):
            try:
                patch_res = sb_admin(
                    "admins",
                    method="PATCH",
                    data={"token": new_token, "token_expires": expires},
                    query=f"?id=eq.{admin['id']}"
                )
                print(f"PATCH STATUS (attempt {attempt+1}): {patch_res.status_code}", flush=True)
                print(f"PATCH BODY: {patch_res.text}", flush=True)
                if patch_res.status_code in (200, 204):
                    saved = True
                    break
                time.sleep(2)
            except Exception as patch_err:
                print(f"PATCH exception (attempt {attempt+1}): {patch_err}", flush=True)
                if attempt < 2:
                    time.sleep(2)

        if not saved:
            return jsonify({"status": "error", "message": "TOKEN_SAVE_FAILED"}), 500

        return jsonify({
            "status": "success",
            "token": new_token,
            "username": admin.get("username"),
            "admin_id": admin["id"]
        })
    except Exception as e:
        print(f"ADMIN AUTH ERROR: {e}")
        return jsonify({"status": "error", "message": "AUTH_FAILED"}), 401


@app.route("/api/admin/dashboard", methods=["GET"])
def admin_dashboard():
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    total_members = sb("users", query="?select=id")
    pending       = sb("access_requests", query="?status=eq.pending&select=id")
    total_admins  = sb("admins", query="?select=id")
    active_votes  = sb("admin_votes", query="?status=eq.open&select=id")

    # Also count pending payments and payouts for dashboard stats
    pending_payments = sb("purchases", query="?status=eq.pending&select=id")
    pending_payouts  = sb("payouts", query="?status=eq.pending&select=id")

    return jsonify({
        "status": "success",
        "total_members":     len(total_members.json())    if isinstance(total_members.json(), list)    else 0,
        "pending_requests":  len(pending.json())          if isinstance(pending.json(), list)          else 0,
        "total_admins":      len(total_admins.json())     if isinstance(total_admins.json(), list)     else 0,
        "active_votes":      len(active_votes.json())     if isinstance(active_votes.json(), list)     else 0,
        "pending_payments":  len(pending_payments.json()) if isinstance(pending_payments.json(), list) else 0,
        "pending_payouts":   len(pending_payouts.json())  if isinstance(pending_payouts.json(), list)  else 0,
    })


@app.route("/api/admin/members", methods=["GET"])
def admin_members():
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    result = sb("users",
                query="?select=id,username,email,rank,is_banned,created_at&order=created_at.desc")
    return jsonify({"status": "success", "members": result.json()})


@app.route("/api/admin/pending-tools", methods=["GET"])
def pending_tools():
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    result = sb("tools", query="?status=eq.pending&select=*&order=created_at.desc")
    return jsonify({"status": "success", "tools": result.json()})


@app.route("/api/admin/admins", methods=["GET"])
def list_admins():
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    result = sb("admins", query="?select=id,username,created_at")
    return jsonify({"status": "success", "admins": result.json()})


@app.route("/api/admin/vote-revoke", methods=["POST"])
@limiter.limit("20 per hour")
def vote_revoke():
    """
    actions:
      propose — start a revoke motion against a target admin
      vote    — cast yes or no on an open motion
      status  — list all open motions with vote counts

    Rules:
      2/3 majority (2 yes votes) = motion passes = target permanently deleted
      Self-vote blocked — you cannot vote on your own revoke
      Motions auto-cancel after 48 hours with no decision
      Proposer automatically casts the first yes vote
    """
    try:
        admin = get_admin_from_token()
        if not admin:
            return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

        data   = request.json or {}
        action = data.get("action", "")

        # ── STATUS ────────────────────────────────────────────────────
        if action == "status":
            now = datetime.now(timezone.utc).isoformat()
            # Auto-cancel timed-out motions
            sb("admin_votes", method="PATCH",
               data={"status": "cancelled", "outcome": "timeout"},
               query=f"?status=eq.open&expires_at=lt.{now}")

            votes = sb("admin_votes", query="?status=eq.open&select=*")
            return jsonify({"status": "success", "motions": votes.json()})

        # ── PROPOSE ───────────────────────────────────────────────────
        elif action == "propose":
            target_id = data.get("target_admin_id")
            if not target_id:
                return jsonify({"status": "error", "message": "TARGET_REQUIRED"}), 400

            # Self-vote block
            if str(target_id) == str(admin["id"]):
                return jsonify({"status": "error", "message": "CANNOT_TARGET_YOURSELF"}), 403

            # Target must exist
            target_res = sb("admins", query=f"?id=eq.{target_id}&select=id,username")
            if not target_res.json():
                return jsonify({"status": "error", "message": "TARGET_NOT_FOUND"}), 404

            # No duplicate open motions
            existing = sb("admin_votes",
                          query=f"?target_admin_id=eq.{target_id}&status=eq.open&select=id")
            if existing.json():
                return jsonify({"status": "error", "message": "MOTION_ALREADY_OPEN"}), 400

            expires = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()

            motion = sb("admin_votes", method="POST", data={
                "proposed_by":     admin["id"],
                "target_admin_id": target_id,
                "votes_yes":       1,                  # Proposer auto-votes yes
                "votes_no":        0,
                "voters":          [str(admin["id"])],
                "status":          "open",
                "outcome":         None,
                "expires_at":      expires
            })

            if motion.status_code in [200, 201]:
                return jsonify({
                    "status": "success",
                    "message": "Motion proposed. Expires in 48 hours.",
                    "motion": motion.json()
                }), 201
            return jsonify({"status": "error", "message": "MOTION_FAILED"}), 500

        # ── VOTE ──────────────────────────────────────────────────────
        elif action == "vote":
            motion_id = data.get("motion_id")
            vote_cast = data.get("vote")  # "yes" or "no"

            if not motion_id or vote_cast not in ["yes", "no"]:
                return jsonify({"status": "error", "message": "INVALID_VOTE_DATA"}), 400

            motion_res = sb("admin_votes",
                            query=f"?id=eq.{motion_id}&status=eq.open&select=*")
            motions = motion_res.json()
            if not motions:
                return jsonify({"status": "error", "message": "MOTION_NOT_FOUND_OR_CLOSED"}), 404

            motion = motions[0]

            # Check expiry
            if is_token_expired(motion.get("expires_at")):
                sb("admin_votes", method="PATCH",
                   data={"status": "cancelled", "outcome": "timeout"},
                   query=f"?id=eq.{motion_id}")
                return jsonify({"status": "error", "message": "MOTION_EXPIRED"}), 400

            # Self-vote block
            if str(admin["id"]) == str(motion["target_admin_id"]):
                return jsonify({"status": "error", "message": "CANNOT_VOTE_ON_YOUR_OWN_REVOKE"}), 403

            # Already voted?
            voters = motion.get("voters") or []
            if str(admin["id"]) in [str(v) for v in voters]:
                return jsonify({"status": "error", "message": "ALREADY_VOTED"}), 400

            votes_yes = motion["votes_yes"] + (1 if vote_cast == "yes" else 0)
            votes_no  = motion["votes_no"]  + (1 if vote_cast == "no"  else 0)
            voters.append(str(admin["id"]))

            # Motion passes — 2 yes votes
            if votes_yes >= 2:
                sb("admins", method="DELETE",
                   query=f"?id=eq.{motion['target_admin_id']}")
                sb("admin_votes", method="PATCH",
                   data={"votes_yes": votes_yes, "votes_no": votes_no,
                         "voters": voters, "status": "closed", "outcome": "passed"},
                   query=f"?id=eq.{motion_id}")
                return jsonify({
                    "status": "success",
                    "message": "MOTION_PASSED — Admin permanently removed.",
                    "outcome": "passed"
                })

            # Motion rejected — 2 no votes
            if votes_no >= 2:
                sb("admin_votes", method="PATCH",
                   data={"votes_yes": votes_yes, "votes_no": votes_no,
                         "voters": voters, "status": "closed", "outcome": "rejected"},
                   query=f"?id=eq.{motion_id}")
                return jsonify({
                    "status": "success",
                    "message": "MOTION_REJECTED — Admin keeps access.",
                    "outcome": "rejected"
                })

            # Still open — save progress
            sb("admin_votes", method="PATCH",
               data={"votes_yes": votes_yes, "votes_no": votes_no, "voters": voters},
               query=f"?id=eq.{motion_id}")
            return jsonify({
                "status": "success",
                "message": "VOTE_CAST",
                "votes_yes": votes_yes,
                "votes_no":  votes_no
            })

        else:
            return jsonify({"status": "error", "message": "INVALID_ACTION"}), 400

    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# TOOLS — APPROVE / REJECT
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/admin/tools/<int:tool_id>/approve", methods=["POST"])
def approve_tool(tool_id):
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    result = sb("tools", method="PATCH",
                data={"status": "approved"},
                query=f"?id=eq.{tool_id}")
    if result.status_code in [200, 201]:
        return jsonify({"status": "success", "message": "Tool approved."})
    return jsonify({"status": "error", "message": "DB_ERROR"}), 500


@app.route("/api/admin/tools/<int:tool_id>/reject", methods=["POST"])
def reject_tool(tool_id):
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    result = sb("tools", method="PATCH",
                data={"status": "rejected"},
                query=f"?id=eq.{tool_id}")
    if result.status_code in [200, 201]:
        return jsonify({"status": "success", "message": "Tool rejected."})
    return jsonify({"status": "error", "message": "DB_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# PAYMENTS — PENDING + CONFIRM + REJECT
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/admin/pending-payments", methods=["GET"])
def pending_payments():
    """
    Returns purchases with status=pending awaiting admin confirmation.
    Expects a 'purchases' table with: id, buyer_id, tool_id, amount_paid,
    binance_tx_id, status, purchased_at.
    Joins buyer username via users table by buyer_id.
    """
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        result = sb("purchases",
                    query="?status=eq.pending&select=id,buyer_id,tool_id,amount_paid,binance_tx_id,purchased_at,title&order=purchased_at.desc")
        purchases = result.json()
        if not isinstance(purchases, list):
            return jsonify({"status": "success", "purchases": []})

        # Enrich with buyer username
        enriched = []
        for p in purchases:
            buyer_res = sb("users", query=f"?id=eq.{p.get('buyer_id')}&select=username")
            buyer_list = buyer_res.json()
            p["buyer_name"] = buyer_list[0]["username"] if buyer_list else "Unknown"
            enriched.append(p)

        return jsonify({"status": "success", "purchases": enriched})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/payments/admin-confirm/<int:purchase_id>", methods=["POST"])
def admin_confirm_payment(purchase_id):
    """
    Confirms a pending purchase. Sets status=confirmed and
    unlocks the tool for the buyer.
    """
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        # Fetch the purchase
        res = sb("purchases", query=f"?id=eq.{purchase_id}&select=*")
        purchases = res.json()
        if not isinstance(purchases, list) or not purchases:
            return jsonify({"status": "error", "message": "PURCHASE_NOT_FOUND"}), 404

        purchase = purchases[0]
        if purchase.get("status") != "pending":
            return jsonify({"status": "error", "message": "ALREADY_PROCESSED"}), 400

        # Confirm purchase
        sb("purchases", method="PATCH",
           data={"status": "confirmed"},
           query=f"?id=eq.{purchase_id}")

        # Grant buyer access to the tool
        sb("user_tools", method="POST", data={
            "user_id": purchase["buyer_id"],
            "tool_id": purchase["tool_id"]
        })

        # Notify buyer
        sb("notifications", method="POST", data={
            "user_id": purchase["buyer_id"],
            "type": "payment_confirmed",
            "message": f"Your payment was confirmed. Tool unlocked.",
            "is_read": False
        })

        return jsonify({"status": "success", "message": "Payment confirmed. Tool unlocked for buyer."})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/payments/admin-reject/<int:purchase_id>", methods=["POST"])
def admin_reject_payment(purchase_id):
    """
    Rejects a pending purchase — sets status=rejected.
    """
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        res = sb("purchases", query=f"?id=eq.{purchase_id}&select=id,status,buyer_id")
        purchases = res.json()
        if not isinstance(purchases, list) or not purchases:
            return jsonify({"status": "error", "message": "PURCHASE_NOT_FOUND"}), 404
        if purchases[0].get("status") != "pending":
            return jsonify({"status": "error", "message": "ALREADY_PROCESSED"}), 400

        sb("purchases", method="PATCH",
           data={"status": "rejected"},
           query=f"?id=eq.{purchase_id}")

        # Notify buyer
        sb("notifications", method="POST", data={
            "user_id": purchases[0]["buyer_id"],
            "type": "payment_rejected",
            "message": "Your payment could not be verified. Please contact support.",
            "is_read": False
        })

        return jsonify({"status": "success", "message": "Payment rejected."})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# PAYOUTS — LIST + MARK SENT
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/admin/payouts", methods=["GET"])
def list_payouts():
    """
    Returns all pending payout requests from sellers.
    Expects a 'payouts' table with: id, user_id, amount, binance_address,
    status, created_at.
    """
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        result = sb("payouts",
                    query="?status=eq.pending&select=id,user_id,amount,binance_address,created_at&order=created_at.desc")
        payouts = result.json()
        if not isinstance(payouts, list):
            return jsonify({"status": "success", "payouts": []})

        # Enrich with seller username
        enriched = []
        for p in payouts:
            user_res = sb("users", query=f"?id=eq.{p.get('user_id')}&select=username")
            user_list = user_res.json()
            p["username"] = user_list[0]["username"] if user_list else "Unknown"
            enriched.append(p)

        return jsonify({"status": "success", "payouts": enriched})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/admin/payouts/<int:payout_id>/mark-sent", methods=["POST"])
def mark_payout_sent(payout_id):
    """
    Marks a payout as sent. Admin confirms they manually transferred USDT.
    """
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        res = sb("payouts", query=f"?id=eq.{payout_id}&select=id,status,user_id,amount")
        payouts = res.json()
        if not isinstance(payouts, list) or not payouts:
            return jsonify({"status": "error", "message": "PAYOUT_NOT_FOUND"}), 404
        if payouts[0].get("status") != "pending":
            return jsonify({"status": "error", "message": "ALREADY_PROCESSED"}), 400

        sb("payouts", method="PATCH",
           data={"status": "sent", "sent_at": datetime.now(timezone.utc).isoformat()},
           query=f"?id=eq.{payout_id}")

        # Notify creator
        sb("notifications", method="POST", data={
            "user_id": payouts[0]["user_id"],
            "type": "payout_sent",
            "message": f"Your payout of ${payouts[0].get('amount', '?')} USDT has been sent.",
            "is_read": False
        })

        return jsonify({"status": "success", "message": "Payout marked as sent."})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# POSTS — FLAGGED / CLEAR / DELETE
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/admin/flagged-posts", methods=["GET"])
def flagged_posts():
    """
    Returns posts flagged for review.
    Expects a 'posts' table with: id, user_id, content, is_flagged, created_at.
    """
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        result = sb("posts",
                    query="?is_flagged=eq.true&select=id,user_id,content,created_at&order=created_at.desc")
        posts = result.json()
        if not isinstance(posts, list):
            return jsonify({"status": "success", "posts": []})

        # Enrich with username
        enriched = []
        for p in posts:
            user_res = sb("users", query=f"?id=eq.{p.get('user_id')}&select=username")
            user_list = user_res.json()
            p["username"] = user_list[0]["username"] if user_list else "Unknown"
            enriched.append(p)

        return jsonify({"status": "success", "posts": enriched})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/admin/posts/<int:post_id>/clear", methods=["POST"])
def clear_post(post_id):
    """Clears the flag on a post — post stays but is no longer flagged."""
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        result = sb("posts", method="PATCH",
                    data={"is_flagged": False},
                    query=f"?id=eq.{post_id}")
        if result.status_code in [200, 201]:
            return jsonify({"status": "success", "message": "Post cleared."})
        return jsonify({"status": "error", "message": "DB_ERROR"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/admin/posts/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    """Permanently deletes a flagged post."""
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        result = sb("posts", method="DELETE", query=f"?id=eq.{post_id}")
        if result.status_code in [200, 204]:
            return jsonify({"status": "success", "message": "Post deleted."})
        return jsonify({"status": "error", "message": "DB_ERROR"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# MEMBERS — BAN + PROMOTE
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/admin/ban", methods=["POST"])
def ban_member():
    """
    Bans a member by user_id. Sets is_banned=true and clears their token.
    """
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        data    = request.json or {}
        user_id = data.get("user_id")
        if not user_id:
            return jsonify({"status": "error", "message": "USER_ID_REQUIRED"}), 400

        # Confirm user exists
        check = sb("users", query=f"?id=eq.{user_id}&select=id,is_banned")
        users = check.json()
        if not isinstance(users, list) or not users:
            return jsonify({"status": "error", "message": "USER_NOT_FOUND"}), 404
        if users[0].get("is_banned"):
            return jsonify({"status": "error", "message": "ALREADY_BANNED"}), 400

        sb("users", method="PATCH",
           data={"is_banned": True, "token": None, "token_expires": None},
           query=f"?id=eq.{user_id}")

        return jsonify({"status": "success", "message": "Member banned."})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/admin/users/<user_id>/promote", methods=["POST"])
def promote_member(user_id):
    """
    Promotes a member to a new rank.
    Expected body: { "rank": "Operator" }
    """
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        data = request.json or {}
        rank = data.get("rank", "").strip()

        VALID_RANKS = ["Ghost", "Operator", "Phantom", "Spectre"]
        if rank not in VALID_RANKS:
            return jsonify({"status": "error", "message": f"INVALID_RANK. Must be one of: {', '.join(VALID_RANKS)}"}), 400

        check = sb("users", query=f"?id=eq.{user_id}&select=id")
        if not check.json():
            return jsonify({"status": "error", "message": "USER_NOT_FOUND"}), 404

        sb("users", method="PATCH",
           data={"rank": rank},
           query=f"?id=eq.{user_id}")

        return jsonify({"status": "success", "message": f"Member promoted to {rank}."})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# COURSES — LIST + CREATE
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/courses", methods=["GET"])
def list_courses():
    """
    Public route — returns all approved courses.
    Expects a 'courses' table with: id, title, description, content,
    category, rank_required, price, is_free, created_at.
    """
    try:
        result = sb("courses",
                    query="?select=id,title,description,category,rank_required,price,is_free,created_at&order=created_at.desc")
        courses = result.json()
        if not isinstance(courses, list):
            return jsonify({"status": "success", "courses": []})
        return jsonify({"status": "success", "courses": courses})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/admin/courses/<int:course_id>/delete", methods=["POST"])
def delete_course(course_id):
    """Admin-only. Permanently deletes a course by ID."""
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        check = sb("courses", query=f"?id=eq.{course_id}&select=id")
        if not check.json():
            return jsonify({"status": "error", "message": "COURSE_NOT_FOUND"}), 404

        result = sb("courses", method="DELETE", query=f"?id=eq.{course_id}")
        if result.status_code in [200, 204]:
            return jsonify({"status": "success", "message": "Course deleted."})
        return jsonify({"status": "error", "message": "DB_ERROR"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/admin/courses/create", methods=["POST"])
def create_course():
    """
    Admin-only. Creates a new course.
    Body: { title, description, content, category, rank_required, price, is_free }
    """
    admin = get_admin_from_token()
    if not admin:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        data  = request.json or {}
        title = data.get("title", "").strip()
        content = data.get("content", "").strip()

        if not title or not content:
            return jsonify({"status": "error", "message": "TITLE_AND_CONTENT_REQUIRED"}), 400

        price   = float(data.get("price", 0))
        is_free = price == 0

        result = sb("courses", method="POST", data={
            "title":         title,
            "description":   data.get("description", "").strip(),
            "content":       content,
            "category":      data.get("category", "General"),
            "rank_required": data.get("rank_required", "Ghost"),
            "price":         price,
            "is_free":       is_free,
            "created_by":    admin["id"]
        })

        if result.status_code in [200, 201]:
            return jsonify({"status": "success", "message": "Course published.", "course": result.json()}), 201
        return jsonify({"status": "error", "message": "DB_ERROR"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# NEW — PROFILE
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/profile", methods=["GET"])
def get_profile():
    """
    Returns full profile for the authenticated user.
    Includes username, email, rank, created_at, tool count, and notifications.
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        user_id = user["id"]

        # Count owned tools
        tools_res = sb("user_tools", query=f"?user_id=eq.{user_id}&select=id")
        tool_count = len(tools_res.json()) if isinstance(tools_res.json(), list) else 0

        # Unread notification count
        notif_res = sb("notifications", query=f"?user_id=eq.{user_id}&is_read=eq.false&select=id")
        unread_count = len(notif_res.json()) if isinstance(notif_res.json(), list) else 0

        return jsonify({
            "status":       "success",
            "id":           user_id,
            "username":     user.get("username"),
            "email":        user.get("email"),
            "rank":         user.get("rank", "Ghost"),
            "created_at":   user.get("created_at"),
            "tool_count":   tool_count,
            "unread_notifications": unread_count
        })
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# NEW — NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/notifications", methods=["GET"])
def get_notifications():
    """Returns the 20 most recent notifications for the authenticated user."""
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        result = sb("notifications",
                    query=f"?user_id=eq.{user['id']}&select=id,type,message,is_read,created_at&order=created_at.desc&limit=20")
        notifs = result.json()
        if not isinstance(notifs, list):
            return jsonify({"status": "success", "notifications": []})
        return jsonify({"status": "success", "notifications": notifs})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/notifications/read-all", methods=["POST"])
def mark_notifications_read():
    """Marks all notifications as read for the authenticated user."""
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        sb("notifications", method="PATCH",
           data={"is_read": True},
           query=f"?user_id=eq.{user['id']}&is_read=eq.false")
        return jsonify({"status": "success", "message": "All notifications marked read."})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# NEW — FORUM: POSTS + REPLIES + REACTIONS
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/posts", methods=["GET"])
def list_posts():
    """
    Returns forum posts, optionally filtered by category.
    Query param: ?category=General
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        category = request.args.get("category", "").strip()
        query = "?select=id,user_id,content,category,created_at,is_flagged&order=created_at.desc&limit=50"
        if category:
            query += f"&category=eq.{category}"

        result = sb("posts", query=query)
        posts = result.json()
        if not isinstance(posts, list):
            return jsonify({"status": "success", "posts": []})

        # Enrich with username, reply count, reaction counts
        enriched = []
        for p in posts:
            uid = p.get("user_id")
            u = sb("users", query=f"?id=eq.{uid}&select=username,rank").json()
            p["username"] = u[0]["username"] if u else "Unknown"
            p["rank"]     = u[0]["rank"]     if u else "Ghost"

            replies = sb("post_replies", query=f"?post_id=eq.{p['id']}&select=id").json()
            p["reply_count"] = len(replies) if isinstance(replies, list) else 0

            reactions = sb("post_reactions", query=f"?post_id=eq.{p['id']}&select=emoji").json()
            counts = {}
            if isinstance(reactions, list):
                for r in reactions:
                    e = r.get("emoji", "👍")
                    counts[e] = counts.get(e, 0) + 1
            p["reactions"] = counts

            enriched.append(p)

        return jsonify({"status": "success", "posts": enriched})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/posts", methods=["POST"])
def create_post():
    """
    Creates a new forum post.
    Body: { content, category }
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        data    = request.json or {}
        content = data.get("content", "").strip()
        category = data.get("category", "General").strip()

        if not content:
            return jsonify({"status": "error", "message": "CONTENT_REQUIRED"}), 400
        if len(content) > 2000:
            return jsonify({"status": "error", "message": "CONTENT_TOO_LONG"}), 400

        result = sb("posts", method="POST", data={
            "user_id":    user["id"],
            "content":    content,
            "category":   category,
            "is_flagged": False
        })

        if result.status_code in [200, 201]:
            return jsonify({"status": "success", "message": "Post created.", "post": result.json()}), 201
        return jsonify({"status": "error", "message": "DB_ERROR"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/posts/<int:post_id>/replies", methods=["GET"])
def get_replies(post_id):
    """Returns all replies for a given post."""
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        result = sb("post_replies",
                    query=f"?post_id=eq.{post_id}&select=id,user_id,content,created_at&order=created_at.asc")
        replies = result.json()
        if not isinstance(replies, list):
            return jsonify({"status": "success", "replies": []})

        # Enrich with username
        enriched = []
        for r in replies:
            u = sb("users", query=f"?id=eq.{r.get('user_id')}&select=username,rank").json()
            r["username"] = u[0]["username"] if u else "Unknown"
            r["rank"]     = u[0]["rank"]     if u else "Ghost"
            enriched.append(r)

        return jsonify({"status": "success", "replies": enriched})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/posts/<int:post_id>/reply", methods=["POST"])
def add_reply(post_id):
    """
    Adds a reply to a post.
    Body: { content }
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        data    = request.json or {}
        content = data.get("content", "").strip()

        if not content:
            return jsonify({"status": "error", "message": "CONTENT_REQUIRED"}), 400
        if len(content) > 1000:
            return jsonify({"status": "error", "message": "REPLY_TOO_LONG"}), 400

        # Confirm post exists
        post_check = sb("posts", query=f"?id=eq.{post_id}&select=id,user_id")
        posts = post_check.json()
        if not isinstance(posts, list) or not posts:
            return jsonify({"status": "error", "message": "POST_NOT_FOUND"}), 404

        result = sb("post_replies", method="POST", data={
            "post_id": post_id,
            "user_id": user["id"],
            "content": content
        })

        if result.status_code in [200, 201]:
            # Notify original post author (if not replying to own post)
            post_author = posts[0].get("user_id")
            if post_author and str(post_author) != str(user["id"]):
                sb("notifications", method="POST", data={
                    "user_id": post_author,
                    "type":    "reply",
                    "message": f"{user['username']} replied to your post.",
                    "is_read": False
                })
            return jsonify({"status": "success", "message": "Reply added.", "reply": result.json()}), 201
        return jsonify({"status": "error", "message": "DB_ERROR"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/posts/<int:post_id>/react", methods=["POST"])
def react_to_post(post_id):
    """
    Adds or removes a reaction on a post.
    Body: { emoji } — e.g. "👍", "🔥", "💀"
    Toggle: if user already reacted with this emoji, it's removed.
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        data  = request.json or {}
        emoji = data.get("emoji", "👍").strip()

        ALLOWED_EMOJIS = ["👍", "🔥", "💀", "👀", "💯", "🤝"]
        if emoji not in ALLOWED_EMOJIS:
            return jsonify({"status": "error", "message": "INVALID_EMOJI"}), 400

        # Confirm post exists
        post_check = sb("posts", query=f"?id=eq.{post_id}&select=id")
        if not post_check.json():
            return jsonify({"status": "error", "message": "POST_NOT_FOUND"}), 404

        # Check if reaction already exists
        existing = sb("post_reactions",
                      query=f"?post_id=eq.{post_id}&user_id=eq.{user['id']}&emoji=eq.{emoji}&select=id")
        existing_list = existing.json()

        if isinstance(existing_list, list) and existing_list:
            # Toggle off — remove reaction
            sb("post_reactions", method="DELETE",
               query=f"?id=eq.{existing_list[0]['id']}")
            return jsonify({"status": "success", "action": "removed", "emoji": emoji})
        else:
            # Add reaction
            sb("post_reactions", method="POST", data={
                "post_id": post_id,
                "user_id": user["id"],
                "emoji":   emoji
            })
            return jsonify({"status": "success", "action": "added", "emoji": emoji})

    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


@app.route("/api/posts/<int:post_id>/flag", methods=["POST"])
def flag_post(post_id):
    """Member flags a post for admin review."""
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        sb("posts", method="PATCH",
           data={"is_flagged": True},
           query=f"?id=eq.{post_id}")
        return jsonify({"status": "success", "message": "Post flagged for review."})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# NEW — MARKETPLACE
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/marketplace", methods=["GET"])
def marketplace():
    """
    Returns approved tools.
    Query params: ?type=script&status=approved (status defaults to approved)
    Also flags which tools the authenticated user already owns.
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        tool_type = request.args.get("type", "").strip()
        query = "?status=eq.approved&select=id,title,description,type,price,creator,created_at&order=created_at.desc"
        if tool_type:
            query += f"&type=eq.{tool_type}"

        result = sb("tools", query=query)
        tools = result.json()
        if not isinstance(tools, list):
            return jsonify({"status": "success", "tools": []})

        # Get user's owned tool IDs
        owned_res = sb("user_tools", query=f"?user_id=eq.{user['id']}&select=tool_id")
        owned_ids = set()
        if isinstance(owned_res.json(), list):
            owned_ids = {str(r["tool_id"]) for r in owned_res.json()}

        for t in tools:
            t["owned"] = str(t["id"]) in owned_ids

        return jsonify({"status": "success", "tools": tools})
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# NEW — TOOL SUBMISSION (CREATOR)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/tools/submit", methods=["POST"])
def submit_tool():
    """
    Creators submit a tool for admin review.
    Body: { title, description, type, price, download_url }
    type options: script | template | guide | other
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        data         = request.json or {}
        title        = data.get("title", "").strip()
        description  = data.get("description", "").strip()
        tool_type    = data.get("type", "other").strip()
        price        = float(data.get("price", 0))
        download_url = data.get("download_url", "").strip()

        if not title or not description:
            return jsonify({"status": "error", "message": "TITLE_AND_DESCRIPTION_REQUIRED"}), 400

        VALID_TYPES = ["script", "template", "guide", "other"]
        if tool_type not in VALID_TYPES:
            tool_type = "other"

        result = sb("tools", method="POST", data={
            "title":        title,
            "description":  description,
            "type":         tool_type,
            "price":        price,
            "creator":      user["username"],
            "creator_id":   user["id"],
            "download_url": download_url,
            "status":       "pending"
        })

        if result.status_code in [200, 201]:
            return jsonify({"status": "success", "message": "Tool submitted for review."}), 201
        return jsonify({"status": "error", "message": "DB_ERROR"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# NEW — PAYMENTS: SUBMIT BUY (TX ID FLOW)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/payments/submit", methods=["POST"])
def submit_payment():
    """
    Member submits a purchase with their Binance TX ID.
    Admin manually confirms/rejects via /api/payments/admin-confirm.
    Body: { tool_id, binance_tx_id }
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        data         = request.json or {}
        tool_id      = data.get("tool_id")
        binance_tx   = data.get("binance_tx_id", "").strip()

        if not tool_id or not binance_tx:
            return jsonify({"status": "error", "message": "TOOL_ID_AND_TX_REQUIRED"}), 400

        # Confirm tool exists and is approved
        tool_res = sb("tools", query=f"?id=eq.{tool_id}&status=eq.approved&select=id,title,price")
        tools = tool_res.json()
        if not isinstance(tools, list) or not tools:
            return jsonify({"status": "error", "message": "TOOL_NOT_FOUND"}), 404

        tool = tools[0]

        # Block duplicate pending purchase
        dup = sb("purchases",
                 query=f"?buyer_id=eq.{user['id']}&tool_id=eq.{tool_id}&status=eq.pending&select=id")
        if isinstance(dup.json(), list) and dup.json():
            return jsonify({"status": "error", "message": "PAYMENT_ALREADY_PENDING"}), 400

        # Block if already owns
        owned = sb("user_tools",
                   query=f"?user_id=eq.{user['id']}&tool_id=eq.{tool_id}&select=id")
        if isinstance(owned.json(), list) and owned.json():
            return jsonify({"status": "error", "message": "ALREADY_OWNED"}), 400

        result = sb("purchases", method="POST", data={
            "buyer_id":      user["id"],
            "tool_id":       tool_id,
            "title":         tool.get("title"),
            "amount_paid":   tool.get("price"),
            "binance_tx_id": binance_tx,
            "status":        "pending"
        })

        if result.status_code in [200, 201]:
            return jsonify({"status": "success", "message": "Payment submitted. Awaiting admin confirmation."}), 201
        return jsonify({"status": "error", "message": "DB_ERROR"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ═══════════════════════════════════════════════════════════════════════
# NEW — PAYOUT REQUEST (CREATOR)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/payouts/request", methods=["POST"])
def request_payout():
    """
    Creator requests a payout.
    Body: { amount, binance_address }
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"status": "error", "message": "UNAUTHORIZED"}), 401

    try:
        data            = request.json or {}
        amount          = float(data.get("amount", 0))
        binance_address = data.get("binance_address", "").strip()

        if amount <= 0:
            return jsonify({"status": "error", "message": "INVALID_AMOUNT"}), 400
        if not binance_address:
            return jsonify({"status": "error", "message": "BINANCE_ADDRESS_REQUIRED"}), 400

        # Block duplicate pending payout
        dup = sb("payouts",
                 query=f"?user_id=eq.{user['id']}&status=eq.pending&select=id")
        if isinstance(dup.json(), list) and dup.json():
            return jsonify({"status": "error", "message": "PAYOUT_ALREADY_PENDING"}), 400

        result = sb("payouts", method="POST", data={
            "user_id":         user["id"],
            "amount":          amount,
            "binance_address": binance_address,
            "status":          "pending"
        })

        if result.status_code in [200, 201]:
            return jsonify({"status": "success", "message": "Payout request submitted."}), 201
        return jsonify({"status": "error", "message": "DB_ERROR"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "SERVER_ERROR"}), 500


# ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
