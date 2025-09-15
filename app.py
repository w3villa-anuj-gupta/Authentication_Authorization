# app.py
from flask import Flask, request, jsonify, make_response, abort
import jwt
import time
import uuid
from functools import wraps
import os

app = Flask(__name__)

# === Configuration (demo only) ===
JWT_ACCESS_SECRET = "8f0c1a9dd92a2f49e39f9f64dfc1af18f3295a3b0f0d5eaf229dbd9283c0c921"    # keep secret on server
JWT_REFRESH_SECRET = "d13d8a71f3c32e9c45af0328e87e24e6cdbfc410ee3d4c91d7a497528c33f1b0"  # separate secret for refresh tokens
ACCESS_TOKEN_EXP = 60 *5    # 1 minutes
REFRESH_TOKEN_EXP = 60 * 60 * 24   # 1 day

# In-memory store for valid refresh tokens (token_jti -> {sub, expires})

refresh_store = {}

# Demo users (username -> dict)
USERS = {
    "user": {"password": "password1", "role": "user"},
    "admin": {"password": "adminpass", "role": "admin"}
}

# === Helpers ===
def now():
    return int(time.time())

def sign_jwt(payload: dict, secret: str):
    return jwt.encode(payload, secret, algorithm="HS256")

def decode_jwt(token: str, secret: str, verify_exp=True):
    options = {"verify_exp": verify_exp}
    return jwt.decode(token, secret, algorithms=["HS256"], options=options)

def generate_access_token(sub: str, role: str):
    payload = {
        "sub": sub,
        "role": role,
        "iat": now(),
        "exp": now() + ACCESS_TOKEN_EXP
    }
    return sign_jwt(payload, JWT_ACCESS_SECRET)

def generate_refresh_token(sub: str):
    jti = str(uuid.uuid4())  # unique id for this refresh token
    payload = {
        "sub": sub,
        "jti": jti,
        "iat": now(),
        "exp": now() + REFRESH_TOKEN_EXP
    }
    token = sign_jwt(payload, JWT_REFRESH_SECRET)
    # store in server-side store for rotation/revocation
    refresh_store[jti] = {"sub": sub, "exp": payload["exp"]}
    return token, jti

def require_bearer(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing bearer token"}), 401
        token = auth.split(" ", 1)[1].strip()
        try:
            payload = decode_jwt(token, JWT_ACCESS_SECRET)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "access token expired"}), 401
        except Exception:
            return jsonify({"error": "invalid access token"}), 401
        request.user = {"sub": payload["sub"], "role": payload.get("role")}
        return f(*args, **kwargs)
    return decorated

# === Routes ===

@app.route("/login", methods=["POST"])
def login():
    """
    Expects JSON: {"username": "...", "password": "..."}
    Issues:
      - access token in JSON response (client keeps in memory)
      - refresh token as HttpOnly, Secure cookie
      - a readable csrf cookie that the client must send back as X-CSRF-Token
    """
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "username/password required"}), 400

    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "invalid credentials"}), 401

    access_token = generate_access_token(username, user["role"])
    refresh_token, jti = generate_refresh_token(username)

    response = make_response(jsonify({
        "access_token": access_token,
        "expires_in": ACCESS_TOKEN_EXP,
        "role": user["role"]
    }))

    # Set refresh token cookie (HttpOnly -> JS cannot read)
    # Using Secure and SameSite to mitigate transport risk and CSRF; Secure requires HTTPS
    response.set_cookie(
        "refresh_token", refresh_token,
        httponly=True,
        secure=False,  # set to True in production (requires HTTPS)
        samesite="Lax",  # Lax or Strict helps mitigate CSRF
        max_age=REFRESH_TOKEN_EXP,
        path="/"
    )

    # Set a non-HttpOnly CSRF cookie for double-submit validation.
    # This cookie is readable by JS and must be sent in X-CSRF-Token header for /refresh and /logout.
    csrf_token = str(uuid.uuid4())
    response.set_cookie(
        "csrf_token", csrf_token,
        httponly=False,
        secure=False,  # True in prod
        samesite="Lax",
        max_age=REFRESH_TOKEN_EXP,
        path="/"
    )

    return response

@app.route("/refresh", methods=["POST"])
def refresh():
    """
    Refreshes tokens. Requires:
      - refresh_token cookie (HttpOnly) — browser sends automatically
      - X-CSRF-Token header that must match csrf_token cookie (double-submit)
    Rotation: invalidate previous refresh jti and issue a new one.
    """
    # CSRF double-submit check
    csrf_cookie = request.cookies.get("csrf_token")
    csrf_header = request.headers.get("X-CSRF-Token")
    if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
        return jsonify({"error": "CSRF check failed"}), 403

    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "no refresh token"}), 401
    try:
        payload = decode_jwt(refresh_token, JWT_REFRESH_SECRET)
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "refresh token expired"}), 401
    except Exception:
        return jsonify({"error": "invalid refresh token"}), 401

    jti = payload.get("jti")
    sub = payload.get("sub")
    if jti not in refresh_store:
        # token not present in store -> revoked/used
        return jsonify({"error": "refresh token invalid or used"}), 401

    # rotate: remove used jti and issue a new refresh token
    del refresh_store[jti]
    new_refresh_token, new_jti = generate_refresh_token(sub)
    access_token = generate_access_token(sub, USERS.get(sub, {}).get("role", "user"))

    response = make_response(jsonify({
        "access_token": access_token,
        "expires_in": ACCESS_TOKEN_EXP
    }))

    # Set new refresh cookie and rotate csrf cookie as well
    response.set_cookie(
        "refresh_token", new_refresh_token,
        httponly=True,
        secure=False,  # True in production
        samesite="Lax",
        max_age=REFRESH_TOKEN_EXP,
        path="/"
    )
    new_csrf = str(uuid.uuid4())
    response.set_cookie(
        "csrf_token", new_csrf,
        httponly=False,
        secure=False,
        samesite="Lax",
        max_age=REFRESH_TOKEN_EXP,
        path="/"
    )

    return response

@app.route("/protected", methods=["GET"])
@require_bearer
def protected():
    # role-check: only admin sees secret
    user = request.user
    if user.get("role") != "admin":
        return jsonify({"message": "You are not authorized to view the secret."}), 403
    return jsonify({"secret": "🎉 The admin secret is: 'Launch codes: 0000'"}), 200

@app.route("/logout", methods=["POST"])
def logout():
    """
    Revoke refresh token server-side and clear cookies.
    Requires CSRF double-submit (to avoid CSRF logout-from-other-session attacks).
    """
    csrf_cookie = request.cookies.get("csrf_token")
    csrf_header = request.headers.get("X-CSRF-Token")
    if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
        return jsonify({"error": "CSRF check failed"}), 403

    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        try:
            payload = decode_jwt(refresh_token, JWT_REFRESH_SECRET)
            jti = payload.get("jti")
            if jti in refresh_store:
                del refresh_store[jti]
        except Exception:
            pass

    # clear cookies
    response = make_response(jsonify({"msg": "logged out"}))
    response.set_cookie("refresh_token", "", max_age=0, path="/")
    response.set_cookie("csrf_token", "", max_age=0, path="/")
    return response

# Utility route to inspect refresh store (for demo only)
@app.route("/_debug/refresh_store", methods=["GET"])
def debug_store():
    return jsonify(refresh_store)

if __name__ == "__main__":
    app.run(port=5000, debug=True)
