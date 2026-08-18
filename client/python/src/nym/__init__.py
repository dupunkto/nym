"""Identity provider and authentication layer.

Nym is a minimal IndieAuth implementation providing an authorization endpoint, which serves
two purposes:

1. decentralised authentication using personal domain names as identity, following the
   IndieAuth specification (https://indieauth.spec.indieweb.org/).
2. centralised authentication layer for in-house applications (similar to OAuth or SSO).

This library provides a Nym client for easily protecting Flask-based applications with
centralised identity management.

Usage:

    from nym import Nym, require_auth

    nym = Nym()
    nym.init_app(app, endpoint="https://nym.example.com", scopes=["profile"])

    @app.route("/protected")
    @require_auth
    def protected():
        ...
"""

import base64
import functools
import hashlib
import logging
import secrets
from urllib.parse import urlencode, urlparse

import requests
from flask import Blueprint, g, jsonify, redirect, request, session

logger = logging.getLogger(__name__)

_STATE_KEY = "_nym_state"
_CODE_VERIFIER_KEY = "_nym_code_verifier"
_REDIRECT_URI_KEY = "_nym_redirect_uri"
_CURRENT_USER_KEY = "current_user"


class Nym:
    """Flask extension for Nym auth. Sets flask.g.current_user/authenticated on every
    request, and registers a blueprint owning the IndieAuth callback route."""

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app, endpoint=None, scopes=None, callback_path="/nym/callback"):
        app.config.setdefault("NYM_ENDPOINT", endpoint)
        app.config.setdefault("NYM_SCOPES", scopes or [])

        if app.config["NYM_ENDPOINT"] is None:
            raise ValueError("Nym requires an 'endpoint' (the IndieAuth endpoint to authenticate against)")

        app.before_request(_fetch_current_user)

        blueprint = Blueprint("nym", __name__)
        blueprint.add_url_rule(callback_path, "callback", _callback)
        app.register_blueprint(blueprint)


def _fetch_current_user():
    user = session.get(_CURRENT_USER_KEY)
    g.current_user = user
    g.authenticated = user is not None


def require_auth(view):
    """Decorator that sends unauthenticated visitors through the IndieAuth login flow."""

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if g.current_user:
            return view(*args, **kwargs)

        return _start_auth()

    return wrapper


def _start_auth():
    from flask import current_app

    endpoint = current_app.config["NYM_ENDPOINT"]
    scopes = current_app.config["NYM_SCOPES"]

    client_id = request.host_url.rstrip("/")
    redirect_uri = request.url

    state = secrets.token_urlsafe(32)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
    )

    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "scope": " ".join(scopes),
    }

    session.clear()
    session[_STATE_KEY] = state
    session[_CODE_VERIFIER_KEY] = code_verifier
    session[_REDIRECT_URI_KEY] = redirect_uri

    parsed = urlparse(endpoint)
    auth_url = parsed._replace(query=urlencode(auth_params)).geturl()

    return redirect(auth_url)


def _callback():
    from flask import current_app

    endpoint = current_app.config["NYM_ENDPOINT"]

    client_id = request.host_url.rstrip("/")
    redirect_uri = session.get(_REDIRECT_URI_KEY, "/")

    try:
        state = _require_param("state")
        me = _require_param("me")
        code = _require_param("code")
        iss = _require_param("iss")
        session_state = _require_session(_STATE_KEY)
        code_verifier = _require_session(_CODE_VERIFIER_KEY)

        if state != session_state:
            raise _AuthError("Invalid state parameter")
        if iss != endpoint:
            raise _AuthError("Invalid issuer")
    except _AuthError as error:
        return _handle_error(str(error))

    token_params = {
        "grant_type": "authorization_code",
        "me": me,
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }

    try:
        body = _verify_code(endpoint, token_params)
    except _AuthError as error:
        return _handle_error(str(error))

    if "me" in body and "meta" not in body:
        return _handle_error("Missing 'meta' value")
    if "meta" in body and "me" not in body:
        return _handle_error("Missing 'me' value")
    if "me" not in body or "meta" not in body:
        return _handle_error(f"Unexpected token endpoint response: {body}")

    session.clear()
    session[_CURRENT_USER_KEY] = body["meta"]

    return redirect(urlparse(redirect_uri).path or "/")


def _verify_code(endpoint, params):
    try:
        response = requests.post(endpoint, data=params, headers={"Accept": "application/json"})
    except requests.RequestException as error:
        raise _AuthError(f"Connection to token endpoint could not be established: {error}") from error

    try:
        body = response.json()
    except ValueError:
        body = response.text

    if response.status_code == 200 and isinstance(body, dict) and "error" in body:
        raise _AuthError(_format_token_error(body))

    if response.status_code != 200:
        raise _AuthError(_format_http_error(response.status_code, body))

    return body


def _format_token_error(body):
    return body.get("error_description") or body.get("error") or f"Token endpoint refused request with: {body}"


def _format_http_error(status, body):
    if isinstance(body, dict) and "error" in body:
        return body["error"]
    if isinstance(body, str):
        return body
    return f"Token endpoint returned HTTP {status}: {body}"


def _require_param(name):
    value = request.args.get(name) or request.form.get(name)
    if value is None:
        raise _AuthError(f"Missing '{name}' parameter")
    return value


def _require_session(key):
    value = session.get(key)
    if value is None:
        raise _AuthError(f"Missing {key} in session")
    return value


def _handle_error(message):
    logger.warning("Nym crashed: %s", message)
    return jsonify({"error": message}), 401


class _AuthError(Exception):
    """Used internally to short-circuit the callback validation chain."""
