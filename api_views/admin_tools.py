import base64
import hashlib
import logging
import os
import random
import string
import subprocess

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Response, request, json
from sqlalchemy.sql import text

from api_views.users import token_validator, error_message_helper
from config import db
from models.user_model import User

'''
Additional intentionally vulnerable endpoints (batch 3), kept outside the
OWASP API Top 10 set VAmPI already covers natively and outside the batch-1
(reports.py/books.py/users.py) and batch-2 (integrations.py) sets. Used as a
source-code test surface for API security scanners (e.g. ClearFlow): raw SQL
injection, a second OS command injection sink shape (subprocess, shell=True),
a hardcoded AES key used in ECB mode, a weak PRNG/hash combo for password-reset
tokens, unrestricted file upload (path traversal to RCE), log injection, and a
hardcoded Stripe-style secret key (critical gitleaks finding).
'''

logger = logging.getLogger('vampi.admin')
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static', 'avatars')

# Hardcoded AES-128 key (CWE-798/CWE-321) used to "encrypt" user notes below.
# Synthetic, throwaway value: never used outside this PoC.
NOTE_ENCRYPTION_KEY = b'0123456789abcdef'

# Hardcoded Stripe-shaped secret key (CWE-798) used to call the (mocked)
# billing provider. Synthetic, throwaway value in the live-key shape
# (sk_live_...) so secret scanners that key off that prefix fire on it;
# never registered with Stripe or used to authenticate anything real.
BILLING_PROVIDER_SECRET_KEY = "sk_live_51HqY2tJ8kZ3nR7wXpL9vQaG4mF6dC1bN0eTyU"


def search_users():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    term = request.args.get('username', '')
    # SQL Injection (CWE-89): the search term is concatenated directly into the
    # SQL string instead of using a parameterized query/the ORM's filter_by, so
    # a crafted username (e.g. "' UNION SELECT password, email, admin --") can
    # read arbitrary columns the response schema doesn't normally expose.
    query = "SELECT username, email, admin FROM users WHERE username LIKE '%" + term + "%'"
    rows = db.session.execute(text(query)).fetchall()
    responseObject = {
        'status': 'success',
        'results': [dict(row._mapping) for row in rows]
    }
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def trace_route():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json() or {}
    host = request_data.get('host', '')
    # OS command injection (CWE-78): host is interpolated into a shell string
    # and run with shell=True via subprocess, a different sink shape than
    # reports.diagnostics (os.popen) so scanners modeling only one subprocess
    # API still get coverage here.
    output = subprocess.check_output("traceroute -m 5 " + host, shell=True, stderr=subprocess.STDOUT)
    responseObject = {'status': 'success', 'output': output.decode(errors='replace')}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def encrypt_note():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json() or {}
    note = request_data.get('note', '')
    padded = note.encode().ljust((len(note) // 16 + 1) * 16, b'\0')
    # Use of a broken/risky cryptographic algorithm (CWE-327): AES in ECB mode
    # leaks plaintext structure (identical blocks -> identical ciphertext), and
    # the key is hardcoded (CWE-798) instead of per-tenant/KMS-managed.
    cipher = Cipher(algorithms.AES(NOTE_ENCRYPTION_KEY), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    responseObject = {'status': 'success', 'ciphertext': ciphertext.hex()}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def request_reset_token(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return Response(error_message_helper("User not found"), 404, mimetype="application/json")
    # Weak PRNG (CWE-330) combined with a weak hash (CWE-327/CWE-916): the
    # token is derived from Python's non-cryptographic `random` module and
    # MD5, both predictable/brute-forceable, instead of `secrets.token_urlsafe`.
    raw = ''.join(random.choice(string.digits) for _ in range(6))
    token = hashlib.md5((username + raw).encode()).hexdigest()
    responseObject = {'status': 'success', 'reset_token': token}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def upload_avatar():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json() or {}
    filename = request_data.get('filename', 'avatar.png')
    content_b64 = request_data.get('content_base64', '')
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    # Unrestricted file upload (CWE-434): the client-supplied filename is used
    # verbatim with no extension allow-list and no path sanitization, so a
    # name like "../../api_views/users.py" or "shell.py" can overwrite
    # application code or plant an executable payload under a servable path.
    target_path = os.path.join(UPLOAD_DIR, filename)
    with open(target_path, 'wb') as f:
        f.write(base64.b64decode(content_b64))
    responseObject = {'status': 'success', 'path': target_path}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def audit_login_attempt():
    request_data = request.get_json() or {}
    username = request_data.get('username', '')
    source_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # Log injection / log forging (CWE-117): unsanitized user input is written
    # straight into the log record, so a username containing CRLF sequences
    # can inject forged log lines (e.g. a fake "admin login succeeded" entry).
    logger.info(f"Login attempt for user={username} from={source_ip}")
    responseObject = {'status': 'success', 'message': 'Attempt recorded.'}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def billing_status():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    # Excessive data exposure: a normal, non-debug endpoint echoes a hardcoded
    # billing-provider secret key back to any authenticated caller.
    responseObject = {
        'status': 'success',
        'provider': 'billing-sandbox',
        'provider_secret_key': BILLING_PROVIDER_SECRET_KEY
    }
    return Response(json.dumps(responseObject), 200, mimetype="application/json")
