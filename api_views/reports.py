import os
import base64

from flask import Response, request, json, render_template_string
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from api_views.users import token_validator, error_message_helper

'''
Additional intentionally vulnerable endpoints, kept outside the OWASP API Top 10
set that VAmPI already covers natively (BOLA, mass assignment, excessive data
exposure, SQLi, broken auth). Used as a source-code test surface for API
security scanners (e.g. ClearFlow): OS command injection, SSTI/RCE, a
hardcoded partner credential leaked in a normal (non-debug) response, and a
hardcoded RSA private key used to sign outbound webhook calls.
'''

# Hardcoded credential used to call the (mocked) credit-bureau partner API.
PARTNER_API_KEY = "partner-sk-test-7f2c1a9d4e6b8891fake"

# RSA private key used to sign outbound webhook calls to the credit-bureau
# partner (CWE-321: Use of Hard-coded Cryptographic Key). Generated solely as
# a throwaway test fixture for this repository: it has never been deployed,
# registered with any provider, or used to sign anything outside this PoC.
# Committing a signing key to source means anyone with repo access can forge
# webhook payloads, and rotating it requires a code change/redeploy instead
# of a secret-store update.
WEBHOOK_SIGNING_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvZhm4zcG13I2D
/Trz4l/Ysg/lQWG5qK6DydalQQ7UgoGccnldRuCAlxpz1IdmVASzINw2VvudJivs
eqADK30S7BMTa1CMJFj6q+zFcujb/54EAXeRF/LxVShUrNTCaAldfY0a87vH431A
US7rJ1u0WgzjGUL8kY1MBOlzYrBvmXsRTaebMra1bBusDfgvlaQTHbfUsMkjWKO4
eHAUaJxfbMoI8iv2wA+qGC04S6I9qBxANvZ/EYt+2lFQ7d5X8mu+7Bl87OVqHAK6
5dqH4TfEl3SP0jVOpyVbTJFsxTmPv/DPKM3OGRlYHTRB4dZR4X8907L/GgnPiVRq
wWgnrx/DAgMBAAECggEAPx62lfdRxSEUOlIIg5jNFj3qE34GbZpDB0E9AeZaMGaw
vvzBKSynAQ+foNx0R4Jn2JC0Psfpr4F7oBP2/n0JeyRCryPY7j3sWXVCdUHng7hH
BLkEbs4YCvoy09oIjNeEu0TB4VeiFYqL2ff9MvnMeihH5/gAz8SPfTJtUq1KwjX4
OhHXhbDEPJQL557LxoGQ7vSzvOahFNzb5uiPv21rjIfdCDKuzIwaIWyFYZmHvvVQ
dpwFPgnCMXfKvVbkolaKQO/DtRL+tzSIpV9ZxyFIhucjrg0fmgq1qDQkS8mTfWKj
5hWQSTGa+sfiy03v7kiNHGso0RPndbP8SbH1lvbB6QKBgQDgpz7vKfu0X6CY6801
LSXwUoQU95L1ExDIF6I9JKmYDMt4n4M5l1HRN6oLHccXJiSW8V6LrMigzAwGAK8U
6uF1w7vBRp/WDkukWbHJFTjgIvHsDbxVl7953VPESmrYs7HyDoWWKip/GQRKu77v
lkyKnbx6Nc+nPHg05dgs/GcUSQKBgQDH33RcoN0Gf+LPb9RED9UmWA7ipOhQwXi7
tn9YJAaELI8C1bdmsuoSNXa6C3ahIdi/Ek3ZZuJVQANoqxMzVOx7p9ulCYYN5YM0
fMjxTsLEHvov8CXNI/aJ3C5XcE0cbWFAjPFo5q75+tAEdSKyq/e9Jz/EPlKDxaZc
6SfpzGn7qwKBgQCPv5SOlo+f0BzEHQY2w4fmKfaoL+6R8LwpPK4sb5wxVeaQbYkb
Pc81j2e4KzqsflSlXRcBSvMpqMb8xE1DljPkFfW664T1BDq0lEwlffXhvZqNUBC1
uB7mTJAAJxoNRZZUa6Rg/OQqZYiQhWfciJC7lcj3bh1MRm4ocvYLewo+OQKBgEOy
HmJFJbdO10407SsERchP6PLAseKwNKk3XZhH02EvCl0Gb7C8BmWWcBkBSvO2WAgX
NgDdROlk3gK0drNbHyGer9kNCbdpNfAwF4sLhxIP/+L+rn71oEn/Jj79TVDEhzzq
v9Us1LTcS1pHJjJn5mfNhF5+UUpKRlePrLIWRwszAoGANrWFor7dumFQz4LR3bll
Wt8ssnSntSIHvmSdBt4+7B7kwF2s1GVmH/ijjEYb9ft1Twq5D5KHj1WS+u0WWSId
15D0Bro1hRbuC40M0675BYdP1c1dEHxotVsdJCMgRpb7zPJAxWRui80OE3ZrUQ1y
5IdkGUMROHFWHbVPHOS8GzI=
-----END PRIVATE KEY-----"""


def diagnostics():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json() or {}
    host = request_data.get('host', '')
    # Command injection: host is interpolated directly into a shell command.
    output = os.popen("ping -c 2 " + host).read()
    responseObject = {'status': 'success', 'output': output}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def render_banner():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json() or {}
    template = request_data.get('template', '')
    # Server-Side Template Injection: client-supplied template string is rendered
    # directly with Jinja2, with no sandboxing.
    rendered = render_template_string(template)
    responseObject = {'status': 'success', 'rendered': rendered}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def partner_status():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    # Excessive data exposure: a normal, non-debug endpoint echoes a hardcoded
    # partner credential back to any authenticated caller.
    responseObject = {
        'status': 'success',
        'partner': 'credit-bureau-sandbox',
        'partner_api_key': PARTNER_API_KEY
    }
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def sign_webhook_payload():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json() or {}
    payload = request_data.get('payload', '')
    # Use of a hardcoded cryptographic key (CWE-321): every call signs with
    # the same RSA private key committed to source, instead of a per-tenant
    # key pulled from a secret store/KMS.
    private_key = serialization.load_pem_private_key(
        WEBHOOK_SIGNING_PRIVATE_KEY.encode(), password=None
    )
    signature = private_key.sign(payload.encode(), padding.PKCS1v15(), hashes.SHA256())
    responseObject = {
        'status': 'success',
        'signature': base64.b64encode(signature).decode()
    }
    return Response(json.dumps(responseObject), 200, mimetype="application/json")
