import os

from flask import Response, request, json, render_template_string

from api_views.users import token_validator, error_message_helper

'''
Additional intentionally vulnerable endpoints, kept outside the OWASP API Top 10
set that VAmPI already covers natively (BOLA, mass assignment, excessive data
exposure, SQLi, broken auth). Used as a source-code test surface for API
security scanners (e.g. ClearFlow): OS command injection, SSTI/RCE, and a
hardcoded partner credential leaked in a normal (non-debug) response.
'''

# Hardcoded credential used to call the (mocked) credit-bureau partner API.
PARTNER_API_KEY = "partner-sk-test-7f2c1a9d4e6b8891fake"


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
