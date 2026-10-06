import os
import io
import base64
import zipfile

import yaml
from lxml import etree
from PIL import ImageMath
from flask import Response, request, json, redirect

from api_views.users import token_validator, error_message_helper

'''
Additional intentionally vulnerable endpoints (batch 2), kept outside the
OWASP API Top 10 set VAmPI already covers natively and outside the batch-1
set in reports.py/books.py/users.py. Used as a source-code test surface for
API security scanners (e.g. ClearFlow): XXE, insecure YAML deserialization,
arbitrary code execution via eval() and via PIL.ImageMath.eval(), open
redirect, and Zip Slip (arbitrary file write on archive extraction).
'''

# Hardcoded cloud credential, shaped like a real AWS secret access key, for
# secret-scanning test coverage. Fake/test value only.
BACKUP_AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/fakeKEY/bPxRfiCYEXAMPLEKEY"

RESTORE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'exports', 'restore')


def import_catalog():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    xml_data = request.get_data()
    # XXE: entities are resolved against the client-supplied DOCTYPE, so a
    # crafted <!ENTITY ... SYSTEM "file:///etc/passwd"> can read arbitrary
    # local files back through the parsed response (or trigger SSRF).
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    try:
        tree = etree.fromstring(xml_data, parser=parser)
        title = tree.findtext('title')
    except etree.XMLSyntaxError as e:
        return Response(error_message_helper(str(e)), 400, mimetype="application/json")
    responseObject = {'status': 'success', 'title': title}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def load_config():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json() or {}
    raw_yaml = request_data.get('config', '')
    # Insecure deserialization: yaml.Loader (not SafeLoader) reconstructs
    # arbitrary Python objects from tags like "!!python/object/apply", giving
    # remote code execution from a client-supplied YAML document.
    parsed = yaml.load(raw_yaml, Loader=yaml.Loader)
    responseObject = {'status': 'success', 'config': str(parsed)}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def run_expression():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json() or {}
    expression = request_data.get('expression', '')
    # Remote code execution: client-supplied expression is passed directly to
    # eval(), with no sandboxing (e.g. "__import__('os').system('id')").
    result = eval(expression)
    responseObject = {'status': 'success', 'result': result}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def calculate_image_metric():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json() or {}
    expression = request_data.get('expression', '')
    # Arbitrary code execution: PIL.ImageMath.eval() builds and evaluates a
    # Python expression from client input (CVE-2022-22817, Pillow < 9.0.0).
    result = ImageMath.eval(expression)
    responseObject = {'status': 'success', 'result': str(result)}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def redirect_to_partner():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    # Open redirect: the client-supplied URL is used verbatim, with no
    # same-origin/allow-list check, enabling phishing redirect chains.
    next_url = request.args.get('next', '/')
    return redirect(next_url)


def restore_backup():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json() or {}
    encoded_zip = request_data.get('archive', '')
    try:
        archive_bytes = base64.b64decode(encoded_zip)
        os.makedirs(RESTORE_DIR, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            # Zip Slip: member names are joined onto the restore directory
            # without stripping "../" segments, so a crafted archive can write
            # files anywhere on disk the process can reach.
            for member in zf.namelist():
                target_path = os.path.join(RESTORE_DIR, member)
                if member.endswith('/'):
                    os.makedirs(target_path, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, 'wb') as out_f:
                    out_f.write(zf.read(member))
    except Exception as e:
        return Response(error_message_helper(str(e)), 400, mimetype="application/json")
    responseObject = {'status': 'success', 'message': 'Backup restored.'}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")
