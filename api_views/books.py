import os
import jsonschema
import requests

from api_views.users import token_validator, error_message_helper
from config import db
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User
from models.books_model import Book
from app import vuln

EXPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'exports')


def get_all_books():
    return_value = jsonify({'Books': Book.get_all_books()})
    return return_value


def add_new_book():
    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, add_book_schema)
    except:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()

        # check if user already has this book title
        book = Book.query.filter_by(user=user, book_title=request_data.get('book_title')).first()
        if book:
            return Response(error_message_helper("Book Already exists!"), 400, mimetype="application/json")
        else:
            newBook = Book(book_title=request_data.get('book_title'), secret_content=request_data.get('secret'),
                           user_id=user.id)
            db.session.add(newBook)
            db.session.commit()
            responseObject = {
                'status': 'success',
                'message': 'Book has been added.'
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")


def get_by_title(book_title):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if vuln:  # Broken Object Level Authorization
            book = Book.query.filter_by(book_title=str(book_title)).first()
            if book:
                responseObject = {
                    'book_title': book.book_title,
                    'secret': book.secret_content,
                    'owner': book.user.username
                }
                return Response(json.dumps(responseObject), 200, mimetype="application/json")
            else:
                return Response(error_message_helper("Book not found!"), 404, mimetype="application/json")
        else:
            user = User.query.filter_by(username=resp['sub']).first()
            book = Book.query.filter_by(user=user, book_title=str(book_title)).first()
            if book:
                responseObject = {
                    'book_title': book.book_title,
                    'secret': book.secret_content,
                    'owner': book.user.username
                }
                return Response(json.dumps(responseObject), 200, mimetype="application/json")
            else:
                return Response(error_message_helper("Book not found!"), 404, mimetype="application/json")


def set_cover(book_title):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    request_data = request.get_json()
    cover_url = request_data.get('cover_url', '')
    # SSRF: the server fetches whatever URL the client supplies, with no
    # allow-list and no block on private/link-local ranges (e.g. cloud
    # metadata at 169.254.169.254).
    try:
        remote = requests.get(cover_url, timeout=5)
    except requests.exceptions.RequestException as e:
        return Response(error_message_helper(str(e)), 400, mimetype="application/json")
    responseObject = {
        'status': 'success',
        'book_title': book_title,
        'content_type': remote.headers.get('Content-Type'),
        'size': len(remote.content)
    }
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def export_book(book_title):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    file_param = request.args.get('file', book_title + '.txt')
    # Path traversal: file_param is concatenated onto the exports directory
    # with no sanitization (e.g. file=../../../../etc/passwd).
    export_path = os.path.join(EXPORTS_DIR, file_param)
    try:
        with open(export_path, 'r') as f:
            content = f.read()
    except OSError as e:
        return Response(error_message_helper(str(e)), 404, mimetype="application/json")
    responseObject = {'status': 'success', 'book_title': book_title, 'content': content}
    return Response(json.dumps(responseObject), 200, mimetype="application/json")