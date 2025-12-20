import json
import os
import random
import shutil
import string
from datetime import timedelta
from http import HTTPStatus
from threading import Lock
from threading import Thread

import flask_wtf
import redbeat
import requests
from celery import Celery
from celery.exceptions import TimeoutError
from celery.schedules import crontab
from celery.schedules import schedule
from dotenv import load_dotenv
from filelock import FileLock
from flask import abort
from flask import Flask
from flask import g
from flask import jsonify
from flask import request
from flask import Response
from flask import send_file
from flask import send_from_directory
from flask_cors import CORS
from flask_login import current_user
from flask_mailman import Mail
from flask_security import auth_required
from flask_security import hash_password
from flask_security import roles_required
from flask_security import Security
from flask_security import SQLAlchemyUserDatastore
from flask_security.models import fsqla_v3 as fsqla
from flask_sqlalchemy import SQLAlchemy
from redbeat import RedBeatSchedulerEntry
from redbeat.schedulers import RedBeatConfig
from src.utils.file import ALLOWED_EXTENSIONS
from src.utils.file import API_TEMP_PATH
from src.utils.file import delete_structure
from src.utils.file import FILES_PATH
from src.utils.file import generate_random_uuid
from src.utils.file import generate_uuid
from src.utils.file import get_current_time
from src.utils.file import get_data
from src.utils.file import get_file_basename
from src.utils.file import get_file_extension
from src.utils.file import get_file_layouts
from src.utils.file import get_file_parsed
from src.utils.file import get_filesystem
from src.utils.file import get_structure_info
from src.utils.file import get_word_count
from src.utils.file import INPUTS_PATH
from src.utils.file import json_to_text
from src.utils.file import OUTPUTS_PATH
from src.utils.file import PRIVATE_PATH
from src.utils.file import save_file_layouts
from src.utils.file import TEMP_PATH
from src.utils.file import update_json_file
from src.utils.system import get_free_space
from src.utils.system import get_private_spaces
from src.utils.system import get_size_api_files
from src.utils.system import get_size_private_spaces
from src.utils.text import compare_dicts_words
from werkzeug.utils import safe_join

# FIXME: uncomment when searching feature is improved and re-enabled
# from elasticsearch import NotFoundError
# from src.elastic_search import create_document
# from src.elastic_search import ElasticSearchClient
# from src.elastic_search import ES_INDEX
# from src.elastic_search import ES_URL
# from src.elastic_search import mapping
# from src.elastic_search import settings

# from src.utils.system import get_logs

load_dotenv()

DEFAULT_CONFIG_FILE = os.environ.get("DEFAULT_CONFIG_FILE", "_configs/default.json")
CONFIG_FILES_LOCATION = os.environ.get("CONFIG_FILES_LOCATION", "_configs")

APP_BASENAME = os.environ.get("APP_BASENAME", "")
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/0")

app = Flask(__name__)
CORS(app, supports_credentials=True)

if APP_BASENAME == "":
    app.config["APPLICATION_ROOT"] = "/"
else:
    app.config["APPLICATION_ROOT"] = APP_BASENAME
    app.config["SESSION_COOKIE_PATH"] = f"/{APP_BASENAME}"

# Set secret key and salt (required)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
app.config["SECURITY_PASSWORD_SALT"] = os.environ["FLASK_SECURITY_PASSWORD_SALT"]

# Get configs from file
app.config.from_pyfile("app.cfg")

# Enable CSRF on all api endpoints
flask_wtf.CSRFProtect(app)

# Setup authentication DB
db = SQLAlchemy(app)
fsqla.FsModels.set_db_info(db)

# Setup mail service - must be configured for production!!!
# mail = Mail(app)


class Role(db.Model, fsqla.FsRoleMixin):
    pass


class User(db.Model, fsqla.FsUserMixin):
    pass


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Setup connection to celery
celery = Celery("celery_app", backend=CELERY_RESULT_BACKEND, broker=CELERY_BROKER_URL)

# Setup connection to ElasticSearch
# FIXME: uncomment when searching feature is improved and re-enabled
# es = ElasticSearchClient(ES_URL, ES_INDEX, mapping, settings)

# logging.basicConfig(filename="record.log", level=logging.DEBUG, format=f'%(asctime)s %(levelname)s : %(message)s')

log = app.logger

lock_system = dict()

RESULT_TYPE_TO_EXTENSION = {
    "pdf_indexed": "pdf",
    "pdf": "pdf",
    "txt": "txt",
    "txt_delimited": "txt",
    "csv": "csv",
    "ner": "json",
    "hocr": "hocr",
    "alto": "xml",
}


#####################################
# ERROR HANDLING
#####################################
def bad_request(message: str = "Bad request syntax or unsupported method"):
    response = jsonify({"message": message})
    response.status_code = 400
    return response


#####################################
# REQUEST HANDLING
#####################################


def format_path(request_data):
    """
    Format request path to get inputs_path, files_path, and outputs_path.

    Returns: (inputs_path, files_path, outputs_path, is_private)
    """
    is_private = "_private" in request_data and (
        request_data["_private"] == "true" or request_data["_private"] is True
    )
    stripped_path = request_data["path"].strip("/")

    if is_private:
        private_space = stripped_path.split("/")[0]
        if private_space == "":  # path for private space must start with space ID
            return bad_request("Path in private space must start with space ID")
        # For private spaces, use subdirectories within the private space
        relative_path = "/".join(stripped_path.split("/")[1:])  # path without space ID
        inputs_path = safe_join(f"{PRIVATE_PATH}/{private_space}/_inputs", relative_path)
        files_path = safe_join(f"{PRIVATE_PATH}/{private_space}/_files", relative_path)
        outputs_path = safe_join(f"{PRIVATE_PATH}/{private_space}/_outputs", relative_path)
    else:
        inputs_path = safe_join(INPUTS_PATH, stripped_path)
        files_path = safe_join(FILES_PATH, stripped_path)
        outputs_path = safe_join(OUTPUTS_PATH, stripped_path)

    return inputs_path, files_path, outputs_path, is_private


def format_filesystem_path(request_data):
    """
    Format request path for filesystem operations.

    Returns: (inputs_path, files_path, outputs_path, inputs_base, files_base, private_space, is_private)
    """
    is_private = "_private" in request_data and (
        request_data["_private"] == "true" or request_data["_private"] is True
    )
    private_space = None

    if is_private:
        stripped_path = request_data["path"].strip("/")
        private_space = stripped_path.split("/")[0]
        if private_space == "":  # path for private space must start with space ID
            return bad_request("Path in private space must start with space ID")

        # Base paths for the private space
        inputs_base = f"{PRIVATE_PATH}/{private_space}/_inputs"
        files_base = f"{PRIVATE_PATH}/{private_space}/_files"

        # Full paths including the relative path
        relative_path = "/".join(stripped_path.split("/")[1:])  # path without space ID
        inputs_path = safe_join(inputs_base, relative_path) if relative_path else inputs_base
        files_path = safe_join(files_base, relative_path) if relative_path else files_base
        outputs_path = safe_join(f"{PRIVATE_PATH}/{private_space}/_outputs", relative_path)
    else:
        inputs_base = INPUTS_PATH
        files_base = FILES_PATH
        inputs_path = safe_join(INPUTS_PATH, request_data["path"].strip("/"))
        files_path = safe_join(FILES_PATH, request_data["path"].strip("/"))
        outputs_path = safe_join(OUTPUTS_PATH, request_data["path"].strip("/"))

    if inputs_path is None or files_path is None:
        abort(HTTPStatus.NOT_FOUND)
    return inputs_path, files_path, outputs_path, inputs_base, files_base, private_space, is_private


# Endpoint requires a non-empty 'path' argument
def requires_arg_path(func):
    func._requires_arg_path = True  # value unimportant
    return func


# Endpoint requires a non-empty 'path' JSON value
def requires_json_path(func):
    func._requires_json_path = True  # value unimportant
    return func


# Endpoint requires a non-empty 'path' form value
def requires_form_path(func):
    func._requires_form_path = True  # value unimportant
    return func


# Endpoint requires an allowed file type
def requires_allowed_file(func):
    func._requires_allowed_file = True  # value unimportant
    return func


# Endpoint requires a document ID argument; used for API calls for OCR of single files, bypassing the creation of workspace folders
def requires_arg_doc_id(func):
    func._requires_arg_doc_id = True  # value unimportant
    return func


# Endpoint requires a document ID JSON value; used for API calls for OCR of single files, bypassing the creation of workspace folders
def requires_json_doc_id(func):
    func._requires_json_doc_id = True  # value unimportant
    return func


# Endpoint is exempt from CSRF; used to bypass csrf.exempt decorator not working
def csrf_exempt(func):
    func._csrf_exempt = True  # value unimportant
    return func


@app.before_request
def abort_bad_request():
    if request.endpoint in app.view_functions:
        view_func = app.view_functions[request.endpoint]
        if hasattr(view_func, "_requires_arg_path"):
            if "path" not in request.values or request.values["path"] == "":
                return bad_request("Missing 'path' argument")
        elif hasattr(view_func, "_requires_json_path"):
            if "path" not in request.json or request.json["path"] == "":
                return bad_request("Missing 'path' parameter")
        elif hasattr(view_func, "_requires_form_path"):
            if "path" not in request.form or request.form["path"] == "":
                return bad_request("Missing 'path' in form")
        elif hasattr(view_func, "_requires_arg_doc_id"):
            if "doc_id" not in request.values or request.values["doc_id"] == "":
                return bad_request("Missing 'doc_id' argument")
        elif hasattr(view_func, "_requires_json_doc_id"):
            if "doc_id" not in request.json or request.json["doc_id"] == "":
                return bad_request("Missing 'doc_id' parameter")
        elif hasattr(view_func, "_requires_allowed_file"):
            if "name" not in request.form:
                return bad_request("Missing 'name' in form")
            if request.form["name"].split(".")[-1].lower() not in ALLOWED_EXTENSIONS:
                abort(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)


# Bypass CSRF check by changing the context flag, due to flask-wtf's "exempt" decorator not working
@app.before_request
def ignore_csrf_if_exempt():
    if request.method != "GET" and request.endpoint in app.view_functions:
        view_func = app.view_functions[request.endpoint]
        if hasattr(view_func, "_csrf_exempt"):
            g.csrf_valid = True


#####################################
# FILE SYSTEM ROUTES
#####################################


@app.route("/files", methods=["GET"])
def get_file_system():
    try:
        # Get filesystem structure from _inputs, metadata from _files
        if "path" not in request.values or request.values["path"] == "":
            filesystem = get_filesystem(INPUTS_PATH)
            filesystem["maxAge"] = os.environ.get("MAX_PRIVATE_SPACE_AGE", "1")
            return filesystem

        _, _, _, inputs_base, files_base, private_space, is_private = format_filesystem_path(
            request.values
        )
        filesystem = get_filesystem(inputs_base, private_space, is_private)
        filesystem["maxAge"] = os.environ.get("MAX_PRIVATE_SPACE_AGE", "1")
        return filesystem
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)


@app.route("/info", methods=["GET"])
def get_info():
    try:
        # Get info using _inputs for structure, _files for metadata
        if "path" not in request.values or request.values["path"] == "":
            return get_filesystem(INPUTS_PATH)

        _, _, _, inputs_base, files_base, private_space, is_private = format_filesystem_path(
            request.values
        )
        return {"info": get_structure_info(inputs_base, files_base, private_space, is_private)}
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)


@app.route("/create-folder", methods=["POST"])
def create_folder():
    data = request.json
    if (
        "path" not in data  # empty path is valid: new top-level public space folder
        or "folder" not in data
        or data["folder"] == ""
    ):
        return bad_request("Missing parameter 'path' or 'folder'")

    inputs_path, files_path, outputs_path, is_private = format_path(data)
    if inputs_path is None or files_path is None:
        abort(HTTPStatus.NOT_FOUND)

    folder = data["folder"]

    if folder.startswith("_") or "/" in folder or "\\" in folder:
        return {
            "success": False,
            "error": "O nome da pasta não pode começar com '_' nem conter '/' ou '\\'",
        }

    # Check if folder exists in _inputs
    new_inputs_folder = safe_join(inputs_path, folder)
    new_files_folder = safe_join(files_path, folder)

    if os.path.exists(new_inputs_folder):
        return {"success": False, "error": "Já existe uma pasta com esse nome"}

    # Create folder in both _inputs and _files
    os.makedirs(new_inputs_folder, exist_ok=True)
    os.makedirs(new_files_folder, exist_ok=True)

    # Metadata goes in _files
    with open(f"{new_files_folder}/_data.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "type": "folder",
                "creation": get_current_time(),
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    return {
        "success": True,
        "message": f"Pasta {folder} criada com sucesso",
    }


@app.route("/get-text-content", methods=["GET"])
@requires_arg_path
def get_text_content():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)
    totalPages = len(os.listdir(files_path + "/_ocr_results"))
    doc, words = get_file_parsed(files_path, is_private)
    data = get_data(safe_join(files_path, "_data.json"))
    edited_without_recreate = (
        data["edited_results"] if "edited_results" in data else False
    )
    return {
        "must_recreate": edited_without_recreate,
        "pages": totalPages,
        "doc": doc,
        "words": words,
        "corpus": [x[:-4] for x in os.listdir("corpus")],
    }


@app.route("/get_txt_delimited", methods=["GET"])
@requires_arg_path
def get_txt_delimited():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if outputs_path is None:
        abort(HTTPStatus.NOT_FOUND)
    return send_file(f"{outputs_path}/_txt_delimited.txt")


@app.route("/get_txt", methods=["GET"])
@requires_arg_path
def get_txt():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if outputs_path is None:
        abort(HTTPStatus.NOT_FOUND)
    return send_file(f"{outputs_path}/_txt.txt")


@app.route("/get_entities", methods=["GET"])
@requires_arg_path
def get_entities():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if outputs_path is None:
        abort(HTTPStatus.NOT_FOUND)
    return send_file(f"{outputs_path}/_entities.json")


# TODO: currently not used
@app.route("/request_entities", methods=["GET"])
@requires_arg_path
def request_entities():
    inputs_path, files_path, outputs_path, inputs_base, files_base, private_space, is_private = format_filesystem_path(
        request.values
    )
    data = get_data(files_path + "/_data.json")

    data["ner"] = {
        "error": False,
        "complete": False,
    }

    update_json_file(f"{files_path}/_data.json", data)

    celery.send_task("request_ner", kwargs={"files_path": files_path, "outputs_path": outputs_path}, ignore_result=True)
    return {
        "success": True,
        "filesystem": get_filesystem(inputs_base, private_space, is_private),
    }


# TODO: currently not used
@app.route("/get_zip", methods=["GET"])
@requires_arg_path
def get_zip():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)
    try:
        celery.send_task("export_file", kwargs={
            "files_path": files_path,
            "outputs_path": outputs_path,
            "filetype": "zip"
        }).get()
    except Exception:
        return {
            "success": False,
            "message": "Pelo menos um ficheiro está a ser processado. Tente mais tarde",
        }
    return send_file(
        safe_join(outputs_path, f"{files_path.split('/')[-1]}.zip")
    )


@app.route("/get_pdf_indexed", methods=["GET"])
@requires_arg_path
def get_pdf_indexed():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)
    promise = celery.send_task("export_file", kwargs={
        "files_path": files_path,
        "outputs_path": outputs_path,
        "inputs_path": inputs_path,
        "filetype": "pdf"
    })
    file = promise.get()
    return send_file(file)


@app.route("/get_pdf", methods=["GET"])
@requires_arg_path
def get_pdf_simple():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)

    promise = celery.send_task(
        "export_file", kwargs={
            "files_path": files_path,
            "outputs_path": outputs_path,
            "inputs_path": inputs_path,
            "filetype": "pdf",
            "simple": True
        }
    )
    file = promise.get()
    return send_file(file)


@app.route("/get_csv", methods=["GET"])
@requires_arg_path
def get_csv():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if outputs_path is None:
        abort(HTTPStatus.NOT_FOUND)
    return send_file(f"{outputs_path}/_index.csv")


@app.route("/get_hocr", methods=["GET"])
@requires_arg_path
def get_hocr():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if outputs_path is None:
        abort(HTTPStatus.NOT_FOUND)
    return send_file(f"{outputs_path}/_hocr.hocr")


@app.route("/get_alto", methods=["GET"])
@requires_arg_path
def get_alto():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if outputs_path is None:
        abort(HTTPStatus.NOT_FOUND)
    return send_file(f"{outputs_path}/_xml.xml")


@app.route("/get_images", methods=["GET"])
@requires_arg_path
def get_images():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)

    promise = celery.send_task("export_file", kwargs={
        "files_path": files_path,
        "outputs_path": outputs_path,
        "filetype": "imgs"
    })
    file = promise.get()
    return send_file(file)


@app.route("/get_original", methods=["GET"])
@requires_arg_path
def get_original():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if inputs_path is None:
        abort(HTTPStatus.NOT_FOUND)
    # Original file is now in _inputs directly (not in a subfolder)
    return send_file(inputs_path)


@app.route("/delete-path", methods=["POST"])
@requires_json_path
def delete_path():
    inputs_path, files_path, outputs_path, inputs_base, files_base, private_space, is_private = format_filesystem_path(request.json)
    try:
        # avoid deleting roots
        if (
            os.path.samefile(INPUTS_PATH, inputs_path)
            or os.path.samefile(FILES_PATH, files_path)
            or os.path.samefile(OUTPUTS_PATH, outputs_path)
            or os.path.samefile(PRIVATE_PATH, inputs_path)
            or os.path.samefile(inputs_path, inputs_base)
            or os.path.samefile(files_path, files_base)
        ):
            abort(HTTPStatus.NOT_FOUND)

        # FIXME: uncomment when searching feature is improved and re-enabled
        # delete_structure(es, files_path)

        # Delete from all three locations
        if os.path.exists(inputs_path):
            if os.path.isfile(inputs_path):
                os.remove(inputs_path)
            else:
                shutil.rmtree(inputs_path)
        if os.path.exists(files_path):
            shutil.rmtree(files_path)
        if os.path.exists(outputs_path):
            shutil.rmtree(outputs_path)
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)

    return {
        "success": True,
        "message": "Apagado com sucesso",
    }


@app.route("/set-upload-stuck", methods=["POST"])
@requires_json_path
def set_upload_stuck():
    inputs_path, files_path, outputs_path, is_private = format_path(request.json)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)

    try:
        data = get_data(f"{files_path}/_data.json")
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)
    data["upload_stuck"] = True
    data["status"]["stage"] = "error"
    update_json_file(f"{files_path}/_data.json", data)

    return {
        "success": True,
        "message": "O upload do ficheiro falhou",
    }


#####################################
# FILES ROUTES
#####################################
def is_filename_reserved(inputs_path, files_path, filename):
    """
    Check if a filename is reserved.
    A filename can be reserved if:
        - It exists as a file or folder in _inputs
        - It is a file that is being processed (metadata in _files)

    :param inputs_path: path in _inputs to check
    :param files_path: path in _files to check metadata
    :param filename: filename to check
    :return: True if reserved, False otherwise
    """
    # Check if file exists directly in _inputs
    if os.path.exists(safe_join(inputs_path, filename)):
        return True

    # Check if there's a processing folder in _files
    files_target = safe_join(files_path, filename)
    if os.path.exists(files_target) and os.path.isdir(files_target):
        return True

    # Check metadata for original_filename
    if os.path.exists(files_path):
        with os.scandir(files_path) as dir_content:
            for f in dir_content:
                if not f.is_dir():
                    continue
                try:
                    data = get_data(f"{f.path}/_data.json")
                    if "original_filename" in data and data["original_filename"] == filename:
                        return True
                except (FileNotFoundError, json.JSONDecodeError):
                    continue
    return False


def find_valid_filename(inputs_path, files_path, basename, extension):
    """
    Find valid name for a file so it doesn't overwrite another file.

    :param inputs_path: path in _inputs
    :param files_path: path in _files
    :param basename: basename of the file
    :param extension: extension of the file
    :return: valid filename
    """
    id = 1
    while is_filename_reserved(inputs_path, files_path, f"{basename} ({id}).{extension}"):
        id += 1

    return f"{basename} ({id}).{extension}"


@app.route("/prepare-upload", methods=["POST"])
@requires_json_path
def prepare_upload():
    if float(get_free_space()[1]) < 10:
        return {
            "success": False,
            "error": "O servidor não tem espaço suficiente. Por favor informe o administrador",
        }

    data = request.json
    if "name" not in data or data["name"] == "":
        return bad_request("Missing parameter 'name'")

    inputs_path, files_path, outputs_path, inputs_base, files_base, private_space, is_private = format_filesystem_path(data)
    filename = data["name"]

    if is_filename_reserved(inputs_path, files_path, filename):
        basename = get_file_basename(filename)
        extension = get_file_extension(filename)
        filename = find_valid_filename(inputs_path, files_path, basename, extension)

    # Path for original file in _inputs
    inputs_target = safe_join(inputs_path, filename)
    # Path for document folder in _files (named after the file)
    files_target = safe_join(files_path, filename)
    # Path for outputs in _outputs (named after the file)
    outputs_target = safe_join(outputs_path, filename)

    # Ensure parent directories exist
    os.makedirs(inputs_path, exist_ok=True)
    os.makedirs(files_path, exist_ok=True)
    os.makedirs(outputs_path, exist_ok=True)

    # Ensure parent folder has _data.json (for proper folder metadata)
    if files_path != FILES_PATH and not os.path.exists(f"{files_path}/_data.json"):
        with open(f"{files_path}/_data.json", "w", encoding="utf-8") as f:
            json.dump(
                {
                    "type": "folder",
                    "creation": get_current_time(),
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

    # Create document metadata folder in _files with subfolders
    os.makedirs(files_target, exist_ok=True)
    os.makedirs(files_target + "/_images", exist_ok=True)
    os.makedirs(files_target + "/_layouts", exist_ok=True)
    os.makedirs(files_target + "/_ocr_results", exist_ok=True)
    os.makedirs(files_target + "/_pages", exist_ok=True)
    os.makedirs(files_target + "/_thumbnails", exist_ok=True)

    # Create outputs folder
    os.makedirs(outputs_target, exist_ok=True)

    extension = filename.split(".")[-1]
    with open(f"{files_target}/_data.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "type": "file",
                "extension": (
                    extension if extension.lower() in ALLOWED_EXTENSIONS else "other"
                ),
                "stored": 0.00,
                "creation": get_current_time(),
                "status": {
                    "stage": "uploading",
                    "message": "A enviar, por favor aguarde...",
                },
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    return {"success": True, "filename": filename}


def join_chunks(inputs_target, files_target, filename, total_count, temp_file_path):
    """
    Join uploaded chunks into the final file.

    :param inputs_target: path where the original file should be saved in _inputs
    :param files_target: path to document folder in _files
    :param filename: the filename
    :param total_count: total number of chunks
    :param temp_file_path: path to temporary chunk storage
    """
    # Save the file to _inputs
    with open(inputs_target, "wb") as f:
        for i in range(total_count):
            with open(f"{temp_file_path}/{i + 1}", "rb") as chunk:
                f.write(chunk.read())
    celery.send_task("prepare_file", kwargs={
        "inputs_path": inputs_target,
        "files_path": files_target
    }, ignore_result=True)
    shutil.rmtree(temp_file_path)


@app.route("/upload-file", methods=["POST"])
@requires_form_path
@requires_allowed_file
def upload_file():
    if float(get_free_space()[1]) < 10:
        return {
            "success": False,
            "error": "O servidor não tem espaço suficiente. Por favor informe o administrador",
        }

    if (
        "file" not in request.files
        or "name" not in request.form
        or "counter" not in request.form
        or "totalCount" not in request.form
    ):
        return bad_request(
            "Missing file or parameter 'name', 'counter', or 'totalCount'"
        )

    inputs_path, files_path, outputs_path, is_private = format_path(request.form)
    file = request.files["file"]
    filename = request.form["name"]
    counter = int(request.form["counter"])
    total_count = int(request.form["totalCount"])

    temp_filename = safe_join(files_path, f"_{filename}").replace("/", "_")
    # Original file goes to _inputs directly
    inputs_target = safe_join(inputs_path, filename)
    # Document metadata folder in _files
    files_target = safe_join(files_path, filename)

    # If only one chunk, save the file directly
    if total_count == 1:
        # Save original file to _inputs
        file.save(inputs_target)

        celery.send_task(
            "prepare_file", kwargs={
                "inputs_path": inputs_target,
                "files_path": files_target
            }, ignore_result=True
        )

        return {"success": True, "finished": True}

    # Create a Lock to process the file
    if temp_filename not in lock_system:
        lock_system[temp_filename] = Lock()

    # If multiple chunks, save the chunk and wait for the other chunks
    file = file.read()

    # Create the folder to save the chunks
    temp_file_path = safe_join(TEMP_PATH, temp_filename)
    if not os.path.exists(temp_file_path):
        os.mkdir(temp_file_path)

    with lock_system[temp_filename]:
        # Save the chunk
        with open(f"{temp_file_path}/{counter}", "wb") as f:
            f.write(file)

        # Number of chunks saved
        chunks_saved = len(os.listdir(f"{temp_file_path}"))
        stored = round(100 * chunks_saved / total_count, 2)

        update_json_file(f"{files_target}/_data.json", {"stored": stored})

        if chunks_saved == total_count:
            del lock_system[temp_filename]

            Thread(
                target=join_chunks,
                args=(inputs_target, files_target, filename, total_count, temp_file_path),
            ).start()

            return {"success": True, "finished": True}

    return {"success": True, "finished": False}


@app.route("/default-config", methods=["GET"])
def get_default_ocr_config():
    """
    Returns the current default OCR configuration.
    """
    return send_from_directory(CONFIG_FILES_LOCATION, "default.json")


@app.route("/config-preset", methods=["GET"])
def get_config_preset():
    """
    Returns the OCR configuration with the specified name.
    """
    data = request.values
    if "name" not in data or data["name"] == "":
        return bad_request("Missing 'name' argument")
    return send_from_directory(CONFIG_FILES_LOCATION, f"{data["name"]}.json")


@app.route("/presets-list", methods=["GET"])
def get_presets_list():
    """
    Returns the names of existing configuration presets, excluding the default.
    """
    config_names = [
        os.path.splitext(config.name)[0]
        for config in os.scandir(CONFIG_FILES_LOCATION)
        if config.is_file()
    ]
    try:
        config_names.remove("default")
    except ValueError:
        log.error("Missing default.json in config files")
    return config_names


@app.route("/get-config", methods=["GET"])
@requires_arg_path
def get_doc_config():
    """
    Get the saved OCR config for a specific document.
    Returns the config object or null if using default/not set.
    """
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)

    data_path = f"{files_path}/_data.json"
    try:
        data = get_data(data_path)
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)

    config = data.get("config", None)
    # Return null if no config or if set to "default"
    if config == "default":
        config = None

    return {"success": True, "config": config}


@app.route("/save-config", methods=["POST"])
@requires_json_path
def configure_ocr():
    req_data = request.json
    if "config" not in req_data:
        return bad_request("Missing parameter 'config'")
    inputs_path, files_path, outputs_path, is_private = format_path(req_data)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)

    data_path = f"{files_path}/_data.json"
    try:
        data = get_data(data_path)
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)  # TODO: improve feedback to users on error

    if isinstance(req_data["config"], dict) or req_data["config"] == "default":
        data["config"] = req_data["config"]
    else:
        return bad_request('Config must be dictionary or "default"')

    update_json_file(data_path, data)

    return {"success": True}


@app.route("/request-ocr", methods=["POST"])
@requires_json_path
def request_ocr():
    """
    Request to perform OCR on a file/folder.

    JSON parameters:
    - path: path to the file/folder\n
    - config: configuration to be used in OCR\n
    - multiple: if it is a folder or not\n
    """

    if float(get_free_space()[1]) < 10:
        return {
            "success": False,
            "error": "O servidor não tem espaço suficiente. Por favor informe o administrador",
        }

    req_data = request.json
    inputs_path, files_path, outputs_path, is_private = format_path(req_data)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)

    config = req_data["config"] if "config" in req_data else None
    multiple = req_data["multiple"] if "multiple" in req_data else False

    if multiple:
        # For folder OCR, scan _files for document folders
        files_list = [
            (f.path, f"{outputs_path}/{f.name}")
            for f in os.scandir(files_path)
            if f.is_dir() and not f.name.startswith("_") and get_data(f"{f.path}/_data.json")["type"] == "file"
        ]
    else:
        files_list = [(files_path, outputs_path)]

    for f_path, o_path in files_list:
        data_path = f"{f_path}/_data.json"
        try:
            data = get_data(data_path)
        except FileNotFoundError:
            abort(
                HTTPStatus.INTERNAL_SERVER_ERROR
            )  # TODO: improve feedback to users on error

        # Replace specified config with saved config, if exists
        if config is None and "config" in data:
            config = data["config"]

        # Remove indexed pages, which will become outdated
        results_path = f"{f_path}/_ocr_results"

        # FIXME: uncomment when searching feature is improved and re-enabled
        """
        pages = [
            f
            for f in os.scandir(results_path)
            if os.path.splitext(f.name)[1] == ".json"
        ]

        if data.get("indexed", False):
            for page in pages:
                page_id = generate_uuid(page.path)
                try:
                    es.delete_document(page_id)
                except NotFoundError:
                    continue
        """

        # Delete previous results in _files
        if os.path.exists(results_path):
            shutil.rmtree(results_path)
        os.makedirs(f"{f_path}/_ocr_results", exist_ok=True)

        # Delete previous outputs in _outputs
        if os.path.exists(o_path):
            shutil.rmtree(o_path)
        os.makedirs(o_path, exist_ok=True)

        data.update(
            {
                "ocr": {"progress": 0},
                "status": {
                    "stage": "ocr",
                    "message": "A começar...",
                },
                "pdf": {"complete": False},
                "pdf_indexed": {"complete": False},
                "txt": {"complete": False},
                "txt_delimited": {"complete": False},
                "csv": {"complete": False},
                "ner": {"complete": False},
                "hocr": {"complete": False},
                "xml": {"complete": False},
                "zip": {"complete": False},
                "indexed": False,
            }
        )
        update_json_file(data_path, data)

        if os.path.exists(f"{f_path}/_images"):
            shutil.rmtree(f"{f_path}/_images")

        celery.send_task(
            "file_ocr", kwargs={
                "files_path": f_path,
                "outputs_path": o_path,
                "config": config
            }, ignore_result=True
        )

    return {
        "success": True,
        "message": "O OCR começou, por favor aguarde",
    }


# FIXME: uncomment when searching feature is improved and re-enabled
"""
@app.route("/index-doc", methods=["POST"])
@requires_json_path
def index_doc():
    data = request.json
    path, _ = format_path(data)
    if path is None:
        abort(HTTPStatus.NOT_FOUND)

    if PRIVATE_PATH in path:  # avoid indexing private spaces
        abort(HTTPStatus.NOT_FOUND)

    data_path = path + "/_data.json"
    hOCR_path = path + "/_ocr_results"
    try:
        data = get_data(data_path)
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)

    pages = [f for f in os.scandir(hOCR_path) if os.path.splitext(f.name)[1] == ".json"]

    extension = data["extension"]
    for i, page in enumerate(pages):
        with open(page, encoding="utf-8") as f:
            hocr = json.load(f)
            text = json_to_text(hocr)

        if data["pages"] > 1:
            doc = create_document(
                page.path,
                data["ocr"]["config"]["engine"],
                data["ocr"]["config"],
                text,
                extension,
                i + 1,
            )
        else:
            doc = create_document(
                page.path, "Tesseract", data["ocr"]["config"], text, extension
            )

        page_id = generate_uuid(page.path)
        es.add_document(page_id, doc)

    update_json_file(data_path, {"indexed": True})

    return {
        "success": True,
        "message": "Documento indexado",
    }


@app.route("/remove-index-doc", methods=["POST"])
@requires_json_path
def remove_index_doc():
    data = request.json
    path, _ = format_path(data)
    if path is None:
        abort(HTTPStatus.NOT_FOUND)

    if PRIVATE_PATH in path:
        abort(HTTPStatus.NOT_FOUND)

    data_path = path + "/_data.json"
    hOCR_path = path + "/_ocr_results"
    pages = [f for f in os.scandir(hOCR_path) if os.path.splitext(f.name)[1] == ".json"]
    try:
        for page in pages:
            page_id = generate_uuid(page.path)
            es.delete_document(page_id)

        update_json_file(data_path, {"indexed": False})

        return {
            "success": True,
            "message": "Documento removido",
        }
    except NotFoundError:
        update_json_file(data_path, {"indexed": False})
        return {
            "success": False,
            "message": "O documento não foi encontrado no index.",
        }
"""


@app.route("/submit-text", methods=["POST"])
def submit_text():
    data = request.json
    if "text" not in data or "remakeFiles" not in data:
        return bad_request("Missing parameter 'text' or 'remakeFiles'")

    texts = data["text"]  # estrutura com texto, nome do ficheiro e url da imagem
    remake_files = data["remakeFiles"]
    data_folder_list = texts[0]["original_file"].strip("/").split("/")[:-2]
    data_folder = "/".join(data_folder_list)

    is_private = "_private" in data and (
        data["_private"] == "true" or data["_private"] is True
    )
    if is_private:
        path = safe_join(PRIVATE_PATH, data_folder)
        data_path = path + "/_data.json"
        private_space = data_folder_list[0]
        if private_space == "":  # path for private space must start with space ID
            return bad_request("Path to private space must start with space ID")
    else:
        path = safe_join(FILES_PATH, data_folder)
        data_path = path + "/_data.json"

    try:
        data = get_data(data_path)
        if not remake_files:
            data["edited_results"] = True
        elif "edited_results" in data:
            del data["edited_results"]
        update_json_file(data_path, data)
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)

    for t in texts:
        text = t["content"]
        if is_private:
            filename = safe_join(PRIVATE_PATH, t["original_file"].strip("/"))
        else:
            filename = safe_join(FILES_PATH, t["original_file"].strip("/"))

        if filename is None:
            abort(HTTPStatus.NOT_FOUND)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(text, f, indent=2, ensure_ascii=False)

    data_update = {"words": get_word_count(path)}
    update_json_file(data_path, data_update)

    if remake_files:
        celery.send_task(
            "make_changes", kwargs={"path": path, "data": data}, ignore_result=True
        )

    return {"success": True}


@app.route("/check-sintax", methods=["POST"])
def check_sintax():
    if "words" not in request.json or "languages" not in request.json:
        return bad_request("Missing parameter 'words' or 'languages'")

    words = request.json["words"].keys()
    languages = request.json["languages"]

    result = compare_dicts_words(words, languages)
    return {"success": True, "result": result}


#####################################
# ELASTICSEARCH
#####################################

# FIXME: uncomment when searching feature is improved and re-enabled
"""
@app.route("/get-docs-list", methods=["GET"])
def get_docs_list():
    return es.get_all_docs_names()


@app.route("/search", methods=["POST"])
def search():
    data = request.json
    if "query" not in data:
        return bad_request("Missing parameter 'query'")

    query = data["query"]
    docs = None

    if "docs" in data and len(data["docs"]):
        docs = data["docs"]

    # for empty query with doc list, get all content of those docs
    if docs and query == "":
        return jsonify(es.get_docs(docs))
    else:
        return jsonify(es.search(query, docs))
"""


#####################################
# PRIVATE SPACES
#####################################
@app.route("/create-private-space", methods=["GET"])
def create_private_space():
    space_id = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    if not os.path.isdir(PRIVATE_PATH):
        os.mkdir(PRIVATE_PATH)
        with open(f"{PRIVATE_PATH}/_data.json", "w", encoding="utf-8") as f:
            json.dump(
                {
                    "type": "folder",
                    "creation": get_current_time(),
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

    # Create the private space directory
    space_path = f"{PRIVATE_PATH}/{space_id}"
    os.mkdir(space_path)

    # Create the three subdirectories for the new structure
    os.mkdir(f"{space_path}/_inputs")
    os.mkdir(f"{space_path}/_files")
    os.mkdir(f"{space_path}/_outputs")

    # Create space metadata
    with open(f"{space_path}/_data.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "type": "folder",
                "creation": get_current_time(),
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    return {"success": True, "space_id": space_id}


#####################################
# LAYOUTS
#####################################
@app.route("/get-layouts", methods=["GET"])
@requires_arg_path
def get_layouts():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)
    try:
        layouts, segmenting = get_file_layouts(files_path, is_private)
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)
    return {"layouts": layouts, "segmenting": segmenting}


@app.route("/save-layouts", methods=["POST"])
@requires_json_path
def save_layouts():
    data = request.json
    if "layouts" not in data:
        return bad_request("Missing parameter 'layouts'")

    inputs_path, files_path, outputs_path, is_private = format_path(data)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)

    doc_data_path = f"{files_path}/_data.json"
    lock_path = f"{doc_data_path}.lock"
    lock = FileLock(lock_path)
    with lock:
        doc_data = get_data(f"{files_path}/_data.json", lock=lock)
        if "segmenting" in doc_data and doc_data["segmenting"]:
            return {"segmenting": True}

    layouts = data["layouts"]
    try:
        save_file_layouts(files_path, layouts)
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)
    return {"success": True}


# TODO: (FIXME) automatic layout generation is relying on fetching async task, may not work if server is under load
@app.route("/generate-automatic-layouts", methods=["GET"])
@requires_arg_path
def generate_automatic_layouts():
    inputs_path, files_path, outputs_path, is_private = format_path(request.values)
    if files_path is None:
        abort(HTTPStatus.NOT_FOUND)

    use_hdbscan = False
    if "use_hdbscan" in request.values:
        use_hdbscan = request.values["use_hdbscan"] in ("true", "True")

    data_path = f"{files_path}/_data.json"
    lock_path = f"{data_path}.lock"
    lock = FileLock(lock_path)
    with lock:
        data = get_data(f"{files_path}/_data.json", lock=lock)
        if "segmenting" in data and data["segmenting"]:
            return {"segmenting": True}
    try:
        celery.send_task(
            "auto_segment", kwargs={"path": files_path, "use_hdbscan": use_hdbscan}
        ).get(timeout=60)
        layouts, segmenting = get_file_layouts(files_path, is_private)
        return {"layouts": layouts, "segmenting": segmenting}
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)
    except TimeoutError:
        return {"segmenting": True}


#####################################
# API-specific endpoints
#####################################
@app.route("/check-status", methods=["GET"])
@requires_arg_doc_id
def api_check_status():
    doc_id = request.values["doc_id"]
    doc_path = safe_join(API_TEMP_PATH, doc_id)
    data_path = safe_join(doc_path, "_data.json")
    try:
        return get_data(data_path)
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)


@app.route("/perform-ocr", methods=["POST"])
def api_perform_ocr():
    if float(get_free_space()[1]) < 10:
        return {
            "success": False,
            "error": "O servidor não tem espaço suficiente. Por favor informe o administrador",
        }

    if "file" not in request.files:
        return bad_request("Missing file")

    file = request.files["file"]
    config = request.form.get("config", None)

    doc_id = generate_random_uuid()[:9]
    doc_path = f"{API_TEMP_PATH}/{doc_id}"
    extension = file.filename.split(".")[-1]
    file_path = f"{doc_path}/{doc_id}.{extension}"
    os.mkdir(doc_path)
    with open(f"{doc_path}/_data.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "type": "file",
                "creation": get_current_time(),
                "extension": (
                    extension if extension.lower() in ALLOWED_EXTENSIONS else "other"
                ),
                "stored": 0.00,  # 0% at start, 100% when all chunks stored, True after prepare_file_ocr
                "status": {
                    "stage": "uploading",
                    "message": "A enviar",
                },
                "ocr": {"progress": 0},
                "pdf": {"complete": False},
                "pdf_indexed": {"complete": False},
                "txt": {"complete": False},
                "txt_delimited": {"complete": False},
                "csv": {"complete": False},
                "ner": {"complete": False},
                "hocr": {"complete": False},
                "xml": {"complete": False},
                "zip": {"complete": False},
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    file.save(file_path)
    # TODO: default to NOT deleting original after OCR?
    celery.send_task(
        "ocr_from_api",
        kwargs={"path": doc_path, "config": config, "delete_on_finish": True},
        ignore_result=True,
    )
    return {
        "success": True,
        "doc_id": doc_id,
        "message": "OCR has been requested. View progress at /check-status, retrieve results at /get-result",
    }


@app.route("/get-result", methods=["GET"])
@requires_arg_doc_id
def api_get_result():
    doc_id = request.values["doc_id"]
    if "type" not in request.values or request.values["type"] == "":
        return bad_request("Missing 'type' argument")
    type = request.values["type"]
    if type not in RESULT_TYPE_TO_EXTENSION.keys():
        return bad_request(f"'{type} is not a supported result format")

    log.debug(f"Requesting result of type {type}")

    doc_path = safe_join(API_TEMP_PATH, doc_id)
    data_path = safe_join(doc_path, "_data.json")
    try:
        data = get_data(data_path)
    except FileNotFoundError:
        abort(HTTPStatus.NOT_FOUND)

    log.debug(
        f"Result is {data.get(type)} at /_export/_{type}.{RESULT_TYPE_TO_EXTENSION[type]}"
    )

    if not data.get(type, {}).get("complete", False):
        abort(HTTPStatus.NOT_FOUND)

    return send_from_directory(
        doc_path, f"_export/_{type}.{RESULT_TYPE_TO_EXTENSION[type]}"
    )


@app.route("/delete-results", methods=["POST"])
@requires_json_doc_id
def api_delete_results():
    doc_id = request.json["doc_id"]
    doc_path = safe_join(API_TEMP_PATH, doc_id)
    if doc_path is None:
        abort(HTTPStatus.NOT_FOUND)
    shutil.rmtree(doc_path)
    return {"success": True, "message": f"Removed {doc_id}"}


#####################################
# LOGIN MANAGEMENT
#####################################
@app.route("/account/check-auth", methods=["GET"])
@auth_required("token", "session")
@roles_required("Admin")
def check_authorized():
    if current_user.is_authenticated:
        return "Logged in"
    else:
        abort(HTTPStatus.FORBIDDEN)


"""
@app.route("/register", methods=["POST"])
def register_user():
    email = request.json["email"]
    password = request.json["password"]
    user_exists = User.query.filter_by(email=email).first() is not None

    if user_exists:
        return jsonify({"error": "Utilizador já registado com este email."}), 409

    new_user = User(email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    session["user_id"] = new_user.id
    return jsonify({
        "id": new_user.id,
        "email": new_user.email
    })
"""

#####################################
# ADMIN ROUTES
#####################################


@app.route("/admin/system-info", methods=["GET"])
@auth_required("token", "session")
@roles_required("Admin")
def get_system_info():
    free_space, free_space_percentage = get_free_space()
    return {
        "free_space": free_space,
        "free_space_percentage": free_space_percentage,
        # "logs": get_logs(),
        "private_spaces": get_private_spaces(),
    }


@app.route("/admin/storage-info", methods=["GET"])
@auth_required("token", "session")
@roles_required("Admin")
def get_storage_info():
    free_space, free_space_percentage = get_free_space()
    data = get_data(f"./{PRIVATE_PATH}/_data.json")
    last_cleanup = data.get("last_cleanup", "nunca")
    return {
        "free_space": free_space,
        "free_space_percentage": free_space_percentage,
        "private_spaces": get_size_private_spaces(),
        "api_files": get_size_api_files(),
        "last_cleanup": last_cleanup,
        "max_age": os.environ.get("MAX_PRIVATE_SPACE_AGE", "1"),
    }


@app.route("/admin/cancel-cleanup", methods=["POST"])
def cancel_cleanup():
    """
    For now, use to quickly cancel all scheduling of private space cleanups.
    Schedule can be recreated by restarting worker or flower.

    TODO: allow recreating schedule through another endpoint,
    or make calls to /admin/schedule-cleanup re-create the schedule if it doesn't exist.
    """
    entry = RedBeatSchedulerEntry.from_key("redbeat:cleanup_private_spaces", app=celery)
    entry.delete()
    return {
        "success": True,
        "message": "Limpeza regular de espaços privados cancelada.",
    }


@app.route("/admin/schedule-cleanup", methods=["POST"])
@auth_required("token", "session")
@roles_required("Admin")
def schedule_private_space_cleanup():
    data = request.json
    if "type" not in data:
        return bad_request("Missing parameter 'type'")

    if data["type"] == "interval":
        if "run_every" not in data or not isinstance(data["run_every"], (int, str)):
            return bad_request(
                "Parameter 'run_every' must be positive whole number as integer or string"
            )
        if data["run_every"] == 0:
            return bad_request("Number of hours between cleanups cannot be zero")
        delta = timedelta(hours=int(data["run_every"]))
        new_schedule = schedule(run_every=delta, app=celery)

    elif data["type"] == "monthly":
        # Default to first minute of the first day of every month
        hour = data["hour"] if "hour" in data else 0
        minute = data["minute"] if "minute" in data else 1
        day_of_month = data["day_of_month"] if "day_of_month" in data else 1
        new_schedule = crontab(minute=minute, hour=hour, day_of_month=day_of_month)

    elif data["type"] == "weekly":
        if "day_of_week" not in data or not isinstance(data["day_of_week"], (int, str)):
            return bad_request(
                "Parameter 'day_of_week' must be a number between 0 (Sunday) and 6 as integer or string"
            )
        if ("hour" in data and not isinstance(data["hour"], (int, str))) or (
            "minute" in data and not isinstance(data["minute"], (int, str))
        ):
            return bad_request(
                "Parameters 'hour' and 'minute' must be numbers as integer or string"
            )

        # Default to first minute of every saturday
        hour = data["hour"] if "hour" in data else 0
        minute = data["minute"] if "minute" in data else 1
        day_of_week = data["day_of_week"] if "day_of_week" in data else 1
        new_schedule = crontab(minute=minute, hour=hour, day_of_week=day_of_week)
    else:
        return bad_request("Unrecognized schedule type")

    entry = RedBeatSchedulerEntry.from_key("redbeat:cleanup_private_spaces", app=celery)
    entry.schedule = new_schedule
    entry = entry.save()
    return {
        "success": True,
        "message": f"Novo agendamento da limpeza de espaços privados: {entry}",
    }


@app.route("/admin/cleanup-private-spaces", methods=["POST"])
@auth_required("token", "session")
@roles_required("Admin")
def perform_private_space_cleanup():
    max_age = int(os.environ.get("MAX_PRIVATE_SPACE_AGE", "1"))
    celery.send_task(
        "cleanup_private_spaces",
        kwargs={"max_private_space_age": max_age},
        ignore_result=True,
    )
    return {
        "success": True,
        "message": f"O sistema irá apagar os espaços privados com mais de {max_age}.",
    }


@app.route("/admin/get-scheduled", methods=["GET"])
@auth_required("token", "session")
@roles_required("Admin")
def get_scheduled_tasks():
    config = RedBeatConfig(celery)
    schedule_key = config.schedule_key
    redis = redbeat.schedulers.get_redis(celery)
    elements = redis.zrange(schedule_key, 0, -1, withscores=False)
    entries = {
        el: RedBeatSchedulerEntry.from_key(key=el, app=celery) for el in elements
    }
    return f"{entries}"


@app.route("/admin/set-max-private-space-age", methods=["POST"])
@auth_required("token", "session")
@roles_required("Admin")
def set_max_private_space_age():
    data = request.json
    if "new_max_age" not in data:
        return bad_request("Missing parameter 'new_max_age'")

    new_max_age = data["new_max_age"]
    try:
        if int(new_max_age) < 1:
            return {
                "success": False,
                "message": f'Invalid number of days: "{new_max_age}", must be positive integer',
            }

        entry = RedBeatSchedulerEntry.from_key(
            "redbeat:cleanup_private_spaces", app=celery
        )
        entry.kwargs = {"max_private_space_age": int(new_max_age)}
        entry = entry.save()
        return {
            "success": True,
            "message": f"Novo agendamento da limpeza de espaços privados: {entry}",
        }
    except ValueError:
        return {
            "success": False,
            "message": f'Invalid number of days: "{new_max_age}", must be positive integer',
        }


@app.route("/admin/delete-private-space", methods=["POST"])
@auth_required("token", "session")
@roles_required("Admin")
def delete_private_space():
    data = request.json
    if "space_id" not in data:
        return bad_request("Missing parameter 'space_id'")
    space_id = data["space_id"]

    space_path = safe_join(PRIVATE_PATH, space_id)
    if space_path is None:
        abort(HTTPStatus.NOT_FOUND)

    shutil.rmtree(space_path)

    return {
        "success": True,
        "message": "Apagado com sucesso",
        "private_spaces": get_size_private_spaces(),
    }


@app.route("/admin/save-config", methods=["POST"])
@auth_required("token", "session")
@roles_required("Admin")
def save_ocr_config():
    data = request.json
    if "config_name" not in data or data["config_name"] == "":
        return bad_request("Missing parameter 'config_name'")
    if (
        "config" not in data
        or not isinstance(data["config"], dict)
        or not data["config"]
    ):  # not empty dict
        return bad_request(
            "Missing parameter 'config'. Must be a non-empty dictionary."
        )
    config_name = data["config_name"]
    config = data["config"]

    config_path = safe_join(CONFIG_FILES_LOCATION, f"{config_name}.json")
    if config_path is None:
        return bad_request(f"Invalid config name: {config_name}")

    if "edit" in data:
        if data["edit"] and not os.path.exists(config_path):
            return {
                "success": False,
                "message": f"A configuração '{config_name}' não existe.",
            }
        elif not data["edit"] and os.path.exists(config_path):
            return {
                "success": False,
                "message": f"A configuração '{config_name}' já existe.",
            }

    if "edit" in data and data["edit"]:
        message = "Configuração atualizada."
    else:
        message = "Configuração guardada."

    # TODO: check validity of config
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    return {"success": True, "message": message}


@app.route("/admin/delete-config", methods=["POST"])
@auth_required("token", "session")
@roles_required("Admin")
def delete_ocr_config():
    data = request.json
    if "config_name" not in data or data["config_name"] == "":
        return bad_request("Missing parameter 'config_name'")
    config_name = data["config_name"]

    if config_name == "default":
        return {
            "success": False,
            "message": "A configuração predefinida não pode ser apagada.",
        }

    config_path = safe_join(CONFIG_FILES_LOCATION, f"{config_name}.json")
    if config_path is None:
        return bad_request(f"Invalid config name: {config_name}")

    if not os.path.exists(config_path):
        return {
            "success": False,
            "message": f"A configuração '{config_name}' não existe.",
        }

    os.remove(config_path)
    return {"success": True, "message": "Configuração apagada."}


@app.route("/admin/flower/", defaults={"fullpath": ""}, methods=["GET", "POST"])
@app.route("/admin/flower/<path:fullpath>", methods=["GET", "POST"])
@auth_required("token", "session")
@roles_required("Admin")
@csrf_exempt  # csrf token cannot be added to AJAX requests sent from flower's views
def proxy_flower(fullpath):
    """
    Proxy requests to the Flower Celery manager. Flower can be setup to allow operations without authentication,
    as authentication can be ensured through this endpoint.
    :param fullpath: rest of the path to the Flower API
    :return: response from Flower
    """
    # log.debug(
    #     f'Requesting to flower {request.base_url.replace(request.host_url, f"http://flower:5050/{APP_BASENAME}/")}'
    # )
    res = requests.request(
        method=request.method,
        url=request.base_url.replace(
            request.host_url, f"http://flower:5050/{APP_BASENAME}/"
        ),
        params=request.query_string,
        headers={k: v for k, v in request.headers if k.lower() != "host"},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
    )

    # exclude "hop-by-hop headers" defined by RFC 2616 section 13.5.1 ref. https://www.rfc-editor.org/rfc/rfc2616#section-13.5.1
    excluded_headers = [
        "content-encoding",
        "content-length",
        "transfer-encoding",
        "connection",
    ]
    headers = [
        (k, v) for k, v in res.raw.headers.items() if k.lower() not in excluded_headers
    ]

    response = Response(res.content, res.status_code, headers)
    return response


#####################################
# MAIN
#####################################
# Create the three main directories for the new structure
if not os.path.exists(f"./{INPUTS_PATH}/"):
    os.mkdir(f"./{INPUTS_PATH}/")

if not os.path.exists(f"./{FILES_PATH}/"):
    os.mkdir(f"./{FILES_PATH}/")

# Create root _data.json for _files if it doesn't exist
if not os.path.exists(f"./{FILES_PATH}/_data.json"):
    with open(f"./{FILES_PATH}/_data.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "type": "folder",
                "creation": get_current_time(),
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

if not os.path.exists(f"./{OUTPUTS_PATH}/"):
    os.mkdir(f"./{OUTPUTS_PATH}/")

if not os.path.exists(f"./{TEMP_PATH}/"):
    os.mkdir(f"./{TEMP_PATH}/")

if not os.path.exists(f"./{PRIVATE_PATH}/"):
    os.mkdir(f"./{PRIVATE_PATH}/")

    with open(f"./{PRIVATE_PATH}/_data.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "type": "folder",
                "creation": get_current_time(),
                "last_cleanup": "nunca",
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

if not os.path.exists(f"./{API_TEMP_PATH}/"):
    os.mkdir(f"./{API_TEMP_PATH}/")

with app.app_context():
    # drop and rebuild database to ensure only the credentials currently in environment allow admin access
    # FIXME: allowing creation of more users will require better way of managing admins, to ensure credentials can be revoked without interfering with other users
    db.drop_all()
    db.session.commit()

    db.create_all()
    if not security.datastore.find_role("Admin"):
        security.datastore.create_role(name="Admin")

    admin_email = os.environ["ADMIN_EMAIL"]
    admin_pass = os.environ["ADMIN_PASS"]
    del os.environ["ADMIN_EMAIL"]
    del os.environ["ADMIN_PASS"]

    if not security.datastore.find_user(email=admin_email):
        security.datastore.create_user(
            email=admin_email, password=hash_password(admin_pass), roles=["Admin"]
        )

    db.session.commit()


if __name__ == "__main__":
    # app.config['DEBUG'] = os.environ.get('DEBUG', False)
    app.run(host="0.0.0.0", port=5001, threaded=True, use_reloader=False)
