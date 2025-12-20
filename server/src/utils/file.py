import json
import os
import random
import re
import uuid
from datetime import datetime
from json import JSONDecodeError
from os import environ

import pytz
import requests
from filelock import FileLock

# from string import punctuation

FILES_PATH = environ.get("FILES_PATH", "_files")
INPUTS_PATH = environ.get("INPUTS_PATH", "_inputs")
OUTPUTS_PATH = environ.get("OUTPUTS_PATH", "_outputs")
TEMP_PATH = environ.get("TEMP_PATH", "_pending-files")
PRIVATE_PATH = environ.get("PRIVATE_PATH", "_private_spaces")
API_TEMP_PATH = environ.get("API_TEMP_PATH", "_files/_tmp")

ALLOWED_EXTENSIONS = (
    "pdf",
    "jpg",
    "jpeg",
    "jfif",
    "pjpeg",
    "pjp",  # JPEG
    "png",
    "tiff",
    "tif",  # TIFF
    "bmp",
    "gif",
    "webp",
    "pnm",  # image/x-portable-anymap
    "jp2",  # JPEG 2000
    "zip",
)

IMAGE_PREFIX = environ.get("IMAGE_PREFIX", "")
TIMEZONE = pytz.timezone("Europe/Lisbon")

##################################################
# FILESYSTEM UTILS
##################################################

# File system structure (three separate trees with mirrored structure):
#
# _inputs/                          (original files - displayed in UI)
#   - folder1/
#     - subfolder/
#       - filename.pdf              (the original submitted file)
#
# _files/                           (metadata and processing data)
#   - folder1/
#     - _data.json                  (folder metadata)
#     - subfolder/
#       - _data.json                (folder metadata)
#       - filename.pdf/             (document folder)
#         - _data.json              (document metadata)
#         - _ocr_results/           (OCR JSON results per page)
#         - _pages/                 (extracted pages as images)
#         - _layouts/               (layout definitions)
#         - _thumbnails/            (document thumbnails)
#         - _images/                (extracted images from layouts)
#
# _outputs/                         (exported results)
#   - folder1/
#     - subfolder/
#       - filename.pdf/
#         - _txt.txt
#         - _pdf.pdf
#         - _pdf_indexed.pdf
#         - _index.csv
#         - _entities.json
#         - _images.zip


def get_relative_path(full_path, is_private=False, private_space=None):
    """
    Extract the relative path from a full path by removing the base directory prefix.

    :param full_path: the full path (e.g., '_inputs/folder/file.pdf')
    :param is_private: whether the path is in a private space
    :param private_space: the private space ID if applicable
    :return: the relative path (e.g., 'folder/file.pdf')
    """
    if is_private and private_space:
        prefix = f"{PRIVATE_PATH}/{private_space}"
        if full_path.startswith(prefix):
            return full_path[len(prefix):].strip("/")
    for base in [INPUTS_PATH, FILES_PATH, OUTPUTS_PATH]:
        if full_path.startswith(base):
            return full_path[len(base):].strip("/")
    return full_path.strip("/")


def get_inputs_path(relative_path, is_private=False, private_space=None):
    """
    Get the full path in _inputs for a relative path.

    :param relative_path: the relative path within the file structure
    :param is_private: whether the path is in a private space
    :param private_space: the private space ID if applicable
    :return: full path in the inputs directory
    """
    if is_private and private_space:
        return f"{PRIVATE_PATH}/{private_space}/_inputs/{relative_path}".rstrip("/")
    return f"{INPUTS_PATH}/{relative_path}".rstrip("/")


def get_files_path(relative_path, is_private=False, private_space=None):
    """
    Get the full path in _files for a relative path.

    :param relative_path: the relative path within the file structure
    :param is_private: whether the path is in a private space
    :param private_space: the private space ID if applicable
    :return: full path in the files directory
    """
    if is_private and private_space:
        return f"{PRIVATE_PATH}/{private_space}/_files/{relative_path}".rstrip("/")
    return f"{FILES_PATH}/{relative_path}".rstrip("/")


def get_outputs_path(relative_path, is_private=False, private_space=None):
    """
    Get the full path in _outputs for a relative path.

    :param relative_path: the relative path within the file structure
    :param is_private: whether the path is in a private space
    :param private_space: the private space ID if applicable
    :return: full path in the outputs directory
    """
    if is_private and private_space:
        return f"{PRIVATE_PATH}/{private_space}/_outputs/{relative_path}".rstrip("/")
    return f"{OUTPUTS_PATH}/{relative_path}".rstrip("/")


def get_ner_file(files_path, outputs_path):
    """
    Request NER entities from the text file and save to outputs.

    :param files_path: path to document folder in _files (for reading _data.json if needed)
    :param outputs_path: path to document folder in _outputs (for reading txt and writing entities)
    :return: True if successful, False otherwise
    """
    txt_file_path = f"{outputs_path}/_txt.txt"
    if not os.path.exists(txt_file_path):
        return False

    with open(txt_file_path, "rb") as file:
        r = requests.post(
            "https://iris.sysresearch.org/anonimizador/from-text",
            files={"file": file},
        )
    try:
        ner = r.json()
    except JSONDecodeError:
        return False

    if r.status_code == 200:
        with open(f"{outputs_path}/_entities.json", "w", encoding="utf-8") as f:
            json.dump(ner, f, indent=2, ensure_ascii=False)
        return True
    else:
        return False


def get_current_time():
    """
    Get the current time in the correct format

    :return: current time
    """
    return datetime.now().astimezone(TIMEZONE).strftime("%d/%m/%Y %H:%M:%S")


def get_file_parsed(path, is_private):
    """
    Return the text off all the pages of the file

    :param path: path to the file
    :return: list with the text of each page
    """
    original_extension = path.split(".")[-1]
    extension = original_extension.lower()
    page_extension = (
        ".png"
        if (extension == "pdf" or extension == "zip")
        else f".{original_extension}"
    )
    url_prefix = IMAGE_PREFIX + (
        "/private/" if is_private else "/images/"
    )  # TODO: secure private space images

    path += "/_ocr_results"
    files = [
        f"{path}/{f}"
        for f in os.listdir(path)
        if os.path.isfile(os.path.join(path, f))
        and ".json" in f
        and "_data.json" not in f
    ]

    files.sort(key=lambda x: int(x.split("/")[-1].split("_")[-1].split(".")[0]))

    data = []
    words = {}
    for id, file in enumerate(files):
        basename = get_file_basename(file)
        with open(file, encoding="utf-8") as f:
            hocr = json.load(f)

            for sectionId, s in enumerate(hocr):
                for lineId, l in enumerate(s):
                    for wordId, w in enumerate(l):
                        t = w["text"]  # .lower().strip()
                        """
                        # ignoring isolated punctuation and digits affects the editing interface,
                        # since they get excluded from the "words" array and won't appear when looked for

                        while t:
                            if t[0] in punctuation + "«»—":
                                t = t[1:]
                            else:
                                break

                        while t:
                            if t[-1] in punctuation + "«»—":
                                t = t[:-1]
                            else:
                                break

                        if t == "" or t.isdigit():
                            continue

                        hocr[sectionId][lineId][wordId]["clean_text"] = t
                        """

                        if t in words:
                            words[t]["pages"].append(id)
                        else:
                            words[t] = {"pages": [id], "syntax": True}
            if is_private:
                file = re.sub(f"^{PRIVATE_PATH}", "", file)
            else:
                file = re.sub(f"^{FILES_PATH}", "", file)

            data.append(
                {
                    "original_file": file,
                    "content": hocr,
                    "page_number": int(basename.split("_")[-1]),
                    "page_url": url_prefix
                    + "/".join(file.split("/")[1:-2])
                    + f"/_pages/{basename}"
                    + page_extension,
                }
            )
    return data, words


def get_file_layouts(path, is_private):
    data = get_data(f"{path}/_data.json")
    layouts = []
    basename = get_file_basename(path)
    original_extension = path.split(".")[-1]
    extension = original_extension.lower()
    page_extension = (
        ".png"
        if (extension == "pdf" or extension == "zip")
        else f".{original_extension}"
    )
    url_prefix = IMAGE_PREFIX + (
        f"/private/{path.replace(PRIVATE_PATH, '')}"
        if is_private
        else f"/images/{path.replace(FILES_PATH, '')}"
    )

    for page in range(data["pages"]):
        filename = f"{path}/_layouts/{basename}_{page}.json"
        page_url = url_prefix + f"/_pages/{basename}_{page}" + page_extension

        if os.path.exists(filename):
            with open(filename, encoding="utf-8") as f:
                layouts.append(
                    {
                        "boxes": json.load(f),
                        "page_url": page_url,
                        "page_number": page,
                        "done": True,
                    }
                )
        else:
            layouts.append(
                {"boxes": [], "page_url": page_url, "page_number": page, "done": False}
            )

    return layouts, data["segmenting"] if "segmenting" in data else False


def save_file_layouts(path, layouts):
    data_file = f"{path}/_data.json"
    data = get_data(data_file)
    if data["type"] != "file":
        raise FileNotFoundError

    basename = get_file_basename(path)
    if not os.path.isdir(f"{path}/_layouts"):
        os.mkdir(f"{path}/_layouts")

    has_layout = False
    for page_id, page in enumerate(layouts):
        layouts = page["boxes"]
        if not has_layout and len(layouts) > 0:
            has_layout = True

        filename = f"{path}/_layouts/{basename}_{page_id}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(layouts, f, indent=2, ensure_ascii=False)

    data["has_layout"] = has_layout
    update_json_file(data_file, data)


def generate_uuid(path):
    random.seed(path)
    return str(
        uuid.UUID(bytes=bytes(random.getrandbits(8) for _ in range(16)), version=4)
    )


def generate_random_uuid():
    return uuid.uuid4().hex


def delete_structure(client, path):
    """
    Delete all the files in the structure
    """
    data = get_data(path + "/_data.json")
    if data["type"] == "file":
        if data.get("indexed", False):
            files = [f"{path}/{f}" for f in os.listdir(path) if f.endswith(".txt")]
            for file in files:
                file_id = generate_uuid(file)
                client.delete_document(file_id)

    else:
        folders = [
            f"{path}/{f}" for f in os.listdir(path) if os.path.isdir(f"{path}/{f}")
        ]
        for folder in folders:
            delete_structure(client, folder)


def get_filesystem(path, private_space: str = None, is_private: bool = False) -> dict:
    """
    Get the filesystem structure starting from INPUTS_PATH.

    :param path: path to the folder (relative or in _inputs)
    :param private_space: name of the private space, if applicable
    :param is_private: whether the target path is a private space
    """
    # Determine the inputs path for structure and files path for metadata
    if is_private and private_space:
        inputs_base = f"{PRIVATE_PATH}/{private_space}/_inputs"
        files_base = f"{PRIVATE_PATH}/{private_space}/_files"
    else:
        inputs_base = INPUTS_PATH
        files_base = FILES_PATH

    files = get_structure(inputs_base, files_base, private_space, is_private)
    info = get_structure_info(inputs_base, files_base, private_space, is_private)

    if files is None:
        if path != INPUTS_PATH and PRIVATE_PATH not in path:
            files = {path: []}
        else:
            files = {"files": []}

    return {**files, "info": info}


def size_to_units(size):
    """
    Receives a size in bytes and returns a string formatted with the appropriate unit.
    :param size: size in bytes
    :return: string with rounded size and appropriate unit
    """
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size / 1024:.2f} KB"
    elif size < 1024**3:
        return f"{size / 1024 ** 2:.2f} MB"
    else:
        return f"{size / 1024 ** 3:.2f} GB"


def get_ocr_size(path):
    """
    Get the size of the hocr files

    :param path: path to the folder
    :return: size of the files
    """

    files = [
        f"{path}/{f}"
        for f in os.listdir(path)
        if os.path.isfile(os.path.join(path, f)) and ".json" in f
    ]
    size = 0
    for file in files:
        size += os.path.getsize(file)

    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size / 1024:.2f} KB"
    elif size < 1024**3:
        return f"{size / 1024 ** 2:.2f} MB"
    else:
        return f"{size / 1024 ** 3:.2f} GB"


def get_document_files_size(files_path, inputs_path=None, outputs_path=None, extension=None, from_api: bool = False):
    """
    Get the total size of files related to a document across all three folders.

    :param files_path: path to document folder in _files (metadata/processing)
    :param inputs_path: path to original file in _inputs (optional, calculated if not provided)
    :param outputs_path: path to document folder in _outputs (optional, calculated if not provided)
    :param extension: extension of the original file, used for API documents
    :param from_api: whether the method is being called for a file from the API
    :return: total size in bytes
    """
    size = 0

    # Size of original file in _inputs
    if inputs_path and os.path.exists(inputs_path):
        if os.path.isfile(inputs_path):
            size += os.path.getsize(inputs_path)
    elif from_api:
        # API files have the original inside the _files path
        original_path = f"{files_path}/{get_file_basename(files_path)}.{extension}"
        if os.path.exists(original_path):
            size += os.path.getsize(original_path)

    # Size of metadata/processing files in _files
    if os.path.exists(files_path):
        for dirpath, folders, filenames in os.walk(files_path):
            for f in filenames:
                subpath = os.path.join(dirpath, f)
                if not os.path.islink(subpath):
                    size += os.path.getsize(subpath)

    # Size of output files in _outputs
    if outputs_path and os.path.exists(outputs_path):
        for dirpath, folders, filenames in os.walk(outputs_path):
            for f in filenames:
                subpath = os.path.join(dirpath, f)
                if not os.path.islink(subpath):
                    size += os.path.getsize(subpath)

    return size


def get_folder_size(path):
    """
    Returns the size of the folder's entire contents recursively.
    :param path: path to the folder
    :return: total size in bytes
    """
    size = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            subpath = os.path.join(dirpath, f)
            if not os.path.islink(subpath):
                size += os.path.getsize(subpath)
    return size


def get_file_size(path, path_complete=True):
    """
    Returns the file's size.

    :param path: path to the file
    :param path_complete: whether the path points directly to a file;
        if False, assumes path is a folder and looks for a file with the folder's name inside it
    :return: file size in bytes
    """
    if not path_complete:
        name = path.split("/")[-1]
        path = f"{path}/{name}"
    if not os.path.exists(path):
        return 0
    return os.path.getsize(path)


def get_folder_info(inputs_path, files_path, private_space=None, is_private=False):
    """
    Get the info of the folder.

    :param inputs_path: path to the folder in _inputs (for listing contents)
    :param files_path: path to the folder in _files (for metadata)
    :param private_space: name of the private space if applicable
    :param is_private: whether this is a private space
    """
    info = {}
    try:
        data = get_data(f"{files_path}/_data.json")
    except (FileNotFoundError, JSONDecodeError):
        return {}

    if "type" not in data:
        return {}

    if data["type"] == "folder":
        n_subfolders = 0
        n_docs = 0
        # Scan contents from _inputs path
        if os.path.exists(inputs_path):
            for content in os.scandir(inputs_path):
                if content.is_dir() and not content.name.startswith("_"):
                    # Check metadata in _files path
                    content_files_path = f"{files_path}/{content.name}"
                    try:
                        content_data = get_data(f"{content_files_path}/_data.json")
                        if "type" in content_data:
                            if content_data["type"] == "folder":
                                n_subfolders += 1
                            elif content_data["type"] == "file":
                                n_docs += 1
                    except (FileNotFoundError, JSONDecodeError):
                        # Check if it's a file (file in inputs, folder in files)
                        if content.is_file():
                            n_docs += 1
                        else:
                            n_subfolders += 1
                elif content.is_file() and not content.name.startswith("_"):
                    # This is a document (file in _inputs)
                    n_docs += 1
        data["contents"] = {"documents": n_docs, "subfolders": n_subfolders}

        # Calculate folder size from _files path (metadata/processing data)
        folder_size = 0
        if os.path.exists(files_path):
            dirs_dict = {}
            for root, dirs, files in os.walk(files_path, topdown=False):
                size = sum(os.path.getsize(os.path.join(root, name)) for name in files)
                subdir_size = sum(dirs_dict.get(os.path.join(root, d), 0) for d in dirs)
                folder_size = dirs_dict[root] = size + subdir_size
        data["size"] = size_to_units(folder_size)

    # Sanitize important paths from the info key to get relative path
    if is_private and private_space:
        relative_path = files_path.replace(f"{PRIVATE_PATH}/{private_space}/_files", "").strip("/")
    else:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")

    info[relative_path] = data
    return info


def get_structure_info(inputs_base, files_base, private_space=None, is_private=False):
    """
    Get the info of each file/folder by walking _inputs and reading metadata from _files.

    :param inputs_base: base path in _inputs to walk
    :param files_base: base path in _files for metadata
    :param private_space: name of private space if applicable
    :param is_private: whether this is a private space
    """
    if not is_private and PRIVATE_PATH in inputs_base:
        raise FileNotFoundError
    if API_TEMP_PATH in inputs_base:
        raise FileNotFoundError

    info = {}

    # Walk the _inputs tree
    for root, folders, files in os.walk(inputs_base, topdown=True):
        root = root.replace("\\", "/")
        # ignore reserved folders by pruning them from search tree
        folders[:] = [f for f in folders if not f.startswith("_")]
        if root.split("/")[-1].startswith("_"):
            continue
        # ignore possible private path folders
        if not is_private and (PRIVATE_PATH in root or root in PRIVATE_PATH.split("/")):
            continue
        # if in a private space, ignore folders not from this private space
        if is_private and f"{PRIVATE_PATH}/{private_space}" not in root:
            continue

        # Calculate the relative path from inputs_base
        relative_path = root.replace(inputs_base, "").strip("/")
        files_path = f"{files_base}/{relative_path}".rstrip("/")

        # Get folder info using both inputs and files paths
        folder_info = get_folder_info(root, files_path, private_space, is_private)
        info = {**info, **folder_info}

        # Also get info for files (documents) in this folder
        for filename in files:
            if filename.startswith("_"):
                continue
            # For documents, the file is in _inputs, metadata folder is in _files
            doc_inputs_path = f"{root}/{filename}"
            doc_files_path = f"{files_path}/{filename}"
            doc_info = get_folder_info(doc_inputs_path, doc_files_path, private_space, is_private)
            info = {**info, **doc_info}

    return info


def get_structure(inputs_path, files_path, private_space=None, is_private=False):
    """
    Build the file system structure from _inputs tree with metadata from _files.

    Returns a dict like:
    {
        'files': [
            {
                'folder1': ['file.pdf']
            },
            {
                'folder2': []
            }
        ]
    }

    :param inputs_path: path in _inputs to read structure from
    :param files_path: corresponding path in _files for metadata
    :param private_space: name of private space if applicable
    :param is_private: whether this is a private space
    """
    if not is_private and PRIVATE_PATH in inputs_path:
        raise FileNotFoundError
    if API_TEMP_PATH in inputs_path:
        raise FileNotFoundError

    filesystem = {}

    # Determine if this is a root folder
    if is_private and private_space:
        is_root = inputs_path == f"{PRIVATE_PATH}/{private_space}/_inputs"
    else:
        is_root = inputs_path == INPUTS_PATH

    if is_root:
        name = "files"
    else:
        name = inputs_path.split("/")[-1]

        # Check if this is a document (file in _inputs, folder in _files)
        if os.path.isfile(inputs_path):
            # This is a document file
            return name

        # Check metadata in _files for folders
        try:
            data = get_data(f"{files_path}/_data.json")
            if "type" not in data:
                return None
            if data["type"] == "file":
                return name
        except (FileNotFoundError, JSONDecodeError):
            # No metadata yet, treat as regular folder
            pass

    if not os.path.exists(inputs_path):
        return None

    contents = []

    # List all items in inputs_path (both files and folders)
    items = sorted([
        f for f in os.listdir(inputs_path)
        if not f.startswith("_")
    ])

    for item in items:
        item_inputs_path = f"{inputs_path}/{item}"
        item_files_path = f"{files_path}/{item}"

        # ignore possible private path folders
        if not is_private and item in PRIVATE_PATH.split("/"):
            continue
        # if in a private space, ignore items not from this private space
        if is_private and f"{PRIVATE_PATH}/{private_space}" not in item_inputs_path:
            continue

        if os.path.isfile(item_inputs_path):
            # This is a document file - just add the filename
            contents.append(item)
        elif os.path.isdir(item_inputs_path):
            # This is a folder - recurse
            result = get_structure(item_inputs_path, item_files_path, private_space, is_private)
            if result is not None:
                contents.append(result)

    filesystem[name] = contents
    return filesystem


##################################################
# FILES UTILS
##################################################


def get_page_count(target_path, extension):
    """
    Get the number of pages of a file
    """
    if extension.lower() in ("pdf", "zip", "tif", "tiff"):
        return len(os.listdir(f"{target_path}/_pages"))
    elif extension.lower() in ALLOWED_EXTENSIONS:  # some other than pdf or zip
        return 1
    return None


def get_word_count(path):
    n_words = 0
    ocr_folder = f"{path}/_ocr_results"
    with os.scandir(ocr_folder) as ocr_results:
        for entry in ocr_results:
            if entry.is_file() and entry.name.endswith(".json"):
                with open(entry.path, encoding="utf-8") as file:
                    text = file.read()
                    if text == "":
                        continue
                    for paragraph in json.loads(text):
                        for line in paragraph:
                            n_words += len(line)
    return n_words


def get_file_basename(filename):
    """
    Get the basename of a file

    :param file: file name
    :return: basename of the file
    """
    basename = ".".join(filename.replace("\\", "/").split("/")[-1].split(".")[:-1])
    if basename == "":
        # no extension, get entire filename.
        # files submitted through API call are stored in a folder named with a UUID,
        # and original document's basename is the same UUID
        basename = filename.replace("\\", "/").split("/")[-1]
    return basename


def get_file_extension(filename):
    """
    Get the extension of a file

    :param file: file name
    :return: extension of the file
    """
    return filename.split(".")[-1]


def get_page_extension_from_original(filename):
    original_extension = filename.split(".")[-1]
    if original_extension == "pdf" or original_extension == "zip":
        return "png"
    else:
        return original_extension


def json_to_text(json_d):
    """
    Convert json to text
    :param json_d: json with the hOCR data
    :return: text
    """
    pars = []
    for paragraph in json_d:
        lines = [" ".join(word["text"] for word in line) for line in paragraph]
        pars.append("\n".join(lines))
    return "\n\n".join(pars).strip()


##################################################
# OCR UTILS
##################################################


def get_data(file, lock=None):
    """
    Update the JSON data from the file.
    :param file: file to read from
    :param lock: file lock if already existing, to avoid recursive locks
    """
    if not os.path.exists(file):
        raise FileNotFoundError
    if lock is None:
        lock_path = f"{file}.lock"
        lock = FileLock(lock_path)
    with lock, open(file, encoding="utf-8") as f:
        text = f.read()
        if text == "":
            return {}
        return json.loads(text)


def get_doc_len(file) -> int:
    with open(file, encoding="utf-8") as f:
        text = f.read()
        if text == "":
            return -1
        return int(json.loads(text)["pages"])


def update_json_file(file, data, lock=None):
    """
    Update the JSON data contained in the file.
    :param file: file to update
    :param data: new or updated data
    :param lock: file lock if already existing, to avoid recursive locks
    """
    if not os.path.exists(file):
        raise FileNotFoundError

    # TODO: ensure atomic operations to handle multiple users making changes to the same files/folders
    if lock is None:
        lock_path = f"{file}.lock"
        lock = FileLock(lock_path)
    with lock:
        previous_data = get_data(file, lock)
        with open(file, "w", encoding="utf-8") as f:
            previous_data.update(data)
            json.dump(previous_data, f, ensure_ascii=False, indent=2)


def dump_json_file(file, data, lock=None):
    """
    Dump the JSON data into the file.
    :param file: file to update
    :param data: new or updated data
    :param lock: file lock if already existing, to avoid recursive locks
    """
    if not os.path.exists(file):
        raise FileNotFoundError

    # TODO: ensure atomic operations to handle multiple users making changes to the same files/folders
    if lock is None:
        lock_path = f"{file}.lock"
        lock = FileLock(lock_path)
    with lock, open(file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
