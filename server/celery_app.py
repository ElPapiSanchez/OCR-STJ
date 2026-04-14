import glob
import json
import logging as log
import os
import shutil
import tempfile
import time
import traceback
import uuid
import zipfile
from contextlib import suppress
from datetime import datetime
from io import BytesIO

import pypdfium2 as pdfium
from celery import Celery
from celery import chord
from celery import group
from celery.canvas import Signature
from celery.schedules import crontab
from dotenv import load_dotenv
from filelock import FileLock
from PIL import Image
from PIL import ImageDraw
from redbeat import RedBeatSchedulerEntry
from src.engines import ocr_pytesseract
from src.engines import ocr_tesserocr
from src.utils.export import export_csv
from src.utils.export import export_file
from src.utils.export import export_from_existing
from src.utils.export import load_fonts
from src.utils.file import ALLOWED_EXTENSIONS
from src.utils.file import API_TEMP_PATH
from src.utils.file import dump_json_file
from src.utils.file import FILES_PATH
from src.utils.file import generate_random_uuid
from src.utils.file import get_current_time
from src.utils.file import get_data
from src.utils.file import get_doc_len
from src.utils.file import get_document_files_size
from src.utils.file import get_file_basename
from src.utils.file import get_file_size
from src.utils.file import get_inherited_config
from src.utils.file import get_ner_file
from src.utils.file import get_ocr_size
from src.utils.file import get_page_count
from src.utils.file import get_word_count
from src.utils.file import INPUTS_PATH
from src.utils.file import OUTPUTS_PATH
from src.utils.file import PRIVATE_PATH
from src.utils.file import save_file_layouts
from src.utils.file import size_to_units
from src.utils.file import TIMEZONE
from src.utils.file import update_json_file
from src.utils.image import parse_images

OCR_ENGINES = (
    "pytesseract",
    "tesserocr",
)

load_dotenv()

DEFAULT_CONFIG_FILE = os.environ.get("DEFAULT_CONFIG_FILE", "_configs/default.json")

CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/0")

celery = Celery("celery_app", backend=CELERY_RESULT_BACKEND, broker=CELERY_BROKER_URL)

# celery.conf.beat_max_loop_interval = 30  # in seconds; default 5 seconds or 5 minutes depending on task schedule

# ensure redis lock never expires (no other workers checking beat scheudle)
celery.conf.redbeat_lock_timeout = 0

# 0 is highest, 10 is lowest; use lowest by default
celery.conf.task_default_priority = 10

celery.conf.worker_pool_restarts = True  # allow restarting worker pool from Flower

celery.conf.worker_prefetch_multiplier = 1  # prefetch only 1 task per process/thread
celery.conf.worker_disable_prefetch = True  # may not work before celery 5.6
celery.conf.task_acks_late = True  # ack tasks only after completion; required for disabling prefetch but should be False if there are multiple workers
# next version of celery (5.6) may allow disabling prefetch while still using early ack

# Preload fonts to avoid lazy loading
load_fonts()


@celery.task(name="auto_segment", priority=0)
def task_auto_segment(path, use_hdbscan=False):
    data_path = f"{path}/_data.json"
    lock_path = f"{data_path}.lock"
    lock = FileLock(lock_path)
    with lock:
        data = get_data(data_path, lock=lock)
        if "segmenting" in data and data["segmenting"]:
            return {"segmenting": True}
        else:
            update_json_file(data_path, {"segmenting": True}, lock=lock)

    if use_hdbscan:
        return parse_images(path)
    pages_path = f"{path}/_pages"
    if not os.path.exists(pages_path):
        log.error(f"Error in parsing images at {path}: missing /_pages")
        raise FileNotFoundError

    original_extension = path.split(".")[-1]
    extension = original_extension.lower()
    page_extension = (
        ".png"
        if (extension == "pdf" or extension == "zip")
        else f".{original_extension}"
    )
    basename = get_file_basename(path)

    # Grab all the images already in the folder
    images = [
        x
        for x in glob.glob(f"{pages_path}/{basename}_*{page_extension}")
        if x[-5] != "$"
    ]
    sorted_images = sorted(images, key=lambda x: int(x.split("_")[-1].split(".")[0]))

    all_layouts = []

    for img in sorted_images:
        box_coords = ocr_tesserocr.auto_get_boxes(img)
        formatted_boxes = []

        for box in box_coords:
            left, top, width, height = box
            formatted_box = {
                "_uniq_id": uuid.uuid4().hex[
                    :16
                ],  # each line in the sortable list must have a constant unique ID
                "groupId": "temp",
                "checked": False,
                "type": "text",
                "squares": [
                    {
                        "id": "temp",
                        "top": top,
                        "left": left,
                        "bottom": top + height,
                        "right": left + width,
                    }
                ],
                "copyId": None,
            }
            formatted_boxes.append(formatted_box)

        all_layouts.append({"boxes": formatted_boxes})

    layouts_path = f"{path}/_layouts"
    if not os.path.isdir(layouts_path):
        os.mkdir(layouts_path)

    sorted_all_layouts = []
    for page, layout in enumerate(all_layouts):
        # This orders the segments based on typical reading order: top-left to bottom-right.
        sorted_layout = sorted(
            layout["boxes"],
            key=lambda c: (c["squares"][0]["top"], c["squares"][0]["left"]),
        )

        for i, box_group in enumerate(sorted_layout):
            box_group["groupId"] = f"{page + 1}.{i + 1}"
            for b in box_group["squares"]:
                b["id"] = f"{page + 1}.{i + 1}"

        sorted_all_layouts.append({"boxes": sorted_layout})

    save_file_layouts(path, sorted_all_layouts)
    with lock:
        update_json_file(data_path, {"segmenting": False}, lock=lock)

    return {"status": "success"}


@celery.task(name="export_file", priority=2)
def task_export(files_path, filetype, outputs_path=None, inputs_path=None, delimiter=False, force_recreate=False, simple=False, compress=True):
    """
    Export a file to a specific format.

    :param files_path: path to document folder in _files
    :param filetype: type of file to export
    :param outputs_path: path to document folder in _outputs
    :param inputs_path: path to original file in _inputs
    :param delimiter: for txt, add delimiter between pages
    :param force_recreate: force recreation of existing files
    :param simple: for PDF, create simple version without index
    :param compress: for PDF, whether to apply compression
    """
    # Calculate outputs_path if not provided
    if outputs_path is None:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"

    return export_file(files_path, filetype, outputs_path=outputs_path, inputs_path=inputs_path,
                       delimiter=delimiter, force_recreate=force_recreate, simple=simple, compress=compress)


@celery.task(name="make_changes", priority=2)
def task_make_changes(files_path, outputs_path, data):
    """
    Regenerate export files after text changes.

    :param files_path: path to document folder in _files
    :param outputs_path: path to document folder in _outputs
    :param data: document metadata
    """
    data_file = files_path + "/_data.json"
    update_json_file(
        data_file,
        {
            "status": {
                "stage": "exporting",
                "message": "A gerar resultados",
            }
        },
    )

    # Calculate inputs_path to find original file
    relative_path = files_path.replace(FILES_PATH, "").strip("/")
    doc_basename = get_file_basename(files_path)
    original_extension = data.get("extension", "pdf")
    if relative_path.count('/') == 0:
        inputs_path = f"{INPUTS_PATH}/{doc_basename}.{original_extension}"
    else:
        inputs_path = f"{INPUTS_PATH}/{relative_path.rsplit('/', 1)[0]}/{doc_basename}.{original_extension}".replace("//", "/")

    # Extract compression setting from config (default to True if not specified or None)
    config = data.get("ocr", {}).get("config", {})
    
    # Handle both dict config and "default" string
    if isinstance(config, dict):
        compress_value = config.get("compress")
    else:
        # Config is "default" string or something else
        compress_value = None
    
    compress_pdf = True if compress_value is None else bool(compress_value)

    # Recreate formats already created, as well as any added to the config later
    recreate_types = {
        type_name
        for type_name, value in data.items()
        if isinstance(value, dict) and "complete" in value and value["complete"]
    }
    if "config" in data and "outputs" in data["config"]:
        recreate_types.update(data["config"]["outputs"])

    # Ensure outputs folder exists
    os.makedirs(outputs_path, exist_ok=True)
    created_time = get_current_time()

    if "txt" in recreate_types:
        update_json_file(
            data_file,
            {
                "status": {
                    "stage": "exporting",
                    "message": "A gerar texto",
                }
            },
        )
        export_file(files_path, "txt", outputs_path=outputs_path, force_recreate=True)
        data["txt"] = {
            "complete": True,
            "size": size_to_units(
                get_file_size(outputs_path + "/_txt.txt", path_complete=True)
            ),
            "creation": created_time,
        }

    if "txt_delimited" in recreate_types:
        update_json_file(
            data_file,
            {
                "status": {
                    "stage": "exporting",
                    "message": "A gerar texto delimitado",
                }
            },
        )
        export_file(files_path, "txt", outputs_path=outputs_path, delimiter=True, force_recreate=True)
        data["txt_delimited"] = {
            "complete": True,
            "size": size_to_units(
                get_file_size(outputs_path + "/_txt_delimited.txt", path_complete=True)
            ),
            "creation": created_time,
        }

    if "pdf_indexed" in recreate_types:
        update_json_file(
            data_file,
            {
                "status": {
                    "stage": "exporting",
                    "message": "A gerar PDF com índice",
                }
            },
        )
        recreate_csv = "csv" in recreate_types
        with suppress(FileNotFoundError):
            os.remove(outputs_path + "/_pdf_indexed.pdf")
        export_file(
            files_path,
            "pdf",
            outputs_path=outputs_path,
            inputs_path=inputs_path,
            force_recreate=True,
            keep_temp=data["pdf"]["complete"],
            get_csv=recreate_csv,
            compress=compress_pdf,
        )

        exported_pdf = pdfium.PdfDocument(
            f"{outputs_path}/_pdf_indexed.pdf", autoclose=True
        )
        data["pdf_indexed"] = {
            "complete": True,
            "size": size_to_units(
                get_file_size(outputs_path + "/_pdf_indexed.pdf", path_complete=True)
            ),
            "creation": created_time,
            "pages": len(exported_pdf),
        }

    if "pdf" in recreate_types:
        update_json_file(
            data_file,
            {
                "status": {
                    "stage": "exporting",
                    "message": "A gerar PDF",
                }
            },
        )
        recreate_csv = "csv" in recreate_types and "pdf_indexed" not in recreate_types
        with suppress(FileNotFoundError):
            os.remove(outputs_path + "/_pdf.pdf")
        export_file(
            files_path,
            "pdf",
            outputs_path=outputs_path,
            inputs_path=inputs_path,
            force_recreate=True,
            simple=True,
            already_temp=data["pdf_indexed"]["complete"],
            get_csv=recreate_csv,
            compress=compress_pdf,
        )
        data["pdf"] = {
            "complete": True,
            "size": size_to_units(
                get_file_size(outputs_path + "/_pdf.pdf", path_complete=True)
            ),
            "creation": created_time,
            "pages": get_page_count(files_path, "pdf"),
        }

    if (
        "csv" in recreate_types
        and "pdf_indexed" not in recreate_types
        and "pdf" not in recreate_types
    ):
        update_json_file(
            data_file,
            {
                "status": {
                    "stage": "exporting",
                    "message": "A gerar CSV",
                }
            },
        )
        export_csv(files_path, outputs_path=outputs_path, force_recreate=True)

    if "csv" in recreate_types:
        data["csv"] = {
            "complete": True,
            "size": size_to_units(
                get_file_size(outputs_path + "/_index.csv", path_complete=True)
            ),
            "creation": created_time,
        }

    if "ner" in recreate_types:
        try:
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": "A obter entidades",
                    }
                },
            )
            # NER is retrieved from .txt results
            if "txt" not in recreate_types:
                export_file(files_path, "txt", outputs_path=outputs_path, force_recreate=True)

            task_request_ner(files_path, outputs_path)
        except Exception as e:
            log.error(f"Error fetching NER for {files_path}: {e}")
            data["ner"] = {"complete": False, "error": True}

    data["status"] = {
        "stage": "post-ocr",
    }
    if "edited_results" in data:
        del data["edited_results"]
    # dump to ensure removal of "edited_results" is applied
    dump_json_file(data_file, data)
    return {"status": "success"}


@celery.task(name="count_doc_pages", priority=0)
def task_count_doc_pages(files_path: str = None, inputs_path: str = None, extension: str = None, path: str = None):
    """
    Updates the metadata of the document at the given path with its page count.

    :param files_path: path to document folder in _files
    :param inputs_path: path to original file in _inputs
    :param extension: the document's original extension
    :param path: legacy parameter
    """
    # Support legacy usage
    if files_path is None and path is not None:
        files_path = path
        from_api = path.startswith(API_TEMP_PATH)
        if from_api:
            inputs_path = f"{path}/{get_file_basename(path)}.{extension}"
        else:
            inputs_path = path
    else:
        from_api = files_path.startswith(API_TEMP_PATH) if files_path else False

    # Calculate relative path for outputs
    if not from_api and files_path:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"
    else:
        outputs_path = None

    update_json_file(
        f"{files_path}/_data.json",
        {
            "pages": get_page_count(files_path, extension),
            "stored": True,
            "size": size_to_units(get_file_size(inputs_path, path_complete=True) if inputs_path and os.path.isfile(inputs_path) else 0),
            "total_size": size_to_units(
                get_document_files_size(files_path, inputs_path=inputs_path, outputs_path=outputs_path, extension=extension, from_api=from_api)
            ),
            "status": {
                "stage": "waiting",
            },
        },
    )


@celery.task(name="ocr_from_api", priority=9)
def task_perform_direct_ocr(
    path: str, config: dict | None, delete_on_finish: bool = False
):
    async_ocr = task_file_ocr.si(
        path=path, config=config, delete_on_finish=delete_on_finish
    )
    prepare_file_from_api(path=path, callback=async_ocr)


def prepare_file_from_api(path: str, callback: Signature | None = None):
    """
    Same as task_prepare_file_ocr but does not generate thumbnails, which aren't needed for API usage
    """
    data_folder = f"{path}/_data.json"
    try:
        if not os.path.exists(f"{path}/_pages"):
            os.mkdir(f"{path}/_pages")

        update_json_file(
            data_folder,
            {
                "status": {
                    "stage": "preparing",
                    "message": "A preparar o documento",
                }
            },
        )

        data = get_data(f"{path}/_data.json")
        original_extension = data["extension"]
        extension = original_extension.lower()

        basename = get_file_basename(path)

        if extension == "pdf":
            # For API files, the original PDF is in the same folder as metadata
            inputs_path = f"{path}/{basename}.pdf"
            
            pdf = pdfium.PdfDocument(inputs_path)
            num_pages = len(pdf)
            pdf.close()

            pdf_prep_callback = task_count_doc_pages.si(
                path=path, extension=original_extension
            ).set(link=callback, ignore_result=True)
            
            # FIXED: Now passing all 4 required arguments (files_path, inputs_path, basename, i)
            chord(
                task_extract_pdf_page.si(path, inputs_path, basename, i) for i in range(num_pages)
            )(pdf_prep_callback)

        elif extension == "zip":
            temp_folder_name = f"{path}/{generate_random_uuid()}"
            os.mkdir(temp_folder_name)

            with zipfile.ZipFile(f"{path}/{basename}.zip", "r") as zip_ref:
                zip_ref.extractall(temp_folder_name)

            page_paths = [
                f"{temp_folder_name}/{file}"
                for file in os.listdir(temp_folder_name)
                if os.path.isfile(os.path.join(temp_folder_name, file))
            ]

            # sort pages alphabetically, case-insensitive
            # casefold for better internationalization, original string appended as fallback
            page_paths.sort(key=lambda s: (s.casefold(), s))

            for i, page in enumerate(page_paths):
                im = Image.open(page)
                im.save(
                    f"{path}/_pages/{basename}_{i}.png", format="PNG"
                )  # using PNG to keep RGBA

            shutil.rmtree(temp_folder_name)

            task_count_doc_pages(path=path, extension=original_extension)
            if callback is not None:
                callback.apply_async(ignore_result=True)

        elif extension in ("tif", "tiff"):
            img = Image.open(
                f"{path}/{basename}.{original_extension}", formats=["tiff"]
            )
            n_frames = img.n_frames
            if n_frames == 1:
                original_path = f"{path}/{basename}.{original_extension}"
                link_path = f"{path}/_pages/{basename}_0.{original_extension}"
                if not os.path.exists(link_path):
                    os.link(original_path, link_path)
            else:
                compression = img._compression
                for i in range(0, n_frames):
                    img.seek(i)
                    img.save(
                        f"{path}/_pages/{basename}_{i}.{original_extension}",
                        save_all=False,
                        compression=compression,
                    )

            task_count_doc_pages(path=path, extension=original_extension)
            if callback is not None:
                callback.apply_async(ignore_result=True)

        elif extension in ALLOWED_EXTENSIONS:  # some other than pdf
            original_path = f"{path}/{basename}.{original_extension}"
            link_path = f"{path}/_pages/{basename}_0.{original_extension}"
            if not os.path.exists(link_path):
                os.link(original_path, link_path)

            task_count_doc_pages(path=path, extension=original_extension)
            if callback is not None:
                callback.apply_async(ignore_result=True)

        else:
            raise FileNotFoundError("No file with a valid extension was found")

    except Exception as e:
        data = get_data(data_folder)
        data["ocr"] = data.get("ocr", {})
        data["ocr"]["exceptions"] = str(e)
        data["status"] = {
            "stage": "error",
            "message": "Erro a preparar documento",
        }
        update_json_file(data_folder, data)
        log.error(f"Error in preparing OCR for file at {path}: {e}")
        raise e


@celery.task(name="prepare_file")
def task_prepare_file_ocr(inputs_path: str = None, files_path: str = None, path: str = None, callback: Signature | None = None):
    """
    Prepare a file for OCR by extracting pages and generating thumbnails.

    :param inputs_path: path to original file in _inputs
    :param files_path: path to document folder in _files
    :param path: legacy parameter, used if inputs_path/files_path not provided
    :param callback: optional callback to run after preparation
    """
    # Support legacy usage where path points to _files location with original inside
    if inputs_path is None and files_path is None and path is not None:
        # Legacy mode - original file inside _files folder
        files_path = path
        basename = get_file_basename(path)
        data = get_data(f"{files_path}/_data.json")
        original_extension = data["extension"]
        inputs_path = f"{files_path}/{basename}.{original_extension}"

    data_folder = f"{files_path}/_data.json"
    try:
        if not os.path.exists(f"{files_path}/_pages"):
            os.mkdir(f"{files_path}/_pages")

        update_json_file(
            data_folder,
            {
                "status": {
                    "stage": "preparing",
                    "message": "A preparar o documento",
                }
            },
        )

        data = get_data(f"{files_path}/_data.json")
        original_extension = data["extension"]
        extension = original_extension.lower()

        basename = get_file_basename(files_path)

        log.info(f"🔨 {basename}: Preparing file | extension={extension}")

        if extension == "pdf":
            pdf = pdfium.PdfDocument(inputs_path)
            num_pages = len(pdf)
            pdf.close()
            
            log.info(f"📑 {basename}: Extracting {num_pages} PDF page(s)")

            pdf_prep_callback = task_count_doc_pages.si(
                files_path=files_path, inputs_path=inputs_path, extension=original_extension
            ).set(link=callback, ignore_result=True)
            chord(
                task_extract_pdf_page.si(files_path, inputs_path, basename, i) for i in range(num_pages)
            )(pdf_prep_callback)

        elif extension == "zip":
            temp_folder_name = f"{files_path}/{generate_random_uuid()}"
            os.mkdir(temp_folder_name)

            with zipfile.ZipFile(inputs_path, "r") as zip_ref:
                zip_ref.extractall(temp_folder_name)

            page_paths = [
                f"{temp_folder_name}/{file}"
                for file in os.listdir(temp_folder_name)
                if os.path.isfile(os.path.join(temp_folder_name, file))
            ]

            # sort pages alphabetically, case-insensitive
            page_paths.sort(key=lambda s: (s.casefold(), s))
            
            log.info(f"📦 {basename}: Extracting {len(page_paths)} page(s) from ZIP")

            for i, page in enumerate(page_paths):
                im = Image.open(page)
                im.save(
                    f"{files_path}/_pages/{basename}_{i}.png", format="PNG"
                )

                # Generate document thumbnails with first page
                if i == 0:
                    img_rgb = im.convert("RGB")
                    thumb_128 = img_rgb.copy()
                    thumb_128.thumbnail((128, 128))
                    thumb_128.save(
                        f"{files_path}/_thumbnails/{basename}.zip_128.thumbnail", "JPEG"
                    )
                    img_rgb.thumbnail((600, 600))
                    img_rgb.save(
                        f"{files_path}/_thumbnails/{basename}.zip_600.thumbnail", "JPEG"
                    )

            shutil.rmtree(temp_folder_name)

            task_count_doc_pages(files_path=files_path, inputs_path=inputs_path, extension=original_extension)
            if callback is not None:
                callback.apply_async(ignore_result=True)
            
            log.info(f"✅ {basename}: ZIP file preparation completed")

        elif extension in ("tif", "tiff"):
            img = Image.open(inputs_path, formats=["tiff"])
            n_frames = img.n_frames
            
            log.info(f"🖼️ {basename}: Processing TIFF with {n_frames} frame(s)")
            
            if n_frames == 1:
                link_path = f"{files_path}/_pages/{basename}_0.{original_extension}"
                if not os.path.exists(link_path):
                    os.link(inputs_path, link_path)

                # Generate document thumbnails
                img_rgb = img.convert("RGB")
                thumb_128 = img_rgb.copy()
                thumb_128.thumbnail((128, 128))
                thumb_128.save(
                    f"{files_path}/_thumbnails/{basename}.{original_extension}_128.thumbnail",
                    "JPEG",
                )
                img_rgb.thumbnail((600, 600))
                img_rgb.save(
                    f"{files_path}/_thumbnails/{basename}.{original_extension}_600.thumbnail",
                    "JPEG",
                )
            else:
                compression = getattr(img, '_compression', 'tiff_deflate')
                img.save(
                    f"{files_path}/_pages/{basename}_0.{original_extension}",
                    save_all=False,
                    compression=compression,
                )
                # Generate document thumbnails with first page
                img_rgb = img.convert("RGB")
                thumb_128 = img_rgb.copy()
                thumb_128.thumbnail((128, 128))
                thumb_128.save(
                    f"{files_path}/_thumbnails/{basename}.{original_extension}_128.thumbnail",
                    "JPEG",
                )
                img_rgb.thumbnail((600, 600))
                img_rgb.save(
                    f"{files_path}/_thumbnails/{basename}.{original_extension}_600.thumbnail",
                    "JPEG",
                )

                for i in range(1, n_frames):
                    img.seek(i)
                    img.save(
                        f"{files_path}/_pages/{basename}_{i}.{original_extension}",
                        save_all=False,
                        compression=compression,
                    )

            task_count_doc_pages(files_path=files_path, inputs_path=inputs_path, extension=original_extension)
            if callback is not None:
                callback.apply_async(ignore_result=True)
            
            log.info(f"✅ {basename}: TIFF file preparation completed ({n_frames} frame(s))")

        elif extension in ALLOWED_EXTENSIONS:  # some other than pdf
            link_path = f"{files_path}/_pages/{basename}_0.{original_extension}"
            if not os.path.exists(link_path):
                # Use copy instead of hard link since _inputs and _files may be on different volumes
                shutil.copy2(inputs_path, link_path)

            # Generate document thumbnails
            img = Image.open(inputs_path)
            img_rgb = img.convert("RGB")
            thumb_128 = img_rgb.copy()
            thumb_128.thumbnail((128, 128))
            thumb_128.save(
                f"{files_path}/_thumbnails/{basename}.{original_extension}_128.thumbnail",
                "JPEG",
            )
            img_rgb.thumbnail((600, 600))
            img_rgb.save(
                f"{files_path}/_thumbnails/{basename}.{original_extension}_600.thumbnail",
                "JPEG",
            )

            task_count_doc_pages(files_path=files_path, inputs_path=inputs_path, extension=original_extension)
            if callback is not None:
                callback.apply_async(ignore_result=True)
            
            log.info(f"✅ {basename}: Image file preparation completed")

        else:
            raise FileNotFoundError("No file with a valid extension was found")

    except Exception as e:
        data = get_data(data_folder)
        data["ocr"] = data.get("ocr", {})
        data["ocr"]["exceptions"] = str(e)
        data["status"] = {
            "stage": "error",
            "message": "Erro a preparar documento",
        }
        update_json_file(data_folder, data)
        log.error(f"❌ {basename}: File preparation failed with error: {e}")
        raise e


@celery.task(name="request_ner")
def task_request_ner(files_path, outputs_path=None):
    """
    Request NER (Named Entity Recognition) from the text output.

    :param files_path: path to document folder in _files
    :param outputs_path: path to document folder in _outputs
    """
    if outputs_path is None:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"

    data = get_data(files_path + "/_data.json")

    success = get_ner_file(files_path, outputs_path)
    creation_date = get_current_time()
    if success:
        data["ner"] = {
            "complete": True,
            "size": size_to_units(
                get_file_size(f"{outputs_path}/_entities.json", path_complete=True)
            ),
            "creation": creation_date,
        }
    else:
        data["ner"] = {"complete": False, "error": True}

        update_json_file(files_path + "/_data.json", data)


@celery.task(name="process_folder_sequential")
def task_process_folder_sequential(files_list: list, config: dict = None, is_private: bool = False, current_index: int = 0):
    """
    Process files in a folder sequentially to avoid memory exhaustion.
    Queues one file at a time. When complete, automatically queues the next file.
    
    :param files_list: List of tuples (files_path, outputs_path) for each file
    :param config: OCR configuration to use
    :param is_private: Whether this is a private folder
    :param current_index: Current file index being processed
    """
    if current_index >= len(files_list):
        log.info(f"🎉 FOLDER OCR COMPLETE: All {len(files_list)} file(s) processed")
        return {"status": "complete", "files_processed": len(files_list)}
    
    f_path, o_path = files_list[current_index]
    basename = get_file_basename(f_path)
    
    # Only log folder progress for first file, every 3rd file, and last file to reduce spam
    if current_index == 0 or (current_index + 1) % 3 == 0 or current_index == len(files_list) - 1:
        log.info(f"🚀 Starting file {current_index + 1}/{len(files_list)}: {basename}")
    
    try:
        data_path = f"{f_path}/_data.json"
        data = get_data(data_path)
        
        # Check if this file was removed from queue before we started it
        current_stage = data.get("status", {}).get("stage", "")
        if current_stage == "removed_from_queue":
            log.info(f"⏭️ {basename}: Skipped (removed from queue)")
            
            # Reset the removed document to post-upload immediately so it can be OCR'd again
            try:
                data["status"] = {
                    "stage": "post-upload",
                    "message": "Pronto para OCR",
                }
                update_json_file(data_path, data)
                # Removed verbose reset log
            except Exception as e:
                log.error(f"Failed to reset removed document {basename}: {e}")
            
            # Skip this file and move to the next one
            task_process_folder_sequential.apply_async(
                kwargs={
                    "files_list": files_list,
                    "config": config,
                    "is_private": is_private,
                    "current_index": current_index + 1
                },
                ignore_result=True
            )
            return {"status": "skipped", "reason": "removed_from_queue"}
        
        # Determine config for this file
        file_config = config
        if file_config is None:
            if "config" in data and data["config"] != "default":
                file_config = data["config"]
            else:
                inherited = get_inherited_config(f_path, is_private)
                if inherited:
                    file_config = inherited
        
        # Update status from "queued" to "ocr"
        data["status"] = {
            "stage": "ocr",
            "message": "A começar...",
        }
        if file_config:
            data["config"] = file_config
        update_json_file(data_path, data)
        
        # Queue this file's OCR (it will automatically trigger export when pages complete)
        celery.send_task(
            "file_ocr",
            kwargs={
                "files_path": f_path,
                "outputs_path": o_path,
                "config": file_config
            },
            ignore_result=True
        )
        
        # Queue a monitoring task that will check when this file is done and trigger the next
        celery.send_task(
            "monitor_file_completion",
            kwargs={
                "files_path": f_path,
                "files_list": files_list,
                "config": config,
                "is_private": is_private,
                "current_index": current_index
            },
            countdown=10,
            ignore_result=True
        )
        
        return {"status": "queued", "current_file": current_index + 1, "total_files": len(files_list)}
        
    except Exception as e:
        log.error(f"❌ {basename}: Failed to queue (file {current_index + 1}/{len(files_list)}): {e}")
        # Continue with next file even if this one failed
        task_process_folder_sequential.apply_async(
            kwargs={
                "files_list": files_list,
                "config": config,
                "is_private": is_private,
                "current_index": current_index + 1
            },
            ignore_result=True
        )
        return {"status": "error", "file": basename}


@celery.task(name="reset_cancelled_document")
def task_reset_cancelled_document(files_path: str):
    """
    Reset a cancelled document back to post-upload status so it can be OCR'd again.
    This is mainly for standalone documents (not in folder queues).
    For folder queues, the monitor task handles the reset immediately.
    
    :param files_path: path to the document folder
    """
    try:
        data_file = f"{files_path}/_data.json"
        if not os.path.exists(data_file):
            return {"status": "file_not_found"}
        
        data = get_data(data_file)
        current_stage = data.get("status", {}).get("stage", "")
        
        # Only reset if still in cancelled state (user might have started new OCR already)
        if current_stage == "cancelled":
            basename = get_file_basename(files_path)
            log.info(f"🔄 {basename}: Resetting cancelled document to post-upload")
            
            data["status"] = {
                "stage": "post-upload",
                "message": "Pronto para OCR",
            }
            update_json_file(data_file, data)
            return {"status": "reset_complete"}
        else:
            return {"status": "no_reset_needed", "current_stage": current_stage}
            
    except Exception as e:
        log.error(f"Error resetting cancelled document {files_path}: {e}")
        return {"status": "error", "error": str(e)}


@celery.task(name="monitor_file_completion")
def task_monitor_file_completion(files_path: str, files_list: list, config: dict, is_private: bool, current_index: int):
    """
    Monitor if a file has completed all OCR and export tasks.
    When complete, trigger the next file in the folder.
    
    :param files_path: path to current document being monitored
    :param files_list: full list of files in folder
    :param config: OCR configuration
    :param is_private: whether this is a private folder
    :param current_index: index of file being monitored
    """
    basename = get_file_basename(files_path)
    data_file = f"{files_path}/_data.json"
    
    try:
        data = get_data(data_file)
        stage = data.get("status", {}).get("stage", "")
        
        # Check if file is complete (post-ocr) or failed (error) or cancelled
        if stage == "post-ocr":
            log.info(f"✅ {basename}: Completed, starting next file")
            # This file is done, start the next one
            task_process_folder_sequential.apply_async(
                kwargs={
                    "files_list": files_list,
                    "config": config,
                    "is_private": is_private,
                    "current_index": current_index + 1
                },
                ignore_result=True
            )
            return {"status": "next_file_queued"}
            
        elif stage == "error":
            log.warning(f"⚠️ {basename}: Failed, starting next file anyway")
            # This file failed, but continue with next one
            task_process_folder_sequential.apply_async(
                kwargs={
                    "files_list": files_list,
                    "config": config,
                    "is_private": is_private,
                    "current_index": current_index + 1
                },
                ignore_result=True
            )
            return {"status": "next_file_queued_after_error"}
            
        elif stage == "cancelled":
            log.info(f"🚫 {basename}: Cancelled by user, starting next file")
            
            # Reset the cancelled document to post-upload immediately so it can be OCR'd again
            try:
                data["status"] = {
                    "stage": "post-upload",
                    "message": "Pronto para OCR",
                }
                update_json_file(data_file, data)
                # Removed verbose reset log
            except Exception as e:
                log.error(f"Failed to reset cancelled document {basename}: {e}")
            
            # Move to next file
            task_process_folder_sequential.apply_async(
                kwargs={
                    "files_list": files_list,
                    "config": config,
                    "is_private": is_private,
                    "current_index": current_index + 1
                },
                ignore_result=True
            )
            return {"status": "next_file_queued_after_cancel"}
            
        else:
            # Still processing, check again in 10 seconds (reduced frequency to minimize log spam)
            celery.send_task(
                "monitor_file_completion",
                kwargs={
                    "files_path": files_path,
                    "files_list": files_list,
                    "config": config,
                    "is_private": is_private,
                    "current_index": current_index
                },
                countdown=10,
                ignore_result=True
            )
            return {"status": "still_processing", "stage": stage}
            
    except Exception as e:
        log.error(f"❌ {basename}: Monitor failed: {e}, starting next file anyway")
        # If we can't monitor, move to next file to avoid getting stuck
        task_process_folder_sequential.apply_async(
            kwargs={
                "files_list": files_list,
                "config": config,
                "is_private": is_private,
                "current_index": current_index + 1
            },
            ignore_result=True
        )
        return {"status": "monitor_error"}


@celery.task(name="process_pages_in_batches")
def task_process_pages_in_batches(
    chord_results=None,  # First param to receive chord results
    files_path=None,
    outputs_path=None,
    ocr_engine_name=None,
    lang=None,
    config=None,
    output_types=None,
    delete_on_finish=None,
    images=None,
    batch_size=None,
    current_batch_index=None,
):
    """
    Process OCR pages in batches (e.g., 3 pages at a time) to balance speed and memory.
    Each batch processes in parallel, then waits before starting the next batch.
    
    NOTE: chord_results is automatically passed by Celery chord callback and is ignored.
    
    :param chord_results: Results from previous batch (ignored, automatically passed by chord)
    :param files_path: path to document folder
    :param outputs_path: path to outputs folder
    :param ocr_engine_name: name of OCR engine to use
    :param lang: language code
    :param config: OCR configuration
    :param output_types: list of output formats
    :param delete_on_finish: whether to delete files after completion
    :param images: list of all image filenames to process
    :param batch_size: number of pages to process in parallel per batch
    :param current_batch_index: index of the current batch to process
    """
    basename = get_file_basename(files_path)
    total_pages = len(images)
    total_batches = (total_pages + batch_size - 1) // batch_size
    
    # Check if document has been cancelled
    data_file = f"{files_path}/_data.json"
    doc_data = get_data(data_file)
    current_stage = doc_data.get("status", {}).get("stage", "")
    
    log.warning(f"🔍 CANCEL CHECK in batch coordinator: stage={current_stage}, is_cancelled={current_stage == 'cancelled'}")
    
    if current_stage == "cancelled":
        log.warning(f"🚫 {basename}: Batch processing aborted (document cancelled)")
        return {"status": "cancelled"}
    
    # Check if all batches are complete
    if current_batch_index >= total_batches:
        # All pages done - trigger export
        log.info(f"✅ {basename}: All {total_batches} batches ({total_pages} pages) completed, starting export")
        celery.send_task(
            "export_results",
            kwargs={
                "files_path": files_path,
                "outputs_path": outputs_path,
                "output_types": output_types,
            },
            ignore_result=True
        )
        return {"status": "all_batches_complete", "triggering_export": True}
    
    # Calculate batch range
    start_idx = current_batch_index * batch_size
    end_idx = min(start_idx + batch_size, total_pages)
    batch_images = images[start_idx:end_idx]
    
    log.info(f"📦 {basename}: Processing batch {current_batch_index + 1}/{total_batches} (pages {start_idx + 1}-{end_idx}/{total_pages})")
    
    # Create tasks for this batch
    batch_tasks = []
    for img in batch_images:
        batch_tasks.append(
            task_page_ocr.s(
                files_path=files_path,
                outputs_path=outputs_path,
                filename=img,
                ocr_engine_name=ocr_engine_name,
                lang=lang,
                config=config,
                output_types=output_types,
                delete_on_finish=delete_on_finish,
            )
        )
    
    # Create callback for next batch (using .si() to ignore chord results)
    next_batch_task = task_process_pages_in_batches.si(
        files_path=files_path,
        outputs_path=outputs_path,
        ocr_engine_name=ocr_engine_name,
        lang=lang,
        config=config,
        output_types=output_types,
        delete_on_finish=delete_on_finish,
        images=images,
        batch_size=batch_size,
        current_batch_index=current_batch_index + 1,
    )
    
    # Process this batch in parallel, then trigger next batch
    chord(batch_tasks)(next_batch_task)
    
    return {"status": "batch_queued", "batch": current_batch_index, "pages": f"{start_idx + 1}-{end_idx}"}


@celery.task(name="process_pages_sequential")
def task_process_pages_sequential(
    files_path: str,
    outputs_path: str,
    ocr_engine_name: str,
    lang: str,
    config: dict,
    output_types: list,
    delete_on_finish: bool,
    images: list,
    current_page_index: int,
):
    """
    Process OCR pages sequentially (one at a time) to prevent memory exhaustion.
    After each page completes, trigger the next page or export if all pages are done.
    
    :param files_path: path to document folder
    :param outputs_path: path to outputs folder
    :param ocr_engine_name: name of OCR engine to use
    :param lang: language code
    :param config: OCR configuration
    :param output_types: list of output formats
    :param delete_on_finish: whether to delete files after completion
    :param images: list of all image filenames to process
    :param current_page_index: index of the current page to process
    """
    basename = get_file_basename(files_path)
    total_pages = len(images)
    
    # Check if we've processed all pages
    if current_page_index >= total_pages:
        # All pages done - trigger export
        log.info(f"✅ {basename}: All {total_pages} pages completed, starting export")
        celery.send_task(
            "export_results",
            kwargs={
                "files_path": files_path,
                "outputs_path": outputs_path,
                "output_types": output_types,
            },
            ignore_result=True
        )
        return {"status": "all_pages_complete", "triggering_export": True}
    
    # Process current page
    current_image = images[current_page_index]
    log.info(f"📄 {basename}: Processing page {current_page_index + 1}/{total_pages}")
    
    try:
        # Call the actual OCR task synchronously (blocking)
        result = task_page_ocr(
            files_path=files_path,
            outputs_path=outputs_path,
            filename=current_image,
            ocr_engine_name=ocr_engine_name,
            lang=lang,
            config=config,
            output_types=output_types,
            delete_on_finish=delete_on_finish,
        )
        
        # Page completed successfully, queue next page
        celery.send_task(
            "process_pages_sequential",
            kwargs={
                "files_path": files_path,
                "outputs_path": outputs_path,
                "ocr_engine_name": ocr_engine_name,
                "lang": lang,
                "config": config,
                "output_types": output_types,
                "delete_on_finish": delete_on_finish,
                "images": images,
                "current_page_index": current_page_index + 1,
            },
            ignore_result=True
        )
        
        return {"status": "page_complete", "page": current_page_index, "queued_next": True}
        
    except Exception as e:
        log.error(f"❌ {basename}: Page {current_page_index} failed: {e}")
        
        # Continue with next page even if this one failed
        celery.send_task(
            "process_pages_sequential",
            kwargs={
                "files_path": files_path,
                "outputs_path": outputs_path,
                "ocr_engine_name": ocr_engine_name,
                "lang": lang,
                "config": config,
                "output_types": output_types,
                "delete_on_finish": delete_on_finish,
                "images": images,
                "current_page_index": current_page_index + 1,
            },
            ignore_result=True
        )
        
        return {"status": "page_failed", "page": current_page_index, "error": str(e)}


@celery.task(name="file_ocr")
def task_file_ocr(
    files_path: str = None,
    outputs_path: str = None,
    config: dict | str | None = None,
    delete_on_finish: bool = False,
    path: str = None,  # Legacy parameter
):
    """
    Prepare the OCR of a file.

    :param files_path: path to document folder in _files (or API_TEMP_PATH for API files)
    :param outputs_path: path to document folder in _outputs (or _export subfolder for API files)
    :param config: config to use
    :param delete_on_finish: whether the original file and pages should be deleted after processing
    :param path: legacy parameter, used if files_path/outputs_path not provided
    """
    # Check if this is an API file (stored in API_TEMP_PATH)
    from src.utils.file import API_TEMP_PATH
    is_api_file = API_TEMP_PATH in files_path if files_path else (API_TEMP_PATH in path if path else False)
    
    # Support legacy usage
    if files_path is None and path is not None:
        files_path = path
        if is_api_file:
            outputs_path = f"{files_path}/_export"
        else:
            relative_path = files_path.replace(FILES_PATH, "").strip("/")
            outputs_path = f"{OUTPUTS_PATH}/{relative_path}"
    elif outputs_path is None and files_path is not None:
        if is_api_file:
            outputs_path = f"{files_path}/_export"
        else:
            relative_path = files_path.replace(FILES_PATH, "").strip("/")
            outputs_path = f"{OUTPUTS_PATH}/{relative_path}"

    data_file = f"{files_path}/_data.json"    
    basename = get_file_basename(files_path)
    
    # Removed verbose "task_file_ocr started" log
    
    try:
        with open(DEFAULT_CONFIG_FILE) as f:
            default_config = json.load(f)
        
        if (
            not config
            or config == "{}"
            or (isinstance(config, str) and config == "default")
        ):
            config = default_config
        else:
            # Build string with Tesseract run configuration
            if "engine" in config:
                if config["engine"].lower() not in OCR_ENGINES:
                    raise ValueError(
                        f"Invalid OCR engine value; possible values are {OCR_ENGINES}",
                        config["engine"],
                    )
            else:
                config["engine"] = default_config["engine"]
            if "lang" not in config:
                config["lang"] = default_config["lang"]
            if "engineMode" not in config:
                config["engineMode"] = default_config["engineMode"]
            if "segmentMode" not in config:
                config["segmentMode"] = default_config["segmentMode"]
            if "thresholdMethod" not in config:
                config["thresholdMethod"] = default_config["thresholdMethod"]
            if "outputs" not in config:
                config["outputs"] = default_config["outputs"]

            if "dpi" not in config and "dpi" in default_config:
                config["dpi"] = default_config["dpi"]
            if "otherParams" not in config and "otherParams" in default_config:
                config["otherParams"] = default_config["otherParams"]

        # ensure other params are defined as a dict of names to values
        other_params = config.get("otherParams", None)
        if (
            other_params is not None
            and not isinstance(other_params, dict)
            and isinstance(other_params, str)
        ):
            other_params_dict = {}
            for param in other_params.split(";"):
                n, v = param.split("=")
                other_params_dict[n.strip()] = v.strip()
            config["otherParams"] = other_params_dict

        # Verify parameter values
        ocr_engine = globals()[f'ocr_{config["engine"]}'.lower()]
        valid, errors = ocr_engine.verify_params(config)
        if not valid:
            data = get_data(data_file)
            data["ocr"].update(
                {"progress": 0, "exceptions": {"Parâmetros inválidos:": errors}}
            )
            data["status"] = {
                "stage": "error",
                "message": f"Parâmetros inválidos: {errors}",
            }
            update_json_file(data_file, data)
            log.error(
                f'Error in performing OCR for file at {path}: {data["ocr"]["exceptions"]}'
            )
            return {"status": "error", "errors": errors}

        # Update the information related to the OCR
        data = get_data(data_file)
        
        data["ocr"] = {
            "config": config,
            "progress": 0,
        }
        data["status"] = {
            "stage": "ocr",
            "message": f"({ocr_engine.estimate_ocr_time(config, get_doc_len(data_file))})",
        }
        update_json_file(data_file, data)

        # Build config according to specified engine
        lang, config_formatted = ocr_engine.build_ocr_config(config)

        # Generate the images
        """
        metrics = {}

        log.info(f"Starting OCR process for file: {path}")
        start_total = time.time()

        log.info("Validating input file...")
        validation_start = time.time()
        #prepare_file_ocr(path)
        validation_time = time.time() - validation_start
        metrics['file_validation_time'] = validation_time
        log.info(f"File validation completed in {validation_time:.2f}s")

        log.info("Starting PDF split process...")
        split_start = time.time()
        images = sorted([x for x in os.listdir(path) if x.endswith(".png")])
        split_time = time.time() - split_start
        metrics['pdf_split_time'] = split_time
        log.info(f"PDF split completed in {split_time:.2f}s. Generated {len(images)} pages.")

        if not os.path.exists(f"{path}/ocr_results"):
            os.mkdir(f"{path}/ocr_results")

        log.info("Queuing OCR tasks for each page...")
        queue_start = time.time()
        tasks = [task_page_ocr.s(path, image, config, ocr_algorithm) for image in images]
        log.info(f"Queuing {len(images)} OCR tasks.")
        queue_time = time.time() - queue_start
        metrics['task_queue_time'] = queue_time
        log.info(f"Task queue creation completed in {queue_time:.2f}s")

        chord(tasks)(task_ocr_complete.s(files_path, start_total, metrics))
        """

        if not os.path.exists(f"{files_path}/_ocr_results"):
            os.mkdir(f"{files_path}/_ocr_results")

        # Ensure outputs folder exists
        os.makedirs(outputs_path, exist_ok=True)

        pages_path = f"{files_path}/_pages"
        
        # Check if pages directory exists
        if not os.path.exists(pages_path):
            raise FileNotFoundError(
                f"Pages directory not found. The document may need to be re-uploaded or re-prepared. "
                f"Expected path: {pages_path}"
            )
        
        images = sorted([x for x in os.listdir(pages_path)])

        if not images:
            raise FileNotFoundError("Page folder is empty")

        log.info(f"📋 {basename}: Starting BATCHED OCR (max 3 parallel at a time) for {len(images)} page(s) | lang={lang} | engine={config['engine']}")

        # Process pages in controlled batches
        # Strategy: Use chord with batches, process batches sequentially
        PARALLEL_PAGE_LIMIT = 3
        
        # Start the batched processing coordinator
        celery.send_task(
            "process_pages_in_batches",
            kwargs={
                "files_path": files_path,
                "outputs_path": outputs_path,
                "ocr_engine_name": f'ocr_{config["engine"]}',
                "lang": lang,
                "config": config_formatted,
                "output_types": config["outputs"],
                "delete_on_finish": delete_on_finish,
                "images": images,
                "batch_size": PARALLEL_PAGE_LIMIT,
                "current_batch_index": 0,
            },
            ignore_result=True
        )
        
        log.info(f"✅ {basename}: Batched OCR coordinator started")
        
        return {"status": "success"}

    except Exception as e:
        data = get_data(data_file)
        data["ocr"]["exceptions"] = str(e)
        data["status"] = {
            "stage": "error",
            "message": "Erro durante OCR",
        }
        update_json_file(data_file, data)
        log.error(f"❌ {basename}: task_file_ocr failed with error: {e}")

        return {"status": "error"}


@celery.task(name="extract_pdf_page")
def task_extract_pdf_page(files_path, inputs_path, basename, i):
    """
    Extracts a single PDF page and saves it as a PNG file.
    This runs on separate Celery workers for parallelization.

    :param files_path: path to document folder in _files (for pages and thumbnails)
    :param inputs_path: path to original PDF file in _inputs
    :param basename: basename of the document
    :param i: page index
    """
    try:
        pdf = pdfium.PdfDocument(inputs_path)
        page = pdf[i]
        bitmap = page.render(
            300 / 72
        )  # You can adjust DPI here (e.g., 150 / 72 for smaller files)
        pdf.close()
        pil_image = bitmap.to_pil()
        output_path = f"{files_path}/_pages/{basename}_{i}.png"

        # Use BytesIO for buffered I/O
        buffer = BytesIO()
        pil_image.save(buffer, format="PNG", compress_level=6)
        buffer.seek(0)

        # Use temporary file for atomic write
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png", dir=files_path) as temp:
            temp.write(buffer.getvalue())

        # Atomically move the temporary file to the final location
        shutil.move(temp.name, output_path)

        # Ensure file read access permissions are set
        os.chmod(output_path, 0o644)  # rw-r--r--

        # Verify the PNG to ensure it’s not truncated
        try:
            with Image.open(output_path) as img:
                img.load()  # Force load to check for truncation
            log.debug(
                f"Verified page {i} from {basename}.pdf is valid (size: {os.path.getsize(output_path)} bytes)"
            )
        except Exception as e:
            log.error(f"Invalid PNG generated for page {i}: {e}")
            with suppress(FileNotFoundError):
                os.remove(output_path)  # Remove truncated file
            raise

        # Generate document thumbnails with first page
        if i == 0:
            thumb_128 = pil_image.copy()
            thumb_128.thumbnail((128, 128))
            thumb_128.save(f"{files_path}/_thumbnails/{basename}.pdf_128.thumbnail", "JPEG")
            pil_image.thumbnail((600, 600))
            pil_image.save(f"{files_path}/_thumbnails/{basename}.pdf_600.thumbnail", "JPEG")

        log.debug(f"Extracted page {i} from {basename}.pdf")

    except Exception as e:
        log.error(f"Error extracting page {i} from {basename}.pdf: {e}")


"""
@celery.task(name="ocr_complete")
def task_ocr_complete(results, path, start_time, initial_metrics):
    #
    # Callback task executed after all OCR tasks for a PDF are complete.
    # Calculates the total processing time.
    #
    try:
        total_time = time.time() - start_time
        log.info(f"{path}: Total OCR time for the entire PDF: {total_time:.2f} seconds")

        valid_results = [r.get("metricas") for r in results if isinstance(r, dict) and "metricas" in r]

        if not valid_results:
            log.warning(f"{path}: No valid OCR results to process. Skipping metric calculations.")
            return {
                "status": "success",
                "metrics": {
                    "total_time": total_time,
                    "file_validation_time": initial_metrics.get('file_validation_time'),
                    "pdf_split_time": initial_metrics.get('pdf_split_time'),
                    "task_queue_time": initial_metrics.get('task_queue_time'),
                    "average_image_load_time": 0,
                    "average_ocr_time": 0,
                    "average_save_time": 0,
                }
            }


        # Calculate averages correctly
        avg_image_load_time = sum(r.get('image_load_time', 0) for r in valid_results) / len(valid_results)
        avg_ocr_time = sum(r.get('ocr_time', 0) for r in valid_results) / len(valid_results)
        avg_save_time = sum(r.get('save_time', 0) for r in valid_results) / len(valid_results)

        final_metrics = {
            "total_time": total_time,
            "file_validation_time": initial_metrics.get('file_validation_time'),
            "pdf_split_time": initial_metrics.get('pdf_split_time'),
            "task_queue_time": initial_metrics.get('task_queue_time'),
            "average_image_load_time": avg_image_load_time,
            "average_ocr_time": avg_ocr_time,
            "average_save_time": avg_save_time,
        }

        log.info(f"Final metrics for {path}: {json.dumps(final_metrics, indent=2)}")
        return {"status": "success", "metrics": final_metrics}

    except Exception as e:
        log.error(f"Error calculating total OCR time for {path}: {e}")
        return {"status": "error", "error": str(e)}
"""


def preprocess_image_for_ocr(image, config, debug_save_path=None):
    """
    Apply comprehensive preprocessing pipeline to improve OCR quality.
    Returns preprocessed PIL Image or numpy array depending on operations applied.
    
    Pipeline steps:
    1. Convert to grayscale
    2. CLAHE (Contrast Limited Adaptive Histogram Equalization)
    3. Median blur for noise reduction
    4. Thresholding (adaptive Gaussian, OTSU, Sauvola, or none)
    5. Morphological opening (removes small noise)
    6. Morphological closing (fills small gaps)
    7. Deskew
    
    :param image: Input image (PIL Image, path string, or numpy array)
    :param config: Configuration dictionary containing preprocessing settings
    :param debug_save_path: If provided, save the preprocessed image to this path for debugging
    :return: Preprocessed PIL Image
    """
    import cv2
    import numpy as np
    from PIL import Image
    
    preprocessing = config.get("preprocessing", {})
    
    # If preprocessing disabled, return original
    if not preprocessing.get("enabled", True):
        print("🔧 PREPROCESSING: Disabled - using original image")
        return image
    
    print("🔧 PREPROCESSING: Starting pipeline...")
    steps_applied = []
    
    # Convert PIL to numpy array for OpenCV operations
    if isinstance(image, str):
        image = Image.open(image)
    if isinstance(image, Image.Image):
        img_array = np.array(image)
    else:
        img_array = image
    
    original_shape = img_array.shape
    print(f"   📐 Input image: {original_shape}")
    
    # Step 1: Convert to grayscale
    if preprocessing.get("grayscale", True):
        if len(img_array.shape) == 3:
            img_array = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            steps_applied.append("grayscale")
            print(f"   ✓ Step 1: Grayscale conversion → {img_array.shape}")
    
    # Step 2: CLAHE (Contrast Limited Adaptive Histogram Equalization)
    if preprocessing.get("clahe", True):
        clip_limit = preprocessing.get("clahe_clip_limit", 2.0)
        tile_size = preprocessing.get("clahe_tile_size", 8)
        clahe = cv2.createCLAHE(clipLimit=clip_limit, tileGridSize=(tile_size, tile_size))
        img_array = clahe.apply(img_array)
        steps_applied.append(f"CLAHE(clip={clip_limit}, tile={tile_size})")
        print(f"   ✓ Step 2: CLAHE enhancement (clip_limit={clip_limit}, tile_size={tile_size})")
    
    # Step 3: Median blur for noise reduction
    if preprocessing.get("median_blur", True):
        kernel = preprocessing.get("median_blur_kernel", 3)
        img_array = cv2.medianBlur(img_array, kernel)
        steps_applied.append(f"median_blur({kernel}x{kernel})")
        print(f"   ✓ Step 3: Median blur (kernel={kernel})")
    
    # Step 4: Thresholding
    threshold_method = preprocessing.get("threshold_method", "adaptive_gaussian")
    if threshold_method == "adaptive_gaussian":
        block_size = preprocessing.get("adaptive_block_size", 11)
        c = preprocessing.get("adaptive_c", 2)
        img_array = cv2.adaptiveThreshold(
            img_array, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
            cv2.THRESH_BINARY, block_size, c
        )
        steps_applied.append(f"adaptive_gaussian(block={block_size}, C={c})")
        print(f"   ✓ Step 4: Adaptive Gaussian threshold (block_size={block_size}, C={c})")
    elif threshold_method == "otsu":
        _, img_array = cv2.threshold(img_array, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        steps_applied.append("otsu")
        print(f"   ✓ Step 4: OTSU threshold")
    elif threshold_method == "sauvola":
        # Use local window-based Sauvola thresholding
        window_size = preprocessing.get("sauvola_window", 25)
        k = preprocessing.get("sauvola_k", 0.2)
        img_array = apply_sauvola_threshold(img_array, window_size, k)
        steps_applied.append(f"sauvola(window={window_size}, k={k})")
        print(f"   ✓ Step 4: Sauvola threshold (window={window_size}, k={k})")
    else:
        print(f"   ⊘ Step 4: Threshold skipped (method={threshold_method})")
    
    # Step 5: Morphological opening (removes small noise)
    if preprocessing.get("morphological_opening", True):
        kernel_size = preprocessing.get("morph_kernel_size", 3)
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (kernel_size, kernel_size))
        img_array = cv2.morphologyEx(img_array, cv2.MORPH_OPEN, kernel)
        steps_applied.append(f"opening({kernel_size}x{kernel_size})")
        print(f"   ✓ Step 5: Morphological opening (kernel={kernel_size})")
    
    # Step 6: Morphological closing (fills small gaps)
    if preprocessing.get("morphological_closing", True):
        kernel_size = preprocessing.get("morph_kernel_size", 3)
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (kernel_size, kernel_size))
        img_array = cv2.morphologyEx(img_array, cv2.MORPH_CLOSE, kernel)
        steps_applied.append(f"closing({kernel_size}x{kernel_size})")
        print(f"   ✓ Step 6: Morphological closing (kernel={kernel_size})")
    
    # Step 7: Deskew
    if preprocessing.get("deskew", True):
        angle = deskew_image(img_array, return_angle=True)
        if angle is not None and abs(angle) > 0.5:
            img_array = deskew_image(img_array, return_angle=False)
            steps_applied.append(f"deskew({angle:.2f}°)")
            print(f"   ✓ Step 7: Deskew (angle={angle:.2f}°)")
        else:
            print(f"   ⊘ Step 7: Deskew skipped (angle too small: {angle:.2f}°)" if angle else "   ⊘ Step 7: Deskew skipped (no text detected)")
    
    print(f"🔧 PREPROCESSING: Complete! Applied {len(steps_applied)} steps: {', '.join(steps_applied)}")
    
    # Convert back to PIL Image for Tesseract
    result_image = Image.fromarray(img_array)
    
    # Save preprocessed image for debugging if path provided
    if debug_save_path:
        try:
            result_image.save(debug_save_path)
            print(f"💾 PREPROCESSING: Debug image saved to {debug_save_path}")
        except Exception as e:
            print(f"⚠️ PREPROCESSING: Failed to save debug image: {e}")
    
    return result_image


def apply_sauvola_threshold(img, window_size, k):
    """
    Apply Sauvola local thresholding.
    
    Sauvola thresholding is an adaptive method that works well for documents
    with varying illumination or degraded quality.
    
    :param img: Input grayscale image (numpy array)
    :param window_size: Size of the local window
    :param k: Sauvola parameter (typically 0.2-0.5)
    :return: Binary thresholded image
    """
    import cv2
    import numpy as np
    
    mean = cv2.boxFilter(img.astype(np.float32), -1, (window_size, window_size))
    sq_mean = cv2.boxFilter((img.astype(np.float32))**2, -1, (window_size, window_size))
    variance = sq_mean - mean**2
    std_dev = np.sqrt(np.maximum(variance, 0))
    
    threshold = mean * (1 + k * (std_dev / 128 - 1))
    binary = np.where(img > threshold, 255, 0).astype(np.uint8)
    return binary


def deskew_image(img, return_angle=False):
    """
    Automatically deskew image using minimum area rectangle method.
    
    This finds the skew angle and rotates the image to correct it.
    Only applies rotation if the angle is significant (> 0.5 degrees).
    Limited to ±15 degrees to prevent large unwanted rotations.
    
    :param img: Input image (numpy array)
    :param return_angle: If True, only return the detected angle without rotating
    :return: Deskewed image or angle (depending on return_angle parameter)
    """
    import cv2
    import numpy as np
    
    # Find skew angle using minimum area rectangle
    coords = np.column_stack(np.where(img < 128))
    if len(coords) == 0:
        return None if return_angle else img
    
    angle = cv2.minAreaRect(coords)[-1]
    
    # Normalize angle to -45 to 45 range
    if angle < -45:
        angle = -(90 + angle)
    else:
        angle = -angle
    
    # IMPORTANT: Limit to small corrections only (±15 degrees)
    # This prevents 90-degree rotations when minAreaRect detects wrong orientation
    if abs(angle) > 15:
        print(f"🔧 PREPROCESSING: Deskew angle {angle:.2f}° exceeds limit (±15°), skipping deskew")
        return None if return_angle else img
    
    if return_angle:
        return angle
    
    # Only deskew if angle is significant (> 0.5 degrees) but within limits
    if abs(angle) < 0.5:
        return img
    
    print(f"🔧 PREPROCESSING: Applying deskew rotation: {angle:.2f}°")
    
    # Rotate image
    (h, w) = img.shape[:2]
    center = (w // 2, h // 2)
    M = cv2.getRotationMatrix2D(center, angle, 1.0)
    rotated = cv2.warpAffine(img, M, (w, h), 
                             flags=cv2.INTER_CUBIC, 
                             borderMode=cv2.BORDER_REPLICATE)
    return rotated


@celery.task(name="page_ocr")
def task_page_ocr(
    files_path: str = None,
    outputs_path: str = None,
    filename: str = None,
    ocr_engine_name: str = None,
    lang: str = None,
    output_types: list[str] = None,
    config: str | dict | None = None,
    delete_on_finish: bool = False,
    path: str = None,  # Legacy parameter
):
    """
    Perform the page OCR.

    :param files_path: path to document folder in _files
    :param outputs_path: path to document folder in _outputs
    :param filename: filename of the page
    :param ocr_engine_name: name of the OCR module to use
    :param lang: string of languages to use
    :param config: config to use
    :param output_types: output types to generate directly, if the file is a single page without user-defined text boxes
    :param delete_on_finish: whether the original file and pages should be deleted on finish, keeping only the results
    :param path: legacy parameter
    """
    # Support legacy usage
    if files_path is None and path is not None:
        files_path = path
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"
    elif outputs_path is None and files_path is not None:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"

    data_file = f"{files_path}/_data.json"
    basename = get_file_basename(files_path)
    page_num = filename.split("_")[-1].split(".")[0] if "_" in filename else "0"
    
    # Removed verbose "OCR task started" log to reduce spam
    
    try:
        if filename.split(".")[0][-1] == "$":
            return None

        # hacky way of aborting if another task_page_ocr previously raised an error
        if "exceptions" in get_data(data_file)["ocr"]:
            log.warning(f"⚠️ {basename} | Page {page_num}: Aborted (another page had an error)")
            return {"status": "aborted"}
        
        # Check if document has been cancelled
        doc_data = get_data(data_file)
        current_stage = doc_data.get("status", {}).get("stage", "")
        
        log.warning(f"🔍 CANCEL CHECK in page OCR (page {page_num}): stage={current_stage}, is_cancelled={current_stage == 'cancelled'}")
        
        if current_stage == "cancelled":
            log.warning(f"🚫 {basename} | Page {page_num}: Aborted (document cancelled)")
            return {"status": "cancelled"}

        n_doc_pages = get_doc_len(data_file)
        raw_results = None

        """
        page_metrics = {}
        """

        # Convert the ocr_algorithm to the correct class
        ocr_engine = globals()[ocr_engine_name.lower()]

        layout_path = f"{files_path}/_layouts/{get_file_basename(filename)}.json"

        parsed_json = []
        text_groups = []
        image_groups = []
        ignore_groups = []
        if os.path.exists(layout_path):
            with open(layout_path, encoding="utf-8") as json_file:
                parsed_json = json.load(json_file)

        for item in parsed_json:
            area_type = item["type"]
            if area_type == "text":
                text_groups.append(item)
            elif area_type == "image":
                image_groups.append(item)
            elif area_type == "remove":
                ignore_groups.append(item)

        image_filename = f"{files_path}/_pages/{filename}"
        image = None

        # extract images, if any selected
        if image_groups:
            image = Image.open(image_filename)

            if not os.path.exists(f"{files_path}/_images"):
                os.mkdir(f"{files_path}/_images")

            basename = get_file_basename(filename)
            page_number = int(basename.split("_")[-1]) + 1

            for item_id, item in enumerate(image_groups):
                for sq in item["squares"]:
                    left = sq["left"]
                    top = sq["top"]
                    right = sq["right"]
                    bottom = sq["bottom"]

                    box_coords = (left, top, right, bottom)
                    cropped_image = image.crop(box_coords)
                    cropped_image.save(
                        f"{files_path}/_images/page{page_number}_{item_id + 1}.{filename.split('.')[-1].lower()}"
                    )

        # cover ignored segments, if any selected
        if ignore_groups:
            if image is None:
                image = Image.open(image_filename)

            img_draw = ImageDraw.Draw(image)
            for item in ignore_groups:
                for sq in item["squares"]:
                    box_coords = ((sq["left"], sq["top"]), (sq["right"], sq["bottom"]))
                    img_draw.rectangle(box_coords, fill="white")

        box_coordinates_list = []
        for item in text_groups:
            for sq in item["squares"]:
                left = sq["left"]
                top = sq["top"]
                right = sq["right"]
                bottom = sq["bottom"]

                box_coords = (left, top, right, bottom)
                box_coordinates_list.append(box_coords)

        # DEBUG: Log before validation
        print(f"🔍 DEBUG [{page_num}]: Collected {len(box_coordinates_list)} boxes from {len(text_groups)} text_groups")

        # Validate and clip bounding boxes to image dimensions to prevent Tesseract crashes
        if box_coordinates_list:
            # Load image temporarily just to get dimensions for validation
            temp_image = image if image is not None else Image.open(image_filename)
            img_width, img_height = temp_image.size
            
            print(f"🔍 DEBUG [{page_num}]: Image dims={img_width}x{img_height}, first_box={box_coordinates_list[0] if box_coordinates_list else None}")
            
            # CHECK FOR ORIENTATION MISMATCH
            # If boxes seem to be for a different orientation (e.g., boxes were created for landscape
            # but image is now portrait), detect this and fallback to full-page OCR
            if box_coordinates_list:
                # Calculate expected bounds from all boxes
                all_lefts = [b[0] for b in box_coordinates_list]
                all_tops = [b[1] for b in box_coordinates_list]
                all_rights = [b[2] for b in box_coordinates_list]
                all_bottoms = [b[3] for b in box_coordinates_list]
                
                max_box_width = max(all_rights) if all_rights else 0
                max_box_height = max(all_bottoms) if all_bottoms else 0
                
                # Check if boxes suggest a completely different orientation
                # (e.g., boxes go to 3500 wide but image is only 2480 wide)
                # MADE MORE AGGRESSIVE: Now triggers at 1.05x instead of 1.2x
                width_ratio = max_box_width / img_width if img_width > 0 else 0
                height_ratio = max_box_height / img_height if img_height > 0 else 0
                
                orientation_mismatch = False
                # More aggressive: trigger if ANY dimension is even 5% over
                if width_ratio > 1.05 or height_ratio > 1.05:
                    print(f"🔍 DEBUG [{page_num}]: ORIENTATION MISMATCH! ratios=({width_ratio:.2f}x, {height_ratio:.2f}x) img={img_width}x{img_height} box_extent={max_box_width}x{max_box_height}")
                    
                    log.warning(f"⚠️ {basename} | Page {page_num}: ORIENTATION MISMATCH DETECTED!")
                    log.warning(f"   Image dimensions: {img_width}x{img_height}")
                    log.warning(f"   Box max extent: {max_box_width}x{max_box_height}")
                    log.warning(f"   Ratios: width={width_ratio:.2f}x, height={height_ratio:.2f}x")
                    
                    # Check if this looks like a 90° rotation issue (dimensions swapped)
                    if abs(img_width - max_box_height) < 100 and abs(img_height - max_box_width) < 100:
                        log.warning(f"   → Looks like image was rotated 90° (landscape↔portrait)")
                    
                    orientation_mismatch = True
                else:
                    print(f"🔍 DEBUG [{page_num}]: Orientation OK ratios=({width_ratio:.2f}x, {height_ratio:.2f}x)")
                
                # ALSO check if ANY individual box is completely outside boundaries
                # This catches cases where most boxes are fine but a few are way off
                for idx, box in enumerate(box_coordinates_list):
                    left, top, right, bottom = box
                    if left < 0 or top < 0 or right > img_width or bottom > img_height:
                        print(f"🔍 DEBUG [{page_num}]: Box {idx} COMPLETELY OUTSIDE! box=({left},{top},{right},{bottom}) img={img_width}x{img_height}")
                        
                        log.warning(f"⚠️ {basename} | Page {page_num}: Box {idx+1} completely outside image: ({left},{top},{right},{bottom}) vs {img_width}x{img_height}")
                        orientation_mismatch = True
                        break
                
                if orientation_mismatch:
                    print(f"🔍 DEBUG [{page_num}]: FALLBACK TRIGGERED - clearing all boxes")
                    
                    log.warning(f"⚠️ {basename} | Page {page_num}: Boxes incompatible with current image dimensions → falling back to full-page OCR")
                    box_coordinates_list = []
            
            # AGGRESSIVE PRE-VALIDATION: Check if ANY boxes are problematic BEFORE clipping
            # If so, immediately fallback to full-page OCR to avoid slow Leptonica errors
            # (Only check if we haven't already fallen back due to orientation mismatch)
            has_invalid_boxes = False
            if box_coordinates_list:  # Check again in case orientation mismatch cleared it
                for idx, box in enumerate(box_coordinates_list):
                    left, top, right, bottom = box
                    
                    # Check if box extends beyond image or is at/near boundaries (within 5px)
                    if (left < 0 or top < 0 or 
                        right > img_width or bottom > img_height or
                        left <= 5 or top <= 5 or 
                        right >= img_width - 5 or bottom >= img_height - 5):
                        print(f"🔍 DEBUG [{page_num}]: Box {idx} NEAR BOUNDARY! box=({left},{top},{right},{bottom}) img={img_width}x{img_height}")
                        
                        log.warning(f"⚠️ {basename} | Page {page_num}: Box {idx+1} near/outside boundaries: ({left},{top},{right},{bottom}) vs image {img_width}x{img_height}")
                        has_invalid_boxes = True
                        break
                    
                    # Check minimum size
                    width = right - left
                    height = bottom - top
                    if width < 10 or height < 10:
                        log.warning(f"⚠️ {basename} | Page {page_num}: Box {idx+1} too small: {width}x{height}")
                        has_invalid_boxes = True
                        break
            
            # If ANY box is problematic, skip segmentation entirely for this page
            if has_invalid_boxes:
                log.warning(f"⚠️ {basename} | Page {page_num}: Invalid segmentation boxes detected → falling back to full-page OCR")
                box_coordinates_list = []
            elif box_coordinates_list:  # Only validate if boxes still exist after orientation check
                # All boxes passed pre-validation, now clip and convert to integers
                validated_boxes = []
                
                for idx, box in enumerate(box_coordinates_list):
                    left, top, right, bottom = box
                    
                    # Clip with safety margin
                    left = max(0, min(left, img_width - 2))
                    top = max(0, min(top, img_height - 2))
                    right = max(left + 1, min(right, img_width - 1))
                    bottom = max(top + 1, min(bottom, img_height - 1))
                    
                    # Convert to integers
                    left = int(round(left))
                    top = int(round(top))
                    right = int(round(right))
                    bottom = int(round(bottom))
                    
                    validated_boxes.append((left, top, right, bottom))
                
                box_coordinates_list = validated_boxes
                # Removed verbose validation success log

        page_json = []
        if box_coordinates_list:
            print(f"🔍 DEBUG [{page_num}]: About to OCR with {len(box_coordinates_list)} boxes (first 2: {box_coordinates_list[:2]})")
            
            if image is None:
                image = Image.open(image_filename)
            
            # Create preprocessed folder for debugging
            preprocessed_folder = os.path.join(files_path, "_preprocessed")
            os.makedirs(preprocessed_folder, exist_ok=True)
            debug_save_path = os.path.join(preprocessed_folder, f"{get_file_basename(filename)}_preprocessed.png")
            
            # Apply comprehensive preprocessing pipeline
            image = preprocess_image_for_ocr(image, config, debug_save_path=debug_save_path)
            
            # Removed verbose "Starting segmented OCR" log
            
            # Must OCR each text box. raw_results received but not expected, as currently can only be done with full page

            try:
                if ocr_engine_name.lower() == "ocr_tesserocr":
                    print(f"🔍 DEBUG [{page_num}]: Calling TesserOCR - image.size={image.width}x{image.height}, boxes={len(box_coordinates_list)}")
                    
                    # TesserOCR can load an image once and OCR multiple segments within it
                    all_jsons, raw_results = ocr_engine.get_structure(
                        page=image,
                        lang=lang,
                        config=config,
                        doc_path=files_path,
                        outputs_path=outputs_path,
                        segment_box=box_coordinates_list,
                    )
                else:
                    all_jsons = []
                    # Get JSON result for each box and append to final list
                    for box in box_coordinates_list:
                        box_json, raw_results = ocr_engine.get_structure(
                            page=image,
                            lang=lang,
                            config=config,
                            doc_path=files_path,
                            outputs_path=outputs_path,
                            segment_box=box,
                        )
                        if box_json:
                            all_jsons.append(box_json)

                for json_result in all_jsons:
                    for paragraph in json_result:
                        page_json.append(paragraph)
                        
            except Exception as e:
                log.error(f"OCR engine crashed for {filename} with segmented boxes: {e}")
                traceback.print_exc()
                # Mark this page as failed so the document can be retried
                data = get_data(data_file)
                data["ocr"]["exceptions"] = f"Erro na página {filename}: {str(e)}"
                data["status"] = {
                    "stage": "error",
                    "message": f"Erro durante OCR da página {int(get_file_basename(filename).split('_')[-1]) + 1}",
                }
                update_json_file(data_file, data)
                return {"status": "error"}
                
        else:
            # OCR entire page, may have covered ignored areas
            print(f"🔍 DEBUG [{page_num}]: Entering full-page OCR path (no manual boxes)")

            if (
                n_doc_pages == 1
                and not ignore_groups
                and ocr_engine_name.lower() == "ocr_tesserocr"
            ):
                # TesserOCR needs stored file to generate direct results
                # Use original filename if no ignored areas were covered in memory, else memory data will be stored in /tmp
                image = image_filename
            elif image is None:
                image = Image.open(image_filename)
            
            # Check image dimensions
            if isinstance(image, str):
                temp_img = Image.open(image)
                img_w, img_h = temp_img.size
                temp_img.close()
            else:
                img_w, img_h = image.width, image.height
            
            print(f"🔍 DEBUG [{page_num}]: Full-page image size={img_w}x{img_h}, is_landscape={img_w > img_h}, segmentMode={config.get('segmentMode', 'unknown')}")

            # Don't use single_page optimization if compression is enabled
            # (single_page generates uncompressed PDFs directly from Tesseract)
            compress_enabled = config.get("compress", True) if isinstance(config, dict) else True
            use_single_page = n_doc_pages == 1 and not compress_enabled
            
            # Create preprocessed folder for debugging
            preprocessed_folder = os.path.join(files_path, "_preprocessed")
            os.makedirs(preprocessed_folder, exist_ok=True)
            debug_save_path = os.path.join(preprocessed_folder, f"{get_file_basename(filename)}_preprocessed.png")
            
            # Apply comprehensive preprocessing pipeline
            image = preprocess_image_for_ocr(image, config, debug_save_path=debug_save_path)
            
            try:
                json_results, raw_results = ocr_engine.get_structure(
                    page=image,
                    lang=lang,
                    config=config,
                    doc_path=files_path,
                    outputs_path=outputs_path,
                    output_types=output_types,
                    # If single-page document, take advantage of output types to immediately generate results with Tesseract
                    # BUT: Skip this optimization if compression is enabled, as it bypasses the compression step
                    single_page=use_single_page,
                )
                page_json = json_results
                
            except Exception as e:
                log.error(f"OCR engine crashed for full page {filename}: {e}")
                traceback.print_exc()
                # Mark this page as failed so the document can be retried
                data = get_data(data_file)
                data["ocr"]["exceptions"] = f"Erro na página {filename}: {str(e)}"
                data["status"] = {
                    "stage": "error",
                    "message": f"Erro durante OCR da página {int(get_file_basename(filename).split('_')[-1]) + 1}",
                }
                update_json_file(data_file, data)
                return {"status": "error"}

        # Store formatted OCR output for the page in JSON
        with open(
            f"{files_path}/_ocr_results/{get_file_basename(filename)}.json",
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(page_json, f, indent=2, ensure_ascii=False)

        # Performed OCR of page, update data with percentage-based progress
        files = os.listdir(f"{files_path}/_ocr_results")
        
        # Only log completion for every 3rd page or the last page to reduce spam
        pages_done = len(files)
        if pages_done % 3 == 1 or pages_done == n_doc_pages:
            log.info(f"✅ {basename}: {pages_done}/{n_doc_pages} pages completed")
        
        # Check if compression is enabled to determine progress ranges
        compress_enabled = config.get("compress", True) if isinstance(config, dict) else True
        
        # Calculate percentage: OCR takes 0-40% if compression, 0-80% if not
        ocr_max_percent = 40 if compress_enabled else 80
        pages_done = len(files)
        ocr_percentage = int((pages_done / n_doc_pages) * ocr_max_percent)

        data = get_data(data_file)
        data["ocr"]["progress"] = pages_done
        if data["status"]["stage"] != "error":
            data["status"] = {
                "stage": "ocr",
                "message": f"A processar OCR - Página {pages_done}/{n_doc_pages}",
                "percentage": ocr_percentage,
            }
        update_json_file(data_file, data)

        # Note: Export is now triggered by task_process_pages_sequential when all pages complete
        # This prevents duplicate export triggers that caused parallel compression crashes

        return {"status": "success"}

    except Exception as e:
        traceback.print_exc()
        log.error(f"❌ {basename} | Page {page_num}: OCR failed with error: {e}")
        
        data = get_data(data_file)
        data["ocr"]["exceptions"] = str(e)
        data["status"] = {
            "stage": "error",
            "message": f"Erro durante OCR da página {int(get_file_basename(filename).split('_')[-1]) + 1}",
        }
        update_json_file(data_file, data)
        log.error(f"Error in performing a page's OCR for file at {path}: {e}")

        return {"status": "error"}


@celery.task(name="export_results", priority=2)
def task_export_results(files_path: str = None, outputs_path: str = None, output_types: list[str] = None, path: str = None):
    """
    Export OCR results to various formats.

    :param files_path: path to document folder in _files (or API_TEMP_PATH for API files)
    :param outputs_path: path to document folder in _outputs (or _export subfolder for API files)
    :param output_types: list of output types to generate
    :param path: legacy parameter
    """
    # Check if this is an API file (stored in API_TEMP_PATH)
    from src.utils.file import API_TEMP_PATH
    is_api_file = API_TEMP_PATH in files_path if files_path else False
    
    # Support legacy usage
    if files_path is None and path is not None:
        files_path = path
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"
    elif outputs_path is None and files_path is not None:
        if is_api_file:
            # For API files, outputs go in _export subfolder
            outputs_path = f"{files_path}/_export"
        else:
            relative_path = files_path.replace(FILES_PATH, "").strip("/")
            outputs_path = f"{OUTPUTS_PATH}/{relative_path}"
    else:
        if not is_api_file:
            relative_path = files_path.replace(FILES_PATH, "").strip("/")

    data_file = f"{files_path}/_data.json"
    data = get_data(data_file)
    basename = get_file_basename(files_path)
    
    log.info(f"📤 {basename}: Starting export | output_types={output_types}")

    # Extract compression setting from config (default to True if not specified or None)
    config = data.get("ocr", {}).get("config", {})
    
    # Handle both dict config and "default" string
    if isinstance(config, dict):
        compress_value = config.get("compress")
    else:
        # Config is "default" string or something else
        compress_value = None
    
    compress_pdf = True if compress_value is None else bool(compress_value)

    # Calculate inputs_path to find original file
    doc_basename = get_file_basename(files_path)
    original_extension = data.get("extension", "pdf")
    
    if is_api_file:
        # For API files, original is in the same folder as metadata
        inputs_path = f"{files_path}/{doc_basename}.{original_extension}"
    else:
        # For regular files, original is in INPUTS_PATH
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        inputs_path = f"{INPUTS_PATH}/{relative_path.rsplit('/', 1)[0]}/{doc_basename}.{original_extension}".replace("//", "/")
        # Handle root level files
        if relative_path.count('/') == 0:
            inputs_path = f"{INPUTS_PATH}/{doc_basename}.{original_extension}"

    update_json_file(
        data_file,
        {
            "status": {
                "stage": "exporting",
                "message": "A gerar resultados",
            }
        },
    )

    # Ensure outputs directory exists
    os.makedirs(outputs_path, exist_ok=True)

    try:
        if ("ner" in output_types or "txt" in output_types) and not data["txt"][
            "complete"
        ]:
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": "A gerar texto",
                    }
                },
            )
            export_file(files_path, "txt", outputs_path=outputs_path)
            data["txt"] = {
                "complete": True,
                "size": size_to_units(
                    get_file_size(f"{outputs_path}/_txt.txt", path_complete=True)
                ),
                "creation": get_current_time(),
            }

        if "txt_delimited" in output_types and not data["txt_delimited"]["complete"]:
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": "A gerar texto delimitado",
                    }
                },
            )
            export_file(files_path, "txt", outputs_path=outputs_path, delimiter=True)
            data["txt_delimited"] = {
                "complete": True,
                "size": size_to_units(
                    get_file_size(
                        f"{outputs_path}/_txt_delimited.txt", path_complete=True
                    )
                ),
                "creation": get_current_time(),
            }

        if os.path.exists(f"{files_path}/_images") and os.listdir(f"{files_path}/_images"):
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": "A gerar imagens",
                    }
                },
            )
            export_file(files_path, "imgs", outputs_path=outputs_path)
            data["zip"] = {
                "complete": True,
                "size": size_to_units(
                    get_file_size(f"{outputs_path}/_images.zip", path_complete=True)
                ),
                "creation": get_current_time(),
            }

        if "pdf_indexed" in output_types and not data["pdf_indexed"]["complete"]:
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": "A gerar PDF com índice",
                    }
                },
            )
            keep_temp_images = "pdf" in output_types and not data["pdf"]["complete"]
            export_file(
                files_path,
                "pdf",
                outputs_path=outputs_path,
                inputs_path=inputs_path,
                keep_temp=keep_temp_images,
                get_csv=("csv" in output_types),
                compress=compress_pdf,
            )
            creation_time = get_current_time()
            exported_pdf = pdfium.PdfDocument(
                f"{outputs_path}/_pdf_indexed.pdf", autoclose=True
            )

            data["pdf_indexed"] = {
                "complete": True,
                "size": size_to_units(
                    get_file_size(
                        f"{outputs_path}/_pdf_indexed.pdf", path_complete=True
                    )
                ),
                "creation": creation_time,
                "pages": len(exported_pdf),
            }
            if "csv" in output_types:
                # CSV exported as part of PDF export
                data["csv"] = {
                    "complete": True,
                    "size": size_to_units(
                        get_file_size(f"{outputs_path}/_index.csv", path_complete=True)
                    ),
                    "creation": creation_time,
                }

        if "pdf" in output_types and not data["pdf"]["complete"]:
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": "A gerar PDF",
                    }
                },
            )
            export_file(
                files_path,
                "pdf",
                outputs_path=outputs_path,
                inputs_path=inputs_path,
                simple=True,
                already_temp=("pdf_indexed" in output_types),
                get_csv=("csv" in output_types),
                compress=compress_pdf,
            )
            creation_time = get_current_time()
            data["pdf"] = {
                "complete": True,
                "size": size_to_units(
                    get_file_size(f"{outputs_path}/_pdf.pdf", path_complete=True)
                ),
                "creation": creation_time,
                "pages": get_page_count(files_path, "pdf"),
            }
            if "csv" in output_types:
                # CSV exported as part of PDF export
                data["csv"] = {
                    "complete": True,
                    "size": size_to_units(
                        get_file_size(f"{outputs_path}/_index.csv", path_complete=True)
                    ),
                    "creation": creation_time,
                }

        if "csv" in output_types and not data["csv"]["complete"]:
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": "A gerar CSV",
                    }
                },
            )
            export_csv(files_path, outputs_path=outputs_path)
            data["csv"] = {
                "complete": True,
                "size": size_to_units(
                    get_file_size(f"{outputs_path}/_index.csv", path_complete=True)
                ),
                "creation": get_current_time(),
            }

        if "ner" in output_types:
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": "A obter entidades",
                    }
                },
            )
            success = get_ner_file(files_path, outputs_path)
            if success:
                data["ner"] = {
                    "complete": True,
                    "size": size_to_units(
                        get_file_size(
                            f"{outputs_path}/_entities.json", path_complete=True
                        )
                    ),
                    "creation": get_current_time(),
                }
            else:
                data["ner"] = {"complete": False, "error": True}

        if "hocr" in output_types and not data["hocr"]["complete"]:
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": "A gerar hOCR",
                    }
                },
            )
            export_file(files_path, "hocr", outputs_path=outputs_path)
            if os.path.exists(f"{outputs_path}/_hocr.hocr"):
                data["hocr"] = {
                    "complete": True,
                    "size": size_to_units(
                        get_file_size(f"{outputs_path}/_hocr.hocr", path_complete=True)
                    ),
                    "creation": get_current_time(),
                }

        if "xml" in output_types and not data["xml"]["complete"]:
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": "A gerar ALTO XML",
                    }
                },
            )
            # ALTO export needs implementation
            # export_file(files_path, "xml", outputs_path=outputs_path)

        if files_path.startswith(API_TEMP_PATH):
            original_extension = data["extension"]
            from_api = True
        else:
            original_extension = None
            from_api = False

        data["ocr"]["progress"] = "completed"
        data["status"] = {
            "stage": "post-ocr",
        }
        data["total_size"] = size_to_units(
            get_document_files_size(
                files_path, outputs_path=outputs_path, extension=original_extension, from_api=from_api
            )
        )
        data["words"] = get_word_count(files_path)

        update_json_file(data_file, data)
        
        log.info(f"🎉 {basename}: Export completed successfully | total_size={data['total_size']} | words={data['words']}")
        
        return {"status": "success"}

    except Exception as e:
        traceback.print_exc()
        basename = get_file_basename(files_path)
        log.error(f"❌ {basename}: Export failed with error: {e}")
        
        data = get_data(data_file)
        data["ocr"]["exceptions"] = str(e)
        data["status"] = {
            "stage": "error",
            "message": "Erro a gerar resultados",
        }
        update_json_file(data_file, data)
        log.error(f"Error in exporting results for file at {files_path}: {e}")

        # return {"status": "error", "metricas": page_metrics}
        return {"status": "error"}


@celery.task(name="async_delete_file", priority=0)
def task_delete_file(path: str):
    log.debug(f"Deleting {path}")
    os.remove(path)


@celery.task(name="reset_stuck_ocr", priority=0)
def task_reset_stuck_ocr():
    """
    Reset documents that have been stuck in OCR stage for too long.
    This handles cases where worker crashes (SIGSEGV) leave documents in processing state.
    """
    import time
    from datetime import datetime, timedelta
    
    reset_count = 0
    stuck_threshold_minutes = 5  # Consider stuck if OCR running for more than 5 minutes without updates
    
    try:
        # Scan all document folders in _files
        if not os.path.exists(FILES_PATH):
            return f"Files path does not exist"
        
        for root, dirs, files in os.walk(FILES_PATH):
            if "_data.json" in files:
                data_file = os.path.join(root, "_data.json")
                try:
                    with open(data_file, 'r') as f:
                        data = json.load(f)
                    
                    # Check if document is stuck in OCR stage
                    if data.get("status", {}).get("stage") == "ocr":
                        # Check file modification time to see if it's been stuck
                        file_mtime = os.path.getmtime(data_file)
                        minutes_since_update = (time.time() - file_mtime) / 60
                        
                        if minutes_since_update > stuck_threshold_minutes:
                            log.warning(f"Resetting stuck OCR document: {root} (stuck for {minutes_since_update:.1f} minutes)")
                            
                            # Reset status to error so user can retry
                            data["status"] = {
                                "stage": "error",
                                "message": "OCR interrompido - pode tentar novamente",
                            }
                            
                            # Reset OCR progress
                            if "ocr" in data:
                                data["ocr"]["progress"] = 0
                            
                            with open(data_file, 'w') as f:
                                json.dump(data, f, indent=2, ensure_ascii=False)
                            
                            reset_count += 1
                            
                except Exception as e:
                    log.error(f"Error checking {data_file}: {e}")
                    continue
        
        if reset_count > 0:
            log.info(f"Reset {reset_count} stuck OCR document(s)")
        
        return f"{reset_count} stuck document(s) reset"
        
    except Exception as e:
        log.error(f"Error in reset_stuck_ocr task: {e}")
        return f"Error: {str(e)}"


#####################################
# SCHEDULED TASKS
#####################################
@celery.on_after_configure.connect
def setup_periodic_tasks(sender: Celery, **kwargs):
    # Clean up old private spaces daily at midnight
    entry = RedBeatSchedulerEntry(
        "cleanup_private_spaces",
        task_delete_old_private_spaces.s().task,
        crontab(minute="0", hour="0"),
        kwargs={
            "max_private_space_age": int(os.environ.get("MAX_PRIVATE_SPACE_AGE", "1"))
        },
        app=celery,
    )
    entry.save()
    log.info(f"Created periodic task {entry}")
    
    # Reset stuck OCR documents every 5 minutes
    stuck_ocr_entry = RedBeatSchedulerEntry(
        "reset_stuck_ocr",
        task_reset_stuck_ocr.s().task,
        crontab(minute="*/5"),  # Run every 5 minutes
        app=celery,
    )
    stuck_ocr_entry.save()
    log.info(f"Created periodic task {stuck_ocr_entry}")


@celery.task(name="cleanup_private_spaces", priority=0)
def task_delete_old_private_spaces(max_private_space_age: int):
    log.info(f"Deleting private spaces older than {max_private_space_age} day(s)")

    private_spaces = [f.path for f in os.scandir(f"./{PRIVATE_PATH}/") if f.is_dir()]
    n_deleted = 0
    for folder in private_spaces:
        data = get_data(f"{folder}/_data.json")
        created_time = data["creation"]
        as_datetime = datetime.strptime(created_time, "%d/%m/%Y %H:%M:%S").astimezone(
            TIMEZONE
        )
        now = datetime.now().astimezone(TIMEZONE)
        if (now - as_datetime).days > max_private_space_age:
            shutil.rmtree(folder)
            n_deleted += 1

    update_json_file(
        f"./{PRIVATE_PATH}/_data.json", {"last_cleanup": get_current_time()}
    )
    return f"{n_deleted} private space(s) deleted"
