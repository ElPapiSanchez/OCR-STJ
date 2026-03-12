import base64
import csv
import hashlib
import io
import json
import logging
import os
import re
import shutil
import zipfile
import zlib
from contextlib import suppress
from datetime import datetime

import pypdfium2 as pdfium
from PIL import Image
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfmetrics import getFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from src.utils.file import FILES_PATH
from src.utils.file import get_current_time
from src.utils.file import get_data
from src.utils.file import get_file_basename
from src.utils.file import get_file_size
from src.utils.file import get_page_count
from src.utils.file import INPUTS_PATH
from src.utils.file import json_to_text
from src.utils.file import OUTPUTS_PATH
from src.utils.file import PRIVATE_PATH
from src.utils.file import size_to_units
from src.utils.file import update_json_file
from src.utils.image_compression import mrc_pdf_from_path, mrc_pdf_from_bytes
import fitz

log = logging.getLogger(__name__)

# Reduced from 150 to 100 to prevent OOM (Out of Memory) during compression
# Lower DPI = smaller images in memory = less RAM usage
OUT_DEFAULT_DPI = 100


def _export_pdf_compress_first(
    files_path,
    outputs_path,
    inputs_path,
    data,
    data_file,
    target,
    doc_basename,
    original_extension,
    compression_target_dpi,
    compression_bg_quality,
    compression_fg_quality,
    compression_flatten,
    dpi_original,
    generate_index,
    get_csv,
    simple,
    filename_csv,
):
    """
    COMPRESS-FIRST WORKFLOW: Compress original file, then add OCR text layer directly.
    
    This approach:
    1. Memory efficient: Compresses original TIF/PDF first (reduces from ~100MB to ~1-2MB)
    2. Maintains compression: Adds text directly to compressed PDF (no rebuild/re-expansion)
    3. Avoids OOM: Works with small compressed file, not large intermediate PDFs
    
    Note: Text coordinates use PyMuPDF without horizontal scaling, so text may not be
    perfectly selectable character-by-character, but will be searchable.
    """
    import time
    
    log.info("Starting compress-first workflow with ReportLab coordinate system")
    
    # Step 1: Find original file
    if inputs_path and os.path.isfile(inputs_path):
        original_file_path = inputs_path
    else:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        parts = relative_path.split("/")
        if len(parts) > 1:
            folder_path = "/".join(parts[:-1])
            original_file_path = f"{INPUTS_PATH}/{folder_path}/{doc_basename}.{original_extension}"
        else:
            original_file_path = f"{INPUTS_PATH}/{doc_basename}.{original_extension}"
    
    if not os.path.exists(original_file_path):
        log.error(f"Original file not found: {original_file_path}")
        raise FileNotFoundError(f"Original file not found: {original_file_path}")
    
    log.info(f"Found original file: {original_file_path}")
    
    # Step 2: Compress original file
    print("\n" + "="*70)
    print("📦 COMPRESSING ORIGINAL FILE")
    print("="*70)
    
    update_json_file(
        data_file,
        {
            "status": {
                "stage": "compressing",
                "message": "A comprimir ficheiro original...",
                "progress": 0,
            }
        },
    )
    
    original_size = os.path.getsize(original_file_path)
    print(f"📄 Input: {original_file_path}")
    print(f"📊 Size: {size_to_units(original_size)}")
    
    def compression_progress_callback(current_page, total_pages, stage):
        progress_percent = (current_page / total_pages * 100) if total_pages > 0 else 0
        if stage == "processing":
            message = f"A comprimir - Página {current_page}/{total_pages}"
        else:
            message = "A comprimir..."
        update_json_file(
            data_file,
            {
                "status": {
                    "stage": "compressing",
                    "message": message,
                    "progress": progress_percent,
                }
            },
        )
    
    start_time = time.time()
    
    # Uncompressed copy destination
    if simple:
        uncompressed_filename = f"{outputs_path}/{doc_basename}_uncompressed.pdf"
    else:
        uncompressed_filename = f"{outputs_path}/{doc_basename}_indexed_uncompressed.pdf"
    
    # Temp path for compressed images-only PDF
    temp_compressed_pdf = f"{files_path}/_temp_compressed_images.pdf"
    
    try:
        with open(original_file_path, "rb") as f:
            original_bytes = f.read()
        
        compressed_bytes = mrc_pdf_from_bytes(
            file_bytes=original_bytes,
            filetype=original_extension,
            target_dpi=compression_target_dpi,
            render_dpi=dpi_original,
            output_pdf_path=temp_compressed_pdf,
            output_uncompressed_pdf_path=uncompressed_filename,
            bg_format="JPEG",
            fg_format="JPEG",
            bg_quality=compression_bg_quality,
            fg_quality=compression_fg_quality,
            mask_method="cv",
            flatten_to_jpeg=compression_flatten,
            progress_callback=compression_progress_callback,
        )
        
        compression_time = time.time() - start_time
        compressed_size = os.path.getsize(temp_compressed_pdf)
        compression_ratio = (1 - compressed_size / original_size) * 100 if original_size > 0 else 0
        
        print(f"\n✅ Compressed: {size_to_units(compressed_size)} ({compression_ratio:.1f}% reduction)")
        log.info(f"Compression complete in {compression_time:.2f}s")
        
    except Exception as e:
        log.error(f"Compression failed: {e}")
        print(f"\n❌ COMPRESSION FAILED: {str(e)}")
        if os.path.exists(temp_compressed_pdf):
            os.remove(temp_compressed_pdf)
        raise
    
    # Step 3: Add OCR text layer directly to compressed PDF using PyMuPDF
    print(f"📝 Adding OCR text layer to compressed PDF...")
    
    update_json_file(
        data_file,
        {
            "status": {
                "stage": "exporting",
                "message": "A adicionar texto OCR...",
            }
        },
    )
    
    try:
        # Open compressed PDF with PyMuPDF
        compressed_pdf = fitz.open(temp_compressed_pdf)
        
        # Get OCR results
        ocr_results_path = f"{files_path}/_ocr_results"
        ocr_files = sorted([
            f for f in os.listdir(ocr_results_path)
            if f.endswith(".json") and not f.startswith("_")
        ], key=lambda x: int(re.search(r"_(\d+)", x).group(1)) if re.search(r"_(\d+)", x) else 0)
        
        log.info(f"Found {len(ocr_files)} OCR result files")
        
        # Calculate scale factor for coordinates
        scale_factor = compression_target_dpi / dpi_original
        log.info(f"Coordinate scale factor: {scale_factor}")
        
        words = {}
        
        # Process each page
        for page_idx in range(min(len(compressed_pdf), len(ocr_files))):
            page = compressed_pdf[page_idx]
            page_rect = page.rect
            page_height = page_rect.height
            
            ocr_file = ocr_files[page_idx]
            hocr_path = os.path.join(ocr_results_path, ocr_file)
            
            # Load OCR data
            with open(hocr_path, encoding="utf-8") as f:
                hocrfile = json.load(f)
            
            # Add text to page
            for section in hocrfile:
                for line in section:
                    for word in line:
                        rawtext = word["text"]
                        box = word["box"]  # [x0, y0, x1, y1] in original DPI
                        
                        if not rawtext or not rawtext.strip():
                            continue
                        
                        # Calculate scaled coordinates for compressed PDF
                        x0 = box[0] * scale_factor
                        y0 = box[1] * scale_factor
                        x1 = box[2] * scale_factor
                        y1 = box[3] * scale_factor
                        
                        # Convert to PDF coordinate system (bottom-left origin)
                        pdf_y0 = page_height - y1
                        pdf_y1 = page_height - y0
                        
                        # Calculate box dimensions
                        box_width = x1 - x0
                        box_height = y1 - y0
                        
                        # Estimate appropriate font size based on box height
                        # Typically, font size is roughly 0.7-0.8 of the box height
                        estimated_fontsize = box_height * 0.75
                        
                        # Create bounding box rectangle
                        rect = fitz.Rect(x0, pdf_y0, x1, pdf_y1)
                        
                        # Insert text in the bounding box
                        # PyMuPDF will try to fit the text within the rectangle
                        try:
                            page.insert_textbox(
                                rect,
                                rawtext,
                                fontsize=estimated_fontsize,
                                fontname="helv",  # Helvetica (built-in PDF font)
                                render_mode=3,  # invisible text
                                align=0,  # left-aligned
                            )
                        except:
                            # Fallback to simple insert_text if textbox fails
                            page.insert_text(
                                point=(x0, page_height - (box[3] * scale_factor)),
                                text=rawtext,
                                fontsize=8,
                                fontname="helv",
                                render_mode=3,
                            )
                        
                        # Collect words for index if needed
                        if generate_index:
                            w = rawtext.strip()
                            remove_chars = [",", ".", ":", ";", "!", "?", '"', "'", "(", ")", "[", "]"]
                            for c in remove_chars:
                                w = w.replace(c, "")
                            w = w.lower()
                            
                            if w:
                                if w not in words:
                                    words[w] = {"count": 1, "pages": str(page_idx + 1)}
                                else:
                                    words[w]["count"] += 1
                                    if str(page_idx + 1) not in words[w]["pages"].split(", "):
                                        words[w]["pages"] += f", {page_idx + 1}"
            
            if page_idx % 10 == 0 or page_idx == len(ocr_files) - 1:
                update_json_file(
                    data_file,
                    {
                        "status": {
                            "stage": "exporting",
                            "message": f"A adicionar texto - Página {page_idx + 1}/{len(ocr_files)}",
                        }
                    },
                )
        
        # Save the modified compressed PDF to the target location
        compressed_pdf.save(target, garbage=4, deflate=True, clean=True)
        compressed_pdf.close()
        
        log.info(f"PDF with OCR text layer saved to {target}")
        
        # Generate CSV index if needed
        if not simple and generate_index:
            if get_csv:
                words_list = [
                    item for item in sorted(
                        words.items(), key=lambda item: item[0].lower() + item[0]
                    )
                ]
                export_csv_from_words(filename_csv, words_list)
        
        # Note: Index pages not added to compressed PDF to maintain compression efficiency
        # The CSV export above provides the index data
        if not simple and generate_index:
            log.warning("Index pages skipped for compressed PDF (use CSV export for index data)")
        
        # Clean up temp compressed PDF
        if os.path.exists(temp_compressed_pdf):
            os.remove(temp_compressed_pdf)
        
        final_size = os.path.getsize(target)
        print(f"\n✅ PDF EXPORT COMPLETE!")
        print(f"📄 Output: {target}")
        print(f"📊 Size: {size_to_units(final_size)}")
        print("="*70 + "\n")
        
        # Update metadata
        pdf_type = "pdf" if simple else "pdf_indexed"
        data_update = {
            pdf_type: {
                "compressed_size": size_to_units(final_size),
                "uncompressed_size": size_to_units(original_size),
                "compression_ratio": f"{compression_ratio:.1f}%"
            }
        }
        update_json_file(data_file, data_update)
        
        log.info(f"PDF export complete: {target}")
        return target
        
    except Exception as e:
        log.error(f"Failed to build PDF: {e}", exc_info=True)
        print(f"\n❌ FAILED: {str(e)}")
        # Clean up
        if os.path.exists(temp_compressed_pdf):
            os.remove(temp_compressed_pdf)
        for temp_img in temp_images:
            if os.path.exists(temp_img):
                os.remove(temp_img)
        raise


####################################################
# GENERAL FUNCTIONS
####################################################
def export_file(
    files_path,
    filetype,
    outputs_path=None,
    inputs_path=None,
    delimiter=False,
    force_recreate=False,
    simple=False,
    keep_temp=False,
    already_temp=False,
    get_csv=False,
    compress=True,
):
    """
    Direct to the correct function based on the filetype.

    :param files_path: path to document folder in _files (for metadata and OCR results)
    :param filetype: the filetype to export to
    :param outputs_path: path to document folder in _outputs (for writing exports)
    :param inputs_path: path to original file in _inputs (for reading original if needed)
    :param delimiter: for a txt file, whether a delimiter should be added between pages
    :param force_recreate: whether the file should be recreated, if it already exists
    :param simple: for a PDF, whether it should be simple, rather than with index
    :param get_csv: for a PDF, whether a CSV should be generated additionally
    :param compress: for a PDF, whether to apply MRC compression
    """
    # Calculate outputs_path if not provided (for backward compatibility)
    if outputs_path is None:
        # Extract relative path and construct outputs path
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"

    # Ensure outputs directory exists
    if not os.path.exists(outputs_path):
        os.makedirs(outputs_path, exist_ok=True)

    if simple or get_csv or keep_temp or already_temp:
        # currently, keeping temp is only used for PDF
        log.info(f"export_file calling export_pdf with compress={compress} (type: {type(compress)})")
        return export_pdf(
            files_path,
            outputs_path=outputs_path,
            inputs_path=inputs_path,
            force_recreate=force_recreate,
            simple=simple,
            keep_temp=keep_temp,
            already_temp=already_temp,
            get_csv=get_csv,
            compress=compress,
        )

    func = globals()[f"export_{filetype}"]

    # Prepare common arguments
    kwargs = {
        'outputs_path': outputs_path,
        'force_recreate': force_recreate
    }
    
    # Add inputs_path if provided (needed for PDF export)
    if inputs_path is not None:
        kwargs['inputs_path'] = inputs_path
    
    # Add delimiter if specified (for txt exports)
    if delimiter:
        kwargs['delimiter'] = delimiter
    
    # Add compress parameter for PDF exports
    if filetype == 'pdf':
        kwargs['compress'] = compress
        log.info(f"export_file adding compress to kwargs: {compress} (type: {type(compress)})")

    return func(files_path, **kwargs)


def export_from_existing(files_path: str, outputs_path: str, raw_results: dict | list, output_types: list):
    """
    Export result files from pre-existing output files.

    If raw_results is a dict, any contents whose keys are not in output_types are ignored.

    If raw_results is a list of filenames of pre-generated results, the files should be in the outputs folder, and
    any files whose extensions are not in output_types are ignored.

    :param files_path: Path to document folder in _files (for metadata).
    :param outputs_path: Path to document folder in _outputs (for writing exports).
    :param raw_results: Dictionary of extension keys to respective contents in bytes, or list of filenames of the pregenerated results.
    :param output_types: List of output types to consider.
    """
    data_file = f"{files_path}/_data.json"

    # Ensure outputs directory exists
    if not os.path.exists(outputs_path):
        os.makedirs(outputs_path, exist_ok=True)

    data_update = {}
    if isinstance(raw_results, dict):  # results in memory, in dict
        for extension in raw_results.keys():
            if extension in output_types:
                file_path = f"{outputs_path}/_{extension}.{extension}"
                with open(file_path, "wb") as f:
                    f.write(raw_results[extension])
                creation_date = get_current_time()
                data_update[extension] = {
                    "complete": True,
                    "size": size_to_units(get_file_size(file_path, path_complete=True)),
                    "creation": creation_date,
                }
                if extension == "pdf":
                    data_update[extension]["pages"] = get_page_count(files_path, "pdf")

    elif isinstance(raw_results, list):  # results stored in listed files
        for result in raw_results:
            _, ext = os.path.splitext(result)
            ext = ext.strip(".")
            if ext in output_types:
                file_path = f"{outputs_path}/_{ext}.{ext}"
                os.rename(result, file_path)
                creation_date = get_current_time()
                data_update[ext] = {
                    "complete": True,
                    "size": size_to_units(get_file_size(file_path, path_complete=True)),
                    "creation": creation_date,
                }
                if ext == "pdf":
                    data_update[ext]["pages"] = get_page_count(files_path, "pdf")

    update_json_file(data_file, data_update)


####################################################
# EXPORT TXT FUNCTIONS
####################################################
def export_imgs(files_path, outputs_path=None, force_recreate=False):
    """
    Export the images as a .zip file.

    :param files_path: path to document folder in _files (contains _images subfolder)
    :param outputs_path: path to document folder in _outputs (for writing zip)
    :param force_recreate: force the recreation of the file
    :return: the path to the exported file
    """
    # Calculate outputs_path if not provided
    if outputs_path is None:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"

    # Ensure outputs directory exists
    if not os.path.exists(outputs_path):
        os.makedirs(outputs_path, exist_ok=True)

    filename = f"{outputs_path}/_images.zip"
    if os.path.exists(filename) and not force_recreate:
        return filename

    shutil.make_archive(f"{outputs_path}/_images", "zip", files_path, base_dir="_images")
    return filename


def export_txt(files_path, outputs_path=None, delimiter=False, force_recreate=False):
    """
    Export the file as a .txt file.

    :param files_path: path to document folder in _files (contains _ocr_results)
    :param outputs_path: path to document folder in _outputs (for writing txt)
    :param delimiter: whether a delimiter should be added between pages
    :param force_recreate: force the recreation of the file
    :return: the path to the exported file
    """
    # Calculate outputs_path if not provided
    if outputs_path is None:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"

    # Ensure outputs directory exists
    if not os.path.exists(outputs_path):
        os.makedirs(outputs_path, exist_ok=True)

    filename = f"{outputs_path}/_txt.txt"
    if delimiter:
        filename = f"{outputs_path}/_txt_delimited.txt"
    if os.path.exists(filename) and not force_recreate:
        return filename

    ocr_folder = f"{files_path}/_ocr_results"

    files = [
        os.path.join(ocr_folder, f)
        for f in os.listdir(ocr_folder)
        if os.path.isfile(os.path.join(ocr_folder, f)) and ".json" in f
    ]

    if len(files) > 1:
        files = sorted(files, key=lambda x: int(re.findall(r"\d+", x)[-1]))

    with open(filename, "w", encoding="utf-8") as f:
        for id, file in enumerate(files):
            with open(file, encoding="utf-8") as _f:
                hOCR = json.load(_f)

            if delimiter:
                f.write(f"----- PAGE {(id + 1):04d} -----\n\n")

            f.write(json_to_text(hOCR) + "\n\n")

    return filename


####################################################
# EXPORT CSV FUNCTIONS
####################################################
def export_csv(files_path, outputs_path=None, force_recreate=False):
    """
    Export index words as a CSV file.

    :param files_path: path to document folder in _files (contains _ocr_results)
    :param outputs_path: path to document folder in _outputs (for writing csv)
    :param force_recreate: force the recreation of the file
    :return: the path to the exported file
    """
    # Calculate outputs_path if not provided
    if outputs_path is None:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"

    # Ensure outputs directory exists
    if not os.path.exists(outputs_path):
        os.makedirs(outputs_path, exist_ok=True)

    filename_csv = f"{outputs_path}/_index.csv"
    if os.path.exists(filename_csv) and not force_recreate:
        return filename_csv

    filenames_asterisk = [
        x for x in os.listdir(f"{files_path}/_ocr_results/") if x.endswith(".json")
    ]

    words = {}
    for i, page in enumerate(filenames_asterisk):
        page_basename = get_file_basename(page)
        hocr_path = f"{files_path}/_ocr_results/{page_basename}.json"
        index_words = find_index_words(hocr_path)
        for word in index_words:
            if word not in words:
                words[word] = {"count": index_words[word], "pages": str(i + 1)}
            else:
                words[word]["count"] += index_words[word]
                words[word]["pages"] += f", {i + 1}"

    # Sort the `words` dict by key
    words = [
        item
        for item in sorted(words.items(), key=lambda item: item[0].lower() + item[0])
    ]
    return export_csv_from_words(filename_csv, words)


def export_csv_from_words(filename_csv, index_data):
    with open(filename_csv, mode="w", encoding="utf-8") as csvfile:
        csv_out = csv.writer(csvfile)
        csv_out.writerow(["Palavra", "Ocorrências", "Páginas"])
        csv_out.writerow([" "])
        for word in index_data:
            csv_out.writerow([word[0], word[1]["count"], f'"{word[1]["pages"]}"'])

    return filename_csv


####################################################
# EXPORT PDF FUNCTIONS
####################################################
def export_pdf(
    files_path,
    outputs_path=None,
    inputs_path=None,
    force_recreate=False,
    simple=False,
    keep_temp=False,
    already_temp=False,
    get_csv=False,
    compress=True,
):
    """
    Export the file as a .pdf file.

    :param files_path: path to document folder in _files (for metadata and OCR results)
    :param outputs_path: path to document folder in _outputs (for writing PDF)
    :param inputs_path: path to original file in _inputs (for reading original PDF if needed)
    :param force_recreate: force recreation of the file
    :param simple: generate simple PDF without index
    :param keep_temp: keep temporary images after processing
    :param already_temp: temporary images already exist
    :param get_csv: also generate CSV index
    :param compress: apply MRC compression to reduce PDF file size
    """
    log.info(f"export_pdf called with compress={compress} (type: {type(compress)}), simple={simple}, files_path={files_path}")
    
    # Calculate outputs_path if not provided
    if outputs_path is None:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"

    # Ensure outputs directory exists
    if not os.path.exists(outputs_path):
        os.makedirs(outputs_path, exist_ok=True)

    data_file = f"{files_path}/_data.json"
    filename = f"{outputs_path}/_pdf_indexed.pdf"
    simple_filename = f"{outputs_path}/_pdf.pdf"
    filename_csv = f"{outputs_path}/_index.csv"

    dpi_original = 300
    dpi_compressed = OUT_DEFAULT_DPI

    target = filename if not simple else simple_filename

    if os.path.exists(target) and not force_recreate:
        return target

    data = get_data(data_file)
    original_extension = data["extension"].lower()
    
    # Define compression defaults
    COMPRESSION_DEFAULTS = {
        "compressionTargetDpi": 100,
        "compressionBgQuality": 40,
        "compressionFgQuality": 80,
        "compressionFlattenToJpeg": True
    }
    
    # Get compression settings from config
    config = data.get("config", {})
    if not config and "ocr" in data and "config" in data["ocr"]:
        config = data["ocr"]["config"]
    
    compression_target_dpi = config.get("compressionTargetDpi", COMPRESSION_DEFAULTS["compressionTargetDpi"])
    compression_bg_quality = config.get("compressionBgQuality", COMPRESSION_DEFAULTS["compressionBgQuality"])
    compression_fg_quality = config.get("compressionFgQuality", COMPRESSION_DEFAULTS["compressionFgQuality"])
    compression_flatten = config.get("compressionFlattenToJpeg", COMPRESSION_DEFAULTS["compressionFlattenToJpeg"])
    
    log.info(f"Compression settings: target_dpi={compression_target_dpi}, bg_quality={compression_bg_quality}, fg_quality={compression_fg_quality}, flatten={compression_flatten}")

    doc_basename = get_file_basename(files_path)
    generate_index = get_csv or not simple

    # WORKFLOW DECISION: For PDF/TIF with compression, use compress-first workflow
    # This avoids memory issues by compressing the original file before building the PDF
    if compress and original_extension in ("pdf", "tif", "tiff"):
        log.info(f"Using compress-first workflow for {original_extension} file")
        return _export_pdf_compress_first(
            files_path=files_path,
            outputs_path=outputs_path,
            inputs_path=inputs_path,
            data=data,
            data_file=data_file,
            target=target,
            doc_basename=doc_basename,
            original_extension=original_extension,
            compression_target_dpi=compression_target_dpi,
            compression_bg_quality=compression_bg_quality,
            compression_fg_quality=compression_fg_quality,
            compression_flatten=compression_flatten,
            dpi_original=dpi_original,
            generate_index=generate_index,
            get_csv=get_csv,
            simple=simple,
            filename_csv=filename_csv,
        )
    
    # LEGACY WORKFLOW: For other file types or when compression is disabled
    # Build PDF with images + OCR, then optionally compress
    log.info(f"Using legacy workflow: build PDF with OCR, then compress")
    
    page_extension = original_extension
    # Track whether images are at original DPI or have been downscaled
    images_at_original_dpi = True  # Default for TIF, ZIP, etc.
    
    if original_extension == "pdf":
        page_extension = "png"
        images_at_original_dpi = False  # PDF pages are rendered at dpi_compressed
        if not already_temp:
            if inputs_path and os.path.isfile(inputs_path):
                original_pdf_path = inputs_path
            else:
                original_pdf_path = f"{files_path}/{doc_basename}.pdf"

            pdf = pdfium.PdfDocument(original_pdf_path)
            for i in range(len(pdf)):
                page = pdf[i]
                bitmap = page.render(dpi_compressed / 72)
                pil_image = bitmap.to_pil()
                pil_image.save(f"{files_path}/{doc_basename}_{i}$.{page_extension}")

            pdf.close()

    elif original_extension == "zip":
        page_extension = "png"
        images_at_original_dpi = True  # ZIP images are at their original resolution
        if not already_temp:
            pages_list = [
                p
                for p in os.listdir(f"{files_path}/_pages")
                if os.path.isfile(os.path.join(f"{files_path}/_pages", p))
            ]
            pages_list.sort(key=lambda s: (s.casefold(), s))
            for i, page in enumerate(pages_list):
                os.link(
                    f"{files_path}/_pages/{page}",
                    f"{files_path}/{doc_basename}_{i}$.{page_extension}",
                )

    else:
        # TIF and other formats - images are at original resolution
        images_at_original_dpi = True
        if not already_temp:
            pages_path = f"{files_path}/_pages"
            pages_list = [p.path for p in os.scandir(pages_path) if p.is_file()]
            pages_list.sort(key=lambda s: (s.casefold(), s))
            for i, page in enumerate(pages_list):
                os.link(
                    page,
                    f"{files_path}/{doc_basename}_{i}$.{page_extension}",
                )

    words = {}

    pdf = Canvas(target, pageCompression=1, pagesize=A4)
    pdf.setCreator("hocr-tools")
    pdf.setTitle(target)

    filenames_asterisk = [
        x for x in os.listdir(files_path) if x.endswith(f"$.{page_extension}")
    ]
    images = sorted(
        filenames_asterisk, key=lambda x: int(re.search(r"_(\d+)\$", x).group(1))
    )
    for i, image in enumerate(images):
        image_path = os.path.join(files_path, image)
        image_basename = get_file_basename(image)
        image_basename = image_basename[:-1]

        hocr_path = f"{files_path}/_ocr_results/{image_basename}.json"

        im = Image.open(image_path)
        w, h = im.size
        pdf.setPageSize((w, h))
        pdf.drawImage(image_path, 0, 0, width=w, height=h)

        # For TIF/ZIP: images are at original DPI, so scale_factor = 1.0
        # For PDF: images rendered at dpi_compressed, so scale_factor = dpi_compressed/dpi_original
        if images_at_original_dpi:
            text_scale_factor = 1.0
        else:
            text_scale_factor = None  # Let add_text_layer calculate it
        
        new_words = add_text_layer(
            pdf,
            hocr_path,
            h,
            dpi_original,
            dpi_compressed,
            get_index_words=generate_index,
            scale_factor=text_scale_factor,
        )

        if generate_index:
            for word in new_words:
                if word not in words:
                    words[word] = {"count": new_words[word], "pages": str(i + 1)}
                else:
                    words[word]["count"] += new_words[word]
                    words[word]["pages"] += f", {i + 1}"

        pdf.showPage()

        total_pages = len(images)
        current_page = i + 1
        if current_page in (0, total_pages) or current_page % 10 == 0:
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "exporting",
                        "message": f"A gerar PDF {'com índice ' if not simple else ''}{current_page}/{total_pages}",
                    }
                },
            )

        if not keep_temp:
            with suppress(OSError):
                os.remove(image_path)

    if generate_index:
        words = [
            item
            for item in sorted(
                words.items(), key=lambda item: item[0].lower() + item[0]
            )
        ]

    if get_csv:
        update_json_file(
            data_file,
            {
                "status": {
                    "stage": "exporting",
                    "message": "A gerar CSV",
                }
            },
        )
        export_csv_from_words(filename_csv, words)

    if not simple:
        update_json_file(
            data_file,
            {
                "status": {
                    "stage": "exporting",
                    "message": "A gerar índice",
                }
            },
        )
        rows = 100
        cols = 2
        title_size = 38
        size = 20
        margin_x = 20
        margin_y_title = 40
        margin_y = 2 * margin_y_title

        word_count = len(words)

        for i in range(0, word_count, rows * cols):
            w = 1240
            h = 1754
            pdf.setPageSize((w, h))

            x, y = margin_x, h - margin_y

            set_words = words[i : i + rows * cols]

            available_height = h - 5 * margin_y

            max_rows = available_height // size

            rows = (len(set_words) - 1) // cols + 1
            rows = min(max_rows, rows)

            if i == 0:
                title = pdf.beginText(x, h - margin_y_title)
                title.setTextRenderMode(0)
                title.setFont("Helvetica", title_size)
                title.textOut("Índice de palavras")
                pdf.drawText(title)

            text = pdf.beginText(x, y)
            for col in range(cols):
                for row in range(rows):
                    index = col * rows + row
                    if index >= len(set_words):
                        break

                    word = set_words[index]
                    text.setTextRenderMode(0)

                    text.setFont("Helvetica-Bold", size)
                    text.textOut(word[0])

                    descript = f': {word[1]["pages"]}'
                    text.setFont("Helvetica", size)
                    text.textLine(descript)

                y = h - margin_y
                x += (w - 2 * margin_x) // cols
                text.setTextOrigin(x, y)

            pdf.drawText(text)
            pdf.showPage()

    pdf.save()
    
    uncompressed_size = os.path.getsize(target)
    
    # Apply MRC compression to the generated PDF (legacy workflow)
    if compress:
        log.info(f"PDF compression is enabled, starting compression for: {target}")
        try:
            print("\n" + "="*70)
            print("📦 STARTING PDF COMPRESSION")
            print("="*70)
            
            update_json_file(
                data_file,
                {
                    "status": {
                        "stage": "compressing",
                        "message": "A comprimir PDF - A iniciar...",
                        "progress": 0,
                    }
                },
            )
            
            original_size = os.path.getsize(target)
            print(f"📄 Input file: {target}")
            print(f"📊 Original size: {size_to_units(original_size)} ({original_size:,} bytes)")
            print(f"🎯 Target DPI: {OUT_DEFAULT_DPI}")
            print(f"🔧 Compression settings:")
            print(f"   - Background format: JPEG (quality: 40)")
            print(f"   - Foreground format: JPEG (quality: 80)")
            print(f"   - Mask method: CV (Computer Vision)")
            print(f"\n⏳ Applying MRC (Mixed Raster Content) compression...")
            
            log.info(f"Starting MRC compression for: {target}")
            
            def compression_progress_callback(current_page, total_pages, stage):
                progress_percent = (current_page / total_pages * 100) if total_pages > 0 else 0
                
                if stage == "starting":
                    message = "A comprimir PDF - A iniciar..."
                elif stage == "processing":
                    message = f"A comprimir PDF - Página {current_page}/{total_pages}"
                elif stage == "finalizing":
                    message = "A comprimir PDF - A finalizar..."
                elif stage == "complete":
                    message = "Compressão concluída"
                else:
                    message = "A comprimir PDF"
                
                update_json_file(
                    data_file,
                    {
                        "status": {
                            "stage": "compressing",
                            "message": message,
                            "progress": progress_percent,
                        }
                    },
                )
            
            import time
            start_time = time.time()
            
            doc_basename = get_file_basename(files_path)
            if simple:
                uncompressed_filename = f"{outputs_path}/{doc_basename}_uncompressed.pdf"
            else:
                uncompressed_filename = f"{outputs_path}/{doc_basename}_indexed_uncompressed.pdf"
            
            compressed_pdf_bytes = mrc_pdf_from_path(
                input_path=target,
                target_dpi=compression_target_dpi,
                render_dpi=compression_target_dpi,
                output_pdf_path=target,
                output_uncompressed_pdf_path=uncompressed_filename,
                bg_format="JPEG",
                fg_format="JPEG",
                bg_quality=compression_bg_quality,
                fg_quality=compression_fg_quality,
                mask_method="cv",
                flatten_to_jpeg=compression_flatten,
                progress_callback=compression_progress_callback,
            )
            
            compression_time = time.time() - start_time
            
            compressed_size = os.path.getsize(target)
            uncompressed_file_size = os.path.getsize(uncompressed_filename) if os.path.exists(uncompressed_filename) else uncompressed_size
            compression_ratio = (1 - compressed_size / uncompressed_file_size) * 100 if uncompressed_file_size > 0 else 0
            
            print(f"\n✅ COMPRESSION COMPLETE!")
            print(f"🎯 Target DPI: {compression_target_dpi}")
            print(f"📊 Compressed size: {size_to_units(compressed_size)} ({compressed_size:,} bytes)")
            print(f"📊 Uncompressed size: {size_to_units(uncompressed_file_size)} ({uncompressed_file_size:,} bytes)")
            print(f"💾 Space saved: {size_to_units(uncompressed_file_size - compressed_size)} ({compression_ratio:.1f}% reduction)")
            print(f"⏱️  Compression time: {compression_time:.2f} seconds")
            print(f"💨 Processing speed: {(uncompressed_file_size / compression_time / 1024 / 1024):.2f} MB/s")
            print("="*70 + "\n")
            
            log.info(
                f"PDF compressed successfully: {target} "
                f"({size_to_units(uncompressed_file_size)} → {size_to_units(compressed_size)}, "
                f"{compression_ratio:.1f}% reduction in {compression_time:.2f}s)"
            )
            
            pdf_type = "pdf" if simple else "pdf_indexed"
            data_update = {
                pdf_type: {
                    "compressed_size": size_to_units(compressed_size),
                    "uncompressed_size": size_to_units(uncompressed_file_size),
                    "compression_ratio": f"{compression_ratio:.1f}%"
                }
            }
            update_json_file(data_file, data_update)
        except Exception as e:
            print(f"\n❌ COMPRESSION FAILED: {str(e)}")
            print(f"⚠️  Using uncompressed version")
            print("="*70 + "\n")
            log.warning(f"Failed to compress PDF: {e}. Using uncompressed version.")
    else:
        log.info(f"PDF compression is disabled, skipping compression for: {target}")
        print(f"\n⏭️  SKIPPING PDF COMPRESSION (disabled in configuration)")
        print(f"📄 File: {target}")
        print(f"📊 Size: {size_to_units(os.path.getsize(target))}\n")
    
    return target


def find_index_words(hocr_path):
    index_words = {}
    remove_chars = "«»“”.,;:!?()[]{}\"'"
    with open(hocr_path, encoding="utf-8") as f:
        hocrfile = json.load(f)

    hyphenated_last_word = False

    for section in hocrfile:
        for line_index, line in enumerate(section):
            if hyphenated_last_word:
                previous_word = section[line_index - 1][-1]["text"]
                current_word = line[0]["text"]
                joined_word = previous_word.rstrip("-") + current_word
                line[0]["text"] = joined_word
                hyphenated_last_word = False

                # Remove subwords of the joined word from the index
                if index_words.get(previous_word, 0) != 0:
                    index_words[previous_word] = index_words.get(previous_word, 0) - 1
                    if index_words[previous_word] == 0:
                        del index_words[previous_word]

            for i, word in enumerate(line):
                rawtext = word["text"]

                if (i == len(line) - 1) and rawtext.endswith("-"):
                    hyphenated_last_word = True

                for w in rawtext.split():
                    w = w.strip()
                    for c in remove_chars:
                        w = w.replace(c, "")

                    w = w.lower()

                    index_words[w] = index_words.get(w, 0) + 1

    return index_words


def add_text_layer(
    pdf, hocr_path, height, dpi_original, dpi_compressed, get_index_words=False, scale_factor=None
):
    """Draw an invisible text layer for OCR data
    
    Args:
        pdf: ReportLab canvas object
        hocr_path: Path to OCR results JSON file
        height: Page height in pixels
        dpi_original: Original DPI (for legacy calculation)
        dpi_compressed: Compressed DPI (for legacy calculation)
        get_index_words: Whether to generate word index
        scale_factor: Pre-calculated scale factor (if None, uses dpi_compressed/dpi_original)
    """
    if get_index_words:
        index_words = find_index_words(hocr_path)
    else:
        index_words = None

    # Use provided scale factor or calculate from DPIs
    if scale_factor is None:
        scale_factor = dpi_compressed / dpi_original

    with open(hocr_path, encoding="utf-8") as f:
        hocrfile = json.load(f)

    for section in hocrfile:
        for line in section:
            for word in line:
                rawtext = word["text"]
                box = word["box"]
                b = word["b"]

                font_width = pdf.stringWidth(rawtext, "Times-Roman", 8)
                if font_width <= 0:
                    continue

                text = pdf.beginText()
                text.setTextRenderMode(3)  # double invisible
                text.setFont("Times-Roman", 8)
                x_offset = box[0] * scale_factor
                y_offset = height - b * scale_factor
                text.setTextOrigin(x_offset, y_offset)
                box_width = (box[2] - box[0]) * scale_factor
                width_scale = 100.0 * box_width / font_width
                text.setHorizScale(width_scale)
                text.textLine(rawtext)
                pdf.drawText(text)

    return index_words


def load_fonts():
    """
    Ensure used fonts are registered, to avoid lazy loading during OCR
    """
    # Add more fonts here as needed
    getFont("Times-Roman")
    # load_invisible_font()  # Invisible font not writing text properly in PDF results


# Glyphless variation of vedaal's invisible font retrieved from
# http://www.angelfire.com/pr/pgpf/if.html, which says:
# 'Invisible font' is unrestricted freeware. Enjoy, Improve, Distribute freely
def load_invisible_font():
    font = """
eJzdlk1sG0UUx/+zs3btNEmrUKpCPxikSqRS4jpfFURUagmkEQQoiRXgAl07Y3vL2mvt2ml8APXG
hQPiUEGEVDhWVHyIC1REPSAhBOWA+BCgSoULUqsKcWhVBKjhzfPU+VCi3Flrdn7vzZv33ryZ3TUE
gC6chsTx8fHck1ONd98D0jnS7jn26GPjyMIleZhk9fT0wcHFl1/9GRDPkTxTqHg1dMkzJH9CbbTk
xbWlJfKEdB+Np0pBswi+nH/Nvay92VtfJp4nvEztUJkUHXsdksUOkveXK/X5FNuLD838ICx4dv4N
I1e8+ZqbxwCNP2jyqXoV/fmhy+WW/2SqFsb1pX68SfEpZ/TCrI3aHzcP//jitodvYmvL+6Xcr5mV
vb1ScCzRnPRPfz+LsRSWNasuwRrZlh1sx0E8AriddyzEDfE6EkglFhJDJO5u9fJbFJ0etEMB78D5
4Djm/7kjT0wqhSNURyS+u/2MGJKRu+0ExNkrt1pJti9p2x6b3TBJgmUXuzgnDmI8UWMbkVxeinCw
Mo311/l/v3rF7+01D+OkZYE0PrbsYAu+sSyxU0jLLtIiYzmBrFiwnCT9FcsdOOK8ZHbFleSn0znP
nDCnxbnAnGT9JeYtrP+FOcV8nTlNnsoc3bBAD85adtCNRcsSffjBsoseca/lBE7Q09LiJOm/ttyB
0+IqcwfncJt5q4krO5k7jV7uY+5m7mPebuLKUea7iHvk48w72OYF5rvZT8C8k/WvMN/Dc19j3s02
bzPvZZv3me9j/ox5P9t/xdzPzPVJcc7yGnPL/1+GO1lPVTXM+VNWOTRRg0YRHgrUK5yj1kvaEA1E
xAWiCtl4qJL2ADKkG6Q3XxYjzEcR0E9hCj5KtBd1xCxp6jV5mKP7LJBr1nTRK2h1TvU2w0akCmGl
5lWbBzJqMJsdyaijQaCm/FK5HqspHetoTtMsn4LO0T2mlqcwmlTVOT/28wGhCVKiNANKLiJRlxqB
F603axQznIzRhDSq6EWZ4UUs+xud0VHsh1U1kMlmNwu9kTuFaRqpURU0VS3PVmZ0iE7gct0MG/8+
2fmUvKlfRLYmisd1w8pk1LSu1XUlryM1MNTH9epTftWv+16gIh1oL9abJZyjrfF5a4qccp3oFAcz
Wxxx4DpvlaKKxuytRDzeth5rW4W8qBFesvEX8RFRmLBHoB+TpCmRVCCb1gFCruzHqhhW6+qUF6tC
pL26nlWN2K+W1LhRjxlVGKmRTFYVo7CiJug09E+GJb+QocMCPMWBK1wvEOfRFF2U0klK8CppqqvG
pylRc2Zn+XDQWZIL8iO5KC9S+1RekOex1uOyZGR/w/Hf1lhzqVfFsxE39B/ws7Rm3N3nDrhPuMfc
w3R/aE28KsfY2J+RPNp+j+KaOoCey4h+Dd48b9O5G0v2K7j0AM6s+5WQ/E0wVoK+pA6/3bup7bJf
CMGjwvxTsr74/f/F95m3TH9x8o0/TU//N+7/D/ScVcA=
""".encode(
        "latin1"
    )
    uncompressed = bytearray(zlib.decompress(base64.b64decode(font)))
    ttf = io.BytesIO(uncompressed)
    setattr(ttf, "name", "(invisible.ttf)")
    pdfmetrics.registerFont(TTFont("invisible", ttf))


####################################################
# EXPORT METS/ALTO FUNCTIONS
####################################################
def get_md5_checksum(path):
    with open(path, "rb") as f:
        data = f.read()
        return hashlib.md5(data).hexdigest()


def generate_file(base_path, path, id, seq, mimetype):
    return (
        f'<file CHECKSUMTYPE="MD5" CHECKSUM="{get_md5_checksum(path)}" GROUPID="{seq}" ID="{id}{(seq if seq != 0 else 1):05d}" MIMETYPE="{mimetype}" SEQ="{seq if seq != 0 else 1}" SIZE="{get_file_size(path)}">'
        + "\n\t\t\t\t"
        + f'<FLocat LOCTYPE="OTHER" OTHERLOCTYPE="FILE" xlink:href="{path.replace(base_path, "")[1:]}"/>'
        + "\n\t\t\t</file>"
    )


def create_mets_files(path):
    files_folders = [x for x in os.listdir(path)]
    basename = path.split("/")[-1]

    if basename and basename in files_folders:
        create_document_mets(path)
    else:
        for folder in files_folders:
            if not os.path.isdir(path + "/" + folder):
                continue
            create_mets_files(f"{path}/{folder}")

        create_folder_mets(path)


def create_folder_mets(path):
    if os.path.samefile(path, FILES_PATH) or os.path.samefile(path, PRIVATE_PATH):
        return

    data_path = path + "/_data.json"
    with open(data_path, encoding="utf-8") as f:
        info = json.load(f)

    creation_date = datetime.strptime(info["creation"], "%d/%m/%Y %H:%M:%S").strftime(
        "%Y-%m-%dT%H:%M:%S"
    )

    folders = [
        x
        for x in os.listdir(path)
        if os.path.isdir(path + "/" + x)
        and x != "_ocr_results"
        and x != "alto_schemas"
        and x != "ocr_results.zip"
        and x != "_mets.xml"
        and x != "mets.zip"
        and x != "ocr_results.zip"
    ]

    fileSec = "\n\t\t".join(
        f"""<fileGrp ID="{f}" USE="TEXT">
            <file CHECKSUMTYPE="MD5" CHECKSUM="{get_md5_checksum(path + "/" + f + "/_mets.xml")}" GROUPID="0" ID="ALTO{(id + 1):05d}" MIMETYPE="text/xml" SEQ="1" SIZE="{get_file_size(path + "/" + f + "/_mets.xml")}">
                <FLocat LOCTYPE="OTHER" OTHERLOCTYPE="FILE" xlink:href="{f + "/_mets.xml"}" />
            </file>
        </fileGrp>"""
        for id, f in enumerate(folders)
    )

    structMap = "\n\t\t".join(
        f"""<div TYPE="Folder" ORDER="{id + 1}">
            <fptr FILEID="ALTO{(id + 1):05d}"/>
        </div>"""
        for id, f in enumerate(folders)
    )

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<mets xsi:schemaLocation="http://www.loc.gov/standards/mets/version18/mets.xsd">
    <metsHdr CREATEDATE="{creation_date}">
        <agent ROLE="CREATOR" TYPE="ORGANIZATION">
            <name>INESC-ID LISBOA</name>
        </agent>
    </metsHdr>
    <dmdSec ID="DM1">
        <mdWrap MDTYPE="MODS">
            <xmlData>
                <mods>
                    <titleInfo>
                        <title>{path.split("/")[-1]}</title>
                    </titleInfo>
                </mods>
            </xmlData>
        </mdWrap>
    </dmdSec>
    <amdSec>
        <techMD ID="techMD1">
            <mdWrap>
                <xmlData>
                    <mix>
                        <BasicDigitalObjectInformation>
                            <FormatDesignation>
                                <formatName>text/xml</formatName>
                            </FormatDesignation>
                        </BasicDigitalObjectInformation>
                    </mix>
                </xmlData>
            </mdWrap>
        </techMD>
    </amdSec>
    <fileSec>
        {fileSec}
    </fileSec>
    <structMap ID="SM1" LABEL="Physical Structure" TYPE="PHYSICAL">
        {structMap}
    </structMap>
</mets>"""

    with open(f"{path}/_mets.xml", "w") as f:
        f.write(xml)


def create_document_mets(path):
    if not os.path.isdir(f"{path}/alto_schemas"):
        os.mkdir(f"{path}/alto_schemas")

    data_path = "/".join(path.split("/")[:-1]) + "/_data.json"
    with open(data_path, encoding="utf-8") as f:
        info = json.load(f)

    # Check if all files are ready to be extracted
    for k in info:
        if isinstance(info[k], dict):
            if "complete" in info[k] and info[k]["complete"]:
                continue
            if "progress" in info[k] and info[k]["progress"] == info["pages"]:
                continue

            raise ValueError("Error: Not all files are ready to be extracted")

    single_files = [
        x
        for x in os.listdir(path)
        if os.path.isfile(path + "/" + x)
        and not x.endswith(".json")
        and not x.endswith(".zip")
        and not x.endswith(".xml")
        and not x.endswith(".png")
    ]
    extensions = [x.split(".")[-1] for x in single_files]

    structMap = ""

    files = [
        f"{path}/_ocr_results/{f}"
        for f in os.listdir(f"{path}/_ocr_results")
        if f.endswith(".json")
    ]

    for id, file in enumerate(files):
        export_alto(file)
        structMap += (
            f'\t\t\t<div TYPE="Page" ORDER="{id + 1}">'
            + f'\n\t\t\t\t<fptr FILEID="PNG{(id + 1):05d}"/>'
            + f'\n\t\t\t\t<fptr FILEID="ALTO{(id + 1):05d}"/>'
            + "\n\t\t\t</div>\n"
        )

    png_grp = "\n\t\t\t".join(
        generate_file(
            path,
            f.replace("/_ocr_results", "").replace(".json", ".png"),
            "IMG",
            id + 1,
            "image/png",
        )
        for id, f in enumerate(files)
    )

    alto_grp = "\n\t\t\t".join(
        generate_file(
            path,
            f.replace("/_ocr_results", "/alto_schemas").replace(".json", ".xml"),
            "ALTO",
            id + 1,
            "text/xml",
        )
        for id, f in enumerate(files)
    )

    single_files_grps = "\n\t\t".join(
        f"""<fileGrp ID="{f.split('.')[-1].upper()}GRP{extensions[:id + 1].count(f.split('.')[-1])}" USE="Text">
            <file CHECKSUM="MD5" CHECKSUM="{get_md5_checksum(path + "/" + f)}" GROUPID="0" ID="{f.split('.')[-1].upper()}{extensions[:id + 1].count(f.split('.')[-1]):05d}" SEQ="1" SIZE="{get_file_size(path + "/" + f)}">
                <FLocat LOCTYPE="OTHER" OTHERLOCTYPE="FILE" xlink:href="{f}"/>
            </file>
        </fileGrp>"""
        for id, f in enumerate(single_files)
    )

    single_files_struct = "\n\t\t".join(
        f"""<div ID="DIV{id + 1}" TYPE="CompleteObject">
            <fptr FILEID="{f.split('.')[-1].upper()}{extensions[:id + 1].count(f.split('.')[-1]):05d}"/>
        </div>"""
        for id, f in enumerate(single_files)
    )

    creation_date = datetime.strptime(info["creation"], "%d/%m/%Y %H:%M:%S").strftime(
        "%Y-%m-%dT%H:%M:%S"
    )

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<mets xsi:schemaLocation="http://www.loc.gov/standards/mets/version18/mets.xsd">
    <metsHdr CREATEDATE="{creation_date}">
        <agent ROLE="CREATOR" TYPE="ORGANIZATION">
            <name>INESC-ID LISBOA</name>
        </agent>
    </metsHdr>
    <dmdSec ID="DM1">
        <mdWrap MDTYPE="MODS">
            <xmlData>
                <mods>
                    <titleInfo>
                        <title>{'.'.join(path.split("/")[-1].split(".")[:-1])}</title>
                    </titleInfo>
                </mods>
            </xmlData>
        </mdWrap>
    </dmdSec>
    <amdSec>
        <techMD ID="techMD1">
            <mdWrap>
                <xmlData>
                    <mix>
                        <BasicDigitalObjectInformation>
                            <FormatDesignation>
                                <formatName>image/png</formatName>
                            </FormatDesignation>
                        </BasicDigitalObjectInformation>
                    </mix>
                </xmlData>
            </mdWrap>
        </techMD>
        <techMD ID="techMD2">
            <mdWrap>
                <xmlData>
                    <mix>
                        <BasicDigitalObjectInformation>
                            <FormatDesignation>
                                <formatName>application/pdf</formatName>
                            </FormatDesignation>
                        </BasicDigitalObjectInformation>
                    </mix>
                </xmlData>
            </mdWrap>
        </techMD>
        <techMD ID="techMD3">
            <mdWrap>
                <xmlData>
                    <mix>
                        <BasicDigitalObjectInformation>
                            <FormatDesignation>
                                <formatName>text/plain</formatName>
                            </FormatDesignation>
                        </BasicDigitalObjectInformation>
                    </mix>
                </xmlData>
            </mdWrap>
        </techMD>
        <techMD ID="techMD4">
            <mdWrap>
                <xmlData>
                    <mix>
                        <BasicDigitalObjectInformation>
                            <FormatDesignation>
                                <formatName>text/csv</formatName>
                            </FormatDesignation>
                        </BasicDigitalObjectInformation>
                    </mix>
                </xmlData>
            </mdWrap>
        </techMD>
        <techMD ID="techMD5">
            <mdWrap>
                <xmlData>
                    <mix>
                        <BasicDigitalObjectInformation>
                            <FormatDesignation>
                                <formatName>text/xml</formatName>
                            </FormatDesignation>
                        </BasicDigitalObjectInformation>
                    </mix>
                </xmlData>
            </mdWrap>
        </techMD>
        <techMD ID="techMD6">
            <mdWrap>
                <xmlData>
                    <mix>
                        <BasicDigitalObjectInformation>
                            <FormatDesignation>
                                <formatName>application/json</formatName>
                            </FormatDesignation>
                        </BasicDigitalObjectInformation>
                    </mix>
                </xmlData>
            </mdWrap>
        </techMD>
    </amdSec>
    <fileSec>
        <fileGrp ID="PNGGRP" USE="Images">
            {png_grp}
        </fileGrp>
        <fileGrp ID="ALTOGRP" USE="Text">
            {alto_grp}
        </fileGrp>
            {single_files_grps}
    </fileSec>
    <structMap ID="SM1" LABEL="Physical Structure" TYPE="PHYSICAL">
        <div TYPE="Document">
            {structMap}
        </div>
    </structMap>
    <structMap ID="SM2" LABEL="Logical Structure" TYPE="LOGICAL">
    </structMap>
    <structMap ID="SM3" LABEL="Single File Structure" TYPE="SINGLE_FILE">
        {single_files_struct}
    </structMap>
</mets>"""

    with open(f"{path}/_mets.xml", "w") as f:
        f.write(xml)


def export_hocr(files_path, outputs_path=None, force_recreate=False):
    """
    Export OCR results as hOCR format.
    
    :param files_path: path to document folder in _files (contains _ocr_results)
    :param outputs_path: path to document folder in _outputs (for writing hocr)
    :param force_recreate: force the recreation of the file
    :return: the path to the exported file
    """
    # Calculate outputs_path if not provided
    if outputs_path is None:
        relative_path = files_path.replace(FILES_PATH, "").strip("/")
        outputs_path = f"{OUTPUTS_PATH}/{relative_path}"
    
    # Ensure outputs directory exists
    if not os.path.exists(outputs_path):
        os.makedirs(outputs_path, exist_ok=True)
    
    target = f"{outputs_path}/_hocr.hocr"
    data_file = f"{files_path}/_data.json"
    
    if os.path.exists(target) and not force_recreate:
        return target
    
    # Get all OCR result JSON files
    ocr_results_path = f"{files_path}/_ocr_results"
    if not os.path.exists(ocr_results_path):
        return None
    
    files = sorted([
        f"{ocr_results_path}/{f}"
        for f in os.listdir(ocr_results_path)
        if f.endswith(".json")
    ])
    
    if not files:
        return None
    
    # Build hOCR XML structure
    hocr_content = []
    hocr_content.append('<?xml version="1.0" encoding="UTF-8"?>')
    hocr_content.append('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">')
    hocr_content.append('<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">')
    hocr_content.append('<head>')
    hocr_content.append('<title>hOCR</title>')
    hocr_content.append('<meta http-equiv="content-type" content="text/html; charset=utf-8" />')
    hocr_content.append('<meta name="ocr-system" content="tesseract" />')
    hocr_content.append('<meta name="ocr-capabilities" content="ocr_page ocr_carea ocr_par ocr_line ocrx_word" />')
    hocr_content.append('</head>')
    hocr_content.append('<body>')
    
    # Process each page
    for page_idx, json_file in enumerate(files):
        with open(json_file, encoding="utf-8") as f:
            page_data = json.load(f)
        
        hocr_content.append(f'<div class="ocr_page" id="page_{page_idx + 1}" title="image; bbox 0 0 1000 1000">')
        
        # Process paragraphs (sections)
        for para_idx, paragraph in enumerate(page_data):
            hocr_content.append(f'<div class="ocr_carea" id="page_{page_idx + 1}_para_{para_idx}">')
            
            # Process lines
            for line_idx, line in enumerate(paragraph):
                if not line:
                    continue
                    
                # Calculate line bounding box
                line_boxes = [word["box"] for word in line if "box" in word]
                if line_boxes:
                    x0 = min(box[0] for box in line_boxes)
                    y0 = min(box[1] for box in line_boxes)
                    x1 = max(box[2] for box in line_boxes)
                    y1 = max(box[3] for box in line_boxes)
                    
                    hocr_content.append(f'<span class="ocr_line" id="page_{page_idx + 1}_line_{line_idx}" title="bbox {int(x0)} {int(y0)} {int(x1)} {int(y1)}">')
                    
                    # Process words
                    for word_idx, word in enumerate(line):
                        if "box" in word and "text" in word:
                            box = word["box"]
                            text = word["text"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                            conf = word.get("conf", 95)
                            hocr_content.append(f'<span class="ocrx_word" id="page_{page_idx + 1}_word_{word_idx}" title="bbox {int(box[0])} {int(box[1])} {int(box[2])} {int(box[3])}; x_wconf {int(conf)}">{text}</span>')
                    
                    hocr_content.append('</span>')
            
            hocr_content.append('</div>')
        
        hocr_content.append('</div>')
    
    hocr_content.append('</body>')
    hocr_content.append('</html>')
    
    # Write to file
    with open(target, "w", encoding="utf-8") as f:
        f.write("\n".join(hocr_content))
    
    # Update metadata
    data_update = {
        "hocr": {
            "complete": True,
            "size": size_to_units(get_file_size(target, path_complete=True)),
            "creation": get_current_time(),
        }
    }
    update_json_file(data_file, data_update)
    
    return target


def export_alto(path):
    with open(path, encoding="utf-8") as f:
        hocrfile = json.load(f)

    line_count = 0
    word_count = 0
    blocks = ""
    for sID, s in enumerate(hocrfile):
        blocks += f"""\t\t\t\t\t<TextBlock ID="block_{sID}">\n"""
        for l in s:
            blocks += f"""\t\t\t\t\t\t<TextLine ID="line_{line_count}">\n"""
            for w in l:
                blocks += f"""\t\t\t\t\t\t\t<String ID="word_{word_count}" HPOS="{int(w["box"][0])}" VPOS="{int(w["box"][1])}" WIDTH="{int(w["box"][2] - w["box"][0])}" HEIGHT="{int(w["box"][3] - w["box"][1])}" CONTENT="{w["text"]}"/>\n"""
                word_count += 1
            blocks += """\t\t\t\t\t\t</TextLine>\n"""
            line_count += 1
        blocks += """\t\t\t\t\t</TextBlock>\n"""

    xml = """<?xml version="1.0" encoding="UTF-8"?>
<alto xmlns="http://www.loc.gov/standards/alto/ns-v3#" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.loc.gov/standards/alto/ns-v3# http://www.loc.gov/alto/v3/alto-3-0.xsd">
    <Description>
        <MeasurementUnit>pixel</MeasurementUnit>
        <sourceImageInformation>
            <fileName>{path}</fileName>
        </sourceImageInformation>
    </Description>
    <Layout>
        <Page ID="page_0">
            <PrintSpace>
                <ComposedBlock ID="composed_block_0">
{blocks}                </ComposedBlock>
            </PrintSpace>
        </Page>
    </Layout>
</alto>"""

    path = path.split("/")
    path[-2] = "alto_schemas"
    path[-1] = path[-1].replace(".json", ".xml")

    with open("/".join(path), "w") as f:
        f.write(xml)


def export_zip(path, _):
    create_mets_files("_files")
    basename = path.split("/")[-1]
    with zipfile.ZipFile(f"{path}/{basename}.zip", "w") as zipf:
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".json") or file.endswith(".zip"):
                    continue
                zipf.write(
                    os.path.join(root, file),
                    os.path.relpath(os.path.join(root, file), os.path.join(path, "..")),
                )


if __name__ == "__main__":
    export_zip("files/Test Folder")
