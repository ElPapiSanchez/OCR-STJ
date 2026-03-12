import os
import io
from typing import Optional, Tuple
import logging

import numpy as np
from PIL import Image, ImageFilter, ImageSequence
import fitz  # PyMuPDF

# OpenCV is now required because default mask method is CV
import cv2

# Configure logging
logger = logging.getLogger(__name__)


# -------------------------------
# 1. MRC segmentation – PIL-based (kept as optional fallback)
# -------------------------------

def segment_page_to_mrc_components_pil(pil_img: Image.Image) -> Tuple[Image.Image, Image.Image, Image.Image]:
    """
    PIL-based segmentation.
    Given a PIL Image page (assumed RGB or similar), return:
      - bg_img: smooth colour background (RGB)
      - fg_img: colour foreground-only (text / edges) on white (RGB)
      - mask_img: binary mask (L, 0=background, 255=foreground)
    """
    logger.debug("Starting PIL-based segmentation")
    orig_rgb = pil_img.convert("RGB")
    gray = orig_rgb.convert("L")

    arr = np.asarray(gray, dtype=np.float32)
    p2, p98 = np.percentile(arr, (2, 98))
    logger.debug(f"PIL segmentation: percentiles p2={p2:.2f}, p98={p98:.2f}")
    if p98 > p2:
        arr = (arr - p2) * (255.0 / (p98 - p2))
    arr = np.clip(arr, 0, 255)
    gray = Image.fromarray(arr.astype(np.uint8), mode="L")

    bg_smooth_gray = gray.filter(ImageFilter.GaussianBlur(radius=5))

    arr_gray = np.asarray(gray, dtype=np.float32)
    arr_bg = np.asarray(bg_smooth_gray, dtype=np.float32)
    diff = np.abs(arr_gray - arr_bg)

    mean_diff = diff.mean()
    std_diff = diff.std()
    thr = max(20.0, mean_diff + 1.5 * std_diff)
    logger.debug(f"PIL segmentation: mean_diff={mean_diff:.2f}, std_diff={std_diff:.2f}, threshold={thr:.2f}")
    raw_mask = diff > thr

    mask_pil = Image.fromarray((raw_mask.astype(np.uint8) * 255), mode="L")
    mask_pil = mask_pil.filter(ImageFilter.MedianFilter(size=3))
    mask_arr = np.asarray(mask_pil, dtype=np.uint8)
    mask_final = mask_arr > 127

    mask_img_arr = np.where(mask_final, 255, 0).astype(np.uint8)
    mask_img = Image.fromarray(mask_img_arr, mode="L")

    bg_img = orig_rgb.filter(ImageFilter.GaussianBlur(radius=5))

    rgb_arr = np.asarray(orig_rgb, dtype=np.uint8).copy()
    rgb_arr[~mask_final] = 255
    fg_img = Image.fromarray(rgb_arr, mode="RGB")

    logger.debug("PIL-based segmentation complete")
    return bg_img, fg_img, mask_img

def make_inpainted_background_cv(
    pil_img: Image.Image,
    mask_img: Image.Image,
    inpaint_method: str = "telea",   # "telea" | "ns" | "masked_blur"
    inpaint_radius: int = 3,
    dilate_px: int = 1,
    post_blur_radius: float = 1.5,
) -> Image.Image:
    logger.debug(f"Starting CV inpainting: method={inpaint_method}, radius={inpaint_radius}, dilate={dilate_px}px")
    img_rgb = np.asarray(pil_img.convert("RGB"), dtype=np.uint8)
    mask = np.asarray(mask_img.convert("L"), dtype=np.uint8)
    mask_bin = (mask > 127).astype(np.uint8) * 255

    if dilate_px > 0:
        k = 2 * dilate_px + 1
        kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (k, k))
        mask_bin = cv2.dilate(mask_bin, kernel, iterations=1)

    if inpaint_method == "masked_blur":
        # Fill masked pixels from a blurred image only
        # (fast baseline, not true inpainting)
        blur = cv2.GaussianBlur(img_rgb, (0, 0), sigmaX=5, sigmaY=5)
        out = img_rgb.copy()
        m = mask_bin > 0
        out[m] = blur[m]
    else:
        # OpenCV inpaint expects BGR
        img_bgr = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2BGR)
        flag = cv2.INPAINT_TELEA if inpaint_method == "telea" else cv2.INPAINT_NS
        out_bgr = cv2.inpaint(img_bgr, mask_bin, inpaintRadius=float(inpaint_radius), flags=flag)
        out = cv2.cvtColor(out_bgr, cv2.COLOR_BGR2RGB)

    out_pil = Image.fromarray(out, mode="RGB")

    if post_blur_radius and post_blur_radius > 0:
        out_pil = out_pil.filter(ImageFilter.GaussianBlur(radius=post_blur_radius))

    logger.debug("CV inpainting complete")
    return out_pil

# -------------------------------
# 1b. CV-based mask + segmentation (DEFAULT)
# -------------------------------

def detect_text_mask_cv(
    img_rgb: np.ndarray,
    win_size: int = 35,
    C: int = 10,
    morph_kernel: int = 3,
) -> np.ndarray:
    """
    OpenCV-based text mask.
    img_rgb: HxWx3 RGB uint8 array.
    Returns: mask uint8 (0 background, 255 foreground).
    """
    logger.debug(f"Detecting text mask: win_size={win_size}, C={C}, morph_kernel={morph_kernel}")
    gray = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2GRAY)
    bg = cv2.GaussianBlur(gray, (0, 0), sigmaX=15, sigmaY=15)
    norm = cv2.divide(gray, bg, scale=255)
    norm = cv2.normalize(norm, None, 0, 255, cv2.NORM_MINMAX)

    if win_size % 2 == 0:
        win_size += 1

    th = cv2.adaptiveThreshold(
        norm, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY_INV,
        75,
        10
    )

    nb_components, output, stats, centroids = cv2.connectedComponentsWithStats(th, connectivity=8)
    sizes = stats[1:, cv2.CC_STAT_AREA]
    min_size = max(2, (img_rgb.shape[0] * img_rgb.shape[1]) // 200000)
    logger.debug(f"Connected components: {nb_components}, min_size={min_size}")

    mask = np.zeros_like(th, dtype=np.uint8)
    for i, sz in enumerate(sizes):
        if sz >= min_size:
            mask[output == (i + 1)] = 255

    # Optional morphology, if you want it:
    # kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (morph_kernel, morph_kernel))
    # mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel)

    logger.debug(f"Text mask detection complete")
    return mask


def segment_page_to_mrc_components_cv(
    pil_img: Image.Image,
    win_size: int = 35,
    C: int = 10,
    morph_kernel: int = 3,
) -> Tuple[Image.Image, Image.Image, Image.Image]:
    """
    CV-based segmentation using detect_text_mask_cv for the mask.
    Produces:
      - bg_img: smooth colour background (RGB)
      - fg_img: colour foreground-only (RGB on white)
      - mask_img: binary mask (L, 0/255)
    """
    logger.debug("Starting CV-based segmentation")
    orig_rgb = pil_img.convert("RGB")
    img_np = np.asarray(orig_rgb, dtype=np.uint8)

    mask_np = detect_text_mask_cv(img_np, win_size=win_size, C=C, morph_kernel=morph_kernel)
    mask_np = np.where(mask_np > 0, 255, 0).astype(np.uint8)
    mask_final = mask_np > 0

    mask_img = Image.fromarray(mask_np, mode="L")

    # Background: blurred RGB original
    bg_img = orig_rgb.filter(ImageFilter.GaussianBlur(radius=5))
    

    # Foreground: (keep original RGB; mask is used as soft-mask in PDF)
    fg_arr = img_np.copy()
    # If you want white-out background instead, uncomment:
    # fg_arr[~mask_final] = 255
    fg_img = Image.fromarray(fg_arr, mode="RGB")

    logger.debug("CV-based segmentation complete")
    return bg_img, fg_img, mask_img


# -------------------------------
# 2. PDF assembly helpers
# -------------------------------

def encode_pil_to_bytes(img: Image.Image, fmt: str, **save_params) -> bytes:
    bio = io.BytesIO()
    img.save(bio, format=fmt, **save_params)
    return bio.getvalue()


def _scale_cv_params_for_dpi(
    input_dpi: float,
    base_dpi: float,
    win_size: int,
    C: int,
    morph_kernel: int,
):
    scale = input_dpi / base_dpi
    win = int(round(win_size * scale))
    win = max(3, win | 1)
    mk = max(1, int(round(morph_kernel * scale)))
    C_scaled = max(1, int(round(C * (scale ** 0.5))))
    logger.debug(f"Scaled CV params: input_dpi={input_dpi}, base_dpi={base_dpi}, scale={scale:.2f}, win={win}, C={C_scaled}, mk={mk}")
    return win, C_scaled, mk


def _iter_pil_pages_from_pdf_bytes(pdf_bytes: bytes, render_dpi: int):
    src_pdf_doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        for page in src_pdf_doc:
            pix = page.get_pixmap(dpi=render_dpi)
            mode = "RGB" if pix.alpha == 0 else "RGBA"
            pil_img = Image.frombytes(mode, (pix.width, pix.height), pix.samples)
            if mode == "RGBA":
                pil_img = pil_img.convert("RGB")
            yield pil_img
    finally:
        src_pdf_doc.close()


def _iter_pil_pages_from_tiff_bytes(tiff_bytes: bytes):
    bio = io.BytesIO(tiff_bytes)
    tiff_img = Image.open(bio)
    for pil_page in ImageSequence.Iterator(tiff_img):
        yield pil_page.convert("RGB")


def jpeg_roundtrip_pil(img: Image.Image, quality: int, *, subsampling=2, optimize=True, progressive=True) -> Image.Image:
    """
    Encode to JPEG bytes then decode back to PIL.
    subsampling: 0=4:4:4, 1=4:2:2, 2=4:2:0 (common/smaller)
    """
    b = encode_pil_to_bytes(
        img.convert("RGB"),
        "JPEG",
        quality=int(quality),
        subsampling=subsampling,
        optimize=optimize,
        progressive=progressive,
    )
    return Image.open(io.BytesIO(b)).convert("RGB")


def mrc_pdf_from_bytes(
    file_bytes: bytes,
    filetype: str,
    target_dpi: float,
    *,
    render_dpi: Optional[float] = None,
    output_pdf_path: Optional[str] = None,
    output_uncompressed_pdf_path: Optional[str] = None,
    output_components_dir: Optional[str] = None,
    bg_format: str = "JPEG",
    fg_format: str = "JPEG",
    bg_quality: int = 40,
    fg_quality: int = 80,
    mask_method: str = "cv",  # default to CV
    cv_win_size: int = 20,
    cv_C: int = 10,
    cv_morph_kernel: int = 3,
    flatten_to_jpeg: bool = False,
    flatten_quality: int = 85,
    progress_callback: Optional[callable] = None
) -> bytes:
    """
    Run the MRC-style pipeline on an in-memory PDF or TIFF and return the output PDF bytes.

    Args:
        file_bytes: Input file bytes (PDF or TIFF).
        filetype: "pdf" or "tiff" (also accepts "tif").
        target_dpi: Desired output DPI (used for downsampling and px->pt size mapping).
        render_dpi: For PDFs: rasterization DPI. For TIFFs: overrides metadata DPI if provided.
        output_pdf_path: Optional path to write the output PDF to disk.
        output_uncompressed_pdf_path: Optional path to write the uncompressed PDF (before MRC compression) to disk.
        output_components_dir: Optional dir to dump BG/FG/mask images per page for inspection.
        bg_format/fg_format: "JPEG" or "JPEG2000" (if Pillow supports JP2).
        bg_quality/fg_quality: quality for bg/fg formats.
        mask_method: "cv" (default) or "pil".
        cv_*: CV parameters (scaled with input_dpi vs base_dpi=300).
        flatten_to_jpeg: If True, flatten FG+BG into single JPEG layer.
        flatten_quality: Quality for flattened JPEG.
        progress_callback: Optional callback function(page_num, total_pages, stage) for progress updates (currently not implemented in this version).

    Returns:
        PDF bytes.
    """
    logger.info(f"Starting MRC compression: filetype={filetype}, target_dpi={target_dpi}, render_dpi={render_dpi}")
    logger.info(f"Compression settings: bg_format={bg_format}, bg_quality={bg_quality}, fg_format={fg_format}, fg_quality={fg_quality}")
    logger.info(f"Mask method: {mask_method}, flatten_to_jpeg={flatten_to_jpeg}")
    
    ft = filetype.lower().strip(".")
    if ft not in ("pdf", "tif", "tiff"):
        raise ValueError("filetype must be 'pdf' or 'tiff'/'tif'")

    is_pdf = ft == "pdf"
    is_tiff = not is_pdf

    if target_dpi <= 0:
        raise ValueError("target_dpi must be > 0")

    # Determine effective input DPI
    if is_pdf:
        input_dpi = float(render_dpi) if render_dpi is not None else float(target_dpi)
        input_dpi = float(int(round(input_dpi)))  # PyMuPDF expects integer-ish DPI
        page_iter = _iter_pil_pages_from_pdf_bytes(file_bytes, render_dpi=int(round(input_dpi)))
    else:
        # For TIFFs, try to read metadata DPI unless overridden
        if render_dpi is not None:
            input_dpi = float(render_dpi)
        else:
            bio = io.BytesIO(file_bytes)
            timg = Image.open(bio)
            dpi_tuple = timg.info.get("dpi", (target_dpi, target_dpi))
            input_dpi = float(dpi_tuple[0]) if dpi_tuple else float(target_dpi)
            if input_dpi <= 0:
                input_dpi = float(target_dpi)
        page_iter = _iter_pil_pages_from_tiff_bytes(file_bytes)

    logger.info(f"Input DPI: {input_dpi}, Target DPI: {target_dpi}")
    
    # Downsample scale (true downsampling)
    scale = (target_dpi / input_dpi) if input_dpi > target_dpi else 1.0
    logger.info(f"Downsampling scale: {scale:.4f}")

    if output_components_dir:
        os.makedirs(output_components_dir, exist_ok=True)
        logger.info(f"Saving components to: {output_components_dir}")

    # Output PDF (in-memory)
    out_doc = fitz.open()

    for page_index, pil_page in enumerate(page_iter, start=1):
        logger.info(f"Processing page {page_index}")
        w_px_orig, h_px_orig = pil_page.size
        width_pt = w_px_orig * 72.0 / input_dpi
        height_pt = h_px_orig * 72.0 / input_dpi
        logger.debug(f"Page {page_index} size: {w_px_orig}x{h_px_orig} px, {width_pt:.2f}x{height_pt:.2f} pt")

        # Segment at full resolution
        if mask_method == "cv":
            win_s, C_s, mk_s = _scale_cv_params_for_dpi(
                input_dpi=input_dpi,
                base_dpi=300.0,
                win_size=cv_win_size,
                C=cv_C,
                morph_kernel=cv_morph_kernel,
            )
            bg_full, fg_full, mask_full = segment_page_to_mrc_components_cv(
                pil_page, win_size=win_s, C=C_s, morph_kernel=mk_s
            )
        elif mask_method == "pil":
            bg_full, fg_full, mask_full = segment_page_to_mrc_components_pil(pil_page)
        else:
            raise ValueError("mask_method must be 'cv' or 'pil'")

        # True downsampling after segmentation
        if scale < 1.0:
            logger.debug(f"Downsampling page {page_index} by scale {scale:.4f}")
            new_size = (
                max(1, int(round(w_px_orig * scale))),
                max(1, int(round(h_px_orig * scale))),
            )
            logger.debug(f"New size: {new_size[0]}x{new_size[1]} px")
            bg_img = bg_full.resize(new_size, Image.LANCZOS)
            fg_img = fg_full.resize(new_size, Image.LANCZOS)

            # Downsample mask with block averaging + thresholding
            mask_np = (np.asarray(mask_full, dtype=np.uint8) // 255)

            sy = h_px_orig / new_size[1]
            sx = w_px_orig / new_size[0]
            out = np.zeros((new_size[1], new_size[0]), dtype=np.uint8)

            for y in range(new_size[1]):
                y0 = int(y * sy)
                y1 = int((y + 1) * sy)
                for x in range(new_size[0]):
                    x0 = int(x * sx)
                    x1 = int((x + 1) * sx)
                    block = mask_np[y0:y1, x0:x1]
                    out[y, x] = 255 if block.mean() > 0.5 else 0

            mask_img = Image.fromarray(out, mode="L")
        else:
            bg_img, fg_img, mask_img = bg_full, fg_full, mask_full

        # Encode components
        logger.debug(f"Encoding page {page_index} components")
        bg_bytes = encode_pil_to_bytes(bg_img, bg_format, quality=bg_quality)
        fg_bytes = encode_pil_to_bytes(fg_img, fg_format, quality=fg_quality)
        mask_bytes = encode_pil_to_bytes(mask_img, "PNG", optimize=True)
        
        logger.info(f"Page {page_index} sizes: BG={len(bg_bytes)/1024:.1f}KB, FG={len(fg_bytes)/1024:.1f}KB, Mask={len(mask_bytes)/1024:.1f}KB")

        # Optional dump to disk
        if output_components_dir:
            tag = f"p{page_index:04d}"
            with open(os.path.join(output_components_dir, f"{tag}_bg.{bg_format.lower()}"), "wb") as f:
                f.write(bg_bytes)
            with open(os.path.join(output_components_dir, f"{tag}_fg.{fg_format.lower()}"), "wb") as f:
                f.write(fg_bytes)
            with open(os.path.join(output_components_dir, f"{tag}_mask.png"), "wb") as f:
                f.write(mask_bytes)

        # Encode + insert
        page = out_doc.new_page(width=width_pt, height=height_pt)
        rect = fitz.Rect(0, 0, width_pt, height_pt)

        if flatten_to_jpeg:
            logger.debug(f"Flattening page {page_index} to single JPEG layer")
            # 1) Pre-compress BG/FG first (lossy), then decode back
            bg_j = jpeg_roundtrip_pil(bg_img, quality=bg_quality)
            fg_j = jpeg_roundtrip_pil(fg_img, quality=fg_quality)

            # 2) Composite AFTER lossy BG/FG compression
            flat_img = Image.composite(fg_img, bg_j, mask_img)

            # 3) Final JPEG encode of the flattened page
            flat_bytes = encode_pil_to_bytes(
                flat_img,
                "JPEG",
                quality=flatten_quality,
                subsampling=2,
                optimize=True,
                progressive=True,
            )

            if output_components_dir:
                tag = f"p{page_index:04d}"
                with open(os.path.join(output_components_dir, f"{tag}_flat.jpg"), "wb") as f:
                    f.write(flat_bytes)

            page.insert_image(rect, stream=flat_bytes, overlay=False)


        else:
            bg_bytes = encode_pil_to_bytes(bg_img, bg_format, quality=bg_quality)
            fg_bytes = encode_pil_to_bytes(fg_img, fg_format, quality=fg_quality)
            mask_bytes = encode_pil_to_bytes(mask_img, "PNG", optimize=True)

            # Optional dump
            if output_components_dir:
                tag = f"p{page_index:04d}"
                with open(os.path.join(output_components_dir, f"{tag}_bg.{bg_format.lower()}"), "wb") as f:
                    f.write(bg_bytes)
                with open(os.path.join(output_components_dir, f"{tag}_fg.{fg_format.lower()}"), "wb") as f:
                    f.write(fg_bytes)
                with open(os.path.join(output_components_dir, f"{tag}_mask.png"), "wb") as f:
                    f.write(mask_bytes)

            page.insert_image(rect, stream=bg_bytes, overlay=False)
            page.insert_image(rect, stream=fg_bytes, mask=mask_bytes, overlay=True)


    logger.info("Finalizing PDF output")
    out_bytes = out_doc.tobytes(garbage=4, deflate=True)
    out_doc.close()
    
    logger.info(f"Compression complete. Output size: {len(out_bytes)/1024:.1f}KB")

    if output_pdf_path:
        os.makedirs(os.path.dirname(output_pdf_path) or ".", exist_ok=True)
        with open(output_pdf_path, "wb") as f:
            f.write(out_bytes)
        logger.info(f"Saved compressed PDF to: {output_pdf_path}")
    
    # Save uncompressed version if path is provided (return original file_bytes)
    if output_uncompressed_pdf_path:
        os.makedirs(os.path.dirname(output_uncompressed_pdf_path) or ".", exist_ok=True)
        with open(output_uncompressed_pdf_path, "wb") as f:
            f.write(file_bytes)
        logger.info(f"Saved uncompressed PDF to: {output_uncompressed_pdf_path}")

    return out_bytes


def mrc_pdf_from_path(
    input_path: str,
    target_dpi: float,
    *,
    render_dpi: Optional[float] = None,
    output_pdf_path: Optional[str] = None,
    output_uncompressed_pdf_path: Optional[str] = None,
    output_components_dir: Optional[str] = None,
    progress_callback: Optional[callable] = None,
    **kwargs,
) -> bytes:
    """
    Convenience wrapper if you still want to start from a file path.
    
    Args:
        input_path: Path to input PDF or TIFF file.
        target_dpi: Desired output DPI.
        render_dpi: Rasterization DPI (for PDFs) or override DPI (for TIFFs).
        output_pdf_path: Optional path to write compressed output PDF.
        output_uncompressed_pdf_path: Optional path to write uncompressed PDF.
        output_components_dir: Optional dir to dump component images.
        progress_callback: Optional callback function(page_num, total_pages, stage) (currently not implemented).
        **kwargs: Additional arguments passed to mrc_pdf_from_bytes.
    
    Returns:
        PDF bytes.
    """
    logger.info(f"Processing file: {input_path}")
    ext = os.path.splitext(input_path)[1].lower()
    if ext == ".pdf":
        filetype = "pdf"
    elif ext in (".tif", ".tiff"):
        filetype = "tiff"
    else:
        raise ValueError("Unsupported input extension. Only .pdf and .tif/.tiff are supported.")

    with open(input_path, "rb") as f:
        data = f.read()

    logger.info(f"File size: {len(data)/1024:.1f}KB")

    return mrc_pdf_from_bytes(
        data,
        filetype=filetype,
        target_dpi=target_dpi,
        render_dpi=render_dpi,
        output_pdf_path=output_pdf_path,
        output_uncompressed_pdf_path=output_uncompressed_pdf_path,
        output_components_dir=output_components_dir,
        progress_callback=progress_callback,
        **kwargs,
    )
