import os
import io
from typing import Optional, Tuple

import numpy as np
from PIL import Image, ImageFilter, ImageSequence
import fitz  # PyMuPDF

# OpenCV is now required because default mask method is CV
import cv2


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
    orig_rgb = pil_img.convert("RGB")
    gray = orig_rgb.convert("L")

    arr = np.asarray(gray, dtype=np.float32)
    p2, p98 = np.percentile(arr, (2, 98))
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

    return bg_img, fg_img, mask_img


# -------------------------------
# 1b. CV-based mask + segmentation (DEFAULT)
# -------------------------------

def detect_text_mask_cv(
    img_rgb: np.ndarray,
    win_size: int = 35,
    C: int = 10,
    morph_kernel: int = 3,
    fast_mode: bool = False,  # New parameter for faster processing
) -> np.ndarray:
    """
    OpenCV-based text mask.
    img_rgb: HxWx3 RGB uint8 array.
    Returns: mask uint8 (0 background, 255 foreground).
    fast_mode: If True, uses faster but slightly less accurate segmentation
    """
    gray = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2GRAY)
    
    # Use faster blur in fast mode
    if fast_mode:
        bg = cv2.GaussianBlur(gray, (0, 0), sigmaX=8, sigmaY=8)  # Reduced from 15
    else:
        bg = cv2.GaussianBlur(gray, (0, 0), sigmaX=15, sigmaY=15)
    
    norm = cv2.divide(gray, bg, scale=255)
    norm = cv2.normalize(norm, None, 0, 255, cv2.NORM_MINMAX)

    if win_size % 2 == 0:
        win_size += 1

    th = cv2.adaptiveThreshold(
        norm, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY_INV,
        75 if not fast_mode else 51,  # Smaller window in fast mode
        10
    )

    nb_components, output, stats, centroids = cv2.connectedComponentsWithStats(th, connectivity=8)
    sizes = stats[1:, cv2.CC_STAT_AREA]
    
    # Less strict filtering in fast mode
    if fast_mode:
        min_size = max(2, (img_rgb.shape[0] * img_rgb.shape[1]) // 100000)  # Half the strictness
    else:
        min_size = max(2, (img_rgb.shape[0] * img_rgb.shape[1]) // 200000)

    mask = np.zeros_like(th, dtype=np.uint8)
    for i, sz in enumerate(sizes):
        if sz >= min_size:
            mask[output == (i + 1)] = 255

    # Optional morphology, if you want it:
    # kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (morph_kernel, morph_kernel))
    # mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel)

    return mask


def segment_page_to_mrc_components_cv(
    pil_img: Image.Image,
    win_size: int = 35,
    C: int = 10,
    morph_kernel: int = 3,
    fast_mode: bool = False,  # New parameter for faster processing
) -> Tuple[Image.Image, Image.Image, Image.Image]:
    """
    CV-based segmentation using detect_text_mask_cv for the mask.
    Produces:
      - bg_img: smooth colour background (RGB)
      - fg_img: colour foreground-only (RGB on white)
      - mask_img: binary mask (L, 0/255)
    fast_mode: If True, uses faster but slightly less accurate segmentation
    """
    orig_rgb = pil_img.convert("RGB")
    img_np = np.asarray(orig_rgb, dtype=np.uint8)

    mask_np = detect_text_mask_cv(img_np, win_size=win_size, C=C, morph_kernel=morph_kernel, fast_mode=fast_mode)
    mask_np = np.where(mask_np > 0, 255, 0).astype(np.uint8)
    mask_final = mask_np > 0

    mask_img = Image.fromarray(mask_np, mode="L")

    # Background: blurred RGB original (faster blur in fast mode)
    if fast_mode:
        bg_img = orig_rgb.filter(ImageFilter.GaussianBlur(radius=3))  # Reduced from 5
    else:
        bg_img = orig_rgb.filter(ImageFilter.GaussianBlur(radius=5))

    # Foreground: (keep original RGB; mask is used as soft-mask in PDF)
    fg_arr = img_np.copy()
    # If you want white-out background instead, uncomment:
    # fg_arr[~mask_final] = 255
    fg_img = Image.fromarray(fg_arr, mode="RGB")

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
    fast_mode: bool = False,  # New parameter for faster processing
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
        output_components_dir: Optional dir to dump BG/FG/mask images per page for inspection.
        bg_format/fg_format: "JPEG" or "JPEG2000" (if Pillow supports JP2).
        bg_quality/fg_quality: quality for bg/fg formats.
        mask_method: "cv" (default) or "pil".
        cv_*: CV parameters (scaled with input_dpi vs base_dpi=300).
        flatten_to_jpeg: If True, flatten FG+BG into single JPEG layer.
        flatten_quality: Quality for flattened JPEG.
        progress_callback: Optional callback function(page_num, total_pages, stage) for progress updates.

    Returns:
        PDF bytes.
    """
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
        # Don't create iterator yet - we'll do it after getting page count
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
            bio.close()
        # Don't create iterator yet - we'll do it after getting page count

    # Downsample scale (true downsampling)
    scale = (target_dpi / input_dpi) if input_dpi > target_dpi else 1.0

    if output_components_dir:
        os.makedirs(output_components_dir, exist_ok=True)

    # Output PDF (in-memory)
    out_doc = fitz.open()
    
    # Get total page count WITHOUT loading all pages into memory
    # This prevents OOM on large documents by avoiding eager list creation
    if is_pdf:
        temp_doc = fitz.open(stream=file_bytes, filetype="pdf")
        total_pages = len(temp_doc)
        temp_doc.close()
    else:
        # For TIFF, we need to count frames
        bio = io.BytesIO(file_bytes)
        tiff_img = Image.open(bio)
        total_pages = getattr(tiff_img, 'n_frames', 1)
        bio.close()
    
    print(f"   🔄 Processing {total_pages} pages (DPI: {input_dpi:.0f} → {target_dpi:.0f}, scale: {scale:.2f})")
    
    # Now create the page iterator for processing (one page at a time)
    if is_pdf:
        page_iter = _iter_pil_pages_from_pdf_bytes(file_bytes, render_dpi=int(round(input_dpi)))
    else:
        page_iter = _iter_pil_pages_from_tiff_bytes(file_bytes)
    
    if progress_callback:
        progress_callback(0, total_pages, "starting")

    # Process pages one at a time from iterator (prevents OOM on large documents)
    for page_index, pil_page in enumerate(page_iter, start=1):
        print(f"   📄 Page {page_index}/{total_pages}: ", end="", flush=True)
        
        if progress_callback:
            progress_callback(page_index, total_pages, "processing")
        w_px_orig, h_px_orig = pil_page.size
        width_pt = w_px_orig * 72.0 / input_dpi
        height_pt = h_px_orig * 72.0 / input_dpi

        print(f"segmenting... ", end="", flush=True)
        
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
                pil_page, win_size=win_s, C=C_s, morph_kernel=mk_s, fast_mode=fast_mode
            )
        elif mask_method == "pil":
            bg_full, fg_full, mask_full = segment_page_to_mrc_components_pil(pil_page)
        else:
            raise ValueError("mask_method must be 'cv' or 'pil'")

        # True downsampling after segmentation
        if scale < 1.0:
            print(f"resizing... ", end="", flush=True)
            new_size = (
                max(1, int(round(w_px_orig * scale))),
                max(1, int(round(h_px_orig * scale))),
            )
            bg_img = bg_full.resize(new_size, Image.LANCZOS)
            fg_img = fg_full.resize(new_size, Image.LANCZOS)

            # Downsample mask with block averaging + thresholding
            mask_np = (np.asarray(mask_full, dtype=np.uint8) // 255)

            sy = h_px_orig / new_size[1]
            sx = w_px_orig / new_size[0]
            
            
            
            
            # Fast vectorized mask downsampling using OpenCV (much faster than Python loops)
            mask_np = np.asarray(mask_full, dtype=np.uint8)
            mask_resized = cv2.resize(
                mask_np, 
                new_size, 
                interpolation=cv2.INTER_AREA  # INTER_AREA = block averaging, perfect for downsampling
            )
            # Threshold to binary (>127 = foreground)
            mask_img = Image.fromarray(np.where(mask_resized > 127, 255, 0).astype(np.uint8), mode="L")

        else:
            bg_img, fg_img, mask_img = bg_full, fg_full, mask_full

        print(f"compressing... ", end="", flush=True)
        
        # Encode components
        bg_bytes = encode_pil_to_bytes(bg_img, bg_format, quality=bg_quality)
        fg_bytes = encode_pil_to_bytes(fg_img, fg_format, quality=fg_quality)
        mask_bytes = encode_pil_to_bytes(mask_img, "PNG", optimize=True)
        
        total_page_size = len(bg_bytes) + len(fg_bytes) + len(mask_bytes)
        print(f"✓ ({total_page_size / 1024:.1f} KB)")

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
            # 1) Pre-compress BG/FG first (lossy), then decode back
            bg_j = jpeg_roundtrip_pil(bg_img, quality=bg_quality)
            fg_j = jpeg_roundtrip_pil(fg_img, quality=fg_quality)

            # 2) Composite AFTER lossy BG/FG compression
            flat_img = Image.composite(fg_j, bg_j, mask_img)

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
        
        # Explicit cleanup to free memory after each page (prevents OOM on large documents)
        import gc
        # Clear all page-related objects
        del bg_full, fg_full, mask_full, bg_img, fg_img, mask_img, pil_page
        if 'bg_bytes' in locals():
            del bg_bytes
        if 'fg_bytes' in locals():
            del fg_bytes
        if 'mask_bytes' in locals():
            del mask_bytes
        if 'flat_img' in locals():
            del flat_img
        if 'flat_bytes' in locals():
            del flat_bytes
        gc.collect()

    print(f"   🔨 Finalizing PDF (optimizing and deflating)...")
    
    if progress_callback:
        progress_callback(total_pages, total_pages, "finalizing")
    
    out_bytes = out_doc.tobytes(garbage=4, deflate=True)
    out_doc.close()
    
    if progress_callback:
        progress_callback(total_pages, total_pages, "complete")

    if output_pdf_path:
        os.makedirs(os.path.dirname(output_pdf_path) or ".", exist_ok=True)
        with open(output_pdf_path, "wb") as f:
            f.write(out_bytes)

    return out_bytes


def mrc_pdf_from_path(
    input_path: str,
    target_dpi: float,
    *,
    render_dpi: Optional[float] = None,
    output_pdf_path: Optional[str] = None,
    output_components_dir: Optional[str] = None,
    progress_callback: Optional[callable] = None,
    **kwargs,
) -> bytes:
    """
    Wrapper for mrc_pdf_from_bytes that reads input from a file path.
    
    Args:
        input_path: Path to input PDF or TIFF file.
        target_dpi: Desired output DPI.
        render_dpi: Rasterization DPI (for PDFs) or override DPI (for TIFFs).
        output_pdf_path: Optional path to write output PDF.
        output_components_dir: Optional dir to dump component images.
        progress_callback: Optional callback function(page_num, total_pages, stage).
        **kwargs: Additional arguments passed to mrc_pdf_from_bytes.
    
    Returns:
        PDF bytes.
    """
    ext = os.path.splitext(input_path)[1].lower()
    if ext == ".pdf":
        filetype = "pdf"
    elif ext in (".tif", ".tiff"):
        filetype = "tiff"
    else:
        raise ValueError("Unsupported input extension. Only .pdf and .tif/.tiff are supported.")

    with open(input_path, "rb") as f:
        data = f.read()

    return mrc_pdf_from_bytes(
        data,
        filetype=filetype,
        target_dpi=target_dpi,
        render_dpi=render_dpi,
        output_pdf_path=output_pdf_path,
        output_components_dir=output_components_dir,
        progress_callback=progress_callback,
        **kwargs,
    )
