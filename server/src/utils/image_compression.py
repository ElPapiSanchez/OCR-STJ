import gc
import os
import io
from typing import Optional, Tuple, Any, Dict

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

def make_inpainted_background_cv(
    pil_img: Image.Image,
    mask_img: Image.Image,
    inpaint_method: str = "telea",   # "telea" | "ns" | "masked_blur"
    inpaint_radius: int = 3,
    dilate_px: int = 1,
    post_blur_radius: float = 1.5,
) -> Image.Image:
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

    mask = np.zeros_like(th, dtype=np.uint8)
    for i, sz in enumerate(sizes):
        if sz >= min_size:
            mask[output == (i + 1)] = 255

    # Optional morphology, if you want it:
    # kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (morph_kernel, morph_kernel))
    # mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel)

    return mask


def detect_text_mask_sauvola(
    img_rgb: np.ndarray,
    win: int = 51,
    k: float = 0.2,
    R: float = 128.0,
) -> np.ndarray:
    """Single-window Sauvola binarisation."""
    gray = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2GRAY)

    bg = cv2.GaussianBlur(gray, (0, 0), sigmaX=15, sigmaY=15)
    norm = cv2.divide(gray, bg, scale=255)
    norm = cv2.normalize(norm, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)

    h, w = norm.shape
    norm_f = norm.astype(np.float64)

    win = win | 1
    local_mean = cv2.boxFilter(norm_f, ddepth=-1, ksize=(win, win),
                               borderType=cv2.BORDER_REFLECT)
    local_sq_mean = cv2.boxFilter(norm_f * norm_f, ddepth=-1, ksize=(win, win),
                                  borderType=cv2.BORDER_REFLECT)
    local_var = np.maximum(local_sq_mean - local_mean * local_mean, 0.0)
    local_std = np.sqrt(local_var)

    threshold = local_mean * (1.0 + k * (local_std / R - 1.0))
    mask = np.where(norm_f < threshold, 255, 0).astype(np.uint8)

    nb_components, output, stats, _ = cv2.connectedComponentsWithStats(mask, connectivity=8)
    sizes = stats[1:, cv2.CC_STAT_AREA]
    min_size = max(2, (h * w) // 200000)
    cleaned = np.zeros_like(mask, dtype=np.uint8)
    for i, sz in enumerate(sizes):
        if sz >= min_size:
            cleaned[output == (i + 1)] = 255

    return cleaned


def segment_page_to_mrc_components_cv(
    pil_img: Image.Image,
    win_size: int = 35,
    C: int = 10,
    morph_kernel: int = 3,
    mask_method: str = "sauvola",
    inpaint_bg: bool = False,
    inpaint_method: str = "telea",
    inpaint_radius: int = 3,
    inpaint_dilate_px: int = 1,
    inpaint_post_blur: float = 1.5,
    input_dpi: float = 0.0,
    sauvola_max_dpi: float = 300.0,
) -> Tuple[Image.Image, Image.Image, Image.Image]:
    """
    CV-based segmentation. mask_method selects the binarisation algorithm:
      "sauvola" - Sauvola thresholding (default)
      "cv"      - adaptive Gaussian threshold
    Produces:
      - bg_img: smooth colour background (RGB)
      - fg_img: colour foreground-only (RGB on white)
      - mask_img: binary mask (L, 0/255)

    When inpaint_bg=True, text regions identified by the mask are removed from
    the background via OpenCV inpainting before the blur, preventing ghosted
    text in the final composite.
    """
    orig_rgb = pil_img.convert("RGB")
    img_np = np.asarray(orig_rgb, dtype=np.uint8)

    orig_h, orig_w = img_np.shape[:2]

    if mask_method == "sauvola":
        seg_img = img_np
        if input_dpi > sauvola_max_dpi > 0:
            s = sauvola_max_dpi / input_dpi
            small_w = max(1, int(round(orig_w * s)))
            small_h = max(1, int(round(orig_h * s)))
            seg_img = cv2.resize(img_np, (small_w, small_h),
                                 interpolation=cv2.INTER_AREA)
        mask_np = detect_text_mask_sauvola(seg_img)
        if mask_np.shape[:2] != (orig_h, orig_w):
            mask_np = cv2.resize(mask_np, (orig_w, orig_h),
                                 interpolation=cv2.INTER_NEAREST)
    else:
        mask_np = detect_text_mask_cv(img_np, win_size=win_size, C=C, morph_kernel=morph_kernel)
    mask_np = np.where(mask_np > 0, 255, 0).astype(np.uint8)
    mask_final = mask_np > 0

    mask_img = Image.fromarray(mask_np, mode="L")

    if inpaint_bg:
        bg_img = make_inpainted_background_cv(
            orig_rgb,
            mask_img,
            inpaint_method=inpaint_method,
            inpaint_radius=inpaint_radius,
            dilate_px=inpaint_dilate_px,
            post_blur_radius=inpaint_post_blur,
        )
    else:
        bg_img = orig_rgb.filter(ImageFilter.GaussianBlur(radius=5))

    fg_arr = img_np.copy()
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


def _read_image_dpi(image_bytes: bytes, fallback: float) -> float:
    """Read DPI from JPEG/PNG metadata; return fallback if absent or invalid."""
    try:
        bio = io.BytesIO(image_bytes)
        img = Image.open(bio)
        dpi_info = img.info.get("dpi")
        if dpi_info:
            dpi_val = float(dpi_info[0])
            if dpi_val > 0:
                return dpi_val
    except Exception:
        pass
    return fallback


def _iter_pil_pages_from_image_bytes(image_bytes: bytes):
    """Yield a single RGB PIL image from JPEG or PNG bytes."""
    bio = io.BytesIO(image_bytes)
    img = Image.open(bio)
    yield img.convert("RGB")


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


def _build_pdfa2b_xmp() -> str:
    return (
        '<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description rdf:about=""'
        ' xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/">'
        '<pdfaid:part>2</pdfaid:part>'
        '<pdfaid:conformance>B</pdfaid:conformance>'
        '</rdf:Description>'
        '</rdf:RDF>'
        '</x:xmpmeta>'
        '<?xpacket end="w"?>'
    )


def mrc_pdf_from_bytes(
    file_bytes: bytes,
    filetype: str,
    target_dpi: float,
    *,
    assume_dpi: float = 300.0,
    render_dpi: Optional[float] = None,
    output_pdf_path: Optional[str] = None,
    output_components_dir: Optional[str] = None,
    bg_format: str = "JPEG",
    fg_format: str = "JPEG",
    bg_quality: int = 40,
    fg_quality: int = 80,
    mask_method: str = "sauvola",
    cv_win_size: int = 20,
    cv_C: int = 10,
    cv_morph_kernel: int = 3,
    flatten_to_jpeg: bool = False,
    flatten_quality: int = 85,
    inpaint_bg: bool = False,
    inpaint_method: str = "telea",
    inpaint_radius: int = 3,
    inpaint_dilate_px: int = 1,
    inpaint_post_blur: float = 1.5,
    progress_callback: Optional[callable] = None,
) -> bytes:
    """
    Run the MRC-style pipeline on an in-memory file and return the output PDF bytes.

    Args:
        assume_dpi: DPI to assume when the file has no metadata DPI.  Applied
                    uniformly to all file types (PDF render DPI, TIFF, JPEG, PNG).
        render_dpi: Explicit override — always used as input DPI when set.
    """
    ft = filetype.lower().strip(".")
    if ft not in ("pdf", "tif", "tiff", "jpg", "jpeg", "png"):
        raise ValueError("filetype must be 'pdf', 'tiff'/'tif', 'jpeg'/'jpg', or 'png'")

    is_pdf = ft == "pdf"
    is_tiff = ft in ("tif", "tiff")

    if target_dpi <= 0:
        raise ValueError("target_dpi must be > 0")

    # --- Resolve input DPI uniformly across all file types ---
    if render_dpi is not None:
        input_dpi = float(render_dpi)
    elif is_pdf:
        input_dpi = float(int(round(assume_dpi)))
    elif is_tiff:
        bio = io.BytesIO(file_bytes)
        timg = Image.open(bio)
        dpi_tuple = timg.info.get("dpi")
        if dpi_tuple and float(dpi_tuple[0]) > 0:
            input_dpi = float(dpi_tuple[0])
        else:
            input_dpi = float(assume_dpi)
    else:
        meta_dpi = _read_image_dpi(file_bytes, fallback=0.0)
        input_dpi = meta_dpi if meta_dpi > 0 else float(assume_dpi)

    print(f"📦 COMPRESSION START: filetype={ft}, file_size={len(file_bytes)/1024/1024:.1f}MB")
    print(f"📦 DPI: input={input_dpi:.1f}, target={target_dpi:.1f}, scale={(target_dpi/input_dpi):.4f}")
    print(f"📦 Settings: bg_quality={bg_quality}, fg_quality={fg_quality}, mask_method={mask_method}")

    # Get total page count for progress tracking
    total_pages = 1
    if is_pdf:
        pdf_doc = fitz.open(stream=file_bytes, filetype="pdf")
        total_pages = pdf_doc.page_count
        pdf_doc.close()
        input_dpi = float(int(round(input_dpi)))
        page_iter = _iter_pil_pages_from_pdf_bytes(file_bytes, render_dpi=int(round(input_dpi)))
        print(f"📦 Loading PDF with render_dpi={int(round(input_dpi))}, total_pages={total_pages}")
    elif is_tiff:
        tiff_img = Image.open(io.BytesIO(file_bytes))
        try:
            total_pages = tiff_img.n_frames
        except AttributeError:
            total_pages = 1
        page_iter = _iter_pil_pages_from_tiff_bytes(file_bytes)
        print(f"📦 Loading TIFF iterator, total_pages={total_pages}")
    else:
        page_iter = _iter_pil_pages_from_image_bytes(file_bytes)
        print(f"📦 Loading single image")

    # Downsample scale (true downsampling)
    scale = (target_dpi / input_dpi) if input_dpi > target_dpi else 1.0

    if output_components_dir:
        os.makedirs(output_components_dir, exist_ok=True)

    # Output PDF (in-memory)
    out_doc = fitz.open()

    for page_index, pil_page in enumerate(page_iter, start=1):
        w_px_orig, h_px_orig = pil_page.size
        width_pt = w_px_orig * 72.0 / input_dpi
        height_pt = h_px_orig * 72.0 / input_dpi

        print(f"📦 Page {page_index}: Loaded {w_px_orig}×{h_px_orig}px → {width_pt:.1f}×{height_pt:.1f}pt")

        # Segment at full resolution
        if mask_method in ("cv", "sauvola"):
            win_s, C_s, mk_s = _scale_cv_params_for_dpi(
                input_dpi=input_dpi,
                base_dpi=300.0,
                win_size=cv_win_size,
                C=cv_C,
                morph_kernel=cv_morph_kernel,
            )
            print(f"📦 Page {page_index}: Starting {mask_method.upper()} segmentation (win_size={win_s}, C={C_s})...")
            bg_full, fg_full, mask_full = segment_page_to_mrc_components_cv(
                pil_page, win_size=win_s, C=C_s, morph_kernel=mk_s,
                mask_method=mask_method,
                inpaint_bg=inpaint_bg,
                inpaint_method=inpaint_method,
                inpaint_radius=inpaint_radius,
                inpaint_dilate_px=inpaint_dilate_px,
                inpaint_post_blur=inpaint_post_blur,
                input_dpi=input_dpi,
            )
            print(f"📦 Page {page_index}: Segmentation complete")
        elif mask_method == "pil":
            print(f"📦 Page {page_index}: Starting PIL segmentation...")
            bg_full, fg_full, mask_full = segment_page_to_mrc_components_pil(pil_page)
            if inpaint_bg:
                bg_full = make_inpainted_background_cv(
                    pil_page, mask_full,
                    inpaint_method=inpaint_method,
                    inpaint_radius=inpaint_radius,
                    dilate_px=inpaint_dilate_px,
                    post_blur_radius=inpaint_post_blur,
                )
            print(f"📦 Page {page_index}: Segmentation complete")
        else:
            raise ValueError("mask_method must be 'sauvola', 'cv', or 'pil'")

        del pil_page

        if scale < 1.0:
            new_size = (
                max(1, int(round(w_px_orig * scale))),
                max(1, int(round(h_px_orig * scale))),
            )
            print(f"📦 Page {page_index}: Downsampling {w_px_orig}×{h_px_orig} → {new_size[0]}×{new_size[1]}")
            bg_img = bg_full.resize(new_size, Image.LANCZOS)
            fg_img = fg_full.resize(new_size, Image.LANCZOS)

            mask_area = cv2.resize(np.asarray(mask_full, dtype=np.uint8), new_size, interpolation=cv2.INTER_AREA)
            mask_img = Image.fromarray((mask_area > 127).astype(np.uint8) * 255, mode="L")
            del mask_area
            del bg_full, fg_full, mask_full
        else:
            bg_img, fg_img, mask_img = bg_full, fg_full, mask_full

        page = out_doc.new_page(width=width_pt, height=height_pt)
        rect = fitz.Rect(0, 0, width_pt, height_pt)

        print(f"📦 Page {page_index}: Encoding components...")
        if flatten_to_jpeg:
            bg_j = jpeg_roundtrip_pil(bg_img, quality=bg_quality)
            fg_j = jpeg_roundtrip_pil(fg_img, quality=fg_quality)
            flat_img = Image.composite(fg_img, bg_j, mask_img)
            del bg_j, fg_j, bg_img, fg_img, mask_img
            flat_bytes = encode_pil_to_bytes(
                flat_img,
                "JPEG",
                quality=flatten_quality,
                subsampling=2,
                optimize=True,
                progressive=True,
            )
            del flat_img
            if output_components_dir:
                tag = f"p{page_index:04d}"
                with open(os.path.join(output_components_dir, f"{tag}_flat.jpg"), "wb") as f:
                    f.write(flat_bytes)
            page.insert_image(rect, stream=flat_bytes, overlay=False)
            del flat_bytes
            print(f"📦 Page {page_index}: Flattened JPEG inserted")
        else:
            bg_bytes = encode_pil_to_bytes(bg_img, bg_format, quality=bg_quality)
            del bg_img
            fg_bytes = encode_pil_to_bytes(fg_img, fg_format, quality=fg_quality)
            del fg_img
            mask_bytes = encode_pil_to_bytes(mask_img, "PNG", optimize=True)
            del mask_img
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
            print(f"📦 Page {page_index}: BG/FG/Mask layers inserted")
            del bg_bytes, fg_bytes, mask_bytes

        print(f"📦 Page {page_index}: Complete!")
        
        # Call progress callback if provided
        if progress_callback:
            progress_callback(page_index, total_pages)
        
        gc.collect()

    print(f"📦 Finalizing PDF...")
    out_doc.set_xml_metadata(_build_pdfa2b_xmp())
    out_bytes = out_doc.tobytes(garbage=4, deflate=True)
    out_doc.close()

    print(f"📦 COMPRESSION COMPLETE: Output size={len(out_bytes)/1024/1024:.1f}MB")

    if output_pdf_path:
        os.makedirs(os.path.dirname(output_pdf_path) or ".", exist_ok=True)
        with open(output_pdf_path, "wb") as f:
            f.write(out_bytes)

    return out_bytes


def mrc_pdf_from_path(
    input_path: str,
    target_dpi: float,
    *,
    assume_dpi: float = 300.0,
    render_dpi: Optional[float] = None,
    output_pdf_path: Optional[str] = None,
    output_components_dir: Optional[str] = None,
    **kwargs,
) -> bytes:
    """Convenience wrapper that starts from a file path."""
    ext = os.path.splitext(input_path)[1].lower()
    if ext == ".pdf":
        filetype = "pdf"
    elif ext in (".tif", ".tiff"):
        filetype = "tiff"
    elif ext in (".jpg", ".jpeg"):
        filetype = "jpeg"
    elif ext == ".png":
        filetype = "png"
    else:
        raise ValueError("Unsupported input extension. Only .pdf, .tif/.tiff, .jpg/.jpeg, and .png are supported.")

    with open(input_path, "rb") as f:
        data = f.read()

    return mrc_pdf_from_bytes(
        data,
        filetype=filetype,
        target_dpi=target_dpi,
        assume_dpi=assume_dpi,
        render_dpi=render_dpi,
        output_pdf_path=output_pdf_path,
        output_components_dir=output_components_dir,
        **kwargs,
    )
