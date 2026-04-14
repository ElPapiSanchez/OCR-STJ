from enum import Enum


class LANGS(Enum):
    ARA = "ara"
    CHI_SIM = "chi_sim"
    CHI_TRA = "chi_tra"
    DEU = "deu"
    ENG = "eng"
    EQU = "equ"
    FRA = "fra"
    HIN = "hin"
    IND = "ind"
    ITA = "ita"
    OSD = "osd"
    POR = "por"
    RUS = "rus"
    SPA = "spa"


class ENGINE_MODES(Enum):
    TESSERACT_ONLY = 0
    LSTM_ONLY = 1
    TESSERACT_LSTM_COMBINED = 2
    DEFAULT = 3  # Default


class SEGMENT_MODES(Enum):
    # OSD_ONLY = 0  # TODO: allow producing only OSD file without OCR
    AUTO_OSD = 1
    AUTO_ONLY = 2
    AUTO = 3  # Default
    SINGLE_COLUMN = 4
    SINGLE_BLOCK_VERT_TEXT = 5
    SINGLE_BLOCK = 6
    SINGLE_LINE = 7
    SINGLE_WORD = 8
    CIRCLE_WORD = 9
    SINGLE_CHAR = 10
    SPARSE_TEXT = 11
    SPARSE_TEXT_OSD = 12
    RAW_LINE = 13
    COUNT = 14


class THRESHOLD_METHODS(Enum):
    OTSU = 0  # DEFAULT
    LEPTONICA = 1
    SAUVOLA = 2
    ADAPTIVE_GAUSSIAN = 3
    NONE = -1  # Preprocessing only (bypass Tesseract thresholding)


class OUTPUTS(Enum):
    PDF_INDEXED = "pdf_indexed"
    PDF = "pdf"
    TXT = "txt"
    TXT_DELIMITED = "txt_delimited"
    CSV = "csv"
    NER = "ner"
    HOCR = "hocr"
    ALTO_XML = "xml"
