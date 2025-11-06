import i18next from "i18next";

export const defaultLangs = ["por"];

export const tesseractLangList = () => [
    { value: "deu", description: i18next.t("languages.german") },
    { value: "spa", description: i18next.t("languages.spanish") },
    { value: "fra", description: i18next.t("languages.french") },
    { value: "eng", description: i18next.t("languages.english") },
    { value: "por", description: i18next.t("languages.portuguese") },
    { value: "equ", description: i18next.t("languages.math module") },
    { value: "osd", description: i18next.t("languages.osd module") },
];

export const defaultOutputs = ["pdf"];
export const tesseractOutputsList = () => [
    { value: "pdf_indexed", description: i18next.t("output.pdf indexed") },
    { value: "pdf", description: i18next.t("output.pdf") },
    { value: "txt", description: i18next.t("output.txt") },
    { value: "txt_delimited", description: i18next.t("output.txt delimited") },
    { value: "csv", description: i18next.t("output.csv") },
    { value: "ner", description: i18next.t("output.ner") },
    { value: "hocr", description: i18next.t("output.hocr") },
    { value: "xml", description: i18next.t("output.xml") },
];

export const defaultEngine = "pytesseract";
export const engineList = () => [
    { value: "pytesseract", description: i18next.t("engine.pytesseract") },
    { value: "tesserOCR", description: i18next.t("engine.tesserOCR") },
];

export const defaultEngineMode = 3;
export const tesseractModeList = () => [
    { value: 0, description: i18next.t("mode.original") },
    { value: 1, description: i18next.t("mode.lstm") },
    { value: 2, description: i18next.t("mode.combined") },
    { value: 3, description: i18next.t("mode.default") },
];

export const defaultSegmentationMode = 3;
export const tesseractSegmentList = () => [
    { value: 1, description: i18next.t("segmentation mode.auto with osd") },
    { value: 2, description: i18next.t("segmentation mode.auto no osd") },
    { value: 3, description: i18next.t("segmentation mode.default") },
    { value: 4, description: i18next.t("segmentation mode.column variable lines") },
    { value: 5, description: i18next.t("segmentation mode.block vertical") },
    { value: 6, description: i18next.t("segmentation mode.block uniform") },
    { value: 7, description: i18next.t("segmentation mode.single line") },
    { value: 8, description: i18next.t("segmentation mode.single word") },
    { value: 9, description: i18next.t("segmentation mode.single circle word") },
    { value: 10, description: i18next.t("segmentation mode.single char") },
    { value: 11, description: i18next.t("segmentation mode.sparse text") },
    { value: 12, description: i18next.t("segmentation mode.sparse text osd") },
    { value: 13, description: i18next.t("segmentation mode.single line hack") },
];

export const defaultThresholding = 0;
export const tesseractThreshList = () => [
    { value: 0, description: i18next.t("threshold.otsu") },
    { value: 1, description: i18next.t("threshold.leptonica") },
    { value: 2, description: i18next.t("threshold.sauvola") },
];

export const defaultConfig = {
    lang: defaultLangs,
    outputs: defaultOutputs,
    dpiVal: null,
    otherParams: null,
    engine: defaultEngine,
    engineMode: defaultEngineMode,
    segmentMode: defaultSegmentationMode,
    thresholdMethod: defaultThresholding,
};

export const emptyConfig = {
    lang: [],
    outputs: [],
    engine: "",
    engineMode: -1,
    segmentMode: -1,
    thresholdMethod: -1,
    dpiVal: null,
    otherParams: null,
};
