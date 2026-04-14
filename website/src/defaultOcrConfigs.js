import i18next from "i18next";

export const defaultLangs = ["por"];

// Actual language packs
export const tesseractLanguagesList = () => [
    { value: "ara", translationKey: "languages.arabic" },
    { value: "chi_sim", translationKey: "languages.chinese_simplified" },
    { value: "chi_tra", translationKey: "languages.chinese_traditional" },
    { value: "deu", translationKey: "languages.german" },
    { value: "eng", translationKey: "languages.english" },
    { value: "fra", translationKey: "languages.french" },
    { value: "hin", translationKey: "languages.hindi" },
    { value: "ind", translationKey: "languages.indonesian" },
    { value: "ita", translationKey: "languages.italian" },
    { value: "por", translationKey: "languages.portuguese" },
    { value: "rus", translationKey: "languages.russian" },
    { value: "spa", translationKey: "languages.spanish" },
];

// Special detection modules
export const tesseractModulesList = () => [
    { value: "equ", translationKey: "languages.math module" },
    { value: "osd", translationKey: "languages.osd module" },
];

// Combined list for backwards compatibility
export const tesseractLangList = () => [
    ...tesseractLanguagesList(),
    ...tesseractModulesList(),
];

export const defaultOutputs = ["pdf"];

// Primary outputs shown on main page
export const tesseractMainOutputsList = () => [
    { value: "pdf", translationKey: "output.pdf" },
    { value: "pdf_indexed", translationKey: "output.pdf indexed" },
    { value: "txt", translationKey: "output.txt" },
];

// Advanced outputs shown in "More outputs" dialog
export const tesseractAdvancedOutputsList = () => [
    { value: "txt_delimited", translationKey: "output.txt delimited" },
    { value: "csv", translationKey: "output.csv" },
    { value: "ner", translationKey: "output.ner" },
    { value: "hocr", translationKey: "output.hocr" },
    { value: "xml", translationKey: "output.xml" },
];

// Combined list for backwards compatibility
export const tesseractOutputsList = () => [
    ...tesseractMainOutputsList(),
    ...tesseractAdvancedOutputsList(),
];

export const defaultEngine = "tesserocr";
export const engineList = () => [
    { value: "tesserocr", description: i18next.t("engine.tesserOCR") },
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

export const defaultThresholding = 3;  // Adaptive Gaussian (preprocessing default)
export const tesseractThreshList = () => [
    { value: 0, description: i18next.t("threshold.otsu") },
    { value: 1, description: i18next.t("threshold.leptonica") },
    { value: 2, description: i18next.t("threshold.sauvola") },
    { value: 3, description: i18next.t("threshold.adaptive_gaussian") },
    { value: -1, description: i18next.t("threshold.none") },
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
    compress: true,
    preprocessing: {
        enabled: true,
        grayscale: true,
        clahe: true,
        clahe_clip_limit: 2.5,  // Moderate contrast (was 3.0)
        clahe_tile_size: 8,
        median_blur: true,
        median_blur_kernel: 9,  // Much stronger blur to remove speckle noise (was 5)
        threshold_method: "otsu",  // OTSU works better for uniform backgrounds (was adaptive_gaussian)
        adaptive_block_size: 21,
        adaptive_c: 5,
        morphological_opening: true,
        morphological_closing: true,
        morph_kernel_size: 7,  // Larger kernel for aggressive cleanup (was 5)
        deskew: true,
    },
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
    compress: true,
            preprocessing: {
                enabled: true,
                grayscale: true,
                clahe: true,
                clahe_clip_limit: 2.5,
                clahe_tile_size: 8,
                median_blur: true,
                median_blur_kernel: 9,
                threshold_method: "otsu",
                adaptive_block_size: 21,
                adaptive_c: 5,
                morphological_opening: true,
                morphological_closing: true,
                morph_kernel_size: 7,
                deskew: false,
            },
};
