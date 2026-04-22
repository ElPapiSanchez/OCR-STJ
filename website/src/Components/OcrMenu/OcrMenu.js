import React from 'react';
import axios from "axios";

import {withTranslation} from "react-i18next";

import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import CircularProgress from "@mui/material/CircularProgress";
import Autocomplete from "@mui/material/Autocomplete";
import TextField from "@mui/material/TextField";
import CheckRoundedIcon from "@mui/icons-material/CheckRounded";
import RotateLeft from "@mui/icons-material/RotateLeft";
import SaveIcon from "@mui/icons-material/Save";
import FormControlLabel from "@mui/material/FormControlLabel";
import FormLabel from "@mui/material/FormLabel";
import RadioGroup from "@mui/material/RadioGroup";
import Radio from "@mui/material/Radio";
import FormControl from "@mui/material/FormControl";
import Switch from "@mui/material/Switch";
import MenuItem from "@mui/material/MenuItem";
import Select from "@mui/material/Select";
import InputLabel from "@mui/material/InputLabel";
import Dialog from "@mui/material/Dialog";
import DialogTitle from "@mui/material/DialogTitle";
import DialogContent from "@mui/material/DialogContent";
import DialogActions from "@mui/material/DialogActions";
import SettingsIcon from "@mui/icons-material/Settings";

import {
    defaultConfig,
    emptyConfig,
    engineList,
    tesseractLangList,
    tesseractLanguagesList,
    tesseractModulesList,
    tesseractModeList,
    tesseractOutputsList,
    tesseractMainOutputsList,
    tesseractAdvancedOutputsList,
    tesseractSegmentList,
    tesseractThreshList,
} from "defaultOcrConfigs";

import ReturnButton from 'Components/FileSystem/ReturnButton';
import ConfirmLeave from 'Components/Notifications/ConfirmLeave';
import Notification from 'Components/Notifications/Notification';
import CheckboxList from 'Components/Form/CheckboxList';
import InfoTooltip from 'Components/Form/InfoTooltip';

const API_URL = `${window.location.protocol}//${window.location.host}/${process.env.REACT_APP_API_URL}`;


class OcrMenu extends React.Component {
    constructor(props) {
        super(props);
        const usingDefault = this.props.customConfig == null;  // null or undefined
        const engines = engineList();
        const modes = tesseractModeList();
        const segments = tesseractSegmentList();
        const thresholds = tesseractThreshList();
        const outputs = tesseractOutputsList();
        // hOCR and ALTO are now supported for multi-page documents
        // outputs[outputs.length - 2].disabled = !this.props.isSinglePage && !this.props.isFolder;
        // outputs[outputs.length - 1].disabled = !this.props.isSinglePage && !this.props.isFolder;
        this.state = {
            ...emptyConfig,
            compress: true,  // Ensure compress is always initialized
            compressionTargetDpi: 100,
            compressionBgQuality: 40,
            compressionFgQuality: 80,
            presetsList: [],
            presetName: "",
            defaultConfig: defaultConfig,
            // lists of options in state, to allow changing them dynamically depending on other choices
            // e.g. when choosing an OCR engine that has different parameter values
            engineOptions: engines,
            engineModeOptions: modes,
            segmentModeOptions: segments,
            thresholdMethodOptions: thresholds,
            outputOptions: outputs,
            usingDefault: usingDefault,
            uncommittedChanges: false,
            loaded: false,  // true if default configuration has been fetched and page is ready
            fetchingPreset: false,  // true if selected preset has been fetched
            advancedDialogOpen: false,  // for advanced settings dialog
            moreOutputsDialogOpen: false,  // for more outputs dialog
        }

        // Disable options restricted to single-page if configuring for multi-page documents
        //tesseractOutputsList[tesseractOutputsList.length-2]["disabled"] = !this.props.isSinglePage && !this.props.isFolder;  // hOCR output
        //tesseractOutputsList[tesseractOutputsList.length-1]["disabled"] = !this.props.isSinglePage && !this.props.isFolder;  // ALTO output

        this.confirmLeave = React.createRef();
        this.successNot = React.createRef();
        this.errorNot = React.createRef();

        //this.algoDropdown = React.createRef();

        this.storageMenu = React.createRef();

        this.dpiField = React.createRef();
        this.moreParams = React.createRef();

        this.goBack = this.goBack.bind(this);
        this.leave = this.leave.bind(this);
        this.setLangList = this.setLangList.bind(this);
        this.setOutputList = this.setOutputList.bind(this);
    }

    preventExit(event) {
        event.preventDefault();
        event.returnValue = '';
    }

    fetchDefaultConfig(savedConfig = null) {
        axios.get(API_URL + '/default-config')
            .then(({ data }) => {
                if (!this.state.loaded) {
                    // entering config menu, set initial config
                    // Priority: savedConfig (from backend) > props.customConfig > default
                    const configToApply = savedConfig || this.props.customConfig;
                    const usingDefault = !configToApply || configToApply === "default";
                    const initialConfig = Object.assign({...data}, configToApply);
                    // Ensure compress is always set (default to true if missing)
                    if (initialConfig.compress === undefined || initialConfig.compress === null) {
                        initialConfig.compress = true;
                    }
                    this.setState({...initialConfig, defaultConfig: data, loaded: true, usingDefault: usingDefault});
                } else {
                    this.setState({defaultConfig: data});
                }
            })
            .catch(err => {
                this.errorNot.current.openNotif(this.props.t("error fetch default config"));
                if (!this.state.loaded) {
                    // entering config, use hardcoded default for initial config
                    const configToApply = savedConfig || this.props.customConfig;
                    const usingDefault = !configToApply || configToApply === "default";
                    const initialConfig = Object.assign({...defaultConfig}, configToApply);
                    // Ensure compress is always set (default to true if missing)
                    if (initialConfig.compress === undefined || initialConfig.compress === null) {
                        initialConfig.compress = true;
                    }
                    this.setState({...initialConfig, loaded: true, usingDefault: usingDefault});
                }
            });
    }

    constructPath() {
        // Build path correctly, avoiding double slashes
        let parts = [];
        if (this.props.spaceId) {
            parts.push(this.props.spaceId);
        }
        if (this.props.current_folder) {
            parts.push(this.props.current_folder);
        }
        parts.push(this.props.filename);
        return parts.join('/');
    }

    /**
     * Fetch the document's saved OCR config from the backend.
     * This ensures we always get the latest saved config.
     */
    fetchDocumentConfig() {
        const path = this.constructPath();
        axios.get(API_URL + '/get-config', {
            params: {
                _private: this.props._private,
                path: path
            }
        })
        .then(({ data }) => {
            if (data.success && data.config) {
                // Document has a saved custom config
                this.fetchDefaultConfig(data.config);
            } else {
                // No saved config - use default
                this.fetchDefaultConfig(null);
            }
        })
        .catch(err => {
            // Fallback to using prop or default
            this.fetchDefaultConfig(this.props.customConfig);
        });
    }

    fetchConfigPreset(name) {
        this.setState({fetchingPreset: true});
        axios.get(API_URL + '/config-preset', {
            params: {
                name: name,
            }
        })
            .then(({ data }) => {
                this.setState({
                    ...data,
                    presetName: name,
                    usingDefault: false,
                    fetchingPreset: false,
                    uncommittedChanges: true
                });
            })
            .catch(err => {
                this.errorNot.current.openNotif(this.props.t("error fetch preset"));
                this.setState({presetName: null, fetchingPreset: false});
            });
    }

    fetchPresetsList() {
        axios.get(API_URL + '/presets-list')
            .then(({ data }) => {
                this.setState({presetsList: data});
            })
            .catch(err => {
                this.errorNot.current.openNotif(this.props.t("error fetch presets list"));
            });
    }

    componentDidMount() {
        // Fetch the document's saved config first, which then fetches default config
        this.fetchDocumentConfig();
        this.fetchPresetsList();
        this.interval = setInterval(() => {
            this.fetchDefaultConfig();
            this.fetchPresetsList();
        }, 120000);  // getting an updated default configuration for every 2 minutes on this page is already generous
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
        if (!prevState.uncommittedChanges && this.state.uncommittedChanges) {
            window.addEventListener('beforeunload', this.preventExit);
        } else if (prevState.uncommittedChanges && !this.state.uncommittedChanges) {
            window.removeEventListener('beforeunload', this.preventExit);
        }
    }

    componentWillUnmount() {
        if (this.interval)
            clearInterval(this.interval);
    }

    getConfig() {
        const config = {
            engine: this.state.engine,
            lang: this.state.lang,
            outputs: this.state.outputs,
            engineMode: this.state.engineMode,
            segmentMode: this.state.segmentMode,
            thresholdMethod: this.state.thresholdMethod,
            compress: this.state.compress !== undefined ? this.state.compress : true,
            compressionTargetDpi: Number(this.state.compressionTargetDpi),
            compressionBgQuality: Number(this.state.compressionBgQuality),
            compressionFgQuality: Number(this.state.compressionFgQuality),
            compressionFlattenToJpeg: true,  // Always flatten to JPEG
            preprocessing: this.state.preprocessing,
        }
        if (this.state.dpiVal !== null && this.state.dpiVal !== "") {
            config.dpi = this.state.dpiVal;
        }
        if (this.state.otherParams !== null && this.state.otherParams !== "") {
            config.otherParams = this.state.otherParams;
        }
        return config;
    }

    selectPreset(name) {
        if (name === null || name === "") {  // cleared the preset box, not applying preset
            this.setState({presetName: null});
        } else {
            this.fetchConfigPreset(name);
        }
    }

    restoreDefault() {
        if (this.state.usingDefault) return;
        const restoredConfig = {
            ...this.state.defaultConfig,
            presetName: null,
            usingDefault: true,
            uncommittedChanges: this.props.customConfig != null,  // no changes if was already default
        };
        // Reset compression settings to defaults
        restoredConfig.compressionTargetDpi = 100;
        restoredConfig.compressionBgQuality = 40;
        restoredConfig.compressionFgQuality = 80;
        this.setState(restoredConfig);
    }

    setLangList(checked) {
        this.setState({ lang: checked, usingDefault: false, uncommittedChanges: true });
    }

    setOutputList(checked) {
        this.setState({ outputs: checked, usingDefault: false, uncommittedChanges: true });
    }

    changeDpi(value) {
        value = value.trim()
        if (!(/^[1-9][0-9]*$/.test(value))) {
            this.errorNot.current.openNotif(this.props.t("error dpi must be integer"));
        }
        this.setState({ dpiVal: value, usingDefault: false, uncommittedChanges: true });
    }

    changeEngine(value) {
        this.setState({ engine: value, usingDefault: false, uncommittedChanges: true });
    }

    changeEngineMode(value) {
        this.setState({ engineMode: Number(value), usingDefault: false, uncommittedChanges: true });
    }

    changeSegmentationMode(value) {
        this.setState({ segmentMode: Number(value), usingDefault: false, uncommittedChanges: true });
    }

    changeCompress(value) {
        this.setState({ compress: value, usingDefault: false, uncommittedChanges: true });
    }

    changeThresholdingMethod(value) {
        this.setState({ thresholdMethod: Number(value), usingDefault: false, uncommittedChanges: true });
    }

    changeAdditionalParams(value) {
        this.setState({ otherParams: value, usingDefault: false, uncommittedChanges: true });
    }

    goBack() {
        if (this.state.uncommittedChanges) {
            this.confirmLeave.current.toggleOpen();
        } else {
            window.removeEventListener('beforeunload', this.preventExit);
            this.props.closeOCRMenu();
        }
    }

    leave() {
        window.removeEventListener('beforeunload', this.preventExit);
        this.props.closeOCRMenu();
        this.confirmLeave.current.toggleOpen();
    }

    saveConfig(exit = false) {
        const path = this.constructPath();
        const config = this.state.usingDefault ? "default" : this.getConfig();
        axios.post(API_URL + '/save-config',
            {
                _private: this.props._private,
                path: path,
                config: config,
            },
            {
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(({ data }) => {
                if (data["success"]) {
                    this.setState({ uncommittedChanges: false });

                    this.successNot.current.openNotif(this.props.t("success config saved"));

                    if (exit) {
                        this.leave();
                    } else {
                        this.props.setCurrentCustomConfig(config);
                        // Reload the configuration from server to ensure it's properly saved
                        this.fetchDocumentConfig();
                    }
                } else {
                    this.errorNot.current.openNotif(this.props.t("error config save unexpected"))
                }
            })
            .catch(err => {
                this.errorNot.current.openNotif(this.props.t("error config save failed"));
            });
    }

    render() {
        const valid = (
            (this.state.dpiVal === null || this.state.dpiVal === "" || (/^[1-9][0-9]*$/.test(this.state.dpiVal)))
            && this.state.outputs.length !== 0
        );
        return (
        <>
            <Notification message={""} severity={"success"} ref={this.successNot}/>
            <Notification message={""} severity={"error"} ref={this.errorNot}/>
            <ConfirmLeave leaveFunc={this.leave} saveAndLeaveFunc={() => this.saveConfig(true)} ref={this.confirmLeave} />

            <Box className="toolbar">
                <Box className="noMarginRight" sx={{display: "flex"}}>
                    <ReturnButton
                        disabled={false}
                        returnFunction={this.goBack}
                    />

                    <Typography
                        variant="h5"
                        component="h2"
                        className="toolbarTitle"
                    >
                        {this.props.t("configure ocr")} {this.props.isFolder ? this.props.t("of folder") : this.props.t("of document")}
                    </Typography>
                </Box>

                <Box sx={{display: "flex", flexDirection: "row"}}>
                    <Autocomplete
                        value={this.state.presetName}
                        options={this.state.presetsList}
                        getOptionLabel={(option) => {
                            // Try to get translation for presets, fallback to raw name
                            const translationKey = `presets.${option}`;
                            const translated = this.props.t(translationKey);
                            // If translation key not found, i18next returns the key itself
                            return translated !== translationKey ? translated : option;
                        }}
                        autoHighlight
                        onChange={(e, newValue) => this.selectPreset(newValue)}
                        renderInput={(params) => (
                            <TextField
                                {...params}
                                required
                                placeholder={this.props.t("choose preset")}
                                variant="outlined"
                                size="small"
                                sx={{
                                    height: "2rem",
                                    width: "25rem",
                                }}
                            />
                        )}
                        sx={{marginRight: "1rem", marginTop: "0.5rem"}}
                        slotProps={{
                            paper: {  // dropdown popup props
                                sx: {
                                    width: 'auto',
                                    maxHeight: '70%',
                                }
                            }
                        }}
                    />
                    <Button
                        disabled={this.state.usingDefault}
                        variant="contained"
                        className="menuFunctionButton"
                        startIcon={<RotateLeft />}
                        onClick={() => this.restoreDefault()}
                    >
                        {this.props.t("default values")}
                    </Button>
                    <Button
                        disabled={!valid || !this.state.uncommittedChanges}
                        color="success"
                        variant="contained"
                        className="menuFunctionButton noMarginRight"
                        startIcon={<SaveIcon />}
                        onClick={() => this.saveConfig()}
                    >
                        {this.props.t("save")}
                    </Button>
                </Box>
            </Box>

            {
            this.state.loaded && !this.state.fetchingPreset
            ? <Box
                  className="menuContent"
                  sx={{
                      height: 'auto',  // required for sticky toolbar
                      display: 'flex',
                      flexDirection: 'row',
                      justifyContent: 'space-evenly',
                  }}
            >
                {
                //<AlgoDropdown ref={this.algoDropdown} menu={this}/>
                }
                {/*
                <ChecklistDropdown className="simpleDropdown ocrDropdown"
                                   ref={this.langs}
                                   label={"Língua"}
                                   helperText={"Para melhores resultados, selecione por ordem de relevância"}
                                   options={tesseractLangList}
                                   defaultChoice={[tesseractLangList[defaultLangIndex]]}/>
                */}

                <Box sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    maxHeight: '65vh',
                    overflowY: 'auto',
                    overflowX: 'visible',
                    paddingRight: '1.5rem',
                    paddingLeft: '3rem',
                    paddingTop: '0.25rem',
                    paddingBottom: '0.5rem',
                }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: '0.5rem' }}>
                        <Typography component="legend" sx={{ fontWeight: 500 }}>
                            {this.props.t("languages_section")}
                        </Typography>
                        <InfoTooltip title={this.props.t("ocr_help.language")} />
                    </Box>
                    {/* #region agent log */}
                    {(() => {
                        const rawList = tesseractLanguagesList();
                        const mappedList = rawList.map(opt => ({ value: opt.value, description: this.props.t(opt.translationKey) }));
                        fetch('http://127.0.0.1:7326/ingest/46879f29-c4a4-4a72-82b8-c1d87f64db28',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'00413b'},body:JSON.stringify({sessionId:'00413b',location:'OcrMenu.js:507',message:'Language list transformation',data:{rawSample:rawList[0],mappedSample:mappedList[0],tFunction:typeof this.props.t,tResult:this.props.t('languages.arabic')},timestamp:Date.now(),hypothesisId:'BCD'})}).catch(()=>{});
                        return null;
                    })()}
                    {/* #endregion */}
                    <CheckboxList title=""
                                  options={tesseractLanguagesList().map(opt => ({ 
                                      value: opt.value, 
                                      description: this.props.t(opt.translationKey) 
                                  }))}
                                  checked={this.state.lang}
                                  onChangeCallback={this.setLangList}
                                  showOrder
                                  helperText={this.props.t("helper text language order")}
                                  errorText={this.props.t("error must select language")}/>
                    
                    <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: '0.5rem', marginTop: '1.5rem' }}>
                        <Typography component="legend" sx={{ fontWeight: 500 }}>
                            {this.props.t("special modules")}
                        </Typography>
                        <InfoTooltip title={this.props.t("ocr_help.special_modules")} />
                    </Box>
                    <CheckboxList title=""
                                  options={tesseractModulesList().map(opt => ({ 
                                      value: opt.value, 
                                      description: this.props.t(opt.translationKey) 
                                  }))}
                                  checked={this.state.lang}
                                  onChangeCallback={this.setLangList}
                                  showOrder={false}/>
                </Box>

                <Box sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    width: '30%',
                    maxHeight: '65vh',
                    overflowY: 'auto',
                    overflowX: 'visible',
                    paddingRight: '1rem',
                    paddingLeft: '0.5rem',
                    paddingTop: '0.25rem',
                    paddingBottom: '0.5rem',
                }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: '0.5rem' }}>
                        <TextField ref={this.dpiField}
                               label={this.props.t("dpi")}
                               slotProps={{htmlInput: { inputMode: "numeric", pattern: "[1-9][0-9]*" }}}
                               error={isNaN(this.state.dpiVal)
                                   || (this.state.dpiVal !== null
                                   && this.state.dpiVal !== "" && !(/^[1-9][0-9]*$/.test(this.state.dpiVal)))}
                               value={this.state.dpiVal}
                               onChange={(e) => this.changeDpi(e.target.value)}
                               variant='outlined'
                               size="small"
                               className="simpleInput"
                               sx={{
                                   "& input:focus:invalid + fieldset": {borderColor: "red", borderWidth: 2},
                                   flexGrow: 1,
                               }}
                        />
                        <InfoTooltip title={this.props.t("ocr_help.dpi")} />
                    </Box>

                    {/* Preprocessing Settings */}
                    <Box sx={{ mt: 2, p: 2, border: '1px solid #e0e0e0', borderRadius: 1 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>
                                {this.props.t("preprocessing.title")}
                            </Typography>
                            <InfoTooltip title={this.props.t("ocr_help.preprocessing")} />
                        </Box>
                        
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={this.state.preprocessing?.enabled ?? true}
                                    onChange={(e) => this.setState({
                                        preprocessing: { ...this.state.preprocessing, enabled: e.target.checked },
                                        usingDefault: false,
                                        uncommittedChanges: true
                                    })}
                                />
                            }
                            label={this.props.t("preprocessing.enabled")}
                        />

                        <FormControl fullWidth size="small" sx={{ mt: 2 }}>
                            <InputLabel>{this.props.t("preprocessing.threshold_method")}</InputLabel>
                            <Select
                                value={this.state.preprocessing?.threshold_method ?? "adaptive_gaussian"}
                                onChange={(e) => this.setState({
                                    preprocessing: { ...this.state.preprocessing, threshold_method: e.target.value },
                                    usingDefault: false,
                                    uncommittedChanges: true
                                })}
                                label={this.props.t("preprocessing.threshold_method")}
                                disabled={!this.state.preprocessing?.enabled}
                            >
                                <MenuItem value="adaptive_gaussian">Adaptive Gaussian</MenuItem>
                                <MenuItem value="otsu">OTSU</MenuItem>
                                <MenuItem value="sauvola">Sauvola</MenuItem>
                                <MenuItem value="none">None</MenuItem>
                            </Select>
                        </FormControl>
                    </Box>

                    <Button
                        variant="outlined"
                        startIcon={<SettingsIcon />}
                        onClick={() => this.setState({ advancedDialogOpen: true })}
                        sx={{ mt: 2 }}
                    >
                        {this.props.t("advanced")}
                    </Button>
                </Box>

                <Box sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    maxHeight: '65vh',
                    overflowY: 'auto',
                    overflowX: 'visible',
                    paddingRight: '1.5rem',
                    paddingLeft: '1rem',
                    paddingTop: '0.25rem',
                    paddingBottom: '0.5rem',
                }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: '0.5rem' }}>
                        <Typography component="legend" sx={{ fontWeight: 500 }}>
                            {this.props.t("output formats")}
                        </Typography>
                        <InfoTooltip title={this.props.t("ocr_help.output_formats")} />
                    </Box>
                    <CheckboxList title=""
                                  options={tesseractMainOutputsList().map(opt => ({ 
                                      value: opt.value, 
                                      description: this.props.t(opt.translationKey) 
                                  }))}
                                  checked={this.state.outputs}
                                  onChangeCallback={this.setOutputList}
                                  errorText={this.props.t("error must select output")}/>
                    
                    <Button
                        variant="outlined"
                        onClick={() => this.setState({ moreOutputsDialogOpen: true })}
                        sx={{ mt: 1, mb: 2 }}
                        size="small"
                    >
                        {this.props.t("more outputs")}
                    </Button>
                    {/* Compression Settings */}
                    <FormControl className="simpleDropdown borderTop" sx={{ paddingTop: '1rem', mt: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <FormControlLabel
                                control={
                                    <Switch
                                        checked={this.state.compress !== undefined ? this.state.compress : true}
                                        onChange={(e) => this.changeCompress(e.target.checked)}
                                        color="primary"
                                    />
                                }
                                label={this.props.t("compress pdf")}
                            />
                            <InfoTooltip title={this.props.t("ocr_help.compress_pdf")} />
                        </Box>
                        <Typography variant="caption" color="text.secondary" sx={{ ml: 2, mt: 0.5 }}>
                            {this.props.t("compress pdf description")}
                        </Typography>
                        
                        {/* Compression Settings */}
                        {(this.state.compress !== undefined ? this.state.compress : true) && (
                            <Box sx={{ mt: 2, ml: 2 }}>
                                <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>
                                    {this.props.t('compression settings')}
                                </Typography>

                                {/* Target DPI */}
                                <TextField
                                    label={this.props.t('compression target dpi')}
                                    type="number"
                                    size="small"
                                    fullWidth
                                    value={this.state.compressionTargetDpi}
                                    onChange={(e) => this.setState({ compressionTargetDpi: e.target.value, usingDefault: false, uncommittedChanges: true })}
                                    inputProps={{ min: 50, max: 300 }}
                                    sx={{ mb: 1.5 }}
                                />

                                {/* Background Quality */}
                                <TextField
                                    label={this.props.t('compression bg quality')}
                                    type="number"
                                    size="small"
                                    fullWidth
                                    value={this.state.compressionBgQuality}
                                    onChange={(e) => this.setState({ compressionBgQuality: e.target.value, usingDefault: false, uncommittedChanges: true })}
                                    inputProps={{ min: 1, max: 100 }}
                                    sx={{ mb: 1.5 }}
                                />

                                {/* Foreground Quality */}
                                <TextField
                                    label={this.props.t('compression fg quality')}
                                    type="number"
                                    size="small"
                                    fullWidth
                                    value={this.state.compressionFgQuality}
                                    onChange={(e) => this.setState({ compressionFgQuality: e.target.value, usingDefault: false, uncommittedChanges: true })}
                                    inputProps={{ min: 1, max: 100 }}
                                />
                            </Box>
                        )}
                    </FormControl>
                </Box>

                {/*
                <Box sx={{display: 'flex', flexDirection: 'row', alignItems: 'center'}}>
                    <Button variant="contained" onClick={() => this.performOCR()}>
                        Começar
                    </Button>
                </Box>
                */}
            </Box>

            :<Box sx={{
                width: "100%",
                height: "100%",
                display: "flex",
                flexDirection: "row",
                justifyContent: "center",
                alignItems: "center"
            }}>
                <CircularProgress color="success" />
            </Box>
            }

            {/* Advanced Settings Dialog */}
            <Dialog
                open={this.state.advancedDialogOpen}
                onClose={() => this.setState({ advancedDialogOpen: false })}
                maxWidth="md"
                fullWidth
            >
                <DialogTitle>{this.props.t("advanced ocr settings")}</DialogTitle>
                <DialogContent>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 1 }}>
                        <FormControl className="simpleDropdown">
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <FormLabel id="label-engine-type-select">{this.props.t("engine mode")}</FormLabel>
                                <InfoTooltip title={this.props.t("ocr_help.engine_mode")} />
                            </Box>
                            <RadioGroup
                                aria-labelledby="label-engine-type-select"
                                value={this.state.engineMode}
                                onChange={(e) => this.changeEngineMode(e.target.value)}>
                                {
                                    this.state.engineModeOptions.map((option) =>
                                        <FormControlLabel key={option.value} value={option.value} control={<Radio disableRipple />} label={option.description}/>
                                    )
                                }
                            </RadioGroup>
                        </FormControl>

                        <FormControl className="simpleDropdown">
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <FormLabel id="label-segmentation-select">{this.props.t("segmentation")}</FormLabel>
                                <InfoTooltip title={this.props.t("ocr_help.segmentation")} />
                            </Box>
                            <RadioGroup
                                aria-labelledby="label-segmentation-select"
                                value={this.state.segmentMode}
                                onChange={(e) => this.changeSegmentationMode(e.target.value)}>
                                {
                                    this.state.segmentModeOptions.map((option) =>
                                        <FormControlLabel key={option.value} value={option.value} control={<Radio disableRipple />} label={option.description}/>
                                    )
                                }
                            </RadioGroup>
                        </FormControl>

                        <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                            <TextField ref={this.moreParams}
                                   label={this.props.t("aditional parameters")}
                                   value={this.state.otherParams}
                                   onChange={(e) => this.changeAdditionalParams(e.target.value)}
                                   variant='outlined'
                                   size="small"
                                   fullWidth
                                   sx={{ flexGrow: 1 }}
                            />
                            <InfoTooltip title={this.props.t("ocr_help.additional_params")} />
                        </Box>

                        {/* Tesseract Thresholding Method */}
                        <FormControl className="simpleDropdown" sx={{ mt: 2 }}>
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <FormLabel id="label-thresholding-select">{this.props.t("tesseract thresholding")}</FormLabel>
                                <InfoTooltip title={this.props.t("ocr_help.tesseract_thresholding")} />
                            </Box>
                            <RadioGroup
                                aria-labelledby="label-thresholding-select"
                                value={this.state.thresholdMethod}
                                onChange={(e) => this.changeThresholdingMethod(e.target.value)}>
                                {
                                    this.state.thresholdMethodOptions.map((option) =>
                                        <FormControlLabel key={option.value} value={option.value} control={<Radio disableRipple />} label={option.description}/>
                                    )
                                }
                            </RadioGroup>
                        </FormControl>

                        {/* Preprocessing Pipeline Section */}
                        <Box sx={{ mt: 2, p: 2, border: '1px solid #e0e0e0', borderRadius: 1 }}>
                            <Typography variant="h6" sx={{ mb: 2 }}>{this.props.t("preprocessing.title")}</Typography>
                            
                            <FormControlLabel
                                control={
                                    <Switch
                                        checked={this.state.preprocessing?.enabled ?? true}
                                        onChange={(e) => this.setState({
                                        preprocessing: { ...this.state.preprocessing, enabled: e.target.checked },
                                        usingDefault: false,
                                        uncommittedChanges: true
                                    })}
                                />
                            }
                            label={this.props.t("preprocessing.enabled")}
                            />

                            <Box sx={{ ml: 4, mt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
                                <FormControlLabel
                                    control={
                                        <Switch
                                            checked={this.state.preprocessing?.grayscale ?? true}
                                            onChange={(e) => this.setState({
                                            preprocessing: { ...this.state.preprocessing, grayscale: e.target.checked },
                                            usingDefault: false,
                                            uncommittedChanges: true
                                        })}
                                        disabled={!this.state.preprocessing?.enabled}
                                        />
                                    }
                                    label={this.props.t("preprocessing.grayscale")}
                                />

                                <Box>
                                    <FormControlLabel
                                        control={
                                            <Switch
                                                checked={this.state.preprocessing?.clahe ?? true}
                                                onChange={(e) => this.setState({
                                            preprocessing: { ...this.state.preprocessing, clahe: e.target.checked },
                                            usingDefault: false,
                                            uncommittedChanges: true
                                        })}
                                        disabled={!this.state.preprocessing?.enabled}
                                            />
                                        }
                                        label={this.props.t("preprocessing.clahe")}
                                    />
                                    {this.state.preprocessing?.clahe && (
                                        <Box sx={{ ml: 4, display: 'flex', gap: 2 }}>
                                            <TextField
                                                label={this.props.t("preprocessing.clahe_clip_limit")}
                                                type="number"
                                                value={this.state.preprocessing?.clahe_clip_limit ?? 2.0}
                                                onChange={(e) => this.setState({
                                            preprocessing: { ...this.state.preprocessing, clahe_clip_limit: parseFloat(e.target.value) },
                                            usingDefault: false,
                                            uncommittedChanges: true
                                        })}
                                        size="small"
                                                inputProps={{ min: 1, max: 10, step: 0.1 }}
                                                disabled={!this.state.preprocessing?.enabled}
                                            />
                                            <TextField
                                                label={this.props.t("preprocessing.clahe_tile_size")}
                                                type="number"
                                                value={this.state.preprocessing?.clahe_tile_size ?? 8}
                                                onChange={(e) => this.setState({
                                            preprocessing: { ...this.state.preprocessing, clahe_tile_size: parseInt(e.target.value) },
                                            usingDefault: false,
                                            uncommittedChanges: true
                                        })}
                                        size="small"
                                                inputProps={{ min: 4, max: 32, step: 1 }}
                                                disabled={!this.state.preprocessing?.enabled}
                                            />
                                        </Box>
                                    )}
                                </Box>

                                <Box>
                                    <FormControlLabel
                                        control={
                                            <Switch
                                                checked={this.state.preprocessing?.median_blur ?? true}
                                                onChange={(e) => this.setState({
                                            preprocessing: { ...this.state.preprocessing, median_blur: e.target.checked },
                                            usingDefault: false,
                                            uncommittedChanges: true
                                        })}
                                        disabled={!this.state.preprocessing?.enabled}
                                            />
                                        }
                                        label={this.props.t("preprocessing.median_blur")}
                                    />
                                    {this.state.preprocessing?.median_blur && (
                                        <TextField
                                            sx={{ ml: 4 }}
                                            label={this.props.t("preprocessing.median_blur_kernel")}
                                            type="number"
                                            value={this.state.preprocessing?.median_blur_kernel ?? 3}
                                            onChange={(e) => this.setState({
                                                preprocessing: { ...this.state.preprocessing, median_blur_kernel: parseInt(e.target.value) },
                                                    usingDefault: false,
                                                uncommittedChanges: true
                                            })}
                                            size="small"
                                            inputProps={{ min: 3, max: 9, step: 2 }}
                                            disabled={!this.state.preprocessing?.enabled}
                                        />
                                    )}
                                </Box>

                                <Box>
                                    <FormControl fullWidth size="small">
                                        <InputLabel>{this.props.t("preprocessing.threshold_method")}</InputLabel>
                                        <Select
                                            value={this.state.preprocessing?.threshold_method ?? "adaptive_gaussian"}
                                            onChange={(e) => this.setState({
                                                preprocessing: { ...this.state.preprocessing, threshold_method: e.target.value },
                                                    usingDefault: false,
                                                uncommittedChanges: true
                                            })}
                                            label={this.props.t("preprocessing.threshold_method")}
                                            disabled={!this.state.preprocessing?.enabled}
                                        >
                                            <MenuItem value="adaptive_gaussian">Adaptive Gaussian</MenuItem>
                                            <MenuItem value="otsu">OTSU</MenuItem>
                                            <MenuItem value="sauvola">Sauvola</MenuItem>
                                            <MenuItem value="none">None</MenuItem>
                                        </Select>
                                    </FormControl>
                                    {this.state.preprocessing?.threshold_method === "adaptive_gaussian" && (
                                        <Box sx={{ mt: 1, display: 'flex', gap: 2 }}>
                                            <TextField
                                                label={this.props.t("preprocessing.adaptive_block_size")}
                                                type="number"
                                                value={this.state.preprocessing?.adaptive_block_size ?? 11}
                                                onChange={(e) => this.setState({
                                                    preprocessing: { ...this.state.preprocessing, adaptive_block_size: parseInt(e.target.value) },
                                                    usingDefault: false,
                                                    uncommittedChanges: true
                                                })}
                                                size="small"
                                                inputProps={{ min: 3, max: 99, step: 2 }}
                                                disabled={!this.state.preprocessing?.enabled}
                                            />
                                            <TextField
                                                label={this.props.t("preprocessing.adaptive_c")}
                                                type="number"
                                                value={this.state.preprocessing?.adaptive_c ?? 2}
                                                onChange={(e) => this.setState({
                                                    preprocessing: { ...this.state.preprocessing, adaptive_c: parseInt(e.target.value) },
                                                    usingDefault: false,
                                                    uncommittedChanges: true
                                                })}
                                                size="small"
                                                inputProps={{ min: 0, max: 20, step: 1 }}
                                                disabled={!this.state.preprocessing?.enabled}
                                            />
                                        </Box>
                                    )}
                                </Box>

                                <FormControlLabel
                                    control={
                                        <Switch
                                            checked={this.state.preprocessing?.morphological_opening ?? true}
                                            onChange={(e) => this.setState({
                                                preprocessing: { ...this.state.preprocessing, morphological_opening: e.target.checked },
                                                    usingDefault: false,
                                                uncommittedChanges: true
                                            })}
                                            disabled={!this.state.preprocessing?.enabled}
                                        />
                                    }
                                    label={this.props.t("preprocessing.morphological_opening")}
                                />

                                <Box>
                                    <FormControlLabel
                                        control={
                                            <Switch
                                                checked={this.state.preprocessing?.morphological_closing ?? true}
                                                onChange={(e) => this.setState({
                                                    preprocessing: { ...this.state.preprocessing, morphological_closing: e.target.checked },
                                                    usingDefault: false,
                                                    uncommittedChanges: true
                                                })}
                                                disabled={!this.state.preprocessing?.enabled}
                                            />
                                        }
                                        label={this.props.t("preprocessing.morphological_closing")}
                                    />
                                    {(this.state.preprocessing?.morphological_opening || this.state.preprocessing?.morphological_closing) && (
                                        <TextField
                                            sx={{ ml: 4 }}
                                            label={this.props.t("preprocessing.morph_kernel_size")}
                                            type="number"
                                            value={this.state.preprocessing?.morph_kernel_size ?? 3}
                                            onChange={(e) => this.setState({
                                                preprocessing: { ...this.state.preprocessing, morph_kernel_size: parseInt(e.target.value) },
                                                    usingDefault: false,
                                                uncommittedChanges: true
                                            })}
                                            size="small"
                                            inputProps={{ min: 3, max: 9, step: 2 }}
                                            disabled={!this.state.preprocessing?.enabled}
                                        />
                                    )}
                                </Box>

                                <FormControlLabel
                                    control={
                                        <Switch
                                            checked={this.state.preprocessing?.deskew ?? true}
                                            onChange={(e) => this.setState({
                                                preprocessing: { ...this.state.preprocessing, deskew: e.target.checked },
                                                    usingDefault: false,
                                                uncommittedChanges: true
                                            })}
                                            disabled={!this.state.preprocessing?.enabled}
                                        />
                                    }
                                    label={this.props.t("preprocessing.deskew")}
                                />
                            </Box>
                        </Box>
                    </Box>
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => this.setState({ advancedDialogOpen: false })} color="primary">
                        {this.props.t("close")}
                    </Button>
                </DialogActions>
            </Dialog>

            {/* More Outputs Dialog */}
            <Dialog
                open={this.state.moreOutputsDialogOpen}
                onClose={() => this.setState({ moreOutputsDialogOpen: false })}
                maxWidth="sm"
                fullWidth
            >
                <DialogTitle>{this.props.t("more outputs")}</DialogTitle>
                <DialogContent>
                    <Box sx={{ pt: 1 }}>
                        <CheckboxList title=""
                                      options={tesseractAdvancedOutputsList().map(opt => ({ 
                                          value: opt.value, 
                                          description: this.props.t(opt.translationKey) 
                                      }))}
                                      checked={this.state.outputs}
                                      onChangeCallback={this.setOutputList}/>
                    </Box>
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => this.setState({ moreOutputsDialogOpen: false })} color="primary">
                        {this.props.t("close")}
                    </Button>
                </DialogActions>
            </Dialog>
        </>
        );
    }
}

OcrMenu.defaultProps = {
    _private: false,
    spaceId: "",
    current_folder: null,
    filename: null,
    isFolder: false,
    isSinglePage: false,
    customConfig: null,
    // functions:
    setCurrentCustomConfig: null,
    closeOCRMenu: null,
    showStorageForm: null,
}

export default withTranslation()(OcrMenu);
