import React from 'react';

import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Modal from '@mui/material/Modal';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import ClickAwayListener from "@mui/material/ClickAwayListener";
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import Tooltip from '@mui/material/Tooltip';
import Radio from '@mui/material/Radio';
import RadioGroup from '@mui/material/RadioGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormLabel from '@mui/material/FormLabel';
import FormHelperText from '@mui/material/FormHelperText';

import Notification from 'Components/Notifications/Notification';
import i18next from 'i18next';

const API_URL = `${window.location.protocol}//${window.location.host}/${process.env.REACT_APP_API_URL}`;
const style = {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    width: 'fit-content',
    bgcolor: 'background.paper',
    border: '2px solid #000',
    boxShadow: 24,
    p: 4,
    borderRadius: 2
};

const crossStyle = {
    position: 'absolute',
    top: '0.5rem',
    right: '0.5rem'
}

class OcrPopup extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            open: false,

            path: "",
            filename: null,
            isFolder: false,
            alreadyOcr: false,
            customConfig: null,
            
            presetsList: [],
            selectedPreset: "default",
            configStrategy: "hybrid",
        }

        this.successNot = React.createRef();
        this.errorNot = React.createRef();
        //this.algoDropdown = React.createRef();

        this.storageMenu = React.createRef();

        this.langs = React.createRef();
        this.dpiField = React.createRef();
        this.moreParams = React.createRef();

        // handler to close menu on click outside box
        this.handleClickOutsideMenu = this.handleClickOutsideMenu.bind(this);
        this.fetchPresetsList = this.fetchPresetsList.bind(this);
        this.handlePresetChange = this.handlePresetChange.bind(this);
        this.handleStrategyChange = this.handleStrategyChange.bind(this);
    }
    
    componentDidMount() {
        this.fetchPresetsList();
    }
    
    fetchPresetsList() {
        fetch(API_URL + '/presets-list')
            .then(response => response.json())
            .then(data => {
                // Add 'default' to the beginning if not already present
                const presets = ['default', ...data];
                this.setState({ presetsList: presets });
            })
            .catch(err => {
                console.error("Failed to fetch presets list:", err);
                // Fallback to just default
                this.setState({ presetsList: ['default'] });
            });
    }
    
    handlePresetChange(event) {
        this.setState({ selectedPreset: event.target.value });
    }
    
    handleStrategyChange(event) {
        this.setState({ configStrategy: event.target.value });
    }

    handleClickOutsideMenu() {
        if (this.state.open) {
            this.closeMenu();
        }
    }

    openMenu(path, filename, ocrTargetIsFolder=false, alreadyOcr=false, customConfig=null) {
        this.setState({
            open: true,
            path: path,
            filename: filename,
            isFolder: ocrTargetIsFolder,
            alreadyOcr: alreadyOcr,
            customConfig: customConfig,
            selectedPreset: "default", // Reset to default when opening
            configStrategy: "hybrid", // Reset to hybrid when opening
        });
    }

    closeMenu(callback = null) {
        this.setState({
            open: false,
            path: "",
            filename: null,
            isFolder: false,
            alreadyOcr: false,
            customConfig: null,
            selectedPreset: "default",
            configStrategy: "hybrid",
        }, callback);
    }

    /**
     * Request OCR of the file on the given path from the backend
     */
    performOCR() {
        const path = this.state.path + '/' + this.state.filename;
        const body = {
            "path": path,
            "multiple": this.state.isFolder,
            "_private": this.props._private
        }
        
        // Priority: customConfig > selectedPreset
        if (this.state.customConfig) {
            body["config"] = this.state.customConfig;
        } else if (this.state.selectedPreset && this.state.selectedPreset !== "default") {
            // Send preset name as string to backend
            body["config"] = this.state.selectedPreset;
        }
        // If selectedPreset is "default" or null, don't send config (use system default)
        
        // Send config strategy if folder OCR
        if (this.state.isFolder) {
            body["config_strategy"] = this.state.configStrategy;
        }

        fetch(API_URL + '/request-ocr', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.successNot.current.openNotif(i18next.t(data.message));
                } else {
                    if (data.error) {
                        this.props.showStorageForm(data.error);
                    } else {
                        this.errorNot.current.openNotif(i18next.t(data.message));
                    }
                }

                this.closeMenu(this.props.submitCallback);
            })
            .catch(err => {
               this.errorNot.current.openNotif(i18next.t("admin.request_failed"))
            });
    }

    render() {
        const hasCustomConfig = this.state.customConfig !== null;
        
        return (
            <Box>
                <Notification message={""} severity={"success"} ref={this.successNot}/>
                <Notification message={""} severity={"error"} ref={this.errorNot}/>

                <Modal open={this.state.open}>
                    <ClickAwayListener
                        mouseEvent="onMouseDown"
                        touchEvent="onTouchStart"
                        onClickAway={this.handleClickOutsideMenu}
                    >
                        <Box sx={style}>
                            <Typography id="modal-modal-title" variant="h6" component="h2" sx={{ mb: 2 }}>
                                {i18next.t("run ocr")} {this.state.isFolder ? i18next.t('of folder') : i18next.t('of document')} <b>{this.state.filename}</b>
                            </Typography>

                            {this.state.alreadyOcr
                                && <Typography sx={{color: 'red', mb: 2}}><b>{i18next.t("lose results")}</b></Typography>
                            }

                            {hasCustomConfig && (
                                <Typography sx={{color: 'info.main', mb: 2, fontSize: '0.9rem'}}>
                                    {i18next.t("custom config")}
                                </Typography>
                            )}

                            {!hasCustomConfig && (
                                <FormControl fullWidth sx={{ mb: 3, minWidth: 300 }}>
                                    <InputLabel id="preset-select-label">{i18next.t("select ocr preset")}</InputLabel>
                                    <Select
                                        labelId="preset-select-label"
                                        id="preset-select"
                                        value={this.state.selectedPreset}
                                        label={i18next.t("select ocr preset")}
                                        onChange={this.handlePresetChange}
                                    >
                                        {this.state.presetsList.map((preset) => (
                                            <MenuItem key={preset} value={preset}>
                                                <Tooltip 
                                                    title={i18next.t(`presets.${preset}_desc`)} 
                                                    placement="right"
                                                    arrow
                                                >
                                                    <span style={{ width: '100%', display: 'block' }}>
                                                        {i18next.t(`presets.${preset}`)}
                                                    </span>
                                                </Tooltip>
                                            </MenuItem>
                                        ))}
                                    </Select>
                                </FormControl>
                            )}

                            {this.state.isFolder && (
                                <FormControl component="fieldset" sx={{ mb: 3, width: '100%' }}>
                                    <FormLabel component="legend">{i18next.t("config strategy")}</FormLabel>
                                    <RadioGroup
                                        aria-label="config strategy"
                                        name="config-strategy"
                                        value={this.state.configStrategy}
                                        onChange={this.handleStrategyChange}
                                    >
                                        <FormControlLabel 
                                            value="override_all" 
                                            control={<Radio />} 
                                            label={i18next.t("config strategy override")} 
                                        />
                                        <FormControlLabel 
                                            value="respect_individual" 
                                            control={<Radio />} 
                                            label={i18next.t("config strategy respect")} 
                                        />
                                        <FormControlLabel 
                                            value="hybrid" 
                                            control={<Radio />} 
                                            label={i18next.t("config strategy hybrid")} 
                                        />
                                    </RadioGroup>
                                    <FormHelperText>{i18next.t("config strategy hint")}</FormHelperText>
                                </FormControl>
                            )}

                            <Box sx={{display: 'flex', flexDirection: 'row', alignItems: 'center'}}>
                                <Button variant="contained" onClick={() => this.performOCR()}>
                                    {i18next.t("begin")}
                                </Button>
                            </Box>

                            <IconButton sx={crossStyle} aria-label="close" onClick={() => this.closeMenu()}>
                                <CloseRoundedIcon />
                            </IconButton>
                        </Box>
                    </ClickAwayListener>
                </Modal>
            </Box>
        )
    }
}

OcrPopup.defaultProps = {
    _private: false,
    // functions:
    submitCallback: null,
    showStorageForm: null,
}

export default OcrPopup;
