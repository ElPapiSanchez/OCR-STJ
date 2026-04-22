import React from 'react';
import axios from 'axios';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import LinearProgress from '@mui/material/LinearProgress';
import Paper from '@mui/material/Paper';
import Alert from '@mui/material/Alert';
import Checkbox from '@mui/material/Checkbox';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import TextField from '@mui/material/TextField';
import Switch from '@mui/material/Switch';
import Divider from '@mui/material/Divider';
import Grid from '@mui/material/Grid';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';

import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import FlashOnIcon from '@mui/icons-material/FlashOn';
import DownloadIcon from '@mui/icons-material/Download';
import DeleteIcon from '@mui/icons-material/Delete';

import CheckboxList from 'Components/Form/CheckboxList';
import { tesseractLangList } from 'defaultOcrConfigs';
import Footer from 'Components/Footer/Footer';
import { MODEL, STJ } from 'App';
import logoApp from "static/logoApp.png";
import logoUN from "static/Logo_of_the_United_Nations.svg";

// Construct API URL, removing any double slashes
const apiPath = process.env.REACT_APP_API_URL || 'api';
const cleanApiPath = apiPath.replace(/^\/+|\/+$/g, ''); // Remove leading/trailing slashes
const API_URL = `${window.location.protocol}//${window.location.host}/${cleanApiPath}`;

class ImmediateOCR extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            // File management
            uploadedFile: null,
            docId: null,
            
            // Configuration
            selectedLanguages: ['por'],
            selectedPreset: 'default',
            presetsList: ['default'],
            
            // Output formats
            outputFormats: {
                txt: true,
                pdf: false,
                pdf_indexed: false
            },
            
            // Compression setting
            enableCompression: true,
            compressionTargetDpi: 100,
            compressionBgQuality: 40,
            compressionFgQuality: 80,
            
            // Processing state
            status: 'idle', // idle, uploading, processing, complete, error
            progress: 0,
            statusMessage: '',
            errorMessage: '',
            
            // Results
            availableResults: {
                txt: false,
                pdf: false,
                pdf_indexed: false
            },
            resultSizes: {
                txt: null,
                pdf: { compressed: null, uncompressed: null },
                pdf_indexed: { compressed: null, uncompressed: null }
            }
        };
        
        this.fileInputRef = React.createRef();
        this.pollInterval = null;
        
        this.handleFileSelect = this.handleFileSelect.bind(this);
        this.handleDrop = this.handleDrop.bind(this);
        this.handleDragOver = this.handleDragOver.bind(this);
        this.processFile = this.processFile.bind(this);
        this.pollStatus = this.pollStatus.bind(this);
        this.downloadResult = this.downloadResult.bind(this);
        this.cleanup = this.cleanup.bind(this);
        this.resetForm = this.resetForm.bind(this);
    }
    
    componentWillUnmount() {
        // Cleanup on page leave
        if (this.state.docId) {
            this.cleanup();
        }
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
        }
    }
    
    handleFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            this.setState({ uploadedFile: file, errorMessage: '' });
        }
    }
    
    handleDrop(event) {
        event.preventDefault();
        const file = event.dataTransfer.files[0];
        if (file) {
            this.setState({ uploadedFile: file, errorMessage: '' });
        }
    }
    
    handleDragOver(event) {
        event.preventDefault();
    }
    
    setLanguages(checked) {
        this.setState({ selectedLanguages: checked });
    }
    
    toggleOutputFormat(format) {
        this.setState(prevState => ({
            outputFormats: {
                ...prevState.outputFormats,
                [format]: !prevState.outputFormats[format]
            }
        }));
    }
    
    async processFile() {
        const { 
            uploadedFile, selectedLanguages, selectedPreset, outputFormats, 
            enableCompression,
            compressionTargetDpi, compressionBgQuality, compressionFgQuality 
        } = this.state;
        
        if (!uploadedFile) {
            this.setState({ errorMessage: this.props.t('no file uploaded') });
            return;
        }
        
        if (selectedLanguages.length === 0) {
            this.setState({ errorMessage: this.props.t('language required') });
            return;
        }
        
        const hasOutputSelected = Object.values(outputFormats).some(v => v);
        if (!hasOutputSelected) {
            this.setState({ errorMessage: this.props.t('output required') });
            return;
        }
        
        // Clean up previous results if any
        if (this.state.docId) {
            await this.cleanup();
        }
        
        this.setState({ 
            status: 'uploading',
            statusMessage: this.props.t('uploading'),
            errorMessage: ''
        });
        
        try {
            // Prepare config
            const outputs = [];
            if (outputFormats.txt) outputs.push('txt');
            if (outputFormats.pdf) outputs.push('pdf');
            if (outputFormats.pdf_indexed) outputs.push('pdf_indexed');
            
            const formData = new FormData();
            formData.append('file', uploadedFile);
            
            // Send preset name or full config
            if (selectedPreset && selectedPreset !== 'default') {
                // Send preset name as string, but include compression settings separately
                formData.append('config', selectedPreset);
                // Add compression settings that override preset
                formData.append('compress', enableCompression);
            } else {
                // Send complete config with all required fields including compression settings
                const config = {
                    engine: "tesserocr",
                    lang: selectedLanguages,
                    outputs: outputs,
                    engineMode: 3,
                    segmentMode: 3,
                    thresholdMethod: 0,
                    compress: enableCompression,
                    compressionTargetDpi: Number(compressionTargetDpi),
                    compressionBgQuality: Number(compressionBgQuality),
                    compressionFgQuality: Number(compressionFgQuality),
                    compressionFlattenToJpeg: true  // Always flatten to JPEG
                };
                formData.append('config', JSON.stringify(config));
            }
            
            const response = await axios.post(API_URL + '/perform-ocr', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            });
            
            if (response.data.success) {
                this.setState({ 
                    docId: response.data.doc_id,
                    status: 'processing',
                    statusMessage: this.props.t('processing document')
                });
                
                // Start polling for status
                this.pollInterval = setInterval(this.pollStatus, 2000);
            } else {
                this.setState({ 
                    status: 'error',
                    errorMessage: response.data.error || this.props.t('upload failed')
                });
            }
        } catch (error) {
            console.error('Upload error:', error);
            this.setState({ 
                status: 'error',
                errorMessage: this.props.t('upload failed')
            });
        }
    }
    
    async pollStatus() {
        const { docId, enableCompression, outputFormats } = this.state;
        if (!docId) return;
        
        try {
            const response = await axios.get(API_URL + '/check-status', {
                params: { doc_id: docId }
            });
            
            const data = response.data;
            
            // Translate backend status messages
            let statusMessage = data.status?.message || this.props.t('processing document');
            
            // Check if message is a translation key and use current/total fields if present
            if (statusMessage === 'processing ocr page' && data.status?.current && data.status?.total) {
                statusMessage = this.props.t('processing ocr page', { current: data.status.current, total: data.status.total });
            }
            else if (statusMessage === 'compressing file page' && data.status?.current && data.status?.total) {
                statusMessage = this.props.t('compressing file page', { current: data.status.current, total: data.status.total });
            }
            else if (statusMessage === 'adding text page' && data.status?.current && data.status?.total) {
                statusMessage = this.props.t('adding text page', { current: data.status.current, total: data.status.total });
            }
            // Handle translation keys without parameters
            else if (statusMessage === 'processing ocr') {
                statusMessage = this.props.t('processing ocr');
            }
            else if (statusMessage === 'compressing file') {
                statusMessage = this.props.t('compressing file');
            }
            else if (statusMessage === 'adding text layer') {
                statusMessage = this.props.t('adding text layer');
            }
            else if (statusMessage === 'completed') {
                statusMessage = this.props.t('completed');
            }
            // Legacy: Check for OCR processing messages in Portuguese and translate them
            else if (statusMessage.includes('A processar OCR')) {
                if (statusMessage.match(/Página \d+\/\d+/)) {
                    const match = statusMessage.match(/Página (\d+)\/(\d+)/);
                    if (match) {
                        statusMessage = this.props.t('processing ocr page', { current: match[1], total: match[2] });
                    } else {
                        statusMessage = this.props.t('processing ocr');
                    }
                } else {
                    statusMessage = this.props.t('processing ocr');
                }
            }
            // Legacy: Check for compression messages in Portuguese and translate them
            else if (statusMessage.includes('A comprimir')) {
                if (statusMessage.match(/Página \d+\/\d+/)) {
                    const match = statusMessage.match(/Página (\d+)\/(\d+)/);
                    if (match) {
                        statusMessage = this.props.t('compressing file page', { current: match[1], total: match[2] });
                    } else if (statusMessage.includes('ficheiro original')) {
                        statusMessage = this.props.t('compressing file');
                    } else if (statusMessage.includes('concluída')) {
                        statusMessage = this.props.t('compression complete');
                    } else {
                        statusMessage = this.props.t('compressing pdf');
                    }
                } else if (statusMessage.includes('ficheiro original')) {
                    statusMessage = this.props.t('compressing file');
                } else if (statusMessage.includes('concluída')) {
                    statusMessage = this.props.t('compression complete');
                } else {
                    statusMessage = this.props.t('compressing pdf');
                }
            }
            // Legacy: Check for text layer messages and translate them
            else if (statusMessage.includes('A adicionar texto')) {
                if (statusMessage.match(/Página \d+\/\d+/)) {
                    const match = statusMessage.match(/Página (\d+)\/(\d+)/);
                    if (match) {
                        statusMessage = this.props.t('adding text page', { current: match[1], total: match[2] });
                    } else {
                        statusMessage = this.props.t('adding text layer');
                    }
                } else if (statusMessage.includes('OCR')) {
                    statusMessage = this.props.t('adding text layer');
                }
            }
            // Legacy: Check for completed status
            else if (statusMessage.includes('Concluído')) {
                statusMessage = this.props.t('completed');
            }
            
            // Calculate progress percentage based on backend percentage if available
            let progressPercent = 0;
            const stage = data.status?.stage;
            
            // Use backend percentage if provided (new progress system)
            if (data.status?.percentage !== undefined) {
                progressPercent = data.status.percentage;
            } else {
                // Fallback to old calculation for backwards compatibility
                const hasPdfOutput = outputFormats.pdf || outputFormats.pdf_indexed;
                const willCompress = enableCompression && hasPdfOutput;
                
                if (stage === 'ocr') {
                    const ocrProgress = data.ocr?.progress || 0;
                    const totalPages = data.pages || 1;
                    const ocrPercent = (ocrProgress / totalPages) * 100;
                    
                    if (willCompress) {
                        progressPercent = Math.min(50, ocrPercent * 0.5);
                    } else {
                        progressPercent = Math.min(100, ocrPercent);
                    }
                } else if (stage === 'compressing') {
                    const compressionProgress = data.status?.progress || 0;
                    progressPercent = 50 + (compressionProgress * 0.5);
                } else if (stage === 'exporting') {
                    progressPercent = willCompress ? 95 : 90;
                } else if (stage === 'post-ocr') {
                    progressPercent = 100;
                } else {
                    progressPercent = data.ocr?.progress || 0;
                }
            }
            
            this.setState({ 
                progress: Math.round(progressPercent),
                statusMessage: statusMessage
            });
            
            // Check if complete
            const resultsComplete = {
                txt: data.txt?.complete || false,
                pdf: data.pdf?.complete || false,
                pdf_indexed: data.pdf_indexed?.complete || false
            };
            
            // Get file sizes from response
            const resultSizes = {
                txt: data.txt?.size || null,
                pdf: {
                    compressed: data.pdf?.compressed_size || data.pdf?.size || null,
                    uncompressed: data.pdf?.uncompressed_size || null
                },
                pdf_indexed: {
                    compressed: data.pdf_indexed?.compressed_size || data.pdf_indexed?.size || null,
                    uncompressed: data.pdf_indexed?.uncompressed_size || null
                }
            };
            
            const allComplete = Object.entries(this.state.outputFormats)
                .filter(([_, selected]) => selected)
                .every(([format, _]) => resultsComplete[format]);
            
            if (allComplete && stage !== 'ocr' && stage !== 'compressing') {
                // Processing complete
                clearInterval(this.pollInterval);
                this.pollInterval = null;
                this.setState({ 
                    status: 'complete',
                    progress: 100,
                    availableResults: resultsComplete,
                    resultSizes: resultSizes,
                    statusMessage: this.props.t('ocr complete')
                });
            } else if (stage === 'error') {
                // Error occurred
                clearInterval(this.pollInterval);
                this.pollInterval = null;
                
                // Show detailed error if available
                let errorMsg = data.status?.message || this.props.t('processing failed');
                if (data.ocr?.exceptions) {
                    errorMsg += ` - ${data.ocr.exceptions}`;
                }
                console.error('OCR Error:', errorMsg);
                
                this.setState({ 
                    status: 'error',
                    errorMessage: errorMsg
                });
            }
        } catch (error) {
            console.error('Status check error:', error);
            clearInterval(this.pollInterval);
            this.pollInterval = null;
            this.setState({ 
                status: 'error',
                errorMessage: this.props.t('processing failed')
            });
        }
    }
    
    downloadResult(type) {
        const { docId } = this.state;
        if (!docId) return;
        
        const url = `${API_URL}/get-result?doc_id=${docId}&type=${type}`;
        window.open(url, '_blank');
    }
    
    async cleanup() {
        const { docId } = this.state;
        if (!docId) return;
        
        try {
            await axios.post(API_URL + '/delete-results', 
                { doc_id: docId },
                { headers: { 'Content-Type': 'application/json' } }
            );
        } catch (error) {
            console.error('Cleanup error:', error);
        }
    }
    
    resetForm() {
        // Cleanup first
        if (this.state.docId) {
            this.cleanup();
        }
        
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        
        this.setState({
            uploadedFile: null,
            docId: null,
            status: 'idle',
            progress: 0,
            statusMessage: '',
            errorMessage: '',
            availableResults: {
                txt: false,
                pdf: false,
                pdf_indexed: false
            },
            resultSizes: {
                txt: null,
                pdf: { compressed: null, uncompressed: null },
                pdf_indexed: { compressed: null, uncompressed: null }
            }
        });
        
        if (this.fileInputRef.current) {
            this.fileInputRef.current.value = '';
        }
    }
    
    rerunOCR() {
        // Cleanup previous results but keep the file
        if (this.state.docId) {
            this.cleanup();
        }
        
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        
        // Reset processing state but keep the uploaded file and settings
        this.setState({
            docId: null,
            status: 'idle',
            progress: 0,
            statusMessage: '',
            errorMessage: '',
            availableResults: {
                txt: false,
                pdf: false,
                pdf_indexed: false
            },
            resultSizes: {
                txt: null,
                pdf: { compressed: null, uncompressed: null },
                pdf_indexed: { compressed: null, uncompressed: null }
            }
        });
    }
    
    componentDidMount() {
        // Fetch presets list
        axios.get(API_URL + '/presets-list')
            .then(({ data }) => {
                this.setState({ presetsList: ['default', ...data] });
            })
            .catch(err => {
                console.error('Failed to fetch presets:', err);
            });
    }
    
    render() {
        const { t } = this.props;
        const { 
            uploadedFile, 
            status, 
            progress, 
            statusMessage, 
            errorMessage,
            selectedLanguages,
            selectedPreset,
            presetsList,
            outputFormats,
            enableCompression,
            availableResults,
            resultSizes
        } = this.state;
        
        const isProcessing = status === 'processing' || status === 'uploading';
        const isComplete = status === 'complete';
        const hasError = status === 'error';
        
        return (
            <Box 
                className={`App ${MODEL === STJ ? "theme-stj" : "theme-un"}`}
                sx={{
                    minHeight: "100vh",
                    backgroundColor: "var(--gray-50)",
                    display: "flex",
                    flexDirection: "column"
                }}
            >
                {/* Header */}
                <Box 
                    className="header animate-slideInDown"
                    sx={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "var(--spacing-sm)",
                        padding: "var(--spacing-md) var(--spacing-xl)",
                        backgroundColor: "var(--card-bg)",
                        boxShadow: "var(--shadow-sm)",
                    }}
                >
                    <Box sx={{
                        display: "flex",
                        flexDirection: "row",
                        justifyContent: "space-between",
                        alignItems: "center",
                        width: "100%",
                    }}>
                        <Box sx={{display: "flex", alignItems: "center", gap: "var(--spacing-md)"}}>
                            <img
                                src={MODEL === STJ ? logoApp : logoUN}
                                alt={MODEL === STJ ? "Logótipo do STJ" : "Logótipo da UN"}
                                style={{
                                    maxHeight: "45px",
                                    transition: "transform var(--transition-base)",
                                }}
                            />
                            
                            <Typography
                                variant="h5"
                                component="h1"
                                className="fancy-font"
                                sx={{
                                    display: {xs: "none", md: "block"},
                                    color: "var(--header-text)",
                                }}
                            >
                                {t('immediate ocr')}
                            </Typography>
                        </Box>

                        <Button
                            component={Link}
                            to="/"
                            variant="outlined"
                            startIcon={<ArrowBackIcon />}
                            sx={{
                                textTransform: "none",
                                borderColor: "var(--border-color)",
                                color: "var(--text-primary)",
                                '&:hover': {
                                    borderColor: "var(--accent-primary)",
                                    backgroundColor: "var(--card-hover-bg)",
                                }
                            }}
                        >
                            {t("back") || "Back"}
                        </Button>
                    </Box>
                </Box>

                {/* Main Content */}
                <Box sx={{
                    flexGrow: 1,
                    width: '87vw',
                    marginLeft: 'auto',
                    marginRight: 'auto',
                    marginTop: 'var(--spacing-lg)',
                    marginBottom: 'var(--spacing-lg)',
                }}>
                    {/* Info Alert */}
                    <Alert severity="info" sx={{ mb: 2 }}>
                        {t('temporary processing note')}
                    </Alert>
                    
                    {/* Error Alert */}
                    {hasError && errorMessage && (
                        <Alert 
                            severity="error" 
                            sx={{ mb: 2 }}
                            action={
                                <Button 
                                    color="inherit" 
                                    size="small"
                                    onClick={() => this.setState({ 
                                        status: 'idle',
                                        errorMessage: '',
                                        docId: null,
                                        progress: 0
                                    })}
                                >
                                    {t('retry')}
                                </Button>
                            }
                        >
                            {errorMessage}
                        </Alert>
                    )}

                    {/* Three Column Layout */}
                    <Box sx={{
                        display: 'flex',
                        flexDirection: 'row',
                        justifyContent: 'space-evenly',
                    }}>
                    {/* Left Column - Upload & Languages */}
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
                        width: '40%'
                    }}>
                        {/* Upload Section */}
                        <Box sx={{ mb: 2 }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: '0.75rem' }}>
                                <Typography component="legend" sx={{ fontWeight: 500 }}>
                                    {t('upload for immediate ocr')}
                                </Typography>
                            </Box>
                            <Box
                                onDrop={this.handleDrop}
                                onDragOver={this.handleDragOver}
                                sx={{
                                    border: '2px dashed',
                                    borderColor: uploadedFile ? 'success.main' : 'var(--border-color)',
                                    borderRadius: 'var(--radius-md)',
                                    padding: '24px',
                                    textAlign: 'center',
                                    backgroundColor: uploadedFile ? 'rgba(46, 125, 50, 0.08)' : 'var(--gray-50)',
                                    cursor: 'pointer',
                                    transition: 'all 0.2s',
                                    '&:hover': {
                                        borderColor: 'var(--accent-primary)',
                                        backgroundColor: uploadedFile ? 'rgba(46, 125, 50, 0.12)' : 'var(--accent-light)'
                                    }
                                }}
                                onClick={() => this.fileInputRef.current?.click()}
                            >
                                <CloudUploadIcon sx={{ 
                                    fontSize: 36, 
                                    color: uploadedFile ? 'success.main' : 'var(--text-secondary)', 
                                    mb: 1 
                                }} />
                                <Typography variant="body2" sx={{ fontWeight: 500, mb: 0.5 }}>
                                    {uploadedFile ? t('file uploaded') : t('drag drop files')}
                                </Typography>
                                {uploadedFile && (
                                    <>
                                        <Typography variant="body2" sx={{ color: 'text.primary', display: 'block', mt: 1, fontWeight: 500 }}>
                                            {uploadedFile.name}
                                        </Typography>
                                        <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 0.5 }}>
                                            {(uploadedFile.size / 1024 / 1024).toFixed(2)} MB
                                        </Typography>
                                    </>
                                )}
                                {!uploadedFile && (
                                    <Typography variant="caption" sx={{ color: 'var(--text-secondary)', display: 'block', mt: 0.5 }}>
                                        {t('supported formats')}: PDF, JPG, PNG, TIFF, ZIP
                                    </Typography>
                                )}
                                <input
                                    ref={this.fileInputRef}
                                    type="file"
                                    accept=".pdf,.jpg,.jpeg,.png,.tiff,.tif,.zip"
                                    onChange={this.handleFileSelect}
                                    style={{ display: 'none' }}
                                />
                            </Box>
                        </Box>

                        {/* Languages Section */}
                        <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: '0.5rem', marginTop: '1rem' }}>
                            <Typography component="legend" sx={{ fontWeight: 500 }}>
                                {t('select languages')}
                            </Typography>
                        </Box>
                        <CheckboxList
                            title=""
                            options={tesseractLangList().map(lang => ({
                                value: lang.value,
                                description: t(lang.translationKey),
                                disabled: lang.disabled
                            }))}
                            checked={selectedLanguages}
                            onChangeCallback={(checked) => this.setState({ selectedLanguages: checked })}
                            required
                            showOrder
                            helperText={t('language hint')}
                            errorText={t('language required')}
                        />
                    </Box>

                    {/* Middle Column - Preset & Process Button */}
                    <Box sx={{
                        display: 'flex',
                        flexDirection: 'column',
                        width: '25%',
                        maxHeight: '65vh',
                        overflowY: 'auto',
                        overflowX: 'visible',
                        paddingRight: '1rem',
                        paddingLeft: '0.5rem',
                        paddingTop: '0.25rem',
                        paddingBottom: '0.5rem',
                    }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: '0.5rem' }}>
                            <Typography component="legend" sx={{ fontWeight: 500 }}>
                                {t('select preset')}
                            </Typography>
                        </Box>
                        <FormControl fullWidth size="small">
                            <InputLabel id="preset-select-label">{t('ocr preset')}</InputLabel>
                            <Select
                                labelId="preset-select-label"
                                value={selectedPreset}
                                label={t('ocr preset')}
                                onChange={(e) => this.setState({ selectedPreset: e.target.value })}
                            >
                                {presetsList.map((preset) => (
                                    <MenuItem key={preset} value={preset}>
                                        {t(`presets.${preset}`)}
                                    </MenuItem>
                                ))}
                            </Select>
                        </FormControl>

                        {/* Process Button */}
                        {!isComplete && (
                            <Button
                                variant="contained"
                                size="large"
                                fullWidth
                                startIcon={isProcessing ? <CircularProgress size={20} color="inherit" /> : <FlashOnIcon />}
                                onClick={this.processFile}
                                disabled={!uploadedFile || isProcessing || selectedLanguages.length === 0}
                                sx={{ 
                                    mt: 4,
                                    py: 1.5,
                                    fontSize: '1rem',
                                    fontWeight: 600,
                                    boxShadow: 'var(--shadow-md)',
                                }}
                            >
                                {isProcessing ? t('processing') : t('process now')}
                            </Button>
                        )}
                    </Box>

                    {/* Right Column - Output Formats & Compression */}
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
                        width: '30%'
                    }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: '0.5rem' }}>
                            <Typography component="legend" sx={{ fontWeight: 500 }}>
                                {t('output formats')}
                            </Typography>
                        </Box>
                        <FormGroup>
                            <FormControlLabel
                                control={
                                    <Checkbox
                                        checked={outputFormats.txt}
                                        onChange={() => this.toggleOutputFormat('txt')}
                                    />
                                }
                                label={t('plain text')}
                            />
                            <FormControlLabel
                                control={
                                    <Checkbox
                                        checked={outputFormats.pdf}
                                        onChange={() => this.toggleOutputFormat('pdf')}
                                    />
                                }
                                label={t('pdf simple')}
                            />
                            <FormControlLabel
                                control={
                                    <Checkbox
                                        checked={outputFormats.pdf_indexed}
                                        onChange={() => this.toggleOutputFormat('pdf_indexed')}
                                    />
                                }
                                label={t('pdf searchable')}
                            />
                        </FormGroup>
                        
                        {/* Compression Settings - Only show if PDF output is selected */}
                        {(outputFormats.pdf || outputFormats.pdf_indexed) && (
                            <FormControl className="simpleDropdown borderTop" sx={{ paddingTop: '1rem', mt: 2 }}>
                                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                    <FormControlLabel
                                        control={
                                            <Switch
                                                checked={enableCompression}
                                                onChange={(e) => this.setState({ enableCompression: e.target.checked })}
                                                color="primary"
                                            />
                                        }
                                        label={t('compress pdf')}
                                    />
                                </Box>
                                <Typography variant="caption" color="text.secondary" sx={{ ml: 2, mt: 0.5 }}>
                                    {t('compression info')}
                                </Typography>
                                
                                {enableCompression && (
                                    <Box sx={{ mt: 2, ml: 2 }}>
                                        <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>
                                            {t('compression settings')}
                                        </Typography>
                                        <TextField
                                            label={t('compression target dpi')}
                                            type="number"
                                            size="small"
                                            fullWidth
                                            value={this.state.compressionTargetDpi}
                                            onChange={(e) => this.setState({ compressionTargetDpi: e.target.value })}
                                            inputProps={{ min: 50, max: 300 }}
                                            sx={{ mb: 1.5 }}
                                        />
                                        <TextField
                                            label={t('compression bg quality')}
                                            type="number"
                                            size="small"
                                            fullWidth
                                            value={this.state.compressionBgQuality}
                                            onChange={(e) => this.setState({ compressionBgQuality: e.target.value })}
                                            inputProps={{ min: 1, max: 100 }}
                                            sx={{ mb: 1.5 }}
                                        />
                                        <TextField
                                            label={t('compression fg quality')}
                                            type="number"
                                            size="small"
                                            fullWidth
                                            value={this.state.compressionFgQuality}
                                            onChange={(e) => this.setState({ compressionFgQuality: e.target.value })}
                                            inputProps={{ min: 1, max: 100 }}
                                        />
                                    </Box>
                                )}
                            </FormControl>
                        )}
                    </Box>
                </Box>
                
                {/* Progress Section - Below columns */}
                {isProcessing && (
                    <Card sx={{ backgroundColor: 'var(--card-bg)', boxShadow: 'var(--shadow-sm)', mt: 3 }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                                {t('processing document')}
                            </Typography>
                            <LinearProgress 
                                variant="determinate" 
                                value={progress} 
                                sx={{ height: 10, borderRadius: 5, mb: 1 }}
                            />
                            <Typography variant="body2" sx={{ color: 'var(--text-secondary)' }}>
                                {progress}% - {statusMessage}
                            </Typography>
                        </CardContent>
                    </Card>
                )}
                
                {/* Results Section - Below columns */}
                {isComplete && (
                    <Card sx={{ backgroundColor: 'var(--card-bg)', boxShadow: 'var(--shadow-sm)', mt: 3 }}>
                        <CardContent>
                                <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, color: 'var(--success-main)' }}>
                                    {t('results ready')}
                                </Typography>
                                
                                <Grid container spacing={2}>
                                    {availableResults.txt && (
                                        <Grid item xs={12} sm={6} md={4}>
                                            <Button
                                                variant="contained"
                                                startIcon={<DownloadIcon />}
                                                onClick={() => this.downloadResult('txt')}
                                                fullWidth
                                            >
                                                {t('download text')} {resultSizes.txt && `(${resultSizes.txt})`}
                                            </Button>
                                        </Grid>
                                    )}
                                    {availableResults.pdf && (
                                        <>
                                            <Grid item xs={12} sm={6} md={4}>
                                                <Button
                                                    variant="contained"
                                                    startIcon={<DownloadIcon />}
                                                    onClick={() => this.downloadResult('pdf')}
                                                    fullWidth
                                                >
                                                    {t('pdf simple')}
                                                    {resultSizes.pdf.compressed && ` (${resultSizes.pdf.compressed})`}
                                                </Button>
                                            </Grid>
                                            {enableCompression && resultSizes.pdf.uncompressed && (
                                                <Grid item xs={12} sm={6} md={4}>
                                                    <Button
                                                        variant="outlined"
                                                        startIcon={<DownloadIcon />}
                                                        onClick={() => this.downloadResult('pdf_uncompressed')}
                                                        fullWidth
                                                    >
                                                        {t('pdf simple')} - {t('uncompressed')}
                                                        {` (${resultSizes.pdf.uncompressed})`}
                                                    </Button>
                                                </Grid>
                                            )}
                                        </>
                                    )}
                                    {availableResults.pdf_indexed && (
                                        <>
                                            <Grid item xs={12} sm={6} md={4}>
                                                <Button
                                                    variant="contained"
                                                    startIcon={<DownloadIcon />}
                                                    onClick={() => this.downloadResult('pdf_indexed')}
                                                    fullWidth
                                                >
                                                    {t('pdf searchable')}
                                                    {resultSizes.pdf_indexed.compressed && ` (${resultSizes.pdf_indexed.compressed})`}
                                                </Button>
                                            </Grid>
                                            {enableCompression && resultSizes.pdf_indexed.uncompressed && (
                                                <Grid item xs={12} sm={6} md={4}>
                                                    <Button
                                                        variant="outlined"
                                                        startIcon={<DownloadIcon />}
                                                        onClick={() => this.downloadResult('pdf_indexed_uncompressed')}
                                                        fullWidth
                                                    >
                                                        {t('pdf searchable')} - {t('uncompressed')}
                                                        {` (${resultSizes.pdf_indexed.uncompressed})`}
                                                    </Button>
                                                </Grid>
                                            )}
                                        </>
                                    )}
                                </Grid>
                                
                                <Divider sx={{ my: 3 }} />
                                
                                <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
                                    <Button
                                        variant="contained"
                                        startIcon={<FlashOnIcon />}
                                        onClick={this.rerunOCR.bind(this)}
                                        sx={{ minWidth: 200 }}
                                    >
                                        {t('rerun with different settings')}
                                    </Button>
                                    <Button
                                        variant="outlined"
                                        startIcon={<DeleteIcon />}
                                        onClick={this.resetForm}
                                        sx={{ minWidth: 200 }}
                                    >
                                        {t('upload new document')}
                                    </Button>
                                </Box>
                            </CardContent>
                        </Card>
                )}
                </Box>
            </Box>
        );
    }
}

// Wrap with translation HOC
const ImmediateOCRWithTranslation = (props) => {
    const { t } = useTranslation();
    return <ImmediateOCR {...props} t={t} />;
};

export default ImmediateOCRWithTranslation;
