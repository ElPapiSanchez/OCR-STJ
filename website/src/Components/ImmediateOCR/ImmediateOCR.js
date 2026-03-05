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
import Divider from '@mui/material/Divider';

import HomeIcon from '@mui/icons-material/Home';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import FlashOnIcon from '@mui/icons-material/FlashOn';
import DownloadIcon from '@mui/icons-material/Download';
import DeleteIcon from '@mui/icons-material/Delete';

import CheckboxList from 'Components/Form/CheckboxList';
import { tesseractLangList } from 'defaultOcrConfigs';
import Footer from 'Components/Footer/Footer';

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
            compressionQuality: 'auto', // 'auto', 'fast', or 'high'
            
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
        const { uploadedFile, selectedLanguages, selectedPreset, outputFormats, enableCompression, compressionQuality } = this.state;
        
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
                formData.append('compressionQuality', compressionQuality);
            } else {
                // Send complete config with all required fields
                const config = {
                    engine: "tesserocr",
                    lang: selectedLanguages,
                    outputs: outputs,
                    engineMode: 3,
                    segmentMode: 3,
                    thresholdMethod: 0,
                    compress: enableCompression,
                    compressionQuality: compressionQuality
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
            
            // Check for compression messages in Portuguese and translate them
            if (statusMessage.includes('A comprimir PDF')) {
                if (statusMessage.includes('A iniciar')) {
                    statusMessage = this.props.t('compressing pdf starting');
                } else if (statusMessage.includes('A finalizar')) {
                    statusMessage = this.props.t('compressing pdf finalizing');
                } else if (statusMessage.match(/Página \d+\/\d+/)) {
                    const match = statusMessage.match(/Página (\d+)\/(\d+)/);
                    if (match) {
                        statusMessage = this.props.t('compressing pdf page', { current: match[1], total: match[2] });
                    } else {
                        statusMessage = this.props.t('compressing pdf');
                    }
                } else if (statusMessage.includes('concluída')) {
                    statusMessage = this.props.t('compression complete');
                } else {
                    statusMessage = this.props.t('compressing pdf');
                }
            }
            
            // Calculate progress percentage based on stage
            let progressPercent = 0;
            const stage = data.status?.stage;
            
            // Check if PDF outputs are requested (which may trigger compression)
            const hasPdfOutput = outputFormats.pdf || outputFormats.pdf_indexed;
            const willCompress = enableCompression && hasPdfOutput;
            
            if (stage === 'ocr') {
                // OCR stage: map to 0-50% if compression will occur, otherwise 0-100%
                const ocrProgress = data.ocr?.progress || 0;
                const totalPages = data.pages || 1;
                const ocrPercent = (ocrProgress / totalPages) * 100;
                
                if (willCompress) {
                    // If compression enabled, OCR is 0-50%
                    progressPercent = Math.min(50, ocrPercent * 0.5);
                } else {
                    // If no compression, OCR is 0-100%
                    progressPercent = Math.min(100, ocrPercent);
                }
            } else if (stage === 'compressing') {
                // Compression stage: map to 50-100%
                const compressionProgress = data.status?.progress || 0;
                progressPercent = 50 + (compressionProgress * 0.5);
            } else if (stage === 'exporting') {
                // Exporting stage: use 90-100%
                progressPercent = willCompress ? 95 : 90;
            } else if (stage === 'post-ocr') {
                // Complete
                progressPercent = 100;
            } else {
                // Default to raw progress value for other stages
                progressPercent = data.ocr?.progress || 0;
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
            }
        });
        
        if (this.fileInputRef.current) {
            this.fileInputRef.current.value = '';
        }
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
            availableResults
        } = this.state;
        
        const isProcessing = status === 'processing' || status === 'uploading';
        const isComplete = status === 'complete';
        const hasError = status === 'error';
        
        return (
            <Box sx={{ 
                minHeight: '100vh', 
                display: 'flex', 
                flexDirection: 'column',
                backgroundColor: 'var(--gray-50)'
            }}>
                {/* Header */}
                <Box sx={{ 
                    backgroundColor: 'white',
                    borderBottom: '1px solid var(--border-color)',
                    padding: 'var(--spacing-md) var(--spacing-xl)',
                    boxShadow: 'var(--shadow-sm)'
                }}>
                    <Box sx={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        justifyContent: 'space-between'
                    }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                            <FlashOnIcon sx={{ fontSize: 32, color: 'var(--accent-primary)' }} />
                            <Typography variant="h4" component="h1" sx={{ fontWeight: 600 }}>
                                {t('immediate ocr')}
                            </Typography>
                        </Box>
                        
                        <Button
                            component={Link}
                            to="/"
                            variant="outlined"
                            startIcon={<HomeIcon />}
                            sx={{ textTransform: 'none' }}
                        >
                            {t('return to home')}
                        </Button>
                    </Box>
                </Box>
                
                {/* Main Content */}
                <Box sx={{ 
                    flex: 1,
                    padding: 'var(--spacing-xl)',
                    maxWidth: '1200px',
                    width: '100%',
                    margin: '0 auto'
                }}>
                    {/* Info Alert */}
                    <Alert severity="info" sx={{ mb: 3 }}>
                        {t('temporary processing note')}
                    </Alert>
                    
                    {/* Error Alert */}
                    {hasError && errorMessage && (
                        <Alert severity="error" sx={{ mb: 3 }} onClose={() => this.setState({ errorMessage: '' })}>
                            {errorMessage}
                        </Alert>
                    )}
                    
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                        {/* File Upload Section */}
                        <Paper sx={{ p: 3 }}>
                            <Typography variant="h6" sx={{ mb: 2 }}>
                                {t('upload for immediate ocr')}
                            </Typography>
                            
                            <Box
                                onDrop={this.handleDrop}
                                onDragOver={this.handleDragOver}
                                sx={{
                                    border: '2px dashed var(--border-color)',
                                    borderRadius: 'var(--radius-md)',
                                    padding: '40px',
                                    textAlign: 'center',
                                    backgroundColor: uploadedFile ? 'var(--success-light)' : 'var(--gray-50)',
                                    cursor: 'pointer',
                                    transition: 'all 0.3s',
                                    '&:hover': {
                                        borderColor: 'var(--accent-primary)',
                                        backgroundColor: 'var(--accent-light)'
                                    }
                                }}
                                onClick={() => this.fileInputRef.current?.click()}
                            >
                                <CloudUploadIcon sx={{ fontSize: 48, color: 'var(--text-secondary)', mb: 2 }} />
                                <Typography variant="body1" sx={{ mb: 1 }}>
                                    {uploadedFile ? t('file uploaded') : t('drag drop files')}
                                </Typography>
                                {uploadedFile && (
                                    <Typography variant="body2" sx={{ color: 'var(--text-secondary)', fontWeight: 600 }}>
                                        {uploadedFile.name} ({(uploadedFile.size / 1024 / 1024).toFixed(2)} MB)
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
                        </Paper>
                        
                        {/* Configuration Section */}
                        <Paper sx={{ p: 3 }}>
                            <Typography variant="h6" sx={{ mb: 2 }}>
                                {t('config ocr')}
                            </Typography>
                            
                            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                                {/* Language Selection */}
                                <Box>
                                    <CheckboxList
                                        title={t('select languages')}
                                        options={tesseractLangList()}
                                        checked={selectedLanguages}
                                        onChangeCallback={(checked) => this.setState({ selectedLanguages: checked })}
                                        required
                                        showOrder
                                        helperText={t('language hint')}
                                        errorText={t('language required')}
                                    />
                                </Box>
                                
                                <Divider />
                                
                                {/* Preset Selection */}
                                <FormControl fullWidth>
                                    <InputLabel id="preset-select-label">{t('select preset')}</InputLabel>
                                    <Select
                                        labelId="preset-select-label"
                                        value={selectedPreset}
                                        label={t('select preset')}
                                        onChange={(e) => this.setState({ selectedPreset: e.target.value })}
                                    >
                                        {presetsList.map((preset) => (
                                            <MenuItem key={preset} value={preset}>
                                                {t(`presets.${preset}`)}
                                            </MenuItem>
                                        ))}
                                    </Select>
                                </FormControl>
                            </Box>
                        </Paper>
                        
                        {/* Output Formats Section */}
                        <Paper sx={{ p: 3 }}>
                            <Typography variant="h6" sx={{ mb: 2 }}>
                                {t('select output formats')}
                            </Typography>
                            
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
                            
                            <Divider sx={{ my: 2 }} />
                            
                            {/* Compression Toggle */}
                            <FormControlLabel
                                control={
                                    <Checkbox
                                        checked={enableCompression}
                                        onChange={(e) => {
                                            this.setState({ enableCompression: e.target.checked });
                                        }}
                                    />
                                }
                                label={
                                    <Box>
                                        <Typography variant="body1">{t('enable compression')}</Typography>
                                        <Typography variant="caption" color="text.secondary">
                                            {t('compression info')}
                                        </Typography>
                                    </Box>
                                }
                            />
                            
                            {/* Compression Quality Selector */}
                            {enableCompression && (
                                <Box sx={{ mt: 2, pl: 4 }}>
                                    <FormControl fullWidth size="small">
                                        <InputLabel id="compression-quality-label">{t('compression quality')}</InputLabel>
                                        <Select
                                            labelId="compression-quality-label"
                                            value={this.state.compressionQuality}
                                            label={t('compression quality')}
                                            onChange={(e) => this.setState({ compressionQuality: e.target.value })}
                                        >
                                            <MenuItem value="auto">
                                                <Box>
                                                    <Typography variant="body2">{t('compression auto')}</Typography>
                                                    <Typography variant="caption" color="text.secondary">
                                                        {t('compression auto desc')}
                                                    </Typography>
                                                </Box>
                                            </MenuItem>
                                            <MenuItem value="fast">
                                                <Box>
                                                    <Typography variant="body2">{t('compression fast')}</Typography>
                                                    <Typography variant="caption" color="text.secondary">
                                                        {t('compression fast desc')}
                                                    </Typography>
                                                </Box>
                                            </MenuItem>
                                            <MenuItem value="high">
                                                <Box>
                                                    <Typography variant="body2">{t('compression high quality')}</Typography>
                                                    <Typography variant="caption" color="text.secondary">
                                                        {t('compression high quality desc')}
                                                    </Typography>
                                                </Box>
                                            </MenuItem>
                                        </Select>
                                    </FormControl>
                                </Box>
                            )}
                        </Paper>
                        
                        {/* Process Button */}
                        {!isComplete && (
                            <Button
                                variant="contained"
                                size="large"
                                startIcon={isProcessing ? <CircularProgress size={20} color="inherit" /> : <FlashOnIcon />}
                                onClick={this.processFile}
                                disabled={!uploadedFile || isProcessing}
                                sx={{ 
                                    py: 1.5,
                                    fontSize: '1.1rem',
                                    fontWeight: 600
                                }}
                            >
                                {isProcessing ? statusMessage : t('process now')}
                            </Button>
                        )}
                        
                        {/* Progress Section */}
                        {isProcessing && (
                            <Paper sx={{ p: 3 }}>
                                <Typography variant="h6" sx={{ mb: 2 }}>
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
                            </Paper>
                        )}
                        
                        {/* Results Section */}
                        {isComplete && (
                            <Paper sx={{ p: 3 }}>
                                <Typography variant="h6" sx={{ mb: 2, color: 'var(--success-main)' }}>
                                    {t('results ready')}
                                </Typography>
                                
                                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                    {availableResults.txt && (
                                        <Button
                                            variant="contained"
                                            startIcon={<DownloadIcon />}
                                            onClick={() => this.downloadResult('txt')}
                                            fullWidth
                                        >
                                            {t('download text')}
                                        </Button>
                                    )}
                                    {availableResults.pdf && (
                                        <Button
                                            variant="contained"
                                            startIcon={<DownloadIcon />}
                                            onClick={() => this.downloadResult('pdf')}
                                            fullWidth
                                        >
                                            {t('download pdf')} ({t('pdf simple')})
                                        </Button>
                                    )}
                                    {availableResults.pdf_indexed && (
                                        <Button
                                            variant="contained"
                                            startIcon={<DownloadIcon />}
                                            onClick={() => this.downloadResult('pdf_indexed')}
                                            fullWidth
                                        >
                                            {t('download pdf')} ({t('pdf searchable')})
                                        </Button>
                                    )}
                                    
                                    <Divider sx={{ my: 1 }} />
                                    
                                    <Button
                                        variant="outlined"
                                        startIcon={<DeleteIcon />}
                                        onClick={this.resetForm}
                                        fullWidth
                                    >
                                        {t('upload new document')}
                                    </Button>
                                </Box>
                            </Paper>
                        )}
                    </Box>
                </Box>
                
                <Footer />
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
