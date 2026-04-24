import React from 'react';
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import DeleteForeverIcon from '@mui/icons-material/DeleteForever';
import SettingsIcon from '@mui/icons-material/Settings';
import SettingsSuggestIcon from '@mui/icons-material/SettingsSuggest';
import TuneIcon from '@mui/icons-material/Tune';
import DownloadIcon from '@mui/icons-material/Download';
import EditIcon from '@mui/icons-material/Edit';
import ImageIcon from '@mui/icons-material/Image';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import HourglassEmptyIcon from '@mui/icons-material/HourglassEmpty';

import { withTranslation } from "react-i18next";
import OcrIcon from 'Components/CustomIcons/OcrIcon';
import LayoutIcon from 'Components/CustomIcons/LayoutIcon';
import PdfIcon from 'Components/CustomIcons/PdfIcon';

const API_URL = `${window.location.protocol}//${window.location.host}/${process.env.REACT_APP_API_URL}`;
const BASE_URL = `${window.location.protocol}//${window.location.host}/${process.env.REACT_APP_BASENAME}`;

class DocumentCard extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            info: props.info,
            contextMenu: null,
            imageLoaded: false,
            imageError: false,
            isHovered: false,
        };
    }

    updateInfo(info) {
        this.setState({ info: info });
    }

    componentDidUpdate(prevProps) {
        if (prevProps.info !== this.props.info && this.props.info !== null) {
            this.setState({ info: this.props.info });
        }
    }

    handleOptionsClick(event) {
        event.stopPropagation();
        this.setState({
            contextMenu: this.state.contextMenu === null
                ? { anchorEl: event.currentTarget }
                : null
        });
    }

    handleContextMenu(event) {
        event.preventDefault();
        event.stopPropagation();
        this.setState({
            contextMenu: this.state.contextMenu === null
                ? { mouseX: event.clientX + 2, mouseY: event.clientY - 6 }
                : null
        });
    }

    handleCloseContextMenu() {
        this.setState({ contextMenu: null });
    }

    documentClicked() {
        // Open the Layout Menu (document viewer) when clicking the card
        if (this.state.info?.stored === true) {
            this.props.createLayout(this.props.name);
        }
    }

    performOCR(e, usingCustomConfig) {
        e.stopPropagation();
        this.handleCloseContextMenu();
        const customConfig = usingCustomConfig ? this.state.info?.["config"] : null;
        this.props.performOCR(this.props.name, false, false, customConfig);
    }

    configureOCR(e, usingCustomConfig) {
        e.stopPropagation();
        this.handleCloseContextMenu();
        const customConfig = usingCustomConfig ? this.state.info?.["config"] : null;
        this.props.configureOCR(this.props.name, false, false, customConfig);
    }

    createLayout(e) {
        e.stopPropagation();
        this.handleCloseContextMenu();
        this.props.createLayout(this.props.name);
    }

    editText(e) {
        e.stopPropagation();
        this.handleCloseContextMenu();
        this.props.editText(this.props.name);
    }

    delete(e) {
        e.stopPropagation();
        this.handleCloseContextMenu();
        this.props.deleteItem(this.props.name);
    }

    getStatusBadges() {
        const info = this.state.info;
        if (!info) return null;

        const stored = info["stored"];
        const status = info["status"];
        const ocrInfo = info["ocr"];
        const usingCustomConfig = info?.["config"] && info["config"] !== "default";

        const badges = [];

        // Priority badges (only show one at a time, in order of priority)
        // Show "Preparing" or "Uploading" badge with progress when stored is a number
        if (typeof stored === "number") {
            const isUploading = status?.stage === "uploading";
            badges.push(
                <Box key={isUploading ? "uploading" : "preparing"} className="status-badge warning" sx={{ position: 'absolute', top: 'var(--spacing-sm)', left: 'var(--spacing-sm)' }}>
                    <CircularProgress size={12} sx={{ mr: '4px' }} variant="determinate" value={stored} />
                    {isUploading ? this.props.t("uploading stage") : this.props.t("preparing stage")} ({Math.round(stored)}%)
                </Box>
            );
            return badges;
        }

        if (stored === false) {
            badges.push(
                <Box key="uploading" className="status-badge warning" sx={{ position: 'absolute', top: 'var(--spacing-sm)', left: 'var(--spacing-sm)' }}>
                    <HourglassEmptyIcon sx={{ fontSize: '0.875rem', mr: '4px' }} />
                    {this.props.t("uploading")}
                </Box>
            );
            return badges;
        }

        if (stored === "stuck") {
            badges.push(
                <Box key="error" className="status-badge error" sx={{ position: 'absolute', top: 'var(--spacing-sm)', left: 'var(--spacing-sm)' }}>
                    <ErrorIcon sx={{ fontSize: '0.875rem', mr: '4px' }} />
                    {this.props.t("upload error")}
                </Box>
            );
            return badges;
        }

        // Error state
        if (status?.stage === "error") {
            const errorMsg = status.message 
                ? this.props.t(status.message) 
                : this.props.t("error");
            badges.push(
                <Box key="error" className="status-badge error" sx={{ position: 'absolute', top: 'var(--spacing-sm)', left: 'var(--spacing-sm)' }}>
                    <ErrorIcon sx={{ fontSize: '0.875rem', mr: '4px' }} />
                    {errorMsg}
                </Box>
            );
            return badges;
        }

        // Compression in progress
        if (status?.stage === "compressing") {
            const currentPage = status.current;
            const totalPages = status.total;
            badges.push(
                <Box key="compressing" className="status-badge info" sx={{ position: 'absolute', top: 'var(--spacing-sm)', left: 'var(--spacing-sm)' }}>
                    <CircularProgress 
                        size={12} 
                        sx={{ mr: '4px' }} 
                    />
                    {currentPage && totalPages
                        ? this.props.t("compressing file page", { current: currentPage, total: totalPages })
                        : this.props.t("compressing")
                    }
                </Box>
            );
            return badges;
        }

        // Exporting stage
        if (status?.stage === "exporting") {
            badges.push(
                <Box key="exporting" className="status-badge info" sx={{ position: 'absolute', top: 'var(--spacing-sm)', left: 'var(--spacing-sm)' }}>
                    <CircularProgress size={12} sx={{ mr: '4px' }} />
                    {this.props.t("exporting")}
                </Box>
            );
            return badges;
        }

        // Waiting/queued stage - only show if OCR has been requested
        if (status?.stage === "waiting" && (ocrInfo || stored === false)) {
            badges.push(
                <Box key="waiting" className="status-badge info" sx={{ position: 'absolute', top: 'var(--spacing-sm)', left: 'var(--spacing-sm)' }}>
                    <CircularProgress size={12} sx={{ mr: '4px' }} />
                    {this.props.t("preparing ocr")}
                </Box>
            );
            return badges;
        }

        // OCR progress badge (in progress)
        if (ocrInfo) {
            const progress = ocrInfo["progress"];
            const pages = info["pages"];

            if (progress > 0 && progress < pages) {
                badges.push(
                    <Box key="ocr-progress" className="status-badge info" sx={{ position: 'absolute', top: 'var(--spacing-sm)', left: 'var(--spacing-sm)' }}>
                        <CircularProgress size={12} sx={{ mr: '4px' }} />
                        OCR {progress}/{pages}
                    </Box>
                );
                return badges;
            }
        }

        // Cancelled state
        if (status?.stage === "cancelled") {
            badges.push(
                <Box key="cancelled" className="status-badge warning" sx={{ position: 'absolute', top: 'var(--spacing-sm)', left: 'var(--spacing-sm)' }}>
                    {this.props.t("ocr cancelled")}
                </Box>
            );
            return badges;
        }

        // Persistent indicators (can show multiple at once)
        // OCR complete indicator (top-right) - styled like folder finished badge
        if (status?.stage === "post-ocr" && stored === true) {
            badges.push(
                <Box 
                    key="ocr-complete" 
                    sx={{ 
                        position: 'absolute', 
                        top: 'var(--spacing-sm)', 
                        right: this.state.isHovered ? '3rem' : 'var(--spacing-sm)',
                        backgroundColor: 'rgba(76, 175, 80, 0.9)',
                        display: 'flex',
                        alignItems: 'center',
                        padding: 'var(--spacing-xs) var(--spacing-sm)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: 'var(--font-size-xs)',
                        fontWeight: 600,
                        color: 'white',
                        boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
                        transition: 'right 0.2s ease-in-out',
                        zIndex: 1
                    }}
                >
                    ✓ {this.props.t("queue.finished")}
                </Box>
            );
        }

        // Custom OCR config indicator (top-left)
        if (usingCustomConfig && stored === true) {
            badges.push(
                <Tooltip key="custom-config" title={this.props.t("custom config")} placement="top">
                    <SettingsSuggestIcon
                        sx={{
                            position: 'absolute',
                            top: 'var(--spacing-sm)',
                            left: 'var(--spacing-sm)',
                            fontSize: '1.5rem',
                            color: 'var(--accent-primary)',
                            background: 'rgba(255, 255, 255, 0.9)',
                            borderRadius: '50%',
                            padding: '4px'
                        }}
                    />
                </Tooltip>
            );
        }

        return badges.length > 0 ? badges : null;
    }

    render() {
        if (!this.state.info) {
            return (
                <Box className="file-card skeleton" sx={{ height: '320px' }} />
            );
        }

        const info = this.state.info;
        const stored = info["stored"];
        const pages = info["pages"];
        const size = info["size"];
        const creation = info["creation"];
        const ocrInfo = info["ocr"];
        const usingCustomConfig = info?.["config"] && info["config"] !== "default";

        const isProcessing = stored === false || (ocrInfo && ocrInfo["progress"] < pages);
        const hasOCR = Boolean(ocrInfo);

        // Use large (600px) thumbnail for better quality in card view
        const thumbnailUrl = `${BASE_URL}/${this.props._private ? 'private' : 'images'}/${this.props.thumbnails.large}`;

        return (
            <>
                <Box
                    className="file-card animate-fadeIn"
                    onClick={() => this.documentClicked()}
                    onContextMenu={(e) => this.handleContextMenu(e)}
                    onMouseEnter={() => this.setState({ isHovered: true })}
                    onMouseLeave={() => this.setState({ isHovered: false })}
                    sx={{ opacity: stored === false ? 0.7 : 1, cursor: stored === true ? 'pointer' : 'default' }}
                >
                    <Box className="file-card-thumbnail">
                        {!this.state.imageLoaded && !this.state.imageError && (
                            <Box className="skeleton" sx={{ position: 'absolute', width: '100%', height: '100%' }} />
                        )}
                        {this.state.imageError ? (
                            <PdfIcon sx={{ fontSize: '4rem', color: 'var(--gray-400)' }} />
                        ) : (
                            <img
                                src={thumbnailUrl}
                                alt={this.props.name}
                                onLoad={() => this.setState({ imageLoaded: true })}
                                onError={() => this.setState({ imageError: true })}
                                style={{ display: this.state.imageLoaded ? 'block' : 'none' }}
                            />
                        )}
                        {this.getStatusBadges()}
                    </Box>

                    <Box className="file-card-content">
                        <Box className="file-card-title">{this.props.name}</Box>
                        <Box className="file-card-meta">
                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                <span>{pages} {this.props.t("pages")}</span>
                                <span>{size}</span>
                            </Box>
                            {creation && (
                                <Box sx={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)' }}>
                                    {creation}
                                </Box>
                            )}
                        </Box>
                    </Box>

                    <Box className="file-card-actions">
                        <IconButton
                            size="small"
                            onClick={(e) => this.handleOptionsClick(e)}
                            sx={{
                                position: 'relative',
                                zIndex: 2,
                                '&:hover': {
                                    backgroundColor: 'var(--accent-primary)',
                                    color: 'white'
                                }
                            }}
                        >
                            <MoreVertIcon fontSize="small" />
                        </IconButton>
                    </Box>
                </Box>

                <Menu
                    open={this.state.contextMenu !== null}
                    onClose={() => this.handleCloseContextMenu()}
                    anchorReference={this.state.contextMenu?.anchorEl ? "anchorEl" : "anchorPosition"}
                    anchorEl={this.state.contextMenu?.anchorEl}
                    anchorPosition={
                        this.state.contextMenu?.mouseY
                            ? { top: this.state.contextMenu.mouseY, left: this.state.contextMenu.mouseX }
                            : undefined
                    }
                >
                    <MenuItem onClick={() => this.documentClicked()} disabled={stored !== true}>
                        <VisibilityIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        {this.props.t("see document")}
                    </MenuItem>

                    {hasOCR && (
                        <MenuItem onClick={(e) => this.editText(e)} disabled={isProcessing}>
                            <EditIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                            {this.props.t("edit text")}
                        </MenuItem>
                    )}

                    <MenuItem onClick={(e) => this.createLayout(e)} disabled={stored !== true}>
                        <LayoutIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        {this.props.t("layout create")}
                    </MenuItem>

                    <MenuItem onClick={(e) => this.performOCR(e, usingCustomConfig)} disabled={isProcessing}>
                        <OcrIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        {hasOCR ? this.props.t("repeat ocr") : this.props.t("run ocr")}
                    </MenuItem>

                    <MenuItem onClick={(e) => this.configureOCR(e, usingCustomConfig)} disabled={isProcessing}>
                        {usingCustomConfig ? (
                            <SettingsSuggestIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        ) : (
                            <SettingsIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        )}
                        {this.props.t("config ocr")}
                    </MenuItem>

                    {hasOCR && (
                        <>
                            <MenuItem onClick={(e) => { e.stopPropagation(); this.props.getDocument("txt", this.props.name, "txt"); this.handleCloseContextMenu(); }} disabled={isProcessing}>
                                <DownloadIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                                {this.props.t("download txt")}
                            </MenuItem>
                            <MenuItem onClick={(e) => { e.stopPropagation(); this.props.getDocument("pdf", this.props.name, "pdf"); this.handleCloseContextMenu(); }} disabled={isProcessing}>
                                <DownloadIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                                {this.props.t("download pdf")}
                            </MenuItem>
                            <MenuItem onClick={(e) => { e.stopPropagation(); this.props.getImages(this.props.name); this.handleCloseContextMenu(); }} disabled={isProcessing}>
                                <ImageIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                                {this.props.t("download images")}
                            </MenuItem>
                        </>
                    )}

                    <MenuItem onClick={(e) => { e.stopPropagation(); this.props.getOriginalFile(this.props.name); this.handleCloseContextMenu(); }} disabled={stored !== true}>
                        <DownloadIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        {this.props.t("download original")}
                    </MenuItem>

                    <MenuItem onClick={(e) => this.delete(e)} sx={{ color: 'var(--red-600)' }}>
                        <DeleteForeverIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        {this.props.t("delete")}
                    </MenuItem>
                </Menu>
            </>
        );
    }
}

DocumentCard.defaultProps = {
    name: "",
    thumbnails: { small: "", large: "" },
    _private: false,
    info: null,
    enterDocument: null,
    deleteItem: null,
    getOriginalFile: null,
    getDocument: null,
    getEntities: null,
    requestEntities: null,
    getImages: null,
    editText: null,
    performOCR: null,
    configureOCR: null,
    createLayout: null,
};

export default withTranslation()(DocumentCard);


