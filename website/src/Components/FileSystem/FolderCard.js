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
import FolderIcon from '@mui/icons-material/Folder';
import DescriptionIcon from '@mui/icons-material/Description';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import CancelIcon from '@mui/icons-material/Cancel';

import { withTranslation } from "react-i18next";
import OcrIcon from 'Components/CustomIcons/OcrIcon';

class FolderCard extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            info: props.info,
            contextMenu: null,
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

    folderClicked() {
        this.props.enterFolder(this.props.name);
    }

    performOCR(e, usingCustomConfig) {
        e.stopPropagation();
        this.handleCloseContextMenu();
        const customConfig = usingCustomConfig ? this.state.info?.["config"] : null;
        this.props.performOCR(this.props.name, true, true, customConfig);
    }

    configureOCR(e, usingCustomConfig) {
        e.stopPropagation();
        this.handleCloseContextMenu();
        const customConfig = usingCustomConfig ? this.state.info?.["config"] : null;
        this.props.configureOCR(this.props.name, true, false, customConfig);
    }

    cancelFolderOCR(e) {
        e.stopPropagation();
        this.handleCloseContextMenu();
        this.props.cancelFolderOCR(this.props.name);
    }

    delete(e) {
        e.stopPropagation();
        this.handleCloseContextMenu();
        this.props.deleteItem(this.props.name);
    }

    getQueueStatusBadge() {
        const queueStatus = this.state.info?.["queue_status"];
        if (!queueStatus) return null;

        if (queueStatus.state === "active") {
            return (
                <Box 
                    key="folder-active" 
                    className="status-badge info" 
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
                    <CircularProgress size={12} sx={{ mr: '4px', color: 'white' }} />
                    {this.props.t("queue.processing")}
                </Box>
            );
        }

        if (queueStatus.state === "queued") {
            const position = queueStatus.position || 0;
            return (
                <Box 
                    key="folder-queued" 
                    className="status-badge warning" 
                    sx={{ 
                        position: 'absolute', 
                        top: 'var(--spacing-sm)', 
                        right: this.state.isHovered ? '3rem' : 'var(--spacing-sm)',
                        backgroundColor: 'rgba(255, 152, 0, 0.9)',
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
                    {this.props.t("queue.pending")} (#{position})
                </Box>
            );
        }

        if (queueStatus.state === "finished") {
            return (
                <Box 
                    key="folder-finished" 
                    className="status-badge success" 
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

        return null;
    }

    render() {
        if (!this.state.info) {
            return (
                <Box className="file-card skeleton" sx={{ height: '280px' }} />
            );
        }

        const contents = this.state.info?.["contents"];
        const nDocs = Number(contents?.["documents"]);
        const nSubfolders = Number(contents?.["subfolders"]);
        const size = this.state.info?.["size"];
        const usingCustomConfig = this.state.info?.["config"] && this.state.info["config"] !== "default";

        return (
            <>
                <Box
                    className="file-card folder-card animate-fadeIn"
                    onClick={() => this.folderClicked()}
                    onContextMenu={(e) => this.handleContextMenu(e)}
                    onMouseEnter={() => this.setState({ isHovered: true })}
                    onMouseLeave={() => this.setState({ isHovered: false })}
                >
                    <Box className="file-card-thumbnail">
                        {this.state.isHovered ? (
                            <FolderOpenIcon sx={{ fontSize: '6rem', color: 'var(--gold-600)' }} />
                        ) : (
                            <FolderIcon sx={{ fontSize: '6rem', color: 'var(--gold-600)' }} />
                        )}
                        {this.getQueueStatusBadge()}
                        {usingCustomConfig && (
                            <Tooltip title={this.props.t("custom config")}>
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
                        )}
                    </Box>

                    <Box className="file-card-content">
                        <Box className="file-card-title">{this.props.name}</Box>
                        <Box className="file-card-meta">
                            <Box sx={{ display: 'flex', gap: 'var(--spacing-md)', flexWrap: 'wrap' }}>
                                {nDocs > 0 && (
                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-xs)' }}>
                                        <DescriptionIcon sx={{ fontSize: '0.875rem' }} />
                                        <span>{nDocs} {this.props.t(nDocs === 1 ? "document" : "documents")}</span>
                                    </Box>
                                )}
                                {nSubfolders > 0 && (
                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-xs)' }}>
                                        <FolderIcon sx={{ fontSize: '0.875rem' }} />
                                        <span>{nSubfolders} {this.props.t(nSubfolders === 1 ? "folder" : "folders")}</span>
                                    </Box>
                                )}
                            </Box>
                            {size && (
                                <Box sx={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)', mt: 'var(--spacing-xs)' }}>
                                    {size}
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
                    <MenuItem onClick={() => this.folderClicked()}>
                        <FolderOpenIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        {this.props.t("open folder")}
                    </MenuItem>

                    <Tooltip
                        placement="right"
                        title={this.props.t("folder without files")}
                        disableFocusListener={!isNaN(nDocs) && nDocs !== 0}
                        disableHoverListener={!isNaN(nDocs) && nDocs !== 0}
                        disableTouchListener={!isNaN(nDocs) && nDocs !== 0}
                    >
                        <span>
                            <MenuItem
                                disabled={isNaN(nDocs) || nDocs === 0}
                                onClick={(e) => this.performOCR(e, usingCustomConfig)}
                            >
                                <OcrIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                                {this.props.t("run ocr")}
                            </MenuItem>
                        </span>
                    </Tooltip>

                    <MenuItem onClick={(e) => this.configureOCR(e, usingCustomConfig)}>
                        {usingCustomConfig ? (
                            <SettingsSuggestIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        ) : (
                            <SettingsIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        )}
                        {this.props.t("config ocr")}
                    </MenuItem>

                    {this.state.info?.["queue_status"]?.state === "active" && (
                        <MenuItem onClick={(e) => this.cancelFolderOCR(e)} sx={{ color: 'var(--red-600)' }}>
                            <CancelIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                            {this.props.t("cancel ocr")}
                        </MenuItem>
                    )}

                    <MenuItem onClick={(e) => this.delete(e)} sx={{ color: 'var(--red-600)' }}>
                        <DeleteForeverIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
                        {this.props.t("delete")}
                    </MenuItem>
                </Menu>
            </>
        );
    }
}

FolderCard.defaultProps = {
    name: "",
    info: null,
    enterFolder: null,
    performOCR: null,
    configureOCR: null,
    cancelFolderOCR: null,
    deleteItem: null,
};

export default withTranslation()(FolderCard);


