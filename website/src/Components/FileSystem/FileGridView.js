import React from 'react';
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import GridViewIcon from '@mui/icons-material/GridView';
import ViewListIcon from '@mui/icons-material/ViewList';
import FolderOffIcon from '@mui/icons-material/FolderOff';
import Typography from '@mui/material/Typography';

import { withTranslation } from "react-i18next";

class FileGridView extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            viewMode: localStorage.getItem('fileViewMode') || 'grid', // 'grid' or 'list'
        };
    }

    toggleViewMode() {
        const newMode = this.state.viewMode === 'grid' ? 'list' : 'grid';
        this.setState({ viewMode: newMode });
        localStorage.setItem('fileViewMode', newMode);
        if (this.props.onViewModeChange) {
            this.props.onViewModeChange(newMode);
        }
    }

    renderEmptyState() {
        return (
            <Box className="empty-state">
                <Box className="empty-state-icon">
                    <FolderOffIcon fontSize="inherit" />
                </Box>
                <Typography variant="h5" className="empty-state-title">
                    {this.props.t("empty folder title")}
                </Typography>
                <Typography variant="body1" className="empty-state-description">
                    {this.props.t("empty folder description")}
                </Typography>
            </Box>
        );
    }

    render() {
        const { items, showViewToggle = true } = this.props;
        const { viewMode } = this.state;

        return (
            <Box sx={{ width: '100%' }}>
                {showViewToggle && (
                    <Box
                        sx={{
                            display: 'flex',
                            justifyContent: 'flex-end',
                            mb: 'var(--spacing-md)',
                        }}
                    >
                        <Box className="view-toggle-container">
                            <Tooltip title={this.props.t("grid view")}>
                                <IconButton
                                    size="small"
                                    onClick={() => viewMode !== 'grid' && this.toggleViewMode()}
                                    className={`view-toggle-button ${viewMode === 'grid' ? 'active' : ''}`}
                                >
                                    <GridViewIcon fontSize="small" />
                                </IconButton>
                            </Tooltip>
                            <Tooltip title={this.props.t("list view")}>
                                <IconButton
                                    size="small"
                                    onClick={() => viewMode !== 'list' && this.toggleViewMode()}
                                    className={`view-toggle-button ${viewMode === 'list' ? 'active' : ''}`}
                                >
                                    <ViewListIcon fontSize="small" />
                                </IconButton>
                            </Tooltip>
                        </Box>
                    </Box>
                )}

                {items && items.length === 0 ? (
                    this.renderEmptyState()
                ) : viewMode === 'grid' ? (
                    <Box className="file-grid-container">
                        {items}
                    </Box>
                ) : (
                    <Box sx={{ width: '100%' }}>
                        {items}
                    </Box>
                )}
            </Box>
        );
    }
}

FileGridView.defaultProps = {
    items: [],
    showViewToggle: true,
    onViewModeChange: null,
};

export default withTranslation()(FileGridView);


