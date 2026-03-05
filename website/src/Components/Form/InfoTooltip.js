import React from 'react';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';

function InfoTooltip({ title, placement = "right" }) {
    return (
        <Tooltip 
            title={title} 
            placement={placement}
            arrow
            enterDelay={200}
            leaveDelay={0}
            sx={{
                maxWidth: '400px',
            }}
            componentsProps={{
                tooltip: {
                    sx: {
                        maxWidth: '400px',
                        fontSize: '0.875rem',
                        padding: '0.75rem',
                        backgroundColor: 'rgba(97, 97, 97, 0.95)',
                    }
                }
            }}
        >
            <IconButton 
                size="small"
                sx={{ 
                    padding: '4px',
                    marginLeft: '0.5rem',
                    color: 'text.secondary',
                    '&:hover': {
                        color: 'primary.main',
                    }
                }}
            >
                <InfoOutlinedIcon fontSize="small" />
            </IconButton>
        </Tooltip>
    );
}

export default InfoTooltip;
