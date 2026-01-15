import React from 'react';
import Box from '@mui/material/Box';

const SkeletonCard = () => {
    return (
        <Box className="file-card animate-fadeIn" sx={{ pointerEvents: 'none' }}>
            <Box className="file-card-thumbnail skeleton" />
            <Box className="file-card-content">
                <Box 
                    className="skeleton" 
                    sx={{ 
                        height: '1rem', 
                        width: '80%', 
                        mb: 'var(--spacing-xs)' 
                    }} 
                />
                <Box 
                    className="skeleton" 
                    sx={{ 
                        height: '0.75rem', 
                        width: '60%', 
                        mb: 'var(--spacing-xs)' 
                    }} 
                />
                <Box 
                    className="skeleton" 
                    sx={{ 
                        height: '0.75rem', 
                        width: '40%' 
                    }} 
                />
            </Box>
        </Box>
    );
};

export default SkeletonCard;


