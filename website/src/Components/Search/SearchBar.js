import React, { useState, useRef, useEffect } from 'react';
import Box from '@mui/material/Box';
import TextField from '@mui/material/TextField';
import InputAdornment from '@mui/material/InputAdornment';
import IconButton from '@mui/material/IconButton';
import SearchIcon from '@mui/icons-material/Search';
import ClearIcon from '@mui/icons-material/Clear';
import FilterListIcon from '@mui/icons-material/FilterList';
import Chip from '@mui/material/Chip';
import Collapse from '@mui/material/Collapse';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import OutlinedInput from '@mui/material/OutlinedInput';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import Button from '@mui/material/Button';
import { useTranslation } from 'react-i18next';

const SearchBar = ({ onSearchChange, onFiltersChange, showFilters = true }) => {
    const { t } = useTranslation();
    const [searchQuery, setSearchQuery] = useState('');
    const [showFilterPanel, setShowFilterPanel] = useState(false);
    const [filters, setFilters] = useState({
        fileTypes: [],
        ocrStatus: [],
        dateRange: 'all',
    });
    const searchInputRef = useRef(null);

    const fileTypeOptions = [
        { value: 'pdf', label: 'PDF' },
        { value: 'image', label: 'Images' },
        { value: 'zip', label: 'ZIP' },
    ];

    const ocrStatusOptions = [
        { value: 'complete', label: t('ocr complete') },
        { value: 'processing', label: t('uploading stage') },
        { value: 'pending', label: 'Pending' },
    ];

    const dateRangeOptions = [
        { value: 'all', label: 'All Time' },
        { value: 'today', label: 'Today' },
        { value: 'week', label: 'This Week' },
        { value: 'month', label: 'This Month' },
    ];

    useEffect(() => {
        // Focus search when Cmd/Ctrl+K is pressed
        const handleKeyDown = (e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                e.preventDefault();
                searchInputRef.current?.focus();
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, []);

    const handleSearchChange = (e) => {
        const value = e.target.value;
        setSearchQuery(value);
        if (onSearchChange) {
            onSearchChange(value);
        }
    };

    const handleClearSearch = () => {
        setSearchQuery('');
        if (onSearchChange) {
            onSearchChange('');
        }
    };

    const handleFilterChange = (filterType, value) => {
        const newFilters = { ...filters, [filterType]: value };
        setFilters(newFilters);
        if (onFiltersChange) {
            onFiltersChange(newFilters);
        }
    };

    const handleClearFilters = () => {
        const clearedFilters = {
            fileTypes: [],
            ocrStatus: [],
            dateRange: 'all',
        };
        setFilters(clearedFilters);
        if (onFiltersChange) {
            onFiltersChange(clearedFilters);
        }
    };

    const hasActiveFilters = 
        filters.fileTypes.length > 0 || 
        filters.ocrStatus.length > 0 || 
        filters.dateRange !== 'all';

    return (
        <Box sx={{ width: '100%', mb: 'var(--spacing-md)' }}>
            <Box sx={{ display: 'flex', gap: 'var(--spacing-sm)', alignItems: 'center' }}>
                <TextField
                    fullWidth
                    inputRef={searchInputRef}
                    placeholder={`${t('search')}... (⌘K)`}
                    value={searchQuery}
                    onChange={handleSearchChange}
                    variant="outlined"
                    size="small"
                    sx={{
                        '& .MuiOutlinedInput-root': {
                            borderRadius: 'var(--radius-lg)',
                            backgroundColor: 'var(--card-bg)',
                            transition: 'all var(--transition-fast)',
                            '&:hover': {
                                boxShadow: 'var(--shadow-sm)',
                            },
                            '&.Mui-focused': {
                                boxShadow: 'var(--shadow-md)',
                            },
                        },
                    }}
                    InputProps={{
                        startAdornment: (
                            <InputAdornment position="start">
                                <SearchIcon sx={{ color: 'var(--text-tertiary)' }} />
                            </InputAdornment>
                        ),
                        endAdornment: searchQuery && (
                            <InputAdornment position="end">
                                <IconButton
                                    size="small"
                                    onClick={handleClearSearch}
                                    edge="end"
                                >
                                    <ClearIcon fontSize="small" />
                                </IconButton>
                            </InputAdornment>
                        ),
                    }}
                />
                {showFilters && (
                    <IconButton
                        onClick={() => setShowFilterPanel(!showFilterPanel)}
                        sx={{
                            backgroundColor: showFilterPanel || hasActiveFilters ? 'var(--accent-primary)' : 'var(--card-bg)',
                            color: showFilterPanel || hasActiveFilters ? 'white' : 'var(--text-primary)',
                            borderRadius: 'var(--radius-md)',
                            transition: 'all var(--transition-fast)',
                            '&:hover': {
                                backgroundColor: showFilterPanel || hasActiveFilters ? 'var(--accent-primary)' : 'var(--card-hover-bg)',
                                transform: 'translateY(-1px)',
                            },
                        }}
                    >
                        <FilterListIcon />
                    </IconButton>
                )}
            </Box>

            {showFilters && (
                <Collapse in={showFilterPanel}>
                    <Box
                        sx={{
                            mt: 'var(--spacing-md)',
                            p: 'var(--spacing-lg)',
                            backgroundColor: 'var(--card-bg)',
                            border: '1px solid var(--card-border)',
                            borderRadius: 'var(--radius-lg)',
                            boxShadow: 'var(--shadow-sm)',
                        }}
                    >
                        <Box sx={{ display: 'flex', gap: 'var(--spacing-md)', flexWrap: 'wrap', mb: 'var(--spacing-md)' }}>
                            <FormControl sx={{ minWidth: 200, flex: 1 }} size="small">
                                <InputLabel>File Type</InputLabel>
                                <Select
                                    multiple
                                    value={filters.fileTypes}
                                    onChange={(e) => handleFilterChange('fileTypes', e.target.value)}
                                    input={<OutlinedInput label="File Type" />}
                                    renderValue={(selected) => (
                                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                            {selected.map((value) => (
                                                <Chip
                                                    key={value}
                                                    label={fileTypeOptions.find(o => o.value === value)?.label}
                                                    size="small"
                                                />
                                            ))}
                                        </Box>
                                    )}
                                >
                                    {fileTypeOptions.map((option) => (
                                        <MenuItem key={option.value} value={option.value}>
                                            <Checkbox checked={filters.fileTypes.indexOf(option.value) > -1} />
                                            <ListItemText primary={option.label} />
                                        </MenuItem>
                                    ))}
                                </Select>
                            </FormControl>

                            <FormControl sx={{ minWidth: 200, flex: 1 }} size="small">
                                <InputLabel>OCR Status</InputLabel>
                                <Select
                                    multiple
                                    value={filters.ocrStatus}
                                    onChange={(e) => handleFilterChange('ocrStatus', e.target.value)}
                                    input={<OutlinedInput label="OCR Status" />}
                                    renderValue={(selected) => (
                                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                            {selected.map((value) => (
                                                <Chip
                                                    key={value}
                                                    label={ocrStatusOptions.find(o => o.value === value)?.label}
                                                    size="small"
                                                />
                                            ))}
                                        </Box>
                                    )}
                                >
                                    {ocrStatusOptions.map((option) => (
                                        <MenuItem key={option.value} value={option.value}>
                                            <Checkbox checked={filters.ocrStatus.indexOf(option.value) > -1} />
                                            <ListItemText primary={option.label} />
                                        </MenuItem>
                                    ))}
                                </Select>
                            </FormControl>

                            <FormControl sx={{ minWidth: 180, flex: 1 }} size="small">
                                <InputLabel>Date Range</InputLabel>
                                <Select
                                    value={filters.dateRange}
                                    onChange={(e) => handleFilterChange('dateRange', e.target.value)}
                                    label="Date Range"
                                >
                                    {dateRangeOptions.map((option) => (
                                        <MenuItem key={option.value} value={option.value}>
                                            {option.label}
                                        </MenuItem>
                                    ))}
                                </Select>
                            </FormControl>
                        </Box>

                        {hasActiveFilters && (
                            <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
                                <Button
                                    size="small"
                                    onClick={handleClearFilters}
                                    sx={{ textTransform: 'none' }}
                                >
                                    Clear Filters
                                </Button>
                            </Box>
                        )}
                    </Box>
                </Collapse>
            )}
        </Box>
    );
};

export default SearchBar;


