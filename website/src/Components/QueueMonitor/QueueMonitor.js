import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import CircularProgress from '@mui/material/CircularProgress';
import RefreshIcon from '@mui/icons-material/Refresh';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import PendingActionsIcon from '@mui/icons-material/PendingActions';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import ScheduleIcon from '@mui/icons-material/Schedule';
import WorkIcon from '@mui/icons-material/Work';
import { useTranslation } from 'react-i18next';

const API_URL = `${window.location.protocol}//${window.location.host}/${process.env.REACT_APP_API_URL}`;

const QueueMonitor = ({ compact = false, autoRefresh = true, refreshInterval = 5000 }) => {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const [queueData, setQueueData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchQueueStatus = async () => {
        try {
            const response = await axios.get(`${API_URL}/queue-status`);
            if (response.data.success) {
                setQueueData(response.data);
                setError(null);
            } else {
                setError(response.data.error || 'Failed to fetch queue status');
            }
        } catch (err) {
            console.error('Error fetching queue status:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchQueueStatus();

        if (autoRefresh) {
            const interval = setInterval(fetchQueueStatus, refreshInterval);
            return () => clearInterval(interval);
        }
    }, [autoRefresh, refreshInterval]);

    const handleRefresh = () => {
        setLoading(true);
        fetchQueueStatus();
    };

    // Task name beautification
    const beautifyTaskName = (taskName) => {
        const taskNames = {
            'file_ocr': t('queue.task.file_ocr') || 'File OCR',
            'ocr_from_api': t('queue.task.ocr_from_api') || 'API OCR',
            'page_ocr': t('queue.task.page_ocr') || 'Page OCR',
            'export_file': t('queue.task.export_file') || 'Export File',
            'prepare_file': t('queue.task.prepare_file') || 'Prepare File',
            'auto_segment': t('queue.task.auto_segment') || 'Auto Segment',
        };
        return taskNames[taskName] || taskName;
    };

    if (loading && !queueData) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', padding: 2 }}>
                <CircularProgress size={24} />
            </Box>
        );
    }

    if (error) {
        return (
            <Box sx={{ padding: 2 }}>
                <Typography color="error" variant="body2">
                    {t('queue.error') || 'Error loading queue status'}: {error}
                </Typography>
            </Box>
        );
    }

    if (!queueData) return null;

    const { queue, workers, total_pending } = queueData;

    // Compact view for header/navbar
    if (compact) {
        const hasActivity = queue.active.total > 0 || total_pending > 0;
        
        return (
            <Tooltip title={t('queue.view_details') || 'Click to view queue details'}>
                <Box
                    sx={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 1,
                        padding: '4px 12px',
                        backgroundColor: hasActivity ? 'var(--accent-primary-light)' : 'var(--card-bg)',
                        borderRadius: 'var(--radius-md)',
                        cursor: 'pointer',
                        transition: 'all var(--transition-base)',
                        '&:hover': {
                            backgroundColor: 'var(--card-hover-bg)',
                            transform: 'translateY(-1px)',
                            boxShadow: 'var(--shadow-sm)',
                        }
                    }}
                    onClick={() => navigate('/queue-status')}
                >
                    <PendingActionsIcon sx={{ fontSize: 18, color: hasActivity ? 'var(--accent-primary)' : 'var(--text-secondary)' }} />
                    <Typography variant="caption" sx={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                        {queue.active.total > 0 && `${queue.active.total} ${t('queue.active') || 'active'}`}
                        {queue.active.total > 0 && total_pending > 0 && ' • '}
                        {total_pending > 0 && `${total_pending} ${t('queue.pending') || 'queued'}`}
                        {!hasActivity && (t('queue.idle') || 'Idle')}
                    </Typography>
                    {loading && <CircularProgress size={12} />}
                </Box>
            </Tooltip>
        );
    }

    // Full view for dedicated queue page/section
    return (
        <Box sx={{ width: '100%', padding: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6" sx={{ color: 'var(--text-primary)' }}>
                    {t('queue.title') || 'Task Queue Status'}
                </Typography>
                <IconButton onClick={handleRefresh} disabled={loading} size="small">
                    <RefreshIcon sx={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
                </IconButton>
            </Box>

            {/* Summary Cards */}
            <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 2, mb: 3 }}>
                <Card sx={{ backgroundColor: 'var(--card-bg)', boxShadow: 'var(--shadow-sm)' }}>
                    <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                            <PlayArrowIcon sx={{ color: 'var(--success-color)' }} />
                            <Typography variant="subtitle2" color="textSecondary">
                                {t('queue.active') || 'Active Tasks'}
                            </Typography>
                        </Box>
                        <Typography variant="h4" sx={{ color: 'var(--success-color)', fontWeight: 600 }}>
                            {queue.active.total}
                        </Typography>
                    </CardContent>
                </Card>

                <Card sx={{ backgroundColor: 'var(--card-bg)', boxShadow: 'var(--shadow-sm)' }}>
                    <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                            <PendingActionsIcon sx={{ color: 'var(--warning-color)' }} />
                            <Typography variant="subtitle2" color="textSecondary">
                                {t('queue.queued') || 'Queued Tasks'}
                            </Typography>
                        </Box>
                        <Typography variant="h4" sx={{ color: 'var(--warning-color)', fontWeight: 600 }}>
                            {queue.reserved.total}
                        </Typography>
                    </CardContent>
                </Card>

                <Card sx={{ backgroundColor: 'var(--card-bg)', boxShadow: 'var(--shadow-sm)' }}>
                    <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                            <ScheduleIcon sx={{ color: 'var(--info-color)' }} />
                            <Typography variant="subtitle2" color="textSecondary">
                                {t('queue.scheduled') || 'Scheduled Tasks'}
                            </Typography>
                        </Box>
                        <Typography variant="h4" sx={{ color: 'var(--info-color)', fontWeight: 600 }}>
                            {queue.scheduled.total}
                        </Typography>
                    </CardContent>
                </Card>

                <Card sx={{ backgroundColor: 'var(--card-bg)', boxShadow: 'var(--shadow-sm)' }}>
                    <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                            <WorkIcon sx={{ color: 'var(--text-secondary)' }} />
                            <Typography variant="subtitle2" color="textSecondary">
                                {t('queue.workers') || 'Workers'}
                            </Typography>
                        </Box>
                        <Typography variant="h4" sx={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                            {workers.length}
                        </Typography>
                    </CardContent>
                </Card>
            </Box>

            {/* Task Details */}
            {(queue.active.total > 0 || queue.reserved.total > 0 || queue.scheduled.total > 0) && (
                <Card sx={{ backgroundColor: 'var(--card-bg)', boxShadow: 'var(--shadow-sm)' }}>
                    <CardContent>
                        <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 600 }}>
                            {t('queue.task_breakdown') || 'Task Breakdown'}
                        </Typography>

                        {queue.active.total > 0 && (
                            <Box sx={{ mb: 2 }}>
                                <Typography variant="subtitle2" color="textSecondary" sx={{ mb: 1 }}>
                                    {t('queue.currently_processing') || 'Currently Processing'}
                                </Typography>
                                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                                    {Object.entries(queue.active.by_task).map(([taskName, count]) => (
                                        <Chip
                                            key={taskName}
                                            label={`${beautifyTaskName(taskName)} (${count})`}
                                            color="success"
                                            size="small"
                                            variant="outlined"
                                        />
                                    ))}
                                </Box>
                            </Box>
                        )}

                        {queue.reserved.total > 0 && (
                            <Box sx={{ mb: 2 }}>
                                <Typography variant="subtitle2" color="textSecondary" sx={{ mb: 1 }}>
                                    {t('queue.waiting_in_queue') || 'Waiting in Queue'}
                                </Typography>
                                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                                    {Object.entries(queue.reserved.by_task).map(([taskName, count]) => (
                                        <Chip
                                            key={taskName}
                                            label={`${beautifyTaskName(taskName)} (${count})`}
                                            color="warning"
                                            size="small"
                                            variant="outlined"
                                        />
                                    ))}
                                </Box>
                            </Box>
                        )}

                        {queue.scheduled.total > 0 && (
                            <Box>
                                <Typography variant="subtitle2" color="textSecondary" sx={{ mb: 1 }}>
                                    {t('queue.scheduled_for_later') || 'Scheduled for Later'}
                                </Typography>
                                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                                    {Object.entries(queue.scheduled.by_task).map(([taskName, count]) => (
                                        <Chip
                                            key={taskName}
                                            label={`${beautifyTaskName(taskName)} (${count})`}
                                            color="info"
                                            size="small"
                                            variant="outlined"
                                        />
                                    ))}
                                </Box>
                            </Box>
                        )}
                    </CardContent>
                </Card>
            )}

            {/* Workers Info */}
            {workers.length > 0 && (
                <Card sx={{ backgroundColor: 'var(--card-bg)', boxShadow: 'var(--shadow-sm)', mt: 2 }}>
                    <CardContent>
                        <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 600 }}>
                            {t('queue.worker_details') || 'Worker Details'}
                        </Typography>
                        {workers.map((worker, index) => (
                            <Box key={index} sx={{ mb: 1 }}>
                                <Typography variant="body2" color="textSecondary">
                                    <strong>{worker.name}</strong> • Pool: {worker.pool} • Max Concurrency: {worker.max_concurrency}
                                </Typography>
                            </Box>
                        ))}
                    </CardContent>
                </Card>
            )}

            <style>
                {`
                    @keyframes spin {
                        from { transform: rotate(0deg); }
                        to { transform: rotate(360deg); }
                    }
                `}
            </style>
        </Box>
    );
};

export default QueueMonitor;
