import React, { useState, useEffect } from 'react';
import Snackbar from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import Slide from '@mui/material/Slide';

function SlideTransition(props) {
    return <Slide {...props} direction="up" />;
}

const ToastNotification = React.forwardRef((props, ref) => {
    const [open, setOpen] = useState(false);
    const [message, setMessage] = useState('');
    const [severity, setSeverity] = useState('success'); // 'success' | 'error' | 'warning' | 'info'
    const [duration, setDuration] = useState(4000);

    React.useImperativeHandle(ref, () => ({
        showToast(msg, sev = 'success', dur = 4000) {
            setMessage(msg);
            setSeverity(sev);
            setDuration(dur);
            setOpen(true);
        },
        showSuccess(msg) {
            this.showToast(msg, 'success');
        },
        showError(msg) {
            this.showToast(msg, 'error', 6000);
        },
        showWarning(msg) {
            this.showToast(msg, 'warning', 5000);
        },
        showInfo(msg) {
            this.showToast(msg, 'info');
        },
    }));

    const handleClose = (event, reason) => {
        if (reason === 'clickaway') {
            return;
        }
        setOpen(false);
    };

    return (
        <Snackbar
            open={open}
            autoHideDuration={duration}
            onClose={handleClose}
            TransitionComponent={SlideTransition}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        >
            <Alert
                onClose={handleClose}
                severity={severity}
                variant="filled"
                sx={{
                    borderRadius: 'var(--radius-lg)',
                    boxShadow: 'var(--shadow-xl)',
                    minWidth: '300px',
                }}
            >
                {message}
            </Alert>
        </Snackbar>
    );
});

export default ToastNotification;


