import React, { useState, useRef, useImperativeHandle, forwardRef } from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Modal from '@mui/material/Modal';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import CircularProgress from '@mui/material/CircularProgress';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import { useTranslation } from 'react-i18next';

import Notification from 'Components/Notifications/Notification';

const style = {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    width: 400,
    bgcolor: 'background.paper',
    border: '2px solid #000',
    boxShadow: 24,
    p: 4,
    borderRadius: 2
};

const crossStyle = {
    position: 'absolute',
    top: '0.5rem',
    right: '0.5rem'
}

const ConfirmLeave = forwardRef((props, ref) => {
    const { leaveFunc, saveAndLeaveFunc } = props;
    const { t } = useTranslation();
    const [open, setOpen] = useState(false);
    const [saving, setSaving] = useState(false);
    
    const successNot = useRef();
    const errorNot = useRef();

    // Expose toggleOpen method to parent via ref
    useImperativeHandle(ref, () => ({
        toggleOpen() {
            setOpen(!open);
            setSaving(false); // Reset saving state when reopening
        }
    }));

    const confirm = () => {
        if (leaveFunc) {
            leaveFunc();
        }
    };

    const saveAndConfirm = () => {
        if (saveAndLeaveFunc) {
            setSaving(true);
            saveAndLeaveFunc();
        }
    };

    const toggleModal = () => {
        setOpen(!open);
        setSaving(false); // Reset saving state when closing
    };

    return (
        <Box>
            <Notification message={""} severity={"success"} ref={successNot}/>
            <Notification message={""} severity={"error"} ref={errorNot}/>
            <Modal open={open}>
                <Box sx={style}>
                    <Typography id="modal-modal-title" variant="h6" component="h2">
                        {t("confirm leave title")}
                    </Typography>

                    <p style={{color: 'var(--primary-red)'}}><b>{t("confirm leave warning")}</b></p>

                    <Box sx={{
                        display: 'flex',
                        flexDirection: 'row',
                        gap: '1rem'
                    }}>
                        <Button
                            variant="contained"
                            disabled={saving}
                            sx={{
                                border: '1px solid black',
                                mt: '0.5rem',
                                backgroundColor: '#4caf50',
                                color: 'white !important',
                                '&:hover': {
                                    backgroundColor: '#2e7d32',
                                },
                                '&:disabled': {
                                    backgroundColor: '#a5d6a7',
                                    color: 'white !important',
                                }
                            }}
                            onClick={saveAndConfirm}
                        >
                            {saving ? (
                                <>
                                    <CircularProgress size={16} sx={{ color: 'white', mr: 1 }} />
                                    {t("saving")}...
                                </>
                            ) : (
                                t("save and leave button")
                            )}
                        </Button>
                        <Button
                            variant="contained"
                            disabled={saving}
                            sx={{
                                border: '1px solid black',
                                mt: '0.5rem',
                                backgroundColor: 'var(--primary-red)',
                                color: 'white',
                            }}
                            onClick={confirm}
                        >
                            {t("confirm leave button")}
                        </Button>
                    </Box>

                    <IconButton sx={crossStyle} aria-label="close" onClick={toggleModal}>
                        <CloseRoundedIcon />
                    </IconButton>
                </Box>
            </Modal>
        </Box>
    );
});

ConfirmLeave.defaultProps = {
    leaveFunc: null,
    saveAndLeaveFunc: null
};

export default ConfirmLeave;
