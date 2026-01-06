import React from 'react';

import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Modal from '@mui/material/Modal';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import CircularProgress from '@mui/material/CircularProgress';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import FolderIcon from '@mui/icons-material/Folder';
import AccountTreeIcon from '@mui/icons-material/AccountTree';

import i18n from "i18next";

import Notification from 'Components/Notifications/Notification';

const API_URL = `${window.location.protocol}//${window.location.host}/${process.env.REACT_APP_API_URL}`;

const style = {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    width: 450,
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
};

class SyncMenu extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            open: false,
            path: "",
            loading: false,
            result: null,
        };

        this.successNot = React.createRef();
        this.errorNot = React.createRef();
    }

    openMenu(path) {
        this.setState({ path: path, open: true, loading: false, result: null });
    }

    closeMenu(callback = null) {
        this.setState({ open: false, result: null }, callback);
    }

    sync(recursive) {
        this.setState({ loading: true, result: null });
        
        fetch(API_URL + '/sync-inputs', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                "path": this.state.path,
                "recursive": recursive,
                "_private": this.props._private
            })
        })
            .then(response => response.json())
            .then(data => {
                this.setState({ loading: false });
                if (data.success) {
                    const importedCount = data.imported ? data.imported.length : 0;
                    if (importedCount > 0) {
                        this.setState({ result: data });
                        this.successNot.current.openNotif(
                            i18n.t("sync_success").replace("{count}", importedCount)
                        );
                        // Refresh file list after a short delay
                        setTimeout(() => {
                            this.closeMenu(this.props.submitCallback);
                        }, 1500);
                    } else {
                        this.successNot.current.openNotif(i18n.t("sync_no_new"));
                        setTimeout(() => {
                            this.closeMenu();
                        }, 1500);
                    }
                } else {
                    this.errorNot.current.openNotif(data.error || i18n.t("sync_error"));
                }
            })
            .catch(err => {
                this.setState({ loading: false });
                this.errorNot.current.openNotif(i18n.t("sync_error"));
            });
    }

    render() {
        return (
            <>
                <Modal
                    open={this.state.open}
                    onClose={() => this.closeMenu()}
                    aria-labelledby="sync-modal-title"
                >
                    <Box sx={style}>
                        <IconButton sx={crossStyle} onClick={() => this.closeMenu()}>
                            <CloseRoundedIcon />
                        </IconButton>

                        <Typography id="sync-modal-title" variant="h6" component="h2" sx={{ mb: 2 }}>
                            {i18n.t("sync_title")}
                        </Typography>

                        <Typography variant="body2" sx={{ mb: 3, color: 'text.secondary' }}>
                            {i18n.t("sync_description")}
                        </Typography>

                        {this.state.loading ? (
                            <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
                                <CircularProgress />
                            </Box>
                        ) : this.state.result ? (
                            <Box sx={{ py: 2 }}>
                                <Typography variant="body1" sx={{ fontWeight: 'bold', color: 'success.main' }}>
                                    {i18n.t("sync_success").replace("{count}", this.state.result.imported.length)}
                                </Typography>
                                {this.state.result.skipped > 0 && (
                                    <Typography variant="body2" sx={{ mt: 1, color: 'text.secondary' }}>
                                        {i18n.t("sync_skipped").replace("{count}", this.state.result.skipped)}
                                    </Typography>
                                )}
                            </Box>
                        ) : (
                            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                <Button
                                    variant="contained"
                                    startIcon={<FolderIcon />}
                                    onClick={() => this.sync(false)}
                                    fullWidth
                                    sx={{ py: 1.5 }}
                                >
                                    {i18n.t("sync_current")}
                                </Button>
                                <Button
                                    variant="outlined"
                                    startIcon={<AccountTreeIcon />}
                                    onClick={() => this.sync(true)}
                                    fullWidth
                                    sx={{ py: 1.5 }}
                                >
                                    {i18n.t("sync_recursive")}
                                </Button>
                            </Box>
                        )}
                    </Box>
                </Modal>

                <Notification message={""} severity={"success"} ref={this.successNot} />
                <Notification message={""} severity={"error"} ref={this.errorNot} />
            </>
        );
    }
}

SyncMenu.defaultProps = {
    _private: false,
    submitCallback: null,
};

export default SyncMenu;



