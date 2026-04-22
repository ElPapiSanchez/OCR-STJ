import React from 'react';

import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Modal from '@mui/material/Modal';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import ClickAwayListener from "@mui/material/ClickAwayListener";

import Notification from 'Components/Notifications/Notification';

const API_URL = `${window.location.protocol}//${window.location.host}/${process.env.REACT_APP_API_URL}`;
const style = {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    width: 'fit-content',
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

class DeletePopup extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            open: false,
            path: "",
            filename: null,
            buttonDisabled: false
        }

        this.textField = React.createRef();
        this.successNot = React.createRef();
        this.errorNot = React.createRef();

        // handler to close menu on click outside box
        this.handleClickOutsideMenu = this.handleClickOutsideMenu.bind(this);
    }

    handleClickOutsideMenu() {
        if (this.state.open) {
            this.closeMenu();
        }
    }

    openMenu(path, filename) {
        this.setState({ open: true, path: path, filename: filename });
    }

    closeMenu(callback = null) {
        this.setState({ open: false }, callback);
    }

    deleteItem() {
        this.setState({ buttonDisabled: true });
        // Handle empty path (root folder)
        const path = this.state.path ? 
            `${this.state.path}/${this.state.filename}` : 
            this.state.filename;
        const url = API_URL + '/delete-path';
        console.log('Deleting with URL:', url);
        console.log('Delete - state.path:', this.state.path);
        console.log('Delete - state.filename:', this.state.filename);
        console.log('Delete - combined path:', path);
        console.log('Delete - _private:', this.props._private);
        console.log('API_URL:', API_URL);
        
        fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                "path": path,
                "_private": this.props._private
            })
        })
        .then(async response => {
            console.log('Response status:', response.status, response.statusText);
            const text = await response.text();
            console.log('Response body:', text);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return JSON.parse(text);
        })
        .then(data => {
            this.setState({ buttonDisabled: false });
            if (data.success) {
                this.successNot.current.openNotif(data.message);

                this.closeMenu(this.props.submitCallback);
            } else {
                this.errorNot.current.openNotif(data.error);
            }
        })
        .catch(error => {
            this.setState({ buttonDisabled: false });
            console.error('Delete error:', error);
            this.errorNot.current.openNotif('Failed to delete: ' + error.message);
        });
    }

    render() {
        return (
            <Box>
                <Notification message={""} severity={"success"} ref={this.successNot}/>
                <Notification message={""} severity={"error"} ref={this.errorNot}/>
                <Modal open={this.state.open}>
                    <ClickAwayListener
                        mouseEvent="onMouseDown"
                        touchEvent="onTouchStart"
                        onClickAway={this.handleClickOutsideMenu}
                    >
                        <Box sx={style}>
                            <Typography id="modal-modal-title" variant="h6" component="h2">
                                {this.props.t("confirm delete")} <b>{this.state.filename}</b>?
                            </Typography>

                            <Box sx={{
                                display: 'flex',
                                flexDirection: 'row'
                            }}>
                                <Button
                                    disabled={this.state.buttonDisabled}
                                    color="error"
                                    variant="contained"
                                    sx={{border: '1px solid black', mt: '0.5rem'}}
                                    onClick={() => this.deleteItem()}
                                >
                                    {this.props.t("delete")}
                                </Button>
                            </Box>

                            <IconButton disabled={this.state.buttonDisabled} sx={crossStyle} aria-label="close" onClick={() => this.closeMenu()}>
                                <CloseRoundedIcon />
                            </IconButton>
                        </Box>
                    </ClickAwayListener>
                </Modal>
            </Box>
        )
    }
}

DeletePopup.defaultProps = {
    _private: false,
    // functions:
    submitCallback: null,
    // translation function passed from parent
    t: (key) => key,
}

export default DeletePopup;
