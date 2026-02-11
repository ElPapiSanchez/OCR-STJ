import React, {useEffect, useState} from 'react';
import {Link, useNavigate} from "react-router";
import axios from "axios";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import { useTranslation } from 'react-i18next';

import Footer  from 'Components/Footer/Footer';
// const VersionsMenu = loadComponent('Form', 'VersionsMenu');
// const LogsMenu = loadComponent('Form', 'LogsMenu');
// const Notification = loadComponent('Notifications', 'Notification');

const API_URL = `${window.location.protocol}//${window.location.host}/${process.env.REACT_APP_API_URL}`;
const ADMIN_HOME = (process.env.REACT_APP_BASENAME !== null && process.env.REACT_APP_BASENAME !== "")
    ? `/${process.env.REACT_APP_BASENAME}/admin`
    : '/admin';

const UPDATE_TIME = 30;  // period of fetching system info, in seconds

const Dashboard = (props) => {
    const navigate = useNavigate();
    const { t } = useTranslation();

    const [freeSpace, setFreeSpace] = useState("");
    const [freeSpacePercent, setFreeSpacePercent] = useState("");

    // const versionsMenu = useRef(null);
    // const logsMenu = useRef(null);
    // const successNotif = useRef(null);
    // const errorNotif = useRef(null);

    function getSystemInfo() {
        axios.get(API_URL + '/admin/system-info')
            .then(({ data }) => {
                // if (this.logsMenu.current !== null) this.logsMenu.current.setLogs(data["logs"]);
                setFreeSpace(data["free_space"]);
                setFreeSpacePercent(data["free_space_percentage"]);
            });
    }

    useEffect(() => {
        getSystemInfo();
        const interval = setInterval(getSystemInfo, 1000 * UPDATE_TIME);
        return () => {
            clearInterval(interval);
        }
    }, []);

    return (
        <Box className="App" sx={{height: '100vh'}}>
            {/* <Notification message={""} severity={"success"} ref={successNotif}/> */}
            {/* <Notification message={""} severity={"error"} ref={errorNotif}/> */}

            {/* <VersionsMenu ref={versionsMenu}/> */}
            {/* <LogsMenu ref={logsMenu}/> */}
            <Box sx={{
                    display: 'flex',
                    flexDirection: 'row',
                    justifyContent: 'space-between',
                    alignItems: "center",
                    zIndex: '5',
                    padding: '0.5rem',
                    paddingRight: '2rem',
                    paddingTop: '1rem',
                }}>
                    <Box sx={{
                        display: 'flex',
                        flexDirection: 'row',
                        alignItems: "center",
                    }}>
                        <span>{t("admin.free_storage")}: {freeSpace} ({freeSpacePercent}%)</span>
                    </Box>

                    <Button
                        variant="contained"
                        onClick={() => {
                            axios.post(API_URL + "/account/logout")
                                .then(() => window.location.href = ADMIN_HOME);
                        }}
                        className="menuButton"
                    >
                        <span>{t("logout")}</span>
                    </Button>
            </Box>

            <Box sx={{
                display: 'flex',
                flexDirection: 'column',
                margin: 'auto',
                width: '30vw',
                height: '80vh',
                justifyContent: 'space-evenly',
            }}>
                <Button
                    variant="contained"
                    className="adminMenuButton"
                    onClick={() => navigate('/admin/storage')}
                >
                    {t("admin.manage_storage")}
                </Button>

                <Button
                    variant="contained"
                    className="adminMenuButton"
                    onClick={() => navigate('/admin/config')}
                >
                    {t("admin.configure_ocr_defaults")}
                </Button>

                <Link to="/admin/flower/" target="_blank" rel="noreferrer">
                    <Button
                        variant="contained"
                        className="adminMenuButton"
                        sx={{width: '100%'}}
                    >
                        {t("admin.view_workers_processes")}
                    </Button>
                </Link>
            </Box>

            <Footer />
        </Box>
    );
}

export default Dashboard;
