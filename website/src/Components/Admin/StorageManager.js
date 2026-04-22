import React, {useCallback, useEffect, useRef, useState} from 'react';
import axios from "axios";
import { useNavigate } from "react-router";
import { useTranslation } from 'react-i18next';

import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import DeleteForeverIcon from "@mui/icons-material/DeleteForever";
import RotateLeft from "@mui/icons-material/RotateLeft";
import Typography from "@mui/material/Typography";

import TextField from "@mui/material/TextField";
import Radio from "@mui/material/Radio";
import FormControlLabel from "@mui/material/FormControlLabel";
import CheckRoundedIcon from "@mui/icons-material/CheckRounded";

import { TimePicker } from "@mui/x-date-pickers/TimePicker";

import ReturnButton from 'Components/FileSystem/ReturnButton';
import Notification from 'Components/Notifications/Notification';
import ChangeMaxAgePopup from 'Components/Form/ChangeMaxAgePopup';
import ConfirmActionPopup from 'Components/Form/ConfirmActionPopup';
import CheckboxList from 'Components/Form/CheckboxList';
import TooltipIcon from 'Components/TooltipIcon/TooltipIcon';
import Footer from 'Components/Footer/Footer';

const API_URL = `${window.location.protocol}//${window.location.host}/${process.env.REACT_APP_API_URL}`;
const ADMIN_HOME = (process.env.REACT_APP_BASENAME !== null && process.env.REACT_APP_BASENAME !== "")
                            ? `/${process.env.REACT_APP_BASENAME}/admin`
                            : '/admin';

const numberHoursRegex = /^[1-9][0-9]*$/;
const dayRegex = /^([1-9]|0[1-9]|[1-2][0-9]|3[0-1])$/;

const getWeekDaysOptions = (t) => [
    { value: "mon", description: t("weekdays.monday")},
    { value: "tue", description: t("weekdays.tuesday")},
    { value: "wed", description: t("weekdays.wednesday")},
    { value: "thu", description: t("weekdays.thursday")},
    { value: "fri", description: t("weekdays.friday")},
    { value: "sat", description: t("weekdays.saturday")},
    { value: "sun", description: t("weekdays.sunday")},
]

const sizeRegex = /(\d+(?:\.\d+)?) ([A-Za-z]+)/;  // match both e.g. "50 KB" and "50.00 KB"
const sizeMap = {
    B: 1,
    KB: 1024,
    MB: 1024 * 1024,
    GB: 1024 * 1024 * 1024,
}

const StorageManager = (props) => {
    const navigate = useNavigate();
    const { t } = useTranslation();

    const [freeSpace, setFreeSpace] = useState("");
    const [freeSpacePercent, setFreeSpacePercent] = useState("");
    const [privateSpaces, setPrivateSpaces] = useState([]);
    const [apiFiles, setApiFiles] = useState([]);
    const [lastCleanup, setLastCleanup] = useState(t("never"));
    const [maxPrivateSpaceAge, setMaxPrivateSpaceAge] = useState("1");

    const [refreshing, setRefreshing] = useState(true);
    const [lastUpdate, setLastUpdate] = useState(null);

    const [maxConcurrentFolders, setMaxConcurrentFolders] = useState(1);
    const [activeFolderCount, setActiveFolderCount] = useState(0);
    const [queuedFolderCount, setQueuedFolderCount] = useState(0);

    const [scheduleType, setScheduleType] = useState("interval");

    const [everyHours, setEveryHours] = useState('');

    const [monthTime, setMonthTime] = useState(null);
    const [monthDay, setMonthDay] = useState('');

    const [weekTime, setWeekTime] = useState(null);
    const [weekDays, setWeekDays] = useState([]);

    const [deleteSpaceId, setDeleteSpaceId] = useState(null);
    const [deleteApiDocumentId, setDeleteApiDocumentId] = useState(null);

    const [changeMaxAgePopupOpened, setChangeMaxAgePopupOpened] = useState(false);

    const [confirmPopupOpened, setConfirmPopupOpened] = useState(false);
    const [confirmPopupMessage, setConfirmPopupMessage] = useState("");
    const [confirmPopupSubmitCallback, setConfirmPopupSubmitCallback] = useState(null);

    const successNotif = useRef(null);
    const errorNotif = useRef(null);

    function parseSize(sizeStr) {
        const match = sizeStr.match(sizeRegex);
        if (!match) return 0;
        const value = parseFloat(match[1]);
        const unit = match[2].toUpperCase();
        return value * (sizeMap[unit] || 1);
    }

    function getStorageInfo() {
        setRefreshing(true);
        axios.get(API_URL + '/admin/storage-info')
            .then(({ data }) => {
                const privateSpaces = Object.entries(data["private_spaces"]);
                const apiFiles = Object.entries(data["api_files"]);
                privateSpaces.sort((a, b) => parseSize(b[1].size) - parseSize(a[1].size));
                apiFiles.sort((a, b) => parseSize(b[1].size) - parseSize(a[1].size));

                setFreeSpace(data["free_space"]);
                setFreeSpacePercent(data["free_space_percentage"]);
                setPrivateSpaces(privateSpaces);
                setApiFiles(apiFiles);
                setLastCleanup(data["last_cleanup"]);
                setMaxPrivateSpaceAge(data["max_age"]);
                setLastUpdate(new Date());
                setRefreshing(false);
            });
    }

    function getFolderConcurrency() {
        axios.get(API_URL + '/admin/get-folder-concurrency')
            .then(({ data }) => {
                if (data.success) {
                    setMaxConcurrentFolders(data.max_concurrent_folders);
                    setActiveFolderCount(data.active_count);
                    setQueuedFolderCount(data.queued_count);
                }
            })
            .catch(err => {
                console.error('Failed to fetch folder concurrency:', err);
            });
    }

    function saveFolderConcurrency() {
        axios.post(API_URL + '/admin/set-folder-concurrency',
            {
                max_concurrent_folders: parseInt(maxConcurrentFolders)
            },
            {
                headers: {
                    'Content-Type': 'application/json'
                },
            })
            .then(response => {
                if (response.status !== 200) {
                    throw new Error(t("admin.request_failed"));
                }
                if (response.data["success"]) {
                    successNotif.current.openNotif(t("admin.folder_concurrency_updated"));
                    getFolderConcurrency();  // Refresh the counts
                } else {
                    throw new Error(response.data["message"]);
                }
            })
            .catch(err => {
                errorNotif.current.openNotif(err.message);
            });
    }

    useEffect(() => {
        getStorageInfo();
        getFolderConcurrency();
    }, []);

    const deleteApiDocument = useCallback(() => {
        axios.post(API_URL + "/delete-results",
            {
                "doc_id": deleteApiDocumentId
            },
            {
                headers: {
                    'Content-Type': 'application/json'
                },
            })
            .then(response => {
                if (response.status !== 200) {
                    throw new Error(response.data["message"] || t("admin.request_failed"));
                }
                if (!response.data["success"]) {
                    throw new Error(response.data["message"]);
                }
                closeConfirmationPopup();
                getStorageInfo();
            })
            .catch(err => {
                errorNotif.current.openNotif(err.message);
                closeConfirmationPopup();
            });
    }, [deleteApiDocumentId]);

    const deletePrivateSpace = useCallback(() => {
        axios.post(API_URL + "/admin/delete-private-space",
            {
                "space_id": deleteSpaceId
            },
            {
                headers: {
                    'Content-Type': 'application/json'
                },
            })
            .then(response => {
                if (response.status !== 200) {
                    throw new Error(response.data["message"] || t("admin.request_failed"));
                }
                if (!response.data["success"]) {
                    throw new Error(response.data["message"]);
                }
                closeConfirmationPopup();
                getStorageInfo();
            })
            .catch(err => {
                errorNotif.current.openNotif(err.message);
                closeConfirmationPopup();
            });
    }, [deleteSpaceId]);

    // setup confirmation popup after deleteSpaceId is set by openDeletePopup()
    useEffect(() => {
        if (deleteSpaceId !== null) {
            setConfirmPopupOpened(true);
            setConfirmPopupMessage(`${t("admin.confirm_delete_space")} ${deleteSpaceId}?`);
            setConfirmPopupSubmitCallback(() => deletePrivateSpace);  // set value as function deletePrivateSpace
        } else if (deleteApiDocumentId !== null) {
            setConfirmPopupOpened(true);
            setConfirmPopupMessage(`${t("admin.confirm_delete_document")} ${deleteApiDocumentId}?`);
            setConfirmPopupSubmitCallback(() => deleteApiDocument);  // set value as function deleteApiDocument
        }
    }, [deleteSpaceId, deleteApiDocumentId, deletePrivateSpace, deleteApiDocument])

    function handleScheduleTypeChange(newType) {
        switch (newType) {
            case "interval":
                setWeekTime(null); setWeekDays([]);  // disable weekly
                setMonthTime(null); setMonthDay('');  // disable monthly
                setScheduleType(newType);
                break;
            case "monthly":
                console.log("set monthly")
                setEveryHours('');  // disable interval
                setWeekTime(null); setWeekDays([]);  // disable weekly
                setScheduleType(newType);
                break;
            case "weekly":
                setEveryHours('');  // disable interval
                setMonthTime(null); setMonthDay('');  // disable monthly
                setScheduleType(newType);
                break;
        }
    }

    function handleEveryHoursChange(value) {
        value = value.trim();
        if (!(numberHoursRegex.test(value)) && value !== '') {
            errorNotif.current.openNotif(t("admin.hours_positive_integer"));
        }
        setEveryHours(value);
    }

    function handleMonthDayChange(value) {
        value = value.trim();
        if (!(dayRegex.test(value)) && value !== "0" && value !== '') {
            errorNotif.current.openNotif(t("admin.day_between_1_31"));
        }
        setMonthDay(value);
    }

    function handleWeekDaysChange(choices) {
        setWeekDays(choices);
    }

    function openDeleteApiDocumentPopup(e, documentId) {
        e.stopPropagation();
        setDeleteApiDocumentId(documentId);
        // confirm popup is set up in useEffect
    }

    function openDeleteSpacePopup(e, privateSpace) {
        e.stopPropagation();
        setDeleteSpaceId(privateSpace);
        // confirm popup is set up in useEffect
    }


    function openChangeMaxAgePopup(e) {
        e.stopPropagation();
        setChangeMaxAgePopupOpened(true);
    }

    function closeChangeMaxAgePopup() {
        setChangeMaxAgePopupOpened(false);
    }

    function submittedChangeMaxAge(newMaxAge, responseMessage) {
        setChangeMaxAgePopupOpened(false);
        setMaxPrivateSpaceAge(newMaxAge);
        successNotif.current.openNotif(responseMessage);
    }

    function openCleanupPopup(e) {
        e.stopPropagation();
        setConfirmPopupOpened(true);
        setConfirmPopupMessage(`${t("admin.confirm_remove_sessions")} ${maxPrivateSpaceAge} ${t("days")}?`);
        setConfirmPopupSubmitCallback(() => runPrivateSpaceCleanup);  // set value as function runPrivateSpaceCleanup
    }

    function closeConfirmationPopup() {
        setDeleteSpaceId(null);  // needed when closing or cancelling popup for deletion of single private space
        setDeleteApiDocumentId(null);
        setConfirmPopupOpened(false);
        setConfirmPopupMessage("");
        setConfirmPopupSubmitCallback(null);
    }

    const runPrivateSpaceCleanup = () => {
        axios.post(API_URL + "/admin/cleanup-private-spaces")
            .then(response => {
                if (response.status !== 200) {
                    throw new Error(t("admin.request_failed"));
                }
                if (response.data["success"]) {
                    successNotif.current.openNotif(response.data["message"]);
                } else {
                    throw new Error(response.data["message"]);
                }
                closeConfirmationPopup();
            })
            .catch(err => {
                errorNotif.current.openNotif(err.message);
                closeConfirmationPopup();
            });
    }

    function updateSchedule(e) {
        e.stopPropagation();
        let body;
        if (scheduleType === "interval") {
            body = {
                type: scheduleType,
                run_every: Number(everyHours),
            };
        } else if (scheduleType === "monthly") {
            body = {
                type: scheduleType,
                day_of_month: monthDay,
                hour: monthTime["$H"],
                minute: monthTime["$m"],
            };
        } else if (scheduleType === "weekly") {
            body = {
                type: scheduleType,
                day_of_week: weekDays.join(','),
                hour: weekTime["$H"],
                minute: weekTime["$m"],
            };
        }
        axios.post(API_URL + "/admin/schedule-cleanup",
            body,
            {
                headers: {
                    'Content-Type': 'application/json'
                },
            })
            .then(response => {
                if (response.status !== 200) {
                    throw new Error(t("admin.request_failed"));
                }
                if (response.data["success"]) {
                    successNotif.current.openNotif(response.data["message"]);
                } else {
                    throw new Error(response.data["message"])
                }
            })
            .catch(err => {
                errorNotif.current.openNotif(err.message);
            });
    }

    const valid = (scheduleType === "interval" && numberHoursRegex.test(everyHours))
                        || (scheduleType === "monthly" && monthTime !== null && dayRegex.test(monthDay))
                        || (scheduleType === "weekly" && weekTime !== null && weekDays.length !== 0);
    return (
        <Box className="App" sx={{height: '100vh'}}>
            <Notification message={""} severity={"success"} ref={successNotif}/>
            <Notification message={""} severity={"error"} ref={errorNotif}/>

            <ChangeMaxAgePopup
                open={changeMaxAgePopupOpened}
                maxAge={maxPrivateSpaceAge}
                submitCallback={submittedChangeMaxAge}
                cancelCallback={closeChangeMaxAgePopup}
            />

            <ConfirmActionPopup
                open={confirmPopupOpened}
                message={confirmPopupMessage}
                confirmButtonColor="error"
                submitCallback={confirmPopupSubmitCallback}
                cancelCallback={closeConfirmationPopup}
            />

            {/* <VersionsMenu ref={versionsMenu}/> */}
            {/* <LogsMenu ref={logsMenu}/> */}
            <Box sx={{
                display: 'flex',
                flexDirection: 'row',
                justifyContent: 'center',
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
                    flexGrow: '1',
                    flexBasis: '0',
                }}>
                    <Box>
                        <span>{t("admin.free_storage")}: {freeSpace} ({freeSpacePercent}%)</span>
                    </Box>

                    <Box sx={{marginLeft: '1rem'}}>
                        <span>{t("admin.last_cleanup")}: {lastCleanup}</span>
                    </Box>
                </Box>

                <Typography variant="h4" component="h2">
                    {t("admin.manage_storage")}
                </Typography>

                <Box sx={{
                    display: 'flex',
                    justifyContent: 'right',
                    flexGrow: '1',
                    flexBasis: '0',
                }}>
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
            </Box>

            <Box className="toolbar">
                <Box>
                    <ReturnButton
                        disabled={false}
                        returnFunction={() => navigate('/admin')}
                    />

                    <Button
                        disabled={refreshing}
                        variant="contained"
                        className="menuFunctionButton"
                        startIcon={<RotateLeft />}
                        onClick={() => getStorageInfo()}
                    >
                        {t("refresh")}
                    </Button>
                    <span style={{marginTop: "0.5rem"}}>
                        {t("admin.last_update")}: {lastUpdate ? lastUpdate.toLocaleString("pt-PT") : t("never")}
                    </span>
                </Box>

                <Box>
                    <Button
                        variant="contained"
                        onClick={(e) => openCleanupPopup(e)}
                        className="menuButton menuFunctionButton"
                    >
                        {t("admin.remove_private_spaces_older")} {maxPrivateSpaceAge} {t("days")}
                    </Button>

                    <Button
                        variant="contained"
                        onClick={(e) => openChangeMaxAgePopup(e)}
                        className="menuButton menuFunctionButton"
                    >
                        {t("admin.change_max_age")}
                    </Button>
                </Box>
            </Box>

            <Box sx={{
                display: 'flex',
                flexDirection: 'row',
                justifyContent: 'space-evenly',
                height: 'auto',
                minHeight: '77vh',
                width: '87vw',
                margin: 'auto',
                /*overflow: 'scroll'*/
            }}>
                <Box sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    minWidth: '24%',
                    width: 'fit-content',
                }}>
                    <Box sx = {{
                        display: "flex",
                        flexDirection: "column",
                        zIndex: "1",
                        backgroundColor: "#fff",
                        border: "1px solid black",
                        borderRadius: '0.5rem',
                        position: 'relative',
                        top: "0.5rem",
                        p: "0.5rem 1rem",
                        width: "fit-content",
                        height: "fit-content",
                    }}>
                        <span>{t("admin.api_documents")}</span>
                        {
                            apiFiles.map(([apiFile, info], index) => {
                                return (
                                    <Box
                                        key={index}
                                        sx={{
                                            display: "flex",
                                            flexDirection: "row",
                                            justifyContent: "space-between",
                                            alignItems: "center",
                                            height: "2rem",
                                            lineHeight: "2rem",
                                            borderTop: index !== 0 ? "1px solid black" : "0px solid black",
                                        }}
                                    >
                                        <code>{apiFile}&nbsp;—&nbsp;</code>
                                        <Box sx={{
                                            display: 'flex',
                                            flexDirection: 'row',
                                        }}>
                                            <span style={{alignContent: 'center'}}>
                                                {info["size"]}&nbsp;–&nbsp;{info["creation"]}
                                            </span>
                                            <TooltipIcon
                                                className="negActionButton"
                                                message={t("delete")}
                                                clickFunction={(e) => openDeleteApiDocumentPopup(e, apiFile)}
                                                icon={<DeleteForeverIcon />}
                                            />
                                        </Box>
                                    </Box>
                                )
                            })
                        }
                    </Box>
                </Box>

                <Box sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    minWidth: '24%',
                    width: 'fit-content',
                    alignItems: 'center',
                }}>
                    <Box sx = {{
                            display: "flex",
                            flexDirection: "column",
                            zIndex: "1",
                            backgroundColor: "#fff",
                            border: "1px solid black",
                            borderRadius: '0.5rem',
                            position: 'relative',
                            top: "0.5rem",
                            p: "0.5rem 1rem",
                            width: "fit-content",
                            height: "fit-content",
                    }}>
                        <span>{t("admin.private_spaces")}</span>
                        {
                            privateSpaces.map(([privateSpace, info], index) => {
                                return (
                                    <Box
                                        key={index}
                                        sx={{
                                            display: "flex",
                                            flexDirection: "row",
                                            justifyContent: "space-between",
                                            alignItems: "center",
                                            height: "2rem",
                                            lineHeight: "2rem",
                                            borderTop: index !== 0 ? "1px solid black" : "0px solid black",
                                            cursor: "pointer"
                                        }}
                                        onClick={() => {
                                            navigate(`/space/${privateSpace}`);
                                        }}
                                    >
                                        <code>{privateSpace}&nbsp;—&nbsp;</code>
                                        <Box sx={{
                                            display: 'flex',
                                            flexDirection: 'row',
                                        }}>
                                            <span style={{alignContent: 'center'}}>
                                                {info["size"]}&nbsp;–&nbsp;{info["creation"]}
                                            </span>
                                            <TooltipIcon
                                                className="negActionButton"
                                                message={t("delete")}
                                                clickFunction={(e) => openDeleteSpacePopup(e, privateSpace)}
                                                icon={<DeleteForeverIcon />}
                                            />
                                        </Box>
                                    </Box>
                                )
                            })
                        }
                    </Box>
                </Box>

                <Box sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    width: '45%',
                    paddingLeft: '10px',
                    borderLeft: '1px solid black',
                }}>
                    <Box sx={{
                        display: 'flex',
                        flexDirection: 'column',
                        marginBottom: '2rem',
                        paddingBottom: '1.5rem',
                        borderBottom: '1px solid #ccc',
                    }}>
                        <Typography variant="h5" component="h2" sx={{ marginBottom: '1rem' }}>
                            {t("admin.folder_concurrency_title")}
                        </Typography>

                        <Box sx={{
                            display: 'flex',
                            flexDirection: 'row',
                            justifyContent: 'space-between',
                            marginBottom: '1rem',
                        }}>
                            <Typography>
                                {t("admin.active_folders")}: {activeFolderCount}
                            </Typography>
                            <Typography>
                                {t("admin.queued_folders")}: {queuedFolderCount}
                            </Typography>
                        </Box>

                        <Box sx={{
                            display: 'flex',
                            flexDirection: 'row',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                        }}>
                            <TextField
                                label={t("admin.max_concurrent_folders")}
                                type="number"
                                value={maxConcurrentFolders}
                                onChange={(e) => setMaxConcurrentFolders(e.target.value)}
                                size="small"
                                variant="outlined"
                                inputProps={{ min: 1 }}
                                sx={{ width: '60%' }}
                            />
                            <Button
                                color="success"
                                variant="contained"
                                className="menuFunctionButton"
                                startIcon={<CheckRoundedIcon />}
                                onClick={saveFolderConcurrency}
                                disabled={!maxConcurrentFolders || parseInt(maxConcurrentFolders) < 1}
                            >
                                {t("confirm")}
                            </Button>
                        </Box>
                    </Box>

                    <Box sx={{
                        display: 'flex',
                        flexDirection: 'row',
                        justifyContent: 'space-between',
                    }}>
                        <Typography variant="h5" component="h2">
                            {t("admin.set_cleanup_schedule")}
                        </Typography>

                        <Button
                            disabled={!valid}
                            color="success"
                            variant="contained"
                            className="menuFunctionButton noMarginRight"
                            startIcon={<CheckRoundedIcon />}
                            onClick={(e) => updateSchedule(e)}
                        >
                            {t("confirm")}
                        </Button>
                    </Box>

                    <Box sx={{
                        display: 'flex',
                        flexDirection: 'row',
                        justifyContent: 'space-around',
                    }}>

                        <Box sx={{
                            display: 'flex',
                            flexDirection: 'column',
                        }}>
                            <FormControlLabel
                                label={t("admin.by_interval")}
                                checked={scheduleType === "interval"}
                                control={<Radio size="small"/>}
                                onChange={() => handleScheduleTypeChange("interval")}
                            />

                            <Box sx={{
                                display: 'flex',
                                flexDirection: 'row',
                                alignItems: 'center',
                            }}>
                                <span>{t("every")} </span>
                                <TextField
                                    disabled={scheduleType !== "interval"}
                                    error={!(numberHoursRegex.test(everyHours))}
                                    value={everyHours}
                                    onChange={(e) => handleEveryHoursChange(e.target.value)}
                                    hiddenLabel
                                    size="small"
                                    variant="outlined"
                                    className="simpleInput"
                                    sx={{
                                        width: '4rem',
                                        marginLeft: '0.3rem',
                                        marginRight: '0.3rem',
                                        textAlign: "center",
                                    }}
                                />
                                <span> {t("hours")}</span>
                            </Box>
                        </Box>

                        <Box sx={{
                            display: 'flex',
                            flexDirection: 'column',
                        }}>
                            <FormControlLabel
                                label={t("admin.weekly")}
                                checked={scheduleType === "weekly"}
                                control={<Radio size="small"/>}
                                onChange={() => handleScheduleTypeChange("weekly")}
                            />

                            <TimePicker
                                disabled={scheduleType !== "weekly"}
                                required={scheduleType === "weekly"}
                                label={t("hour")}
                                views={['hours', 'minutes']}
                                ampm={false}
                                value={weekTime}
                                onChange={(value, ctx) => setWeekTime(value)}
                                className="simpleInput hourInput"
                                slotProps={{ textField: { size: "small", error: scheduleType === "weekly" && weekTime === null } }}
                            />
                            {/*
                        <FormControl>
                            <InputLabel>Dia da semana</InputLabel>
                            <Select
                                disabled={scheduleType !== "weekly"}
                                label="Dia da semana"
                                multiple
                                value={weekDays}
                                onChange={(e) => setWeekDays(e.target.value)}
                                input={<OutlinedInput label="Dia da semana" />}
                                variant="standard"
                                renderValue={(selected) => (
                                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                        {selected.map((x) => (
                                            <Chip key={x.code} label={x.name} />
                                        ))}
                                    </Box>
                                )}>
                                {
                                    weekDaysOptions.map((day) => (
                                        <MenuItem key={day.code} value={day}>
                                            <ListItemText primary={day.name} />
                                        </MenuItem>
                                    ))
                                }
                            </Select>

                        </FormControl>


                        <FormControl>
                            <InputLabel>Dia da semana</InputLabel>
                            <Select
                                disabled={scheduleType !== "weekly"}
                                label="Dia da semana"
                                value={weekDays}
                                onChange={(e) => setWeekDays(e.target.value)}
                                input={<OutlinedInput label="Dia da semana" />}
                                variant="standard"
                            >
                                <MenuItem value={0}>Segunda-feira</MenuItem>
                                <MenuItem value={1}>Terça-feira</MenuItem>
                                <MenuItem value={2}>Quarta-feira</MenuItem>
                                <MenuItem value={3}>Quinta-feira</MenuItem>
                                <MenuItem value={4}>Sexta-feira</MenuItem>
                                <MenuItem value={5}>Sábado</MenuItem>
                                <MenuItem value={6}>Domingo</MenuItem>
                            </Select>
                        </FormControl>*/}

                            <CheckboxList
                                disabled={scheduleType !== "weekly"}
                                title={t("admin.week_days")}
                                options={getWeekDaysOptions(t)}
                                checked={weekDays}
                                required={scheduleType === "weekly"}
                                onChangeCallback={handleWeekDaysChange}
                                errorText={t("admin.select_at_least_one_day")}
                            />
                        </Box>

                        <Box sx={{
                            display: 'flex',
                            flexDirection: 'column',
                        }}>
                            <FormControlLabel
                                label={t("admin.monthly")}
                                checked={scheduleType === "monthly"}
                                control={<Radio size="small"/>}
                                onChange={() => handleScheduleTypeChange("monthly")}
                            />

                            <Box sx={{
                                display: 'flex',
                                flexDirection: 'row',
                            }}>
                                <TimePicker
                                    disabled={scheduleType !== "monthly"}
                                    required={scheduleType === "monthly"}
                                    label={t("hour")}
                                    views={['hours', 'minutes']}
                                    ampm={false}
                                    value={monthTime}
                                    onChange={(value, ctx) => setMonthTime(value)}
                                    className="simpleInput hourInput"
                                    slotProps={{ textField: { size: "small", error: scheduleType === "monthly" && monthTime === null } }}
                                />

                                <TextField
                                    disabled={scheduleType !== "monthly"}
                                    required={scheduleType === "monthly"}
                                    error={scheduleType === "monthly" && !(dayRegex.test(monthDay))}
                                    value={monthDay}
                                    onChange={(e) => handleMonthDayChange(e.target.value)}
                                    label={t("day")}
                                    size="small"
                                    variant="outlined"
                                    className="simpleInput"
                                    sx={{
                                        width: '4rem',
                                        marginLeft: '0.3rem',
                                        marginRight: '0.3rem',
                                        textAlign: "center",
                                    }}
                                />
                            </Box>
                        </Box>
                    </Box>
                </Box>
            </Box>

            <Footer />
        </Box>
    );
}

export default StorageManager;
