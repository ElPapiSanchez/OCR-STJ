import './App.css';
import React, {useEffect, useState} from 'react';
import axios from "axios";
import { LocalizationProvider } from "@mui/x-date-pickers/LocalizationProvider";
import { AdapterDayjs } from "@mui/x-date-pickers/AdapterDayjs";
import "dayjs/locale/pt";

import "./i18n";
import { useTranslation } from "react-i18next";

import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Typography from "@mui/material/Typography";
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';

import LockIcon from '@mui/icons-material/Lock';
import HelpIcon from '@mui/icons-material/Help';
import SearchIcon from '@mui/icons-material/Search';
import FlashOnIcon from '@mui/icons-material/FlashOn';

import {
    BrowserRouter,
    Link,
    Navigate,
    Outlet,
    Route,
    Routes,
    useLocation,
    useNavigate,
    useParams
} from "react-router";

import {
    fileSystemState,
    layoutMenuState,
    editingMenuState,
    searchMenuState,
    ocrMenuState
} from "./states";

import logoApp from "static/logoApp.png";
import logoUN from "static/Logo_of_the_United_Nations.svg"
import FileExplorer from 'Components/FileSystem/FileSystem';
import ESPage from 'Components/ElasticSearchPage/ESPage';
import LoginPage from 'Components/Admin/LoginPage';
import AdminDashboard from 'Components/Admin/Dashboard';
import StorageManager from 'Components/Admin/StorageManager';
import ConfigManager from 'Components/Admin/ConfigManager';
import Footer from 'Components/Footer/Footer';
import ImmediateOCRPage from 'Components/ImmediateOCR/ImmediateOCR';
import QueueMonitor from 'Components/QueueMonitor/QueueMonitor';
import QueueStatusPage from 'Components/QueueMonitor/QueueStatusPage';

const API_URL = `${window.location.protocol}//${window.location.host}/${process.env.REACT_APP_API_URL}`;

export const STJ = 1;
export const UN_ARMS = 2;

/**
 * About Versioning:
 * Version -> MAJOR.MINOR.PATCH
 * MAJOR version when you make incompatible API changes
 * MINOR version when you add functionality in a backwards compatible manner
 * PATCH version when you make backwards compatible bug fixes
 */

const VERSION = "1.5.0";

export const MODEL = STJ;

function App() {
    const [isAuthenticated, setIsAuthenticated] = useState(false);

    const { t, i18n } = useTranslation();

    const login = () => {
        setIsAuthenticated(true);
    };
    const logout = () => {
        setIsAuthenticated(false);
    };

    useEffect(() => {
        // Check if admin already logged in
        axios.get(API_URL + "/account/check-auth")
            .then(r => {
                login();
            })
            .catch(e=>{});
    }, []);

    const ProtectedRoute = ({ isAuthenticated }) => {
        const location = useLocation();
        return (isAuthenticated
        ? <Outlet/>
        : <Navigate to="/admin/login" state={{ originPath: location.pathname }} replace />);
    };

    // Allow Form to get the space ID parameter from the route URL
    const WrappedForm = (props) => {
        const { spaceId } = useParams();
        const navigate = useNavigate();
        return <Form spaceId={spaceId} navigate={navigate} />;
    }

    class Form extends React.Component {
        static defaultProps = {
            spaceId: null,
            navigate: null,
        }
        constructor(props) {
            super(props);
            this.state = {
                searchMenu: false,
                editingMenu: false,
                layoutMenu: false,

                currentFileName: null,
                currentFolderPathList: [""],

                ocrTargetIsFolder: false,
                ocrTargetIsSinglePage: false,
                customConfig: null,

                filesChoice: [],
                algorithmChoice: [],
                configChoice: [],

                privateSpacesOpen: false,
                privateSpaces: [],
                freeSpace: props.freeSpace || 0,
                freeSpacePercentage: props.freeSpacePercentage || 0,
            }

            this.header = React.createRef();

            this.fileSystem = React.createRef();

            this.createPrivateSpace = this.createPrivateSpace.bind(this);
            this.leavePrivateSpace = this.leavePrivateSpace.bind(this);
            this.setCurrentPath = this.setCurrentPath.bind(this);
            this.returnToParentFolder = this.returnToParentFolder.bind(this);
            this.enterOcrMenu = this.enterOcrMenu.bind(this);
            this.setCurrentCustomConfig = this.setCurrentCustomConfig.bind(this);
            this.enterLayoutMenu = this.enterLayoutMenu.bind(this);
            this.enterEditingMenu = this.enterEditingMenu.bind(this);
            this.exitMenus = this.exitMenus.bind(this);
            this.closeSearchMenu = this.closeSearchMenu.bind(this);
        }

        getPrivateSpaceId() {
            if (["", "ocr", "ocr-dev", "ocr-prod"].includes(this.props.spaceId)) return null;
            return this.props.spaceId;
        }

        /*
        redirectHome() {
            const currentURL = window.location.href;

            // Check if the current URL is deployed
            if (currentURL.includes('iris.sysresearch.org')) {
                const deployedURL = currentURL.split("/")[3] + (currentURL.includes(process.env.REACT_APP_ADMIN) ? process.env.REACT_APP_ADMIN : "");
                window.location.href = 'https://iris.sysresearch.org/' + deployedURL + '/';
            }
            // Check if the current URL is in the local environment
            else if (currentURL.includes('localhost')) {
                const port = currentURL.split(":")[2].split("/")[0] + (currentURL.includes(process.env.REACT_APP_ADMIN) ? process.env.REACT_APP_ADMIN : "");
                window.location.href = 'http://localhost:' + port + '/';
            }
        }
         */

        createPrivateSpace() {
            return axios.get(API_URL + '/create-private-space')
            .then(({data}) => {
                const spaceId = data["space_id"];
                this.setState({currentFolderPathList: [""]});
                this.props.navigate(`/space/${spaceId}`);
            });
        }

        leavePrivateSpace() {
            this.props.navigate("/");
        }

        setCurrentPath(new_path_list, isDocument=false) {
            // replace(/^\//, '') removes '/' from the start of the path. the server expects non-absolute paths
            let currentFileName = null;
            if (isDocument) {
                currentFileName = new_path_list.pop();
            }
            // ensure empty root item, lost if the path was joined into a string and split again
            if (new_path_list[0] !== "") new_path_list.unshift("");

            this.setState({...fileSystemState, currentFolderPathList: new_path_list, currentFileName: currentFileName});
        }

        enterOcrMenu(filename, ocrTargetIsFolder=false, ocrTargetIsSinglePage=false, customConfig=null) {
            this.setState({
                ...ocrMenuState,
                currentFileName: filename,
                ocrTargetIsFolder: ocrTargetIsFolder,
                ocrTargetIsSinglePage: ocrTargetIsSinglePage,
                customConfig: customConfig,
            });
        }

        /*
        Used to pass down an updated customConfig prop without fetching all info from the server
         */
        setCurrentCustomConfig(customConfig) {
            this.setState({customConfig: customConfig});
        }

        enterLayoutMenu(filename) {
            this.setState({...layoutMenuState, currentFileName: filename});
        }

        enterEditingMenu(filename) {
            this.setState({...editingMenuState, currentFileName: filename});
        }

        exitMenus(callback) {
            this.setState({...fileSystemState, currentFileName: null},
                () => { if (callback) callback(); }
            );
        }

        returnToParentFolder() {
            if (this.state.currentFileName !== null) {
                this.setState({currentFileName: null});
            } else {
                let current_list = this.state.currentFolderPathList;
                current_list.pop();
                this.setCurrentPath(current_list);
            }
        }

        changeFolderFromPath(folder_name) {
            let current_list = this.state.currentFolderPathList;
            if (current_list.length === 1) return;

            current_list.pop();

            // Remove the last element of the path until we find folder_name or until root
            while (current_list.length > 1 && current_list[current_list.length - 1] !== folder_name) {
                current_list.pop();
            }
            this.setCurrentPath(current_list);
        }

        closeSearchMenu() {
            this.setState({...fileSystemState,
                filesChoice: [],
                algorithmChoice: [],
                configChoice: []
            });
        }

        render() {
            const buttonsDisabled = this.state.ocrMenu || this.state.searchMenu || this.state.layoutMenu || this.state.editingMenu;
            return (
                <Box className={`App ${MODEL === STJ ? "theme-stj" : "theme-un"}`}
                     sx={{minHeight: "100vh", display: "flex", flexDirection: "column", backgroundColor: "var(--gray-50)"}}>
                    <Box className="header animate-slideInDown"
                         sx={{
                            display: "flex",
                            flexDirection: "column",
                            gap: "var(--spacing-sm)",
                            padding: "var(--spacing-md) var(--spacing-xl)",
                         }}
                    >
                        <Box sx={{
                            display: "flex",
                            flexDirection: "row",
                            justifyContent: "space-between",
                            alignItems: "center",
                            width: "100%",
                        }}>
                            <Box sx={{display: "flex", alignItems: "center", gap: "var(--spacing-md)"}}>
                                <img
                                    src={MODEL === STJ ? logoApp : logoUN}
                                    alt={MODEL === STJ ? "Logótipo do STJ" : "Logótipo da UN"}
                                    style={{
                                        maxHeight: "80px",
                                        transition: "transform var(--transition-base)",
                                    }}
                                    onMouseEnter={(e) => e.target.style.transform = "scale(1.05)"}
                                    onMouseLeave={(e) => e.target.style.transform = "scale(1)"}
                                />
                                
                                <Typography
                                    variant="h5"
                                    component="h1"
                                    className="fancy-font"
                                    sx={{
                                        display: {xs: "none", md: "block"},
                                        color: "var(--header-text)",
                                    }}
                                >
                                    {
                                        this.getPrivateSpaceId()
                                            ? t("private space") + ' - ' + this.getPrivateSpaceId()
                                            : t("title")
                                    }
                                </Typography>
                            </Box>

                            <Box sx={{display: "flex", alignItems: "center", gap: "var(--spacing-md)"}}>
                                {/* Queue Monitor - Compact View */}
                                <QueueMonitor compact={true} autoRefresh={true} refreshInterval={5000} />

                                <FormControl size="small" sx={{ minWidth: 100 }}>
                                    <Select
                                        value={i18n.language}
                                        onChange={(e) => i18n.changeLanguage(e.target.value)}
                                        sx={{
                                            color: "var(--text-primary)",
                                            fontSize: "var(--font-size-sm)",
                                            borderRadius: "var(--radius-md)",
                                            backgroundColor: "var(--card-bg)",
                                            '& .MuiOutlinedInput-notchedOutline': {
                                                borderColor: "var(--border-color)",
                                            },
                                            '&:hover .MuiOutlinedInput-notchedOutline': {
                                                borderColor: "var(--accent-primary)",
                                            },
                                            '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                                                borderColor: "var(--accent-primary)",
                                            },
                                        }}
                                    >
                                        <MenuItem value="en">EN - English</MenuItem>
                                        <MenuItem value="pt">PT - Português</MenuItem>
                                        <MenuItem value="ar">AR - العربية</MenuItem>
                                        <MenuItem value="zh">ZH - 中文</MenuItem>
                                        <MenuItem value="fr">FR - Français</MenuItem>
                                        <MenuItem value="ru">RU - Русский</MenuItem>
                                        <MenuItem value="es">ES - Español</MenuItem>
                                    </Select>
                                </FormControl>

                                <Typography variant="body2" sx={{ color: "var(--text-tertiary)", fontSize: "var(--font-size-xs)" }}>
                                    {t("version")}: {VERSION}
                                </Typography>

                                <Button
                                    variant="text"
                                    onClick={() => window.open("https://servico-ocr.gitbook.io/manual-ocr", '_blank')}
                                    startIcon={<HelpIcon/>}
                                    className="red-link"
                                    sx={{
                                        textTransform: "none",
                                        padding: "var(--spacing-xs) var(--spacing-sm)",
                                        borderRadius: "var(--radius-md)",
                                        fontSize: "var(--font-size-sm)",
                                        '&:hover': {
                                            backgroundColor: "var(--card-hover-bg)",
                                        },
                                    }}
                                >
                                    {t("user manual")}
                                </Button>
                            </Box>
                        </Box>
                    </Box>

                    <Box sx={{
                        display: 'flex',
                        flexDirection: 'row',
                        width: '87vw',
                        marginLeft: 'auto',
                        marginRight: 'auto',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        paddingTop: 'var(--spacing-sm)',
                        paddingBottom: 'var(--spacing-sm)',
                        marginBottom: 'var(--spacing-sm)',
                    }}>
                        <Box sx={{
                            display: "flex",
                            flexDirection: "row",
                            alignItems: "center",
                            backgroundColor: "var(--card-bg)",
                            borderRadius: "var(--radius-lg)",
                            padding: "var(--spacing-xs)",
                            boxShadow: "var(--shadow-xs)",
                            flexWrap: "wrap",
                            gap: "var(--spacing-xs)",
                        }}>
                            {
                                this.state.currentFolderPathList.map((folder, index) => {
                                    const name = index > 0 ? folder : t("start");
                                    const folderDepth = this.state.currentFolderPathList.length;

                                    if (this.state.searchMenu && index > 0)
                                        return null;

                                    // Show hint of collapsed names when inside deep folder
                                    if (folderDepth > 3 && index === 1) {
                                        return (
                                            <Box key={index} sx={{display: "flex", alignItems: "center", gap: "var(--spacing-xs)"}}>
                                                <Typography sx={{color: "var(--text-tertiary)", fontSize: "var(--font-size-sm)"}}>...</Typography>
                                                <Typography sx={{color: "var(--text-tertiary)", fontSize: "var(--font-size-sm)"}}>/</Typography>
                                            </Box>
                                        )
                                    }

                                    // Hide intermediate folder names when inside deep folder
                                    if (folderDepth > 3 && index > 0 && index < folderDepth - 2) return null;

                                    // If not in menu or inside document "folder" containing original and results,
                                    // make current folder non-clickable (folder names are clickable to go back)
                                    if (!this.state.currentFileName && index > 0 && index === folderDepth - 1) {
                                        return (
                                            <Typography 
                                                key={folder}
                                                className="pathElement" 
                                                sx={{
                                                    color: "var(--text-primary)",
                                                    fontWeight: "var(--font-weight-semibold)",
                                                }}
                                            >
                                                {name}
                                            </Typography>
                                        )
                                    } else return (
                                        <Box
                                            sx={{
                                                display: 'flex',
                                                alignItems: 'center',
                                                gap: 'var(--spacing-xs)',
                                            }}
                                            key={"Box" + folder}
                                        >
                                            <Button
                                                disabled={!this.state.searchMenu && buttonsDisabled}
                                                key={folder}
                                                onClick={() => {
                                                    if (index === 0 && this.state.searchMenu) {
                                                        this.closeSearchMenu();
                                                    } else {
                                                        this.changeFolderFromPath(folder);
                                                    }
                                                }}
                                                className="pathElement pathButton"
                                                variant="text"
                                                sx={{
                                                    minHeight: "auto",
                                                    fontSize: "var(--font-size-sm)",
                                                }}
                                            >
                                                {name}
                                            </Button>
                                            <Typography sx={{color: "var(--text-tertiary)", fontSize: "var(--font-size-sm)"}}>/</Typography>
                                        </Box>
                                    )
                                })
                            }
                            {this.state.currentFileName && (
                                <Typography 
                                    className="pathElement"
                                    sx={{
                                        color: "var(--text-primary)",
                                        fontWeight: "var(--font-weight-semibold)",
                                        fontSize: "var(--font-size-sm)",
                                    }}
                                >
                                    {this.state.currentFileName}
                                </Typography>
                            )}
                        </Box>
                    </Box>

                    <Box>
                        {
                            !this.state.searchMenu
                            ? <FileExplorer ref={this.fileSystem}
                                            _private={Boolean(this.getPrivateSpaceId())}
                                            spaceId={this.props.spaceId || ""}  // spaceId or empty str if null
                                            current_folder={
                                                // replace(/^\//, '') removes '/' from the start of the path. the server expects non-absolute paths
                                                this.state.currentFolderPathList.join('/').replace(/^\//, '')
                                            }
                                            current_file_name={this.state.currentFileName}
                                            ocrTargetIsFolder={this.state.ocrTargetIsFolder}
                                            ocrTargetIsSinglePage={this.state.ocrTargetIsSinglePage}
                                            customConfig={this.state.customConfig}
                                            ocrMenu={this.state.ocrMenu}
                                            layoutMenu={this.state.layoutMenu}
                                            editingMenu={this.state.editingMenu}
                                            createPrivateSpace={this.createPrivateSpace}
                                            leavePrivateSpace={this.leavePrivateSpace}
                                            setCurrentPath={this.setCurrentPath}
                                            returnToParentFolder={this.returnToParentFolder}
                                            enterOcrMenu={this.enterOcrMenu}
                                            setCurrentCustomConfig={this.setCurrentCustomConfig}
                                            enterLayoutMenu={this.enterLayoutMenu}
                                            enterEditingMenu={this.enterEditingMenu}
                                            exitMenus={this.exitMenus}/>
                            : <ESPage filesChoice={this.state.filesChoice}
                                      algorithmChoice={this.state.algorithmChoice}
                                      configChoice={this.state.configChoice}
                                      closeSearchMenu={this.closeSearchMenu}/>
                        }
                    </Box>

                    <Footer />
                </Box>
            )
        }
    }

    return (
        <LocalizationProvider dateAdapter={AdapterDayjs} adapterLocale="pt">
            <BrowserRouter basename={`/${process.env.REACT_APP_BASENAME}`}>
                <Routes>
                    <Route index element={<WrappedForm />} />
                    <Route path="/space/:spaceId" element={<WrappedForm />} />
                    <Route path="/immediate-ocr" element={<ImmediateOCRPage />} />
                    <Route path="/queue-status" element={<QueueStatusPage />} />

                    <Route element={<ProtectedRoute isAuthenticated={isAuthenticated}/>} >
                        <Route exact path="/admin" element={<AdminDashboard />} />
                        <Route exact path="/admin/storage" element={<StorageManager />} />
                        <Route exact path="/admin/config" element={<ConfigManager />} />
                    </Route>
                    <Route exact path="/admin/login" element={<LoginPage isAuthenticated={isAuthenticated} setLoggedIn={login}/>} />
                </Routes>
            </BrowserRouter>
        </LocalizationProvider>
    );
}

export default App;
