import React from 'react';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import { useTranslation } from 'react-i18next';
import QueueMonitor from '../QueueMonitor/QueueMonitor';
import { MODEL, STJ } from '../../App';
import logoApp from "static/logoApp.png";
import logoUN from "static/Logo_of_the_United_Nations.svg";

const QueueStatusPage = () => {
    const { t } = useTranslation();

    return (
        <Box 
            className={`App ${MODEL === STJ ? "theme-stj" : "theme-un"}`}
            sx={{
                minHeight: "100vh",
                backgroundColor: "var(--gray-50)",
                display: "flex",
                flexDirection: "column"
            }}
        >
            {/* Header */}
            <Box 
                className="header animate-slideInDown"
                sx={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "var(--spacing-sm)",
                    padding: "var(--spacing-md) var(--spacing-xl)",
                    backgroundColor: "var(--card-bg)",
                    boxShadow: "var(--shadow-sm)",
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
                                maxHeight: "45px",
                                transition: "transform var(--transition-base)",
                            }}
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
                            {t("queue.page_title") || "Queue Status"}
                        </Typography>
                    </Box>

                    <Button
                        component={Link}
                        to="/"
                        variant="outlined"
                        startIcon={<ArrowBackIcon />}
                        sx={{
                            textTransform: "none",
                            borderColor: "var(--border-color)",
                            color: "var(--text-primary)",
                            '&:hover': {
                                borderColor: "var(--accent-primary)",
                                backgroundColor: "var(--card-hover-bg)",
                            }
                        }}
                    >
                        {t("back") || "Back"}
                    </Button>
                </Box>
            </Box>

            {/* Main Content */}
            <Box sx={{
                flexGrow: 1,
                width: '87vw',
                marginLeft: 'auto',
                marginRight: 'auto',
                marginTop: 'var(--spacing-lg)',
                marginBottom: 'var(--spacing-lg)',
            }}>
                <QueueMonitor compact={false} autoRefresh={true} refreshInterval={3000} />
            </Box>
        </Box>
    );
};

export default QueueStatusPage;
