import React from 'react';

import {useTranslation} from "react-i18next";

import Button from "@mui/material/Button";
import UndoIcon from "@mui/icons-material/Undo";


const ReturnButton = ({ disabled = false, returnFunction = null, sx = {} }) => {
    const { t } = useTranslation();
    return (
        <Button
            disabled={disabled}
            variant="contained"
            startIcon={<UndoIcon />}
            onClick={() => returnFunction()}
            className="menuFunctionButton"
            sx={Object.assign({
                marginLeft: "0.5rem",
                backgroundColor: '#ffffff',
                color: '#000000',
                ':hover': { bgcolor: '#ddd' },
            }, sx)}
        >
            {t("back")}
        </Button>
    );
}

export default ReturnButton;
