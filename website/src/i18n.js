import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./Languages/English/translation.json";
import pt from "./Languages/Portuguese/translation.json";
import ar from "./Languages/Arabic/translation.json";
import zh from "./Languages/Chinese/translation.json";
import fr from "./Languages/French/translation.json";
import ru from "./Languages/Russian/translation.json";
import es from "./Languages/Spanish/translation.json";

i18n.use(initReactI18next).init({
    resources: {
        en: { translation: en },
        pt: { translation: pt },
        ar: { translation: ar },
        zh: { translation: zh },
        fr: { translation: fr },
        ru: { translation: ru },
        es: { translation: es },
    },
    lng: "en", // default language
    fallbackLng: "en",
    interpolation: {
        escapeValue: false,
    },
});

export default i18n;
