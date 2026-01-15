import { useEffect } from 'react';

// Keyboard shortcuts manager
export const useKeyboardShortcuts = (shortcuts) => {
    useEffect(() => {
        const handleKeyDown = (event) => {
            const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
            const modifier = isMac ? event.metaKey : event.ctrlKey;

            // Check each shortcut
            for (const shortcut of shortcuts) {
                const { key, ctrl, shift, alt, callback, preventDefault = true } = shortcut;
                
                const modifierMatch = ctrl ? modifier : !modifier;
                const shiftMatch = shift ? event.shiftKey : !event.shiftKey;
                const altMatch = alt ? event.altKey : !event.altKey;
                const keyMatch = event.key.toLowerCase() === key.toLowerCase();

                if (modifierMatch && shiftMatch && altMatch && keyMatch) {
                    if (preventDefault) {
                        event.preventDefault();
                    }
                    callback(event);
                    break;
                }
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => {
            window.removeEventListener('keydown', handleKeyDown);
        };
    }, [shortcuts]);
};

// Format shortcut display text
export const formatShortcut = (shortcut) => {
    const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
    const parts = [];
    
    if (shortcut.ctrl) {
        parts.push(isMac ? '⌘' : 'Ctrl');
    }
    if (shortcut.shift) {
        parts.push(isMac ? '⇧' : 'Shift');
    }
    if (shortcut.alt) {
        parts.push(isMac ? '⌥' : 'Alt');
    }
    parts.push(shortcut.key.toUpperCase());
    
    return parts.join(isMac ? '' : '+');
};

// Default shortcuts configuration
export const SHORTCUTS = {
    SEARCH: { key: 'k', ctrl: true, label: 'Search' },
    UPLOAD: { key: 'u', ctrl: true, label: 'Upload File' },
    NEW_FOLDER: { key: 'n', ctrl: true, label: 'New Folder' },
    DELETE: { key: 'Delete', label: 'Delete' },
    ESCAPE: { key: 'Escape', label: 'Close/Cancel' },
    SELECT_ALL: { key: 'a', ctrl: true, label: 'Select All' },
};


