"""
System-wide settings management with file locking for thread-safety.
Stores settings in _system_settings.json in the shared files directory.
"""

import json
import os
from filelock import FileLock

# Store in shared volume so server and worker can access the same file
SETTINGS_FILE = "_files/_system_settings.json"
SETTINGS_LOCK_FILE = f"{SETTINGS_FILE}.lock"

DEFAULT_SETTINGS = {
    "max_concurrent_folders": 1,
    "active_folders": [],
    "queued_folders": [],
    "finished_folders": []  # Stores recently completed folders (cleared after 2 minutes)
}


def _read_settings_unlocked():
    """
    Internal function to read settings without locking.
    Only use this when already holding the lock.
    """
    if not os.path.exists(SETTINGS_FILE):
        # Create file with defaults
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_SETTINGS, f, indent=2)
        return DEFAULT_SETTINGS.copy()
    
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            settings = json.load(f)
        
        # Ensure all default keys exist
        for key, value in DEFAULT_SETTINGS.items():
            if key not in settings:
                settings[key] = value
        
        return settings
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error reading system settings: {e}")
        return DEFAULT_SETTINGS.copy()


def _write_settings_unlocked(settings):
    """
    Internal function to write settings without locking.
    Only use this when already holding the lock.
    """
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)


def get_system_settings():
    """
    Get current system settings from JSON file.
    Creates file with defaults if it doesn't exist.
    Thread-safe using file locking.
    
    Returns:
        dict: System settings
    """
    lock = FileLock(SETTINGS_LOCK_FILE, timeout=5)
    with lock:
        return _read_settings_unlocked()


def update_system_setting(key, value):
    """
    Update a specific system setting.
    Thread-safe using file locking.
    
    Args:
        key (str): Setting key to update
        value: New value for the setting
        
    Returns:
        dict: Updated settings
    """
    lock = FileLock(SETTINGS_LOCK_FILE, timeout=5)
    with lock:
        settings = _read_settings_unlocked()
        settings[key] = value
        _write_settings_unlocked(settings)
        return settings


def update_system_settings(updates):
    """
    Update multiple system settings at once.
    Thread-safe using file locking.
    
    Args:
        updates (dict): Dictionary of key-value pairs to update
        
    Returns:
        dict: Updated settings
    """
    lock = FileLock(SETTINGS_LOCK_FILE, timeout=5)
    with lock:
        settings = _read_settings_unlocked()
        settings.update(updates)
        _write_settings_unlocked(settings)
        return settings


def remove_active_folder(folder_id):
    """
    Atomically remove a folder from active_folders by its ID.
    Thread-safe using file locking.
    
    Args:
        folder_id (str): ID of folder to remove
        
    Returns:
        dict: Updated settings with the folder removed
    """
    import logging as log
    lock = FileLock(SETTINGS_LOCK_FILE, timeout=5)
    with lock:
        settings = _read_settings_unlocked()
        active_folders_before = settings.get("active_folders", [])
        log.info(f"🗑️  remove_active_folder: folder_id={folder_id}, active_before={len(active_folders_before)}")
        
        # Remove folder with matching ID
        active_folders = [f for f in active_folders_before if f.get("id") != folder_id]
        settings["active_folders"] = active_folders
        _write_settings_unlocked(settings)
        
        log.info(f"🗑️  remove_active_folder: active_after={len(active_folders)}, removed={len(active_folders_before) - len(active_folders)}")
        return settings


def pop_next_queued_folder():
    """
    Atomically pop the next folder from queued_folders and add it to active_folders.
    Thread-safe using file locking.
    
    Returns:
        tuple: (next_folder dict or None, updated settings)
    """
    lock = FileLock(SETTINGS_LOCK_FILE, timeout=5)
    with lock:
        settings = _read_settings_unlocked()
        queued_folders = settings.get("queued_folders", [])
        
        if not queued_folders:
            return None, settings
        
        next_folder = queued_folders.pop(0)
        settings["queued_folders"] = queued_folders
        _write_settings_unlocked(settings)
        return next_folder, settings


def add_finished_folder(folder_id, folder_path):
    """
    Add a folder to the finished_folders list when it completes.
    Thread-safe using file locking.
    
    Args:
        folder_id (str): ID of the completed folder
        folder_path (str): Path of the completed folder
    """
    import time
    lock = FileLock(SETTINGS_LOCK_FILE, timeout=5)
    with lock:
        settings = _read_settings_unlocked()
        finished_folders = settings.get("finished_folders", [])
        
        # Add new finished folder (no cleanup - keep permanently)
        finished_folders.append({
            "id": folder_id,
            "path": folder_path,
            "completed_at": time.time()
        })
        
        settings["finished_folders"] = finished_folders
        _write_settings_unlocked(settings)
        return settings


def cleanup_old_finished_folders():
    """
    Optional cleanup function - not used by default.
    Remove finished folders older than a specified time.
    Thread-safe using file locking.
    """
    import time
    lock = FileLock(SETTINGS_LOCK_FILE, timeout=5)
    with lock:
        settings = _read_settings_unlocked()
        finished_folders = settings.get("finished_folders", [])
        
        # Keep all finished folders (no time-based cleanup)
        # This function is kept for future use if needed
        
        settings["finished_folders"] = finished_folders
        _write_settings_unlocked(settings)
        return settings
