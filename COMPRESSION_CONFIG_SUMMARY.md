# PDF Compression Configuration Option - Summary

## What Was Added

PDF compression is now a configurable option in the OCR menu that users can enable/disable before running OCR.

## Changes Made

### 1. **Frontend (React)**

#### `website/src/defaultOcrConfigs.js`
- Added `compress: true` to `defaultConfig`
- Added `compress: true` to `emptyConfig`

#### `website/src/Components/OcrMenu/OcrMenu.js`
- Imported `Switch` component from Material-UI
- Added `changeCompress()` method to handle toggle changes
- Updated `getConfig()` to include compress parameter
- Added UI toggle switch with description below the "Additional Parameters" field

#### Translation Files
**Portuguese** (`Languages/Portuguese/translation.json`):
```json
"compress pdf": "Comprimir PDF",
"compress pdf description": "Reduz o tamanho do ficheiro PDF em 60-80% mantendo a qualidade de texto"
```

**English** (`Languages/English/translation.json`):
```json
"compress pdf": "Compress PDF",
"compress pdf description": "Reduces PDF file size by 60-80% while maintaining text quality"
```

### 2. **Backend (Python)**

#### `server/config_files/default.json`
- Added `"compress": true` to default OCR configuration

#### `server/celery_app.py`
- Modified `task_export_results()` to read compress setting from config
- Modified `task_make_changes()` to read compress setting from config
- Pass `compress` parameter to all `export_file()` calls for PDF generation

#### `server/src/utils/export.py`
- Already updated to accept and use `compress` parameter
- Compression is applied when parameter is `True`

## How It Works

### User Flow:

1. **User opens OCR configuration menu**
   - Switch is visible below "Additional Parameters"
   - Default state: **ON** (compression enabled)

2. **User can toggle compression**
   - ON: PDF files will be compressed (60-80% size reduction)
   - OFF: PDF files generated without compression

3. **Configuration is saved**
   - Setting is stored in document's `_data.json` under `config.compress`
   - Persists across OCR runs

4. **During OCR/Export**
   - System reads `compress` setting from config
   - Passes to export functions
   - Compression applied (or skipped) based on setting

### Data Flow:

```
User Toggle (UI)
    ↓
Frontend State (compress: true/false)
    ↓
Saved in Config (config.compress)
    ↓
Backend Reads Config (data["config"]["compress"])
    ↓
Passed to export_file(compress=value)
    ↓
Applied in export_pdf()
```

## UI Location

**OCR Configuration Menu** → **Right Column** → **Bottom Section**

Position:
- After "Additional Parameters" text field
- Before bottom of configuration panel
- Toggle switch with label and helper text

Visual:
```
┌─────────────────────────────────────┐
│ Additional Parameters                │
│ [___________________________]       │
│                                      │
│ [ ◉ ] Compress PDF                 │
│    Reduces PDF file size by 60-80% │
│    while maintaining text quality   │
└─────────────────────────────────────┘
```

## Testing

### To Test:

1. **Start the services:**
   ```bash
   docker-compose up -d
   ```

2. **Open OCR menu for a document**

3. **Check the toggle:**
   - Should be visible at bottom of right column
   - Should be ON by default
   - Should show description text

4. **Run OCR with compression ON:**
   - Check browser: should show "A comprimir PDF" status
   - Check logs: should show compression metrics
   - Check file size: should be 60-80% smaller

5. **Run OCR with compression OFF:**
   - No compression stage should appear
   - Original large PDF generated

### Verification:

**With Compression (ON):**
- Browser shows: "A comprimir PDF - Página X/Y"
- Logs show: Compression metrics and size reduction
- File size: Significantly reduced

**Without Compression (OFF):**
- No compression status in browser
- No compression logs
- File size: Uncompressed (larger)

## Configuration Storage

The setting is stored in `_files/{document}/_data.json`:

```json
{
  "config": {
    "engine": "tesserocr",
    "lang": ["por"],
    "outputs": ["pdf", "txt"],
    "compress": true    // ← This setting
  }
}
```

## Default Behavior

- **Default:** Compression is **ENABLED**
- **Fallback:** If setting is missing, defaults to **TRUE**
- **Override:** Users can toggle OFF if needed

## Benefits

1. **User Control:** Users decide if they want compression
2. **Flexibility:** Can disable for specific documents if needed
3. **Performance:** Can skip compression for faster processing
4. **Quality:** Can disable if concerned about image quality

## Notes

- Compression only affects **PDF** outputs
- Does not affect TXT, CSV, or other formats
- Text searchability is preserved regardless of setting
- Compression uses MRC algorithm (background/foreground separation)

## Migration

Existing documents without this setting:
- Will default to `compress: true`
- No manual migration needed
- Works automatically

## Support

If the toggle doesn't appear:
1. Clear browser cache
2. Rebuild frontend: `npm run build`
3. Restart services

If compression isn't working:
1. Check `_data.json` contains `compress: true`
2. Check server logs for compression output
3. Verify PyMuPDF is installed
