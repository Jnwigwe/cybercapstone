const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    pickFiles:  ()        => ipcRenderer.invoke('dialog:pickFiles'),
    pickFolder: ()        => ipcRenderer.invoke('dialog:pickFolder'),

    getEngineInfo: ()     => ipcRenderer.invoke('get-engine-info'),

    scanFiles:  (paths)   => ipcRenderer.invoke('scan-files', paths),
    onScanFileResult: (cb) => ipcRenderer.on('scan-file-result', (_e, d) => cb(d)),
    onScanComplete:   (cb) => ipcRenderer.on('scan-complete',    (_e, d) => cb(d)),

    quarantineFiles:       (entries) => ipcRenderer.invoke('quarantine-files', entries),
    getQuarantineList:     ()        => ipcRenderer.invoke('get-quarantine-list'),
    deleteQuarantineItem:  (name)    => ipcRenderer.invoke('delete-quarantine-item', name),
    restoreQuarantineItem: (name)    => ipcRenderer.invoke('restore-quarantine-item', name),

    killFiles:        (paths) => ipcRenderer.invoke('kill-files', paths),

    runPidScreamer:   (threshold) => ipcRenderer.invoke('run-pid-screamer', threshold),
    killPidScreamerProcess: (pid) => ipcRenderer.invoke('kill-pid-screamer-process', pid),
    runVtScan:        (filePath, apiKey) => ipcRenderer.invoke('run-vt-scan', filePath, apiKey),

    getScanHistory:   ()      => ipcRenderer.invoke('get-scan-history'),
    clearScanHistory: ()      => ipcRenderer.invoke('clear-scan-history'),
});
