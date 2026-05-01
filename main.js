const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { execFile, exec, execSync } = require('child_process');

// ═══════════════════════════════════════════════════════════════════
// LAYER 1 — HEURISTIC STRING SCANNER (from Gavin Hecke's file_scanner.cpp)
// ═══════════════════════════════════════════════════════════════════

const THREAT_SIGNATURES = [
    { pattern: "/bin/bash -i",  category: "shell",       reason: "Reverse shell invocation" },
    { pattern: "/bin/sh -i",    category: "shell",       reason: "Interactive shell spawn" },
    { pattern: "nc -e",         category: "network",     reason: "Netcat remote execution" },
    { pattern: "/dev/tcp/",     category: "network",     reason: "Bash TCP reverse shell" },
    { pattern: "eval(",         category: "execution",   reason: "Dynamic code evaluation" },
    { pattern: "exec(",         category: "execution",   reason: "Process execution call" },
    { pattern: "system(",       category: "execution",   reason: "System command execution" },
    { pattern: "wget http",     category: "download",    reason: "Remote payload download (wget)" },
    { pattern: "curl http",     category: "download",    reason: "Remote payload download (curl)" },
    { pattern: "chmod 777",     category: "permission",  reason: "Permission escalation (777)" },
    { pattern: "chmod +x",      category: "permission",  reason: "Make file executable" },
    { pattern: "/etc/shadow",   category: "credential",  reason: "Shadow password file access" },
    { pattern: "/etc/passwd",   category: "credential",  reason: "Password file access" },
    { pattern: "LD_PRELOAD",    category: "injection",   reason: "Shared library injection" },
    { pattern: "rm -rf",        category: "destructive", reason: "Recursive forced deletion" },
    { pattern: "dd if=",        category: "destructive", reason: "Raw disk I/O operation" },
    { pattern: "mkfifo",        category: "evasion",     reason: "Named pipe creation" },
    { pattern: "> /dev/null",   category: "evasion",     reason: "Output suppression" },
    { pattern: "base64 -d",     category: "evasion",     reason: "Base64 payload decoding" },
];

const EXTENDED_SIGNATURES = [
    { pattern: "powershell -enc",     category: "execution",   reason: "Encoded PowerShell command" },
    { pattern: "powershell -e ",      category: "execution",   reason: "Encoded PowerShell execution" },
    { pattern: "Invoke-Expression",   category: "execution",   reason: "PowerShell code injection" },
    { pattern: "Invoke-WebRequest",   category: "download",    reason: "PowerShell web download" },
    { pattern: "New-Object Net.WebClient", category: "download", reason: "PowerShell download cradle" },
    { pattern: "DownloadString(",     category: "download",    reason: ".NET download payload" },
    { pattern: "DownloadFile(",       category: "download",    reason: ".NET file download" },
    { pattern: "WScript.Shell",       category: "execution",   reason: "Windows Script Host execution" },
    { pattern: "cmd /c",              category: "execution",   reason: "Command shell execution" },
    { pattern: "reg add",             category: "persistence", reason: "Registry modification" },
    { pattern: "schtasks /create",    category: "persistence", reason: "Scheduled task creation" },
    { pattern: "netsh firewall",      category: "evasion",     reason: "Firewall rule modification" },
    { pattern: "netsh advfirewall",   category: "evasion",     reason: "Advanced firewall modification" },
    { pattern: "stratum+tcp://",      category: "cryptominer", reason: "Cryptocurrency mining pool" },
    { pattern: "xmrig",               category: "cryptominer", reason: "XMRig crypto miner detected" },
    { pattern: "minerd",              category: "cryptominer", reason: "CPU crypto miner binary" },
    { pattern: "tar czf",             category: "exfiltration", reason: "Archive creation for exfiltration" },
    { pattern: "curl -F",             category: "exfiltration", reason: "File upload via curl" },
    { pattern: "curl --upload",       category: "exfiltration", reason: "File upload to remote server" },
    { pattern: "sudo -S",             category: "privilege",    reason: "Automated sudo escalation" },
    { pattern: "setuid",              category: "privilege",    reason: "SUID bit manipulation" },
    { pattern: "setgid",              category: "privilege",    reason: "SGID bit manipulation" },
    { pattern: "ptrace",              category: "antidebug",    reason: "Anti-debugging technique" },
    { pattern: "VirtualBox",          category: "antidebug",    reason: "VM detection (sandbox evasion)" },
    { pattern: "VMware",              category: "antidebug",    reason: "VM detection (sandbox evasion)" },
    { pattern: "AES.new(",            category: "ransomware",   reason: "AES encryption (ransomware pattern)" },
    { pattern: "Fernet(",             category: "ransomware",   reason: "Fernet encryption (ransomware pattern)" },
    { pattern: ".encrypted",          category: "ransomware",   reason: "File encryption renaming" },
    { pattern: "YOUR FILES HAVE BEEN", category: "ransomware",  reason: "Ransom note text detected" },
    { pattern: "bitcoin",             category: "ransomware",   reason: "Bitcoin payment reference" },
];

const ALL_SIGNATURES = [...THREAT_SIGNATURES, ...EXTENDED_SIGNATURES];

const THREAT_TIPS = {
    shell: { title: "Reverse Shell / Shell Access", severity: "Critical", description: "This file attempts to spawn an interactive shell or establish a reverse shell connection.", tips: ["Check firewall for unauthorized outbound connections", "Review running processes for shell sessions", "Scan system for other backdoor files", "Change all passwords immediately", "Monitor network traffic for unknown IPs"] },
    network: { title: "Network Exploitation", severity: "Critical", description: "This file uses network tools to establish unauthorized connections or exfiltrate data.", tips: ["Block target IP addresses in your firewall", "Check netstat for suspicious connections", "Review router/firewall logs", "Isolate machine from network", "Run full network scan"] },
    execution: { title: "Suspicious Code Execution", severity: "High", description: "This file dynamically evaluates or executes code, a common malware technique.", tips: ["Never run files from untrusted sources", "Check for new scheduled tasks or startup entries", "Review recent file modifications in system dirs", "Use application whitelisting", "Scan recently modified files"] },
    download: { title: "Remote Payload Download", severity: "Critical", description: "This file downloads additional malicious payloads from the internet.", tips: ["Check Downloads and Temp folders", "Block URLs found in this file at firewall", "Scan recently downloaded files", "Clear browser cache and temp files", "Review browser extensions"] },
    permission: { title: "Permission Escalation", severity: "High", description: "This file modifies file permissions to enable execution of malicious payloads.", tips: ["Audit file permissions in writable directories", "Remove execute permissions from suspicious files", "Enable audit logging for permission changes", "Check for SUID/SGID binaries"] },
    credential: { title: "Credential Theft", severity: "Critical", description: "This file attempts to access sensitive password/credential files.", tips: ["Change ALL user passwords immediately", "Enable multi-factor authentication", "Check password files for modifications", "Review sudo access", "Check for new user accounts"] },
    injection: { title: "Library Injection", severity: "Critical", description: "This file uses techniques to inject malicious code into running processes.", tips: ["Check LD_PRELOAD environment variable", "Scan /etc/ld.so.preload for unauthorized entries", "Review shared libraries in non-standard locations", "Restart critical services", "Enable library validation"] },
    destructive: { title: "Destructive Operations", severity: "Critical", description: "This file contains commands that can destroy data or wipe disks.", tips: ["Verify backup integrity immediately", "Check for data loss in critical directories", "Review disk health", "Ensure offline backups exist", "Never run this file"] },
    evasion: { title: "Obfuscation & Evasion", severity: "Medium", description: "This file uses techniques to hide its activity or decode hidden payloads.", tips: ["Check for hidden files and directories", "Look for base64-encoded strings", "Review named pipes in /tmp", "Check cron jobs for hidden tasks", "Enable verbose logging"] },
    persistence: { title: "Persistence Mechanism", severity: "High", description: "This file creates persistence mechanisms to survive system reboots.", tips: ["Check startup programs and registry keys", "Review scheduled tasks", "Inspect service configurations", "Check browser extensions", "Review autorun entries"] },
    cryptominer: { title: "Cryptocurrency Miner", severity: "High", description: "This file runs a cryptocurrency miner, consuming system resources.", tips: ["Check CPU usage for abnormal spikes", "Block mining pool connections at firewall", "Review running processes for unknown miners", "Check GPU usage", "Monitor system temperature"] },
    exfiltration: { title: "Data Exfiltration", severity: "Critical", description: "This file attempts to collect and upload sensitive data to remote servers.", tips: ["Check outbound connections for data transfers", "Review recently archived files", "Monitor upload bandwidth", "Check for staged data in temp directories"] },
    privilege: { title: "Privilege Escalation", severity: "Critical", description: "This file attempts to gain elevated system privileges.", tips: ["Review SUID/SGID binaries", "Check sudo configuration", "Review user privileges", "Monitor for unauthorized privilege changes"] },
    antidebug: { title: "Anti-Analysis / Sandbox Evasion", severity: "Medium", description: "This file detects analysis environments to evade security tools.", tips: ["Run in a dedicated analysis sandbox", "Use hardware-based analysis if possible", "Check for additional payload drops", "Review file behavior in isolated environment"] },
    ransomware: { title: "Ransomware Indicators", severity: "Critical", description: "This file shows patterns consistent with ransomware encryption behavior.", tips: ["IMMEDIATELY disconnect from network", "Do NOT pay any ransom", "Restore from clean offline backups", "Report to law enforcement", "Check for ransomware decryption tools online"] },
};

const WHITELISTED_EXTENSIONS = [".md", ".rst", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".log"];

function isWhitelisted(filepath) {
    return WHITELISTED_EXTENSIONS.includes(path.extname(filepath).toLowerCase());
}

function scanFileHeuristic(filepath) {
    try {
        const stats = fs.statSync(filepath);
        if (stats.size > 50 * 1024 * 1024) return { rawCount: 0, adjustedCount: -1, matchedReasons: [], categories: [], skipped: true, skipReason: "File exceeds 50MB limit" };

        let content;
        try { content = fs.readFileSync(filepath, 'utf8'); }
        catch (_) { content = fs.readFileSync(filepath, 'latin1'); }

        const lines = content.split('\n');
        let rawCount = 0;
        const matchedReasons = [];
        const categories = new Set();

        for (const sig of ALL_SIGNATURES) {
            let found = false;
            for (const rawLine of lines) {
                const trimmed = rawLine.trim();
                if (trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('--')) continue;
                if (rawLine.includes(sig.pattern)) { found = true; break; }
            }
            if (found) { rawCount++; matchedReasons.push(sig.reason); categories.add(sig.category); }
        }

        let adjustedCount = rawCount;
        const ext = path.extname(filepath).toLowerCase();
        if (['.md', '.txt', '.rst'].includes(ext)) adjustedCount = Math.floor(rawCount / 3);
        else if (['.conf', '.cfg', '.ini', '.yaml', '.yml'].includes(ext)) adjustedCount = Math.floor((rawCount * 2) / 3);
        else if (['.cpp', '.c', '.java', '.go'].includes(ext)) adjustedCount = Math.floor((rawCount * 4) / 5);

        return { rawCount, adjustedCount, matchedReasons, categories: Array.from(categories), skipped: false };
    } catch (e) {
        return { rawCount: 0, adjustedCount: 0, matchedReasons: [], categories: [], skipped: true, skipReason: e.message };
    }
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 2 — SHA256 HASH ANALYSIS
// ═══════════════════════════════════════════════════════════════════

function computeSHA256(filepath) {
    try {
        const data = fs.readFileSync(filepath);
        return crypto.createHash('sha256').update(data).digest('hex');
    } catch (_) { return null; }
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 3 — ENTROPY ANALYSIS
// ═══════════════════════════════════════════════════════════════════

function computeEntropy(filepath) {
    try {
        const data = fs.readFileSync(filepath);
        if (data.length === 0) return 0;

        const freq = new Array(256).fill(0);
        for (let i = 0; i < data.length; i++) freq[data[i]]++;

        let entropy = 0;
        const len = data.length;
        for (let i = 0; i < 256; i++) {
            if (freq[i] === 0) continue;
            const p = freq[i] / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    } catch (_) { return 0; }
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 4 — PE / EXECUTABLE HEADER ANALYSIS
// ═══════════════════════════════════════════════════════════════════

function analyzeExecutable(filepath) {
    const results = { isPE: false, suspicious: false, reasons: [] };
    try {
        const buf = Buffer.alloc(512);
        const fd = fs.openSync(filepath, 'r');
        fs.readSync(fd, buf, 0, 512, 0);
        fs.closeSync(fd);

        if (buf[0] === 0x4D && buf[1] === 0x5A) {
            results.isPE = true;
            const peOffset = buf.readUInt32LE(0x3C);
            if (peOffset < 480 && buf[peOffset] === 0x50 && buf[peOffset + 1] === 0x45) {
                const characteristics = buf.readUInt16LE(peOffset + 0x16);
                if (characteristics & 0x2000) results.reasons.push('Dynamic Link Library (DLL)');
                if (characteristics & 0x0001) results.reasons.push('No relocation info (packed indicator)');
            }
        }
        else if (buf[0] === 0x7F && buf[1] === 0x45 && buf[2] === 0x4C && buf[3] === 0x46) {
            results.isPE = true;
            results.reasons.push('ELF binary detected');
        }
        else if (buf[0] === 0x23 && buf[1] === 0x21) {
            const line = buf.toString('utf8', 0, Math.min(128, buf.length));
            if (line.includes('/bin/bash') || line.includes('/bin/sh')) {
                results.reasons.push('Shell script with shebang');
            }
        }
    } catch (_) { }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 5 — ClamAV INTEGRATION (uses clamscan if installed)
// ═══════════════════════════════════════════════════════════════════

let clamAvailable = null;

function checkClamAV() {
    return new Promise((resolve) => {
        exec('clamscan --version', (err, stdout) => {
            if (err) {
                clamAvailable = false;
                resolve(false);
            } else {
                clamAvailable = true;
                console.log('[ClamAV] Found:', stdout.trim());
                resolve(true);
            }
        });
    });
}

function clamScanFile(filepath) {
    return new Promise((resolve) => {
        if (!clamAvailable) { resolve({ scanned: false }); return; }

        execFile('clamscan', ['--no-summary', '--infected', filepath], { timeout: 30000 }, (err, stdout, stderr) => {
            if (err && err.code === 1) {
                const match = stdout.match(/:\s*(.+)\s+FOUND/);
                resolve({
                    scanned: true,
                    infected: true,
                    virusName: match ? match[1].trim() : 'Unknown Threat',
                    raw: stdout.trim()
                });
            } else if (err) {
                resolve({ scanned: false, error: err.message });
            } else {
                resolve({ scanned: true, infected: false });
            }
        });
    });
}

// ═══════════════════════════════════════════════════════════════════
// COMBINED THREAT CLASSIFIER
// ═══════════════════════════════════════════════════════════════════

function classifyThreat(heuristicResult, entropyValue, exeAnalysis, clamResult) {
    const reasons = [];
    const categories = new Set();
    let score = 0;

    if (clamResult && clamResult.scanned && clamResult.infected) {
        return {
            status: 'malicious',
            reason: `ClamAV: ${clamResult.virusName}`,
            categories: ['clamav'],
            score: 100,
            scanLayers: ['ClamAV Signature Match']
        };
    }

    if (!heuristicResult.skipped) {
        score += heuristicResult.adjustedCount * 2;
        if (heuristicResult.adjustedCount >= 5) {
            reasons.push(...heuristicResult.matchedReasons.slice(0, 4));
            heuristicResult.categories.forEach(c => categories.add(c));
        } else if (heuristicResult.adjustedCount >= 3) {
            reasons.push(...heuristicResult.matchedReasons.slice(0, 3));
            heuristicResult.categories.forEach(c => categories.add(c));
        }
    }

    if (entropyValue > 7.2 && exeAnalysis.isPE) {
        score += 4;
        reasons.push('High entropy (likely packed/encrypted)');
        categories.add('evasion');
    } else if (entropyValue > 7.5) {
        score += 2;
        reasons.push('Unusually high entropy');
    }

    if (exeAnalysis.reasons.length > 0) {
        score += exeAnalysis.reasons.length;
        reasons.push(...exeAnalysis.reasons);
    }

    const scanLayers = ['Heuristic String Analysis'];
    scanLayers.push('SHA-256 Hash Check');
    scanLayers.push(`Entropy Analysis (${entropyValue.toFixed(2)}/8.00)`);
    if (exeAnalysis.isPE) scanLayers.push('PE/ELF Header Analysis');
    if (clamResult && clamResult.scanned) scanLayers.push('ClamAV Signature Scan');

    if (heuristicResult.skipped) return { status: 'skipped', reason: heuristicResult.skipReason || 'Skipped', categories: [], score: 0, scanLayers };
    if (score >= 10) return { status: 'malicious', reason: reasons.join(', '), categories: Array.from(categories), score, scanLayers };
    if (score >= 6) return { status: 'suspicious', reason: reasons.join(', '), categories: Array.from(categories), score, scanLayers };
    return { status: 'clean', reason: 'No threats detected', categories: [], score, scanLayers };
}

// ═══════════════════════════════════════════════════════════════════
// QUARANTINE ENGINE
// ═══════════════════════════════════════════════════════════════════

const QUARANTINE_DIR = path.join(__dirname, 'quarantine');
const QUARANTINE_LOG = path.join(__dirname, 'quarantine.log');
const SCAN_HISTORY_FILE = path.join(__dirname, 'scan_history.json');
const SETTINGS_FILE = path.join(__dirname, 'settings.json');

function ensureQuarantineDir() {
    if (!fs.existsSync(QUARANTINE_DIR)) fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
}

function logAction(msg) {
    const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
    try { fs.appendFileSync(QUARANTINE_LOG, `[${ts}] ${msg}\n`); } catch (_) { }
}

function quarantineFile(filepath, reason, categories) {
    try {
        ensureQuarantineDir();
        const ts = Date.now();
        const fn = path.basename(filepath);
        const qName = `${ts}_${fn}`;
        const qPath = path.join(QUARANTINE_DIR, qName);
        const sz = fs.statSync(filepath).size;

        fs.copyFileSync(filepath, qPath);
        fs.writeFileSync(qPath + '.metadata', JSON.stringify({
            originalPath: filepath, quarantineTime: new Date().toISOString(),
            reason, categories: categories || [], fileSize: sz, fileName: fn
        }, null, 2));
        try { fs.chmodSync(qPath, 0o444); } catch (_) { }
        fs.unlinkSync(filepath);

        logAction(`QUARANTINED: ${filepath} -> ${qPath} | Reason: ${reason}`);
        return { success: true, quarantineName: qName };
    } catch (e) {
        logAction(`QUARANTINE FAILED: ${filepath} | ${e.message}`);
        return { success: false, error: e.message };
    }
}

function killFile(filepath) {
    try {
        if (!fs.existsSync(filepath)) return { success: false, error: 'File not found' };
        try { fs.chmodSync(filepath, 0o666); } catch (_) { }
        fs.unlinkSync(filepath);
        logAction(`KILLED: ${filepath}`);
        return { success: true };
    } catch (e) { return { success: false, error: e.message }; }
}

// ═══════════════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════════════

function loadSettings() {
    try {
        if (fs.existsSync(SETTINGS_FILE)) {
            return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
        }
    } catch (_) { }
    return { virusTotalApiKey: '' };
}

function saveSettings(settings) {
    try {
        fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ═══════════════════════════════════════════════════════════════════
// SCAN HISTORY
// ═══════════════════════════════════════════════════════════════════

function loadScanHistory() {
    try { if (fs.existsSync(SCAN_HISTORY_FILE)) return JSON.parse(fs.readFileSync(SCAN_HISTORY_FILE, 'utf8')); } catch (_) { }
    return [];
}
function saveScanHistory(h) { try { fs.writeFileSync(SCAN_HISTORY_FILE, JSON.stringify(h, null, 2)); } catch (_) { } }
function addScanRecord(r) { const h = loadScanHistory(); h.unshift(r); if (h.length > 50) h.length = 50; saveScanHistory(h); }

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function getAllFiles(dirPath, arr) {
    try {
        const files = fs.readdirSync(dirPath);
        arr = arr || [];
        files.forEach(f => {
            const fp = path.join(dirPath, f);
            try { if (fs.statSync(fp).isDirectory()) getAllFiles(fp, arr); else arr.push(fp); } catch (_) { }
        });
        return arr;
    } catch (_) { return arr || []; }
}

function getFileType(filepath) {
    const ext = path.extname(filepath).toLowerCase();
    const map = {
        '.exe':'Executable','.dll':'Library','.sys':'Driver','.bat':'Batch Script','.cmd':'CMD Script',
        '.ps1':'PowerShell','.sh':'Shell Script','.py':'Python','.rb':'Ruby','.js':'JavaScript',
        '.pdf':'PDF','.doc':'Word Doc','.docx':'Word Doc','.zip':'ZIP','.rar':'RAR','.7z':'7-Zip',
        '.cpp':'C++ Source','.c':'C Source','.h':'Header','.java':'Java','.go':'Go','.rs':'Rust',
        '.txt':'Text','.md':'Markdown','.json':'JSON','.html':'HTML','.css':'CSS',
        '.png':'Image','.jpg':'Image','.svg':'SVG','.mp3':'Audio','.mp4':'Video',
    };
    return map[ext] || (ext ? ext.substring(1).toUpperCase() + ' File' : 'Unknown');
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

// ═══════════════════════════════════════════════════════════════════
// VIRUSTOTAL ENGINE
// ═══════════════════════════════════════════════════════════════════

async function vtScanFile(filepath, apiKeyArg) {
    const settings = loadSettings();

    const apiKey =
        apiKeyArg ||
        settings.virusTotalApiKey ||
        '';

    if (!apiKey) {
        return { error: 'Please save your VirusTotal API key in Settings first.' };
    }

    if (!filepath || !fs.existsSync(filepath)) {
        return { error: 'Selected file does not exist.' };
    }

    const reportPath = path.join(__dirname, 'scan_report.json');

    try {
        if (fs.existsSync(reportPath)) {
            fs.unlinkSync(reportPath);
        }
    } catch (_) {}

    const sha256 = computeSHA256(filepath);
    if (!sha256) {
        return { error: 'Failed to compute file hash.' };
    }

    async function vtGet(url) {
        const res = await fetch(url, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
                'accept': 'application/json'
            }
        });

        const text = await res.text();
        let data = null;
        try { data = text ? JSON.parse(text) : null; } catch (_) {}

        return {
            ok: res.ok,
            status: res.status,
            data,
            text
        };
    }

    async function vtUpload(filePath) {
        const fileBuffer = fs.readFileSync(filePath);
        const fileName = path.basename(filePath);

        const form = new FormData();
        form.append(
            'file',
            new Blob([fileBuffer]),
            fileName
        );

        const res = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': apiKey,
                'accept': 'application/json'
            },
            body: form
        });

        const text = await res.text();
        let data = null;
        try { data = text ? JSON.parse(text) : null; } catch (_) {}

        return {
            ok: res.ok,
            status: res.status,
            data,
            text
        };
    }

    function normalizeStats(stats) {
        return {
            malicious: stats?.malicious || 0,
            suspicious: stats?.suspicious || 0,
            harmless: stats?.harmless || 0,
            undetected: stats?.undetected || 0,
            timeout: stats?.timeout || 0,
            confirmed_timeout: stats?.['confirmed-timeout'] || 0,
            failure: stats?.failure || 0,
            type_unsupported: stats?.['type-unsupported'] || 0
        };
    }

    function severityFrom(stats) {
        if ((stats.malicious || 0) >= 3) return 'HIGH';
        if ((stats.malicious || 0) >= 1 || (stats.suspicious || 0) >= 2) return 'MEDIUM';
        return 'LOW';
    }

    function recommendedAction(stats, severity) {
        if (severity === 'HIGH') return 'QUARANTINE (high confidence detections; isolate file; do not execute)';
        if (severity === 'MEDIUM') return 'REVIEW (some detections; verify source; consider isolating)';
        if ((stats.malicious || 0) === 0 && (stats.suspicious || 0) === 0) {
            return 'ALLOW (no detections; keep monitoring; verify source if unknown)';
        }
        return 'REVIEW (low signals present; verify source)';
    }

    function extractDetectionReasons(lastAnalysisResults) {
        if (!lastAnalysisResults || typeof lastAnalysisResults !== 'object') {
            return {
                engines: [],
                reasons: [],
                summaryLine: ''
            };
        }

        const detected = [];

        for (const [engineName, resultObj] of Object.entries(lastAnalysisResults)) {
            const category = resultObj?.category || '';
            const result = (resultObj?.result || '').trim();

            if (category === 'malicious' || category === 'suspicious') {
                detected.push({
                    engine: engineName,
                    category,
                    result: result || (category === 'malicious' ? 'malicious verdict' : 'suspicious verdict')
                });
            }
        }

        const uniqueReasons = [];
        const seenReasons = new Set();

        for (const item of detected) {
            const reasonText = item.result;
            const key = reasonText.toLowerCase();
            if (!seenReasons.has(key)) {
                seenReasons.add(key);
                uniqueReasons.push(reasonText);
            }
        }

        const engineNames = detected.map(d => d.engine);

        let summaryLine = '';
        if (detected.length > 0) {
            const preview = detected
                .slice(0, 3)
                .map(d => `${d.engine}: ${d.result}`)
                .join(' | ');
            summaryLine = preview;
        }

        return {
            engines: engineNames,
            reasons: uniqueReasons,
            summaryLine
        };
    }

    try {
        // 1) check existing VT hash report
        const fileLookup = await vtGet(`https://www.virustotal.com/api/v3/files/${sha256}`);

        if (fileLookup.ok && fileLookup.data?.data?.attributes) {
            const attrs = fileLookup.data.data.attributes;
            const stats = normalizeStats(attrs.last_analysis_stats);
            const severity = severityFrom(stats);
            const recommended = recommendedAction(stats, severity);
            const detectionInfo = extractDetectionReasons(attrs.last_analysis_results);

            const report = {
                started_at: new Date().toISOString(),
                finished_at: new Date().toISOString(),
                target: filepath,
                results: [
                    {
                        file: filepath,
                        sha256,
                        severity,
                        recommended_action: recommended,
                        used_existing_report: true,
                        http_status_initial: fileLookup.status,
                        detection_reasons: detectionInfo.reasons,
                        detection_engines: detectionInfo.engines,
                        detection_summary_line: detectionInfo.summaryLine,
                        stats: {
                            malicious: stats.malicious,
                            suspicious: stats.suspicious,
                            harmless: stats.harmless,
                            undetected: stats.undetected,
                            timeout: stats.timeout,
                            'confirmed-timeout': stats.confirmed_timeout,
                            failure: stats.failure,
                            'type-unsupported': stats.type_unsupported
                        }
                    }
                ],
                summary: {
                    total_scanned: 1,
                    low: severity === 'LOW' ? 1 : 0,
                    medium: severity === 'MEDIUM' ? 1 : 0,
                    high: severity === 'HIGH' ? 1 : 0
                }
            };

            fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');

            return {
                scanned: true,
                sha256,
                usedExisting: true,
                severity,
                recommended_action: recommended,
                quarantined_to: '',
                stats,
                detection_reasons: detectionInfo.reasons,
                detection_engines: detectionInfo.engines,
                detection_summary_line: detectionInfo.summaryLine,
                rawReport: report
            };
        }

        // 2) if not found, upload
        if (fileLookup.status !== 404) {
            return {
                error: `VirusTotal lookup failed (HTTP ${fileLookup.status}).`
            };
        }

        const uploadResp = await vtUpload(filepath);
        if (!uploadResp.ok || !uploadResp.data?.data?.id) {
            return {
                error: `VirusTotal upload failed (HTTP ${uploadResp.status}).`
            };
        }

        const analysisId = uploadResp.data.data.id;

        // 3) poll analysis
        let completed = null;
        const maxPolls = 12;
        const pollDelayMs = 15000;

        for (let i = 0; i < maxPolls; i++) {
            const analysisResp = await vtGet(`https://www.virustotal.com/api/v3/analyses/${analysisId}`);

            if (!analysisResp.ok) {
                return {
                    error: `VirusTotal analysis fetch failed (HTTP ${analysisResp.status}).`
                };
            }

            const status = analysisResp.data?.data?.attributes?.status || '';
            if (status === 'completed') {
                completed = analysisResp.data;
                break;
            }

            await new Promise(r => setTimeout(r, pollDelayMs));
        }

        if (!completed) {
            return {
                error: 'VirusTotal analysis did not complete in time.'
            };
        }

        const attrs = completed.data.attributes || {};
        const stats = normalizeStats(attrs.stats || {});
        const severity = severityFrom(stats);
        const recommended = recommendedAction(stats, severity);
        const detectionInfo = extractDetectionReasons(attrs.results || {});

        const report = {
            started_at: new Date().toISOString(),
            finished_at: new Date().toISOString(),
            target: filepath,
            results: [
                {
                    file: filepath,
                    sha256,
                    severity,
                    recommended_action: recommended,
                    used_existing_report: false,
                    http_status_initial: fileLookup.status,
                    detection_reasons: detectionInfo.reasons,
                    detection_engines: detectionInfo.engines,
                    detection_summary_line: detectionInfo.summaryLine,
                    stats: {
                        malicious: stats.malicious,
                        suspicious: stats.suspicious,
                        harmless: stats.harmless,
                        undetected: stats.undetected,
                        timeout: stats.timeout,
                        'confirmed-timeout': stats.confirmed_timeout,
                        failure: stats.failure,
                        'type-unsupported': stats.type_unsupported
                    }
                }
            ],
            summary: {
                total_scanned: 1,
                low: severity === 'LOW' ? 1 : 0,
                medium: severity === 'MEDIUM' ? 1 : 0,
                high: severity === 'HIGH' ? 1 : 0
            }
        };

        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');

        return {
            scanned: true,
            sha256,
            usedExisting: false,
            severity,
            recommended_action: recommended,
            quarantined_to: '',
            stats,
            detection_reasons: detectionInfo.reasons,
            detection_engines: detectionInfo.engines,
            detection_summary_line: detectionInfo.summaryLine,
            rawReport: report
        };
    } catch (err) {
        return { error: err.message };
    }
}

// ═══════════════════════════════════════════════════════════════════
// PID SCREAMER (cross-platform)
// ═══════════════════════════════════════════════════════════════════

function normalizePath(p) {
    return String(p || '').replace(/\\/g, '/').toLowerCase();
}

function containsSuspiciousKeywords(p) {
    const s = normalizePath(p);
    const keys = [
    'rootkit', 'keylogger', 'backdoor', 'hidden', 'trojan', 'malware',
    'stealer', 'rat', 'payload', 'implant', 'rk_', 'hook', 'inject',

    'dropper', 'loader', 'bot', 'botnet', 'miner', 'coinminer', 'xmrig',
    'cryptominer', 'clipper', 'grabber', 'infostealer', 'passwordstealer',
    'credential', 'cred', 'cookie', 'session', 'token', 'wallet', 'exfil',
    'exfiltration', 'skimmer', 'spy', 'spyware', 'ransom', 'ransomware',
    'locker', 'worm', 'wiper', 'destroyer', 'persistence', 'autorun',
    'startup', 'service', 'daemon', 'task', 'scheduledtask', 'schtask',
    'uacbypass', 'bypass', 'evasion', 'obfusc', 'packed', 'packer',
    'shellcode', 'reflective', 'dllinject', 'processinject', 'hollow',
    'hollowing', 'hijack', 'hooker', 'beacon', 'c2', 'cnc', 'commandandcontrol',
    'reverse', 'revshell', 'shell', 'bindshell', 'meterpreter', 'mimikatz',
    'lsass', 'samdump', 'dumper', 'dump', 'scrape', 'scanner', 'bruteforce',
    'brute', 'phish', 'phishing', 'spoof', 'exploit', 'kit', 'stager',
    'stage1', 'stage2', 'agent', 'implantcore', 'webshell', 'netshell',
    'cmdrun', 'psrun', 'pwsh', 'powersploit', 'empire', 'covenant',
    'sliver', 'quasar', 'njrat', 'remcos', 'darkcomet', 'asyncrat',
    'redline', 'vidar', 'raccoon', 'lokibot', 'azorult', 'emotet',
    'trickbot', 'qakbot', 'dridex', 'formbook', 'agenttesla', 'nanocore',
    'mal_', 'troj_', 'bkdr_', 'steal_', 'miner_', 'bot_', 'rat_', 'grab_'
];
    return keys.some(k => s.includes(k));
}

function isSuspiciousPathCrossPlatform(p) {
    const s = normalizePath(p);
    if (!s) return false;

    if (process.platform === 'win32') {
        if (s.includes('/appdata/local/temp/')) return true;
        if (s.includes('/temp/')) return true;
        if (s.includes('/tmp/')) return true;
        if (s.includes('/programdata/temp/')) return true;

        if (s.includes('/appdata/roaming/')) return true;
        if (s.includes('/appdata/local/')) return true;
        if (s.includes('/users/public/')) return true;
        if (s.includes('/programdata/')) return true;
        if (s.includes('/windows/tasks/')) return true;
        if (s.includes('/windows/temp/')) return true;
        if (s.includes('/recycle.bin/')) return true;
        if (s.includes('/startup/')) return true;
        if (s.includes('/autorun/')) return true;
    } else {
        if (s.includes('/tmp/')) return true;
        if (s.includes('/dev/shm/')) return true;

        if (s.includes('/var/tmp/')) return true;
        if (s.includes('/run/')) return true;
        if (s.includes('/.cache/')) return true;
        if (s.includes('/.local/share/')) return true;
        if (s.includes('/.config/autostart/')) return true;
        if (s.includes('/etc/cron')) return true;
        if (s.includes('/systemd/system/')) return true;
        if (s.includes('/init.d/')) return true;
    }

    if (s.includes('rk_')) return true;
    if (s.includes('rootkit')) return true;
    if (s.includes('.hidden')) return true;
    if (s.includes('keylogger')) return true;
    if (s.includes('backdoor')) return true;
    if (s.includes('payload')) return true;
    if (s.includes('stealer')) return true;
    if (s.includes('rat')) return true;

    return false;
}

function isLikelyFalsePositivePathCrossPlatform(p) {
    const s = normalizePath(p);
    if (!s) return { isFalsePositive: false, reason: '' };

    const legitWindowsPrefixes = [
        '/windows/system32/',
        '/windows/syswow64/',
        '/program files/',
        '/program files (x86)/'
    ];

    const legitLinuxPrefixes = [
        '/usr/bin/',
        '/usr/sbin/',
        '/bin/',
        '/sbin/',
        '/lib/',
        '/lib64/',
        '/snap/'
    ];

    const legitNames = [
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'conhost.exe', 'svchost.exe',
    'explorer.exe', 'taskhostw.exe', 'code.exe', 'chrome.exe', 'firefox.exe',
    'python.exe', 'python3', 'node.exe', 'java.exe', 'gcc', 'g++', 'clang',
    'bash', 'sh', 'dash', 'zsh', 'fish', 'python', 'python3', 'node', 'java',

    'taskmgr.exe',
    'electron.exe',
    'steamwebhelper.exe',
    'discord.exe'
];

    const name = s.split('/').pop() || '';

    const prefixes = process.platform === 'win32' ? legitWindowsPrefixes : legitLinuxPrefixes;

    if (prefixes.some(prefix => s.startsWith(prefix)) && legitNames.some(n => name === n)) {
        return {
            isFalsePositive: true,
            reason: 'System or developer tool path matched a known legitimate binary'
        };
    }

    if (legitNames.some(n => name === n)) {
        return {
            isFalsePositive: true,
            reason: 'Known legitimate process name'
        };
    }

    if (process.platform === 'win32' && s.startsWith('/programdata/') && legitNames.some(n => name === n)) {
    return {
        isFalsePositive: true,
        reason: 'Known legitimate app installed under ProgramData'
    };
}

    return { isFalsePositive: false, reason: '' };
}

function parsePidReport(reportPath) {
    if (!fs.existsSync(reportPath)) return [];

    const lines = fs.readFileSync(reportPath, 'utf8')
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(Boolean);

    const rows = [];
    for (const line of lines) {
        if (line.startsWith('#')) continue;
        if (line.startsWith('No processes met')) continue;

        const parts = line.split('\t');
        if (parts.length < 5) continue;

        rows.push({
            pid: Number(parts[0]),
            filePath: parts[1],
            cpuPercent: String(parts[2]).replace('%', ''),
            flagLabel: parts[3] || 'SUS',
            pathFlag: parts[4] || 'normal',
            falsePositive: parts[5] === 'true',
            falsePositiveReason: parts[6] || ''
        });
    }

    return rows;
}

function writePidReport(rows, reportPath, threshold, modeLabel) {
    const lines = [
        `# Suspicious process report (${modeLabel})`,
        `# CPU threshold enforced: ${threshold}%`,
        '# PID\tExecutable Path\tCPU%\tFLAG\tPATH_FLAG\tFALSE_POSITIVE\tFALSE_POSITIVE_REASON'
    ];

    if (!rows.length) {
        lines.push(`No processes met the CPU threshold (${threshold}%).`);
    } else {
        for (const r of rows) {
            lines.push(
                `${r.pid}\t${r.filePath}\t${r.cpuPercent}%\t${r.flagLabel}\t${r.pathFlag}\t${r.falsePositive ? 'true' : 'false'}\t${r.falsePositiveReason || ''}`
            );
        }
    }

    fs.writeFileSync(path.join(__dirname, 'suspicious_report.txt'), lines.join('\n'), 'utf8');
}

function getPidBinaryPath() {
    if (process.platform === 'win32') {
        return path.join(__dirname, 'simple_pid_screamer.exe');
    }
    return path.join(__dirname, 'simple_pid_screamer');
}

function runPidBinary(threshold) {
    return new Promise((resolve) => {
        const exePath = getPidBinaryPath();
        const reportPath = path.join(__dirname, 'suspicious_report.txt');

        execFile(
            exePath,
            ['--threshold', String(threshold)],
            { cwd: __dirname, maxBuffer: 1024 * 1024 * 20 },
            (err, stdout, stderr) => {
                if (err) {
                    resolve({ error: `Failed to retrieve running processes: ${err.message}` });
                    return;
                }

                const rows = parsePidReport(reportPath);

                resolve({
                    threats: rows.map(r => ({
                        pid: r.pid,
                        path: r.filePath,
                        cpu: Number(r.cpuPercent || 0).toFixed(2),
                        keyword: r.pathFlag === 'suspicious' ? 'suspicious-pattern' : '',
                        reason: r.falsePositive
                            ? `Likely false positive: ${r.falsePositiveReason || 'Known legitimate process'}`
                            : (r.pathFlag === 'suspicious'
                                ? `Hit ${Number(r.cpuPercent || 0).toFixed(2)}% CPU and matched suspicious path/keyword indicators`
                                : `Hit ${Number(r.cpuPercent || 0).toFixed(2)}% CPU`),
                        falsePositive: !!r.falsePositive,
                        falsePositiveReason: r.falsePositiveReason || ''
                    }))
                });
            }
        );
    });
}

async function runPidScreamerSync(cpuThreshold) {
    try {
        return await runPidBinary(cpuThreshold);
    } catch (e) {
        return { error: 'Failed to retrieve running processes: ' + e.message };
    }
}

async function killPidCrossPlatform(pid) {
    try {
        const safePid = Number(pid);

        if (!Number.isInteger(safePid) || safePid <= 0) {
            return { success: false, error: 'Invalid PID' };
        }

        if (process.platform === 'win32') {
            return await new Promise((resolve) => {
                execFile(
                    'taskkill',
                    ['/PID', String(safePid), '/T', '/F'],
                    { windowsHide: true },
                    (err, stdout, stderr) => {
                        if (err) {
                            resolve({
                                success: false,
                                error: String(stderr || stdout || err.message || 'Failed to kill PID').trim()
                            });
                            return;
                        }

                        resolve({
                            success: true,
                            pid: safePid,
                            output: String(stdout || '').trim()
                        });
                    }
                );
            });
        }

        process.kill(safePid, 'SIGKILL');
        return {
            success: true,
            pid: safePid
        };
    } catch (e) {
        return {
            success: false,
            error: e.message
        };
    }
}

// ═══════════════════════════════════════════════════════════════════
// ELECTRON WINDOW
// ═══════════════════════════════════════════════════════════════════

let mainWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200, height: 850, minWidth: 900, minHeight: 650,
        titleBarStyle: 'hidden',
        titleBarOverlay: { color: '#09090B', symbolColor: '#ffffff', height: 40 },
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false, contextIsolation: true
        }
    });
    mainWindow.loadFile('index.html');
}

app.whenReady().then(async () => {
    await checkClamAV();
    createWindow();
    app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

// ═══════════════════════════════════════════════════════════════════
// IPC HANDLERS
// ═══════════════════════════════════════════════════════════════════

ipcMain.handle('dialog:pickFiles', async () => {
    const r = await dialog.showOpenDialog(mainWindow, { properties: ['openFile', 'multiSelections'] });
    return r.filePaths;
});

ipcMain.handle('dialog:pickFolder', async () => {
    const r = await dialog.showOpenDialog(mainWindow, { properties: ['openDirectory'] });
    return r.filePaths;
});

ipcMain.handle('get-engine-info', () => {
    return {
        clamAvailable: clamAvailable === true,
        signatureCount: ALL_SIGNATURES.length,
        layers: clamAvailable ? 5 : 4
    };
});

ipcMain.handle('get-settings', async () => {
    return loadSettings();
});

ipcMain.handle('save-settings', async (event, settings) => {
    const current = loadSettings();
    return saveSettings({ ...current, ...settings });
});

// ── MULTI-LAYER SCAN ──
ipcMain.handle('scan-files', async (event, paths) => {
    try {
        let allFiles = [];
        for (const p of paths) {
            try {
                if (fs.statSync(p).isDirectory()) allFiles = allFiles.concat(getAllFiles(p));
                else allFiles.push(p);
            } catch (_) { }
        }

        const total = allFiles.length;
        const results = [];

        for (let i = 0; i < total; i++) {
            const filePath = allFiles[i];
            const fileName = path.basename(filePath);
            const fileType = getFileType(filePath);
            let fileSize;
            try { fileSize = formatBytes(fs.statSync(filePath).size); } catch (_) { fileSize = '?'; }

            let status, reason, categories, score, scanLayers;

            if (isWhitelisted(filePath)) {
                status = 'clean'; reason = 'Whitelisted file type'; categories = []; score = 0;
                scanLayers = ['Whitelist Check (skipped deep scan)'];
            } else {
                const heuristic = scanFileHeuristic(filePath);
                const sha256 = computeSHA256(filePath);
                const entropy = computeEntropy(filePath);
                const exeAnalysis = analyzeExecutable(filePath);

                let clamResult = { scanned: false };
                if (clamAvailable) {
                    clamResult = await clamScanFile(filePath);
                }

                const cl = classifyThreat(heuristic, entropy, exeAnalysis, clamResult);
                status = cl.status; reason = cl.reason; categories = cl.categories;
                score = cl.score; scanLayers = cl.scanLayers;
            }

            const fileResult = { filePath, fileName, fileType, fileSize, status, reason, categories, score, scanLayers };
            results.push(fileResult);

            event.sender.send('scan-file-result', {
                ...fileResult,
                progress: Math.round(((i + 1) / total) * 100),
                current: i + 1, total
            });

            await new Promise(r => setTimeout(r, 60));
        }

        const summary = {
            total: results.length,
            clean: results.filter(r => r.status === 'clean').length,
            suspicious: results.filter(r => r.status === 'suspicious').length,
            malicious: results.filter(r => r.status === 'malicious').length,
            skipped: results.filter(r => r.status === 'skipped').length,
        };

        addScanRecord({
            id: Date.now(), timestamp: new Date().toISOString(), summary,
            engineLayers: clamAvailable ? 5 : 4,
            files: results.map(r => ({ fileName: r.fileName, status: r.status, reason: r.reason, score: r.score }))
        });

        event.sender.send('scan-complete', summary);
        return { results, summary };
    } catch (err) { console.error("Scan error:", err); throw err; }
});

// ── QUARANTINE ──
ipcMain.handle('quarantine-files', async (event, entries) => {
    const results = [];
    for (const e of entries) {
        const r = quarantineFile(e.filePath, e.reason || 'Malicious', e.categories || []);
        results.push({ filePath: e.filePath, fileName: path.basename(e.filePath), ...r });
    }
    return results;
});

// ── KILL ──
ipcMain.handle('kill-files', async (event, filePaths) => {
    const results = [];
    for (const fp of filePaths) { results.push({ filePath: fp, fileName: path.basename(fp), ...killFile(fp) }); }
    return results;
});

// ── QUARANTINE LIST ──
ipcMain.handle('get-quarantine-list', async () => {
    ensureQuarantineDir();
    const items = [];
    try {
        const files = fs.readdirSync(QUARANTINE_DIR);
        for (const file of files) {
            if (file.endsWith('.metadata')) continue;
            const fp = path.join(QUARANTINE_DIR, file);
            const mp = fp + '.metadata';
            let meta = {};
            if (fs.existsSync(mp)) {
                try { meta = JSON.parse(fs.readFileSync(mp, 'utf8')); } catch (_) {
                    const raw = fs.readFileSync(mp, 'utf8');
                    for (const line of raw.split('\n')) {
                        const idx = line.indexOf(': ');
                        if (idx > -1) { const k = line.substring(0, idx).trim().replace(/ /g, '_').toLowerCase(); meta[k] = line.substring(idx + 2).trim(); }
                    }
                }
            }
            const cats = meta.categories || [];
            const tips = [];
            for (const c of cats) { if (THREAT_TIPS[c]) tips.push(THREAT_TIPS[c]); }
            items.push({
                quarantineName: file, originalPath: meta.originalPath || meta.original_path || 'Unknown',
                quarantineTime: meta.quarantineTime || meta.quarantine_time || 'Unknown',
                reason: meta.reason || 'Unknown', fileSize: meta.fileSize || meta.file_size || 'Unknown',
                fileName: meta.fileName || file, categories: cats, threatTips: tips
            });
        }
    } catch (_) { }
    return items;
});

// ── DELETE FROM QUARANTINE ──
ipcMain.handle('delete-quarantine-item', async (event, qName) => {
    try {
        const fp = path.join(QUARANTINE_DIR, qName);
        try { fs.chmodSync(fp, 0o666); } catch (_) { }
        if (fs.existsSync(fp)) fs.unlinkSync(fp);
        if (fs.existsSync(fp + '.metadata')) fs.unlinkSync(fp + '.metadata');
        logAction(`DELETED FROM QUARANTINE: ${qName}`);
        return { success: true };
    } catch (e) { return { success: false, error: e.message }; }
});

// ── RESTORE FROM QUARANTINE ──
ipcMain.handle('restore-quarantine-item', async (event, qName) => {
    try {
        const fp = path.join(QUARANTINE_DIR, qName);
        const mp = fp + '.metadata';
        let meta = {};
        if (fs.existsSync(mp)) { try { meta = JSON.parse(fs.readFileSync(mp, 'utf8')); } catch (_) { } }
        const dest = meta.originalPath;
        if (!dest) return { success: false, error: 'Original path unknown' };

        try { fs.chmodSync(fp, 0o666); } catch (_) { }
        fs.copyFileSync(fp, dest);
        fs.unlinkSync(fp);
        if (fs.existsSync(mp)) fs.unlinkSync(mp);
        logAction(`RESTORED: ${qName} -> ${dest}`);
        return { success: true, restoredTo: dest };
    } catch (e) { return { success: false, error: e.message }; }
});

// ── PID SCREAMER ──
ipcMain.handle('run-pid-screamer', async (event, threshold) => {
    return await runPidScreamerSync(threshold);
});

// -- KILLER PID --
ipcMain.handle('kill-pid-screamer-process', async (event, pid) => {
    return await killPidCrossPlatform(pid);
});

// ── VIRUSTOTAL ──
ipcMain.handle('run-vt-scan', async (event, filePath, apiKey) => {
    return await vtScanFile(filePath, apiKey);
});

// ── SCAN HISTORY ──
ipcMain.handle('get-scan-history', async () => loadScanHistory());
ipcMain.handle('clear-scan-history', async () => { saveScanHistory([]); return { success: true }; });
