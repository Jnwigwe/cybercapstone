#include "simple_pid_screamer.h"

#include <iostream>
#include <fstream>
#include <algorithm>
#include <set>
#include <map>
#include <sstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <cctype>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <dirent.h>
#endif

static double CPU_THRESHOLD_PERCENT = 10.0;
static int CPU_SAMPLE_MS = 1000;

#ifdef _WIN32
const std::vector<std::string> USER_SCAN_ROOTS = {
    "."
};

const std::vector<std::string> SYSTEM_DIR_PREFIXES = {
    "c:/windows/system32/",
    "c:/windows/syswow64/",
    "c:/program files/",
    "c:/program files (x86)/"
};
#else
const std::vector<std::string> USER_SCAN_ROOTS = {
    "/home",
    "/opt",
    "/usr/local"
};

const std::vector<std::string> SYSTEM_DIR_PREFIXES = {
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/share/",
    "/var/lib/apt/",
    "/var/cache/apt/"
};
#endif

static long long DIR_COUNTER = 0;
static long long FILE_COUNTER = 0;

void resetScanStats() { DIR_COUNTER = 0; FILE_COUNTER = 0; }
long long getDirCount() { return DIR_COUNTER; }
long long getFileCount() { return FILE_COUNTER; }

static std::string toLowerCopy(std::string s) {
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static std::string normalizePathCopy(std::string s) {
    std::replace(s.begin(), s.end(), '\\', '/');
    return toLowerCopy(s);
}

bool isUnderPrefix(const std::string &path, const std::string &prefix) {
    std::string p = normalizePathCopy(path);
    std::string fx = normalizePathCopy(prefix);
    if (p == fx) return true;
    return p.size() >= fx.size() && p.compare(0, fx.size(), fx) == 0;
}

bool isSystemPath(const std::string &path) {
    for (const auto &prefix : SYSTEM_DIR_PREFIXES) {
        if (isUnderPrefix(path, prefix)) return true;
    }
    return false;
}

bool isNumericPidDir(const std::string &name) {
    if (name.empty()) return false;
    for (char c : name) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

static bool containsAnyToken(const std::string &text, const std::vector<std::string> &tokens) {
    for (const auto &tok : tokens) {
        if (!tok.empty() && text.find(tok) != std::string::npos) return true;
    }
    return false;
}

static bool containsSuspiciousKeywordsInternal(const std::string &path) {
    std::string p = normalizePathCopy(path);
    const char* keys[] = {
        "rootkit", "keylogger", "backdoor", "hidden", "trojan", "malware",
        "stealer", "rat", "payload", "implant", "rk_", "hook", "inject",
        "dropper", "loader", "bot", "botnet", "miner", "coinminer", "xmrig",
        "cryptominer", "clipper", "grabber", "infostealer", "passwordstealer",
        "credential", "cred", "cookie", "session", "token", "wallet", "exfil",
        "exfiltration", "skimmer", "spy", "spyware", "ransom", "ransomware",
        "locker", "worm", "wiper", "destroyer", "persistence", "autorun",
        "startup", "service", "daemon", "task", "scheduledtask", "schtask",
        "uacbypass", "bypass", "evasion", "obfusc", "packed", "packer",
        "shellcode", "reflective", "dllinject", "processinject", "hollow",
        "hollowing", "hijack", "hooker", "beacon", "c2", "cnc", "commandandcontrol",
        "reverse", "revshell", "shell", "bindshell", "meterpreter", "mimikatz",
        "lsass", "samdump", "dumper", "dump", "scrape", "scanner", "bruteforce",
        "brute", "phish", "phishing", "spoof", "exploit", "kit", "stager",
        "stage1", "stage2", "agent", "implantcore", "webshell", "netshell",
        "cmdrun", "psrun", "pwsh", "powersploit", "empire", "covenant",
        "sliver", "quasar", "njrat", "remcos", "darkcomet", "asyncrat",
        "redline", "vidar", "raccoon", "lokibot", "azorult", "emotet",
        "trickbot", "qakbot", "dridex", "formbook", "agenttesla", "nanocore",
        "mal_", "troj_", "bkdr_", "steal_", "miner_", "bot_", "rat_", "grab_"
    };

    for (const char* k : keys) {
        if (p.find(k) != std::string::npos) return true;
    }
    return false;
}

bool isSuspiciousPath(const std::string &path) {
    if (path.empty()) return false;
    if (isSystemPath(path)) return false;

    std::string p = normalizePathCopy(path);

#ifdef _WIN32
    if (p.find("/appdata/local/temp/") != std::string::npos) return true;
    if (p.find("/temp/") != std::string::npos) return true;
    if (p.find("/tmp/") != std::string::npos) return true;
    if (p.find("/programdata/temp/") != std::string::npos) return true;
    if (p.find("/appdata/roaming/") != std::string::npos) return true;
    if (p.find("/users/public/") != std::string::npos) return true;
    if (p.find("/windows/tasks/") != std::string::npos) return true;
    if (p.find("/windows/temp/") != std::string::npos) return true;
    if (p.find("/recycle.bin/") != std::string::npos) return true;
    if (p.find("/startup/") != std::string::npos) return true;
    if (p.find("/autorun/") != std::string::npos) return true;
#else
    if (p.find("/tmp/") != std::string::npos) return true;
    if (p.find("/var/tmp/") != std::string::npos) return true;
    if (p.find("/run/") != std::string::npos) return true;
    if (p.find("/dev/shm/") != std::string::npos) return true;
    if (p.find("/.cache/") != std::string::npos) return true;
    if (p.find("/.local/share/") != std::string::npos) return true;
    if (p.find("/.config/autostart/") != std::string::npos) return true;
    if (p.find("/etc/cron") != std::string::npos) return true;
    if (p.find("/systemd/system/") != std::string::npos) return true;
    if (p.find("/init.d/") != std::string::npos) return true;
#endif

    if (p.find("rk_") != std::string::npos) return true;
    if (p.find("rootkit") != std::string::npos) return true;
    if (p.find(".hidden") != std::string::npos) return true;
    if (p.find("keylogger") != std::string::npos) return true;
    if (p.find("backdoor") != std::string::npos) return true;
    if (p.find("payload") != std::string::npos) return true;
    if (p.find("stealer") != std::string::npos) return true;
    if (p.find("rat") != std::string::npos) return true;

    return false;
}

bool shouldSkipDir(const std::string &path) {
#ifdef _WIN32
    (void)path;
    return false;
#else
    if (path == "/proc" || path.rfind("/proc/", 0) == 0) return true;
    if (path == "/sys"  || path.rfind("/sys/", 0)  == 0) return true;
    if (path == "/dev"  || path.rfind("/dev/", 0)  == 0) return true;
    if (path == "/run"  || path.rfind("/run/", 0)  == 0) return true;
    return false;
#endif
}

static bool isLikelyFalsePositivePath(const std::string &path, std::string &reasonOut) {
    std::string p = normalizePathCopy(path);

#ifdef _WIN32
    const std::vector<std::string> legitPrefixes = {
        "c:/windows/system32/",
        "c:/windows/syswow64/",
        "c:/program files/",
        "c:/program files (x86)/"
    };
#else
    const std::vector<std::string> legitPrefixes = {
        "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/lib/", "/lib64/",
        "/snap/", "/opt/google/", "/opt/microsoft/", "/opt/brave/", "/opt/firefox/"
    };
#endif

    const std::vector<std::string> legitNames = {
    "bash", "sh", "dash", "zsh", "fish",
    "systemd", "dbus", "networkmanager", "gnome-shell",
    "code", "code-insiders", "chrome", "chromium", "firefox",
    "python", "python3", "node", "npm", "java", "javac",
    "gcc", "g++", "clang", "make", "cmake",

    "powershell", "pwsh", "explorer", "svchost", "taskhostw", "conhost", "cmd",
    "powershell.exe", "pwsh.exe", "explorer.exe", "svchost.exe", "taskhostw.exe",
    "conhost.exe", "cmd.exe", "python.exe", "node.exe", "chrome.exe", "firefox.exe",

    "taskmgr.exe",
    "electron.exe",
    "steamwebhelper.exe",
    "discord.exe"
};

    std::string name = p.substr(p.find_last_of('/') + 1);

    for (const auto &prefix : legitPrefixes) {
        if (p.rfind(prefix, 0) == 0 && containsAnyToken(name, legitNames)) {
            reasonOut = "System or developer tool path matched a known legitimate binary";
            return true;
        }
    }

    if (p.rfind("c:/programdata/", 0) == 0 && containsAnyToken(name, legitNames)) {
    reasonOut = "Known legitimate app installed under ProgramData";
    return true;
}

    if (containsAnyToken(name, legitNames)) {
        reasonOut = "Known legitimate process name";
        return true;
    }

    return false;
}

#ifdef _WIN32

static unsigned long long fileTimeToULL(const FILETIME &ft) {
    ULARGE_INTEGER ui;
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    return ui.QuadPart;
}

static bool readSystemCpuTicks(unsigned long long &totalTicksOut) {
    FILETIME idleFt{}, kernelFt{}, userFt{};
    if (!GetSystemTimes(&idleFt, &kernelFt, &userFt)) return false;

    unsigned long long kernel = fileTimeToULL(kernelFt);
    unsigned long long user   = fileTimeToULL(userFt);

    totalTicksOut = kernel + user;
    return true;
}

static bool readProcCpuTicks(proc_id_t pid, unsigned long long &procTicksOut) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;

    FILETIME createFt{}, exitFt{}, kernelFt{}, userFt{};
    BOOL ok = GetProcessTimes(h, &createFt, &exitFt, &kernelFt, &userFt);
    CloseHandle(h);

    if (!ok) return false;

    procTicksOut = fileTimeToULL(kernelFt) + fileTimeToULL(userFt);
    return true;
}

static std::string getWindowsProcessPath(proc_id_t pid, const std::string &fallbackName = "") {
    char buffer[MAX_PATH * 4] = {0};

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        DWORD size = static_cast<DWORD>(sizeof(buffer));
        if (QueryFullProcessImageNameA(h, 0, buffer, &size)) {
            CloseHandle(h);
            return std::string(buffer, size);
        }
        CloseHandle(h);
    }

    return fallbackName;
}

std::string getExePathForPid(proc_id_t pid) {
    return getWindowsProcessPath(pid, "");
}

std::map<std::string, std::vector<proc_id_t>> buildExeToPidMap() {
    std::map<std::string, std::vector<proc_id_t>> exeToPid;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return exeToPid;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe)) {
        do {
            proc_id_t pid = pe.th32ProcessID;
            std::string exePath = getWindowsProcessPath(pid, pe.szExeFile);
            if (!exePath.empty()) {
                exeToPid[exePath].push_back(pid);
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return exeToPid;
}

static std::unordered_map<proc_id_t, double> computeCpuPercentTopLikeSharedWindow(
    const std::map<std::string, std::vector<proc_id_t>> &exeToPid,
    int windowMs
) {
    std::unordered_map<proc_id_t, double> out;

    unsigned long long total1 = 0, total2 = 0;
    if (!readSystemCpuTicks(total1)) return out;

    std::unordered_map<proc_id_t, unsigned long long> proc1;
    proc1.reserve(4096);

    for (const auto &kv : exeToPid) {
        for (proc_id_t pid : kv.second) {
            if (proc1.find(pid) != proc1.end()) continue;
            unsigned long long ticks = 0;
            if (readProcCpuTicks(pid, ticks)) proc1[pid] = ticks;
        }
    }

    Sleep(static_cast<DWORD>(windowMs));

    if (!readSystemCpuTicks(total2)) return out;
    if (total2 <= total1) return out;

    unsigned long long dTotal = total2 - total1;
    out.reserve(proc1.size());

    for (const auto &it : proc1) {
        proc_id_t pid = it.first;
        unsigned long long p1 = it.second;

        unsigned long long p2 = 0;
        if (!readProcCpuTicks(pid, p2)) continue;
        if (p2 < p1) continue;

        unsigned long long dProc = p2 - p1;

        double cpuPct =
    (static_cast<double>(dProc) / static_cast<double>(dTotal)) *
    100.0;

        if (cpuPct < 0.0) cpuPct = 0.0;
        out[pid] = cpuPct;
    }

    return out;
}

void scanFilesystemRec(const std::string &rootDir,
                       std::vector<std::string> &suspiciousFiles,
                       int depth,
                       int maxDepth)
{
    (void)rootDir;
    (void)suspiciousFiles;
    (void)depth;
    (void)maxDepth;
}

#else

static bool readTotalCpuTicks(unsigned long long &totalTicksOut) {
    std::ifstream f("/proc/stat");
    if (!f.is_open()) return false;

    std::string line;
    if (!std::getline(f, line)) return false;

    std::istringstream iss(line);
    std::string cpuLabel;
    iss >> cpuLabel;
    if (cpuLabel != "cpu") return false;

    unsigned long long v = 0;
    unsigned long long sum = 0;
    while (iss >> v) sum += v;

    totalTicksOut = sum;
    return true;
}

static bool readProcCpuTicks(proc_id_t pid, unsigned long long &procTicksOut) {
    std::string statPath = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream sf(statPath);
    if (!sf.is_open()) return false;

    std::string line;
    std::getline(sf, line);
    if (line.empty()) return false;

    size_t rparen = line.rfind(')');
    if (rparen == std::string::npos) return false;

    std::string after = line.substr(rparen + 2);
    std::istringstream iss(after);

    std::vector<std::string> tok;
    std::string t;
    while (iss >> t) tok.push_back(t);

    if (tok.size() < 13) return false;

    try {
        unsigned long long utimeTicks = std::stoull(tok[11]);
        unsigned long long stimeTicks = std::stoull(tok[12]);
        procTicksOut = utimeTicks + stimeTicks;
        return true;
    } catch (...) {
        return false;
    }
}

static std::unordered_map<proc_id_t, double> computeCpuPercentTopLikeSharedWindow(
    const std::map<std::string, std::vector<proc_id_t>> &exeToPid,
    int windowMs
) {
    std::unordered_map<proc_id_t, double> out;

    unsigned long long total1 = 0, total2 = 0;
    if (!readTotalCpuTicks(total1)) return out;

    std::unordered_map<proc_id_t, unsigned long long> proc1;
    proc1.reserve(4096);

    for (const auto &kv : exeToPid) {
        for (proc_id_t pid : kv.second) {
            if (proc1.find(pid) != proc1.end()) continue;
            unsigned long long ticks = 0;
            if (readProcCpuTicks(pid, ticks)) proc1[pid] = ticks;
        }
    }

    struct timespec ts{};
    ts.tv_sec  = windowMs / 1000;
    ts.tv_nsec = (windowMs % 1000) * 1000000L;
    nanosleep(&ts, nullptr);

    if (!readTotalCpuTicks(total2)) return out;
    if (total2 <= total1) return out;

    unsigned long long dTotal = total2 - total1;

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0) ncpu = 1;

    out.reserve(proc1.size());

    for (const auto &it : proc1) {
        proc_id_t pid = it.first;
        unsigned long long p1 = it.second;

        unsigned long long p2 = 0;
        if (!readProcCpuTicks(pid, p2)) continue;
        if (p2 < p1) continue;

        unsigned long long dProc = p2 - p1;

        double cpuPct = (double)dProc / (double)dTotal * 100.0 * (double)ncpu;
        if (cpuPct < 0.0) cpuPct = 0.0;
        out[pid] = cpuPct;
    }

    return out;
}

std::string getExePathForPid(proc_id_t pid) {
    char buffer[PATH_MAX];
    std::string linkPath = "/proc/" + std::to_string(pid) + "/exe";

    ssize_t len = readlink(linkPath.c_str(), buffer, sizeof(buffer) - 1);
    if (len == -1) return "";

    buffer[len] = '\0';
    return std::string(buffer);
}

std::map<std::string, std::vector<proc_id_t>> buildExeToPidMap() {
    std::map<std::string, std::vector<proc_id_t>> exeToPid;

    DIR *procDir = opendir("/proc");
    if (!procDir) return exeToPid;

    struct dirent *entry;
    while ((entry = readdir(procDir)) != nullptr) {
        std::string name = entry->d_name;
        if (!isNumericPidDir(name)) continue;

        proc_id_t pid = static_cast<proc_id_t>(std::stoi(name));
        std::string exePath = getExePathForPid(pid);
        if (exePath.empty()) continue;

        exeToPid[exePath].push_back(pid);
    }

    closedir(procDir);
    return exeToPid;
}

void scanFilesystemRec(const std::string &rootDir,
                       std::vector<std::string> &suspiciousFiles,
                       int depth,
                       int maxDepth)
{
    if (depth > maxDepth) return;
    if (shouldSkipDir(rootDir)) return;

    DIR *dir = opendir(rootDir.c_str());
    if (!dir) return;

    ++DIR_COUNTER;

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;

        std::string fullPath = rootDir;
        if (!fullPath.empty() && fullPath.back() != '/') fullPath += "/";
        fullPath += name;

        struct stat st{};
        if (stat(fullPath.c_str(), &st) == -1) continue;

        if (S_ISDIR(st.st_mode)) {
            scanFilesystemRec(fullPath, suspiciousFiles, depth + 1, maxDepth);
        } else {
            ++FILE_COUNTER;
            if (isSuspiciousPath(fullPath)) suspiciousFiles.push_back(fullPath);
        }
    }

    closedir(dir);
}

#endif

static std::vector<std::string> normalizeRoots(const std::vector<std::string> &rootsRaw) {
    std::vector<std::string> roots;
    roots.reserve(rootsRaw.size());

#ifdef _WIN32
    char cwdBuf[MAX_PATH];
    std::string cwd = GetCurrentDirectoryA(MAX_PATH, cwdBuf) ? std::string(cwdBuf) : "c:/";
#else
    char cwdBuf[PATH_MAX];
    std::string cwd = (::getcwd(cwdBuf, sizeof(cwdBuf)) != nullptr) ? std::string(cwdBuf) : "/";
#endif

    for (const auto &r : rootsRaw) {
        if (r.empty()) continue;

        std::string abs = r;
#ifdef _WIN32
        if (!(r.size() > 1 && r[1] == ':') && !(r.size() > 1 && r[0] == '\\' && r[1] == '\\')) {
            abs = cwd;
            if (!abs.empty() && abs.back() != '/' && abs.back() != '\\') abs += "/";
            abs += r;
        }
#else
        if (r[0] != '/') {
            abs = cwd;
            if (!abs.empty() && abs.back() != '/') abs += "/";
            abs += r;
        }
#endif
        roots.push_back(normalizePathCopy(abs));
    }

    return roots;
}

static bool isUnderAnyRoot(const std::string &path, const std::vector<std::string> &rootsAbs) {
    if (rootsAbs.empty()) return true;
    std::string p = normalizePathCopy(path);

    for (const auto &root : rootsAbs) {
        if (root == "/" || root == "c:/") return true;
        if (p.size() >= root.size() && p.compare(0, root.size(), root) == 0) return true;
    }
    return false;
}

std::vector<SuspiciousRecord> runPidScreamerScan(double cpuThreshold,
                                                 int sampleMs,
                                                 const std::vector<std::string> &rootsInput)
{
    std::vector<std::string> rootsRaw = rootsInput.empty() ? USER_SCAN_ROOTS : rootsInput;
    std::vector<std::string> rootsAbs = normalizeRoots(rootsRaw);

    std::map<std::string, std::vector<proc_id_t>> exeToPid = buildExeToPidMap();
    std::unordered_map<proc_id_t, double> cpuPctMap =
        computeCpuPercentTopLikeSharedWindow(exeToPid, sampleMs);

#ifndef _WIN32
    std::vector<std::string> suspiciousFilesFromFs;
    resetScanStats();
    for (const auto &root : rootsAbs) {
        struct stat st{};
        if (stat(root.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            scanFilesystemRec(root, suspiciousFilesFromFs, 0, 25);
        }
    }
#else
    resetScanStats();
#endif

    std::vector<SuspiciousRecord> suspiciousRecords;
    std::set<std::pair<proc_id_t, std::string>> seen;

    auto addRecord = [&](proc_id_t pid, const std::string &path) {
        auto key = std::make_pair(pid, path);
        if (!seen.insert(key).second) return;

        SuspiciousRecord rec{};
        rec.pid = pid;
        rec.filePath = path;
        rec.cpuPercent = -1.0;
        rec.flagLabel = "SUS";
        rec.pathFlag = isSuspiciousPath(path) || containsSuspiciousKeywordsInternal(path);
        rec.falsePositive = false;
        rec.falsePositiveReason.clear();

        std::string fpReason;
        if (isLikelyFalsePositivePath(path, fpReason)) {
            rec.falsePositive = true;
            rec.falsePositiveReason = fpReason;
            rec.flagLabel = "FP";
        }

        auto it = cpuPctMap.find(pid);
        if (it != cpuPctMap.end()) {
            rec.cpuPercent = it->second;
        }

        if (rec.cpuPercent >= 0.0 && rec.cpuPercent >= cpuThreshold) {
            suspiciousRecords.push_back(rec);
        }
    };

#ifndef _WIN32
    std::vector<std::string> suspiciousFilesFromFs;
    for (const auto &root : rootsAbs) {
        struct stat st{};
        if (stat(root.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            scanFilesystemRec(root, suspiciousFilesFromFs, 0, 25);
        }
    }

    for (const std::string &filePath : suspiciousFilesFromFs) {
        auto it = exeToPid.find(filePath);
        if (it == exeToPid.end()) continue;
        for (proc_id_t pid : it->second) addRecord(pid, filePath);
    }
#endif

    for (const auto &kv : exeToPid) {
        const std::string &exePath = kv.first;
        const std::vector<proc_id_t> &pids = kv.second;

#ifndef _WIN32
        if (!isUnderAnyRoot(exePath, rootsAbs)) continue;
#endif

        for (proc_id_t pid : pids) addRecord(pid, exePath);
    }

    std::sort(suspiciousRecords.begin(), suspiciousRecords.end(),
              [](const SuspiciousRecord &a, const SuspiciousRecord &b) {
                  if (a.cpuPercent == b.cpuPercent) return a.pid > b.pid;
                  return a.cpuPercent > b.cpuPercent;
              });

    return suspiciousRecords;
}

void writePidScreamerReport(const std::vector<SuspiciousRecord> &records,
                            double cpuThreshold,
                            int sampleMs,
                            const std::string &reportPath)
{
    std::ofstream report(reportPath);
    if (!report.is_open()) return;

    report << "# Suspicious process report (cross-platform)\n";
    report << "# CPU threshold enforced: " << cpuThreshold << "%\n";
    report << "# CPU sample window (ms): " << sampleMs << "\n";
    report << "# PID\tExecutable Path\tCPU%\tFLAG\tPATH_FLAG\tFALSE_POSITIVE\tFALSE_POSITIVE_REASON\n";

    if (records.empty()) {
        report << "No processes met the CPU threshold (" << cpuThreshold << "%).\n";
        return;
    }

    for (const auto &rec : records) {
        report << rec.pid << "\t"
               << rec.filePath << "\t"
               << rec.cpuPercent << "%\t"
               << rec.flagLabel << "\t"
               << (rec.pathFlag ? "suspicious" : "normal") << "\t"
               << (rec.falsePositive ? "true" : "false") << "\t"
               << rec.falsePositiveReason << "\n";
    }
}

static void printUsage(const char* prog) {
    std::cout
        << "Usage:\n"
        << "  " << prog << " [--threshold N] [--window-ms N] [roots...]\n\n"
        << "Examples:\n"
        << "  " << prog << " --threshold 25 --window-ms 1000\n"
        << "  " << prog << " --threshold 5 .\n\n";
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
    std::cout << "=== Simple Windows/Linux PID Screamer (Cross-Platform) ===\n";
#else
    std::cout << "=== Simple Windows/Linux PID Screamer (Cross-Platform) ===\n";
#endif

    std::vector<std::string> rootsRaw;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        if (a == "--help" || a == "-h") {
            printUsage(argv[0]);
            return 0;
        }

        if (a == "--threshold" || a == "--cpu-threshold") {
            if (i + 1 >= argc) {
                std::cerr << "[ERROR] Missing value after " << a << "\n";
                return 1;
            }
            try {
                CPU_THRESHOLD_PERCENT = std::stod(argv[++i]);
            } catch (...) {
                std::cerr << "[ERROR] Invalid threshold value: " << argv[i] << "\n";
                return 1;
            }
            if (CPU_THRESHOLD_PERCENT < 0.0) CPU_THRESHOLD_PERCENT = 0.0;
            continue;
        }

        if (a == "--window-ms" || a == "--sample-ms") {
            if (i + 1 >= argc) {
                std::cerr << "[ERROR] Missing value after " << a << "\n";
                return 1;
            }
            try {
                CPU_SAMPLE_MS = std::stoi(argv[++i]);
            } catch (...) {
                std::cerr << "[ERROR] Invalid window-ms value: " << argv[i] << "\n";
                return 1;
            }
            if (CPU_SAMPLE_MS < 100) CPU_SAMPLE_MS = 100;
            if (CPU_SAMPLE_MS > 5000) CPU_SAMPLE_MS = 5000;
            continue;
        }

        rootsRaw.emplace_back(a);
    }

    std::vector<SuspiciousRecord> suspiciousRecords =
        runPidScreamerScan(CPU_THRESHOLD_PERCENT, CPU_SAMPLE_MS, rootsRaw);

    writePidScreamerReport(suspiciousRecords, CPU_THRESHOLD_PERCENT, CPU_SAMPLE_MS);

    std::cout << "\n=== Suspicious process scan results ===\n";
    std::cout << "(CPU threshold enforced: " << CPU_THRESHOLD_PERCENT
              << "% | sample: " << CPU_SAMPLE_MS << "ms)\n";

    if (suspiciousRecords.empty()) {
        std::cout << "No processes met the CPU threshold (" << CPU_THRESHOLD_PERCENT << "%).\n";
    } else {
        for (const auto &rec : suspiciousRecords) {
            std::cout << "[" << rec.flagLabel << "] PID: " << rec.pid
                      << " | EXE: " << rec.filePath
                      << " | CPU: " << rec.cpuPercent << "%"
                      << " | PATH_FLAG: " << (rec.pathFlag ? "suspicious" : "normal");
            if (rec.falsePositive) {
                std::cout << " | FALSE_POSITIVE: true"
                          << " | FP_REASON: " << rec.falsePositiveReason;
            }
            std::cout << "\n";
        }
    }

    std::cout << "\nScan complete. Report saved to suspicious_report.txt\n";
    return 0;
}
