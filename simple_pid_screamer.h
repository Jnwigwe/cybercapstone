#pragma once

#include <string>
#include <vector>
#include <map>

#ifdef _WIN32
#include <windows.h>
using proc_id_t = DWORD;
#else
#include <sys/types.h>
using proc_id_t = pid_t;
#endif

struct SuspiciousRecord {
    proc_id_t pid;
    std::string filePath;
    double cpuPercent;
    std::string flagLabel;
    bool pathFlag;
    bool falsePositive;
    std::string falsePositiveReason;
};

extern const std::vector<std::string> USER_SCAN_ROOTS;
extern const std::vector<std::string> SYSTEM_DIR_PREFIXES;

bool isUnderPrefix(const std::string &path, const std::string &prefix);
bool isSystemPath(const std::string &path);
bool isNumericPidDir(const std::string &name);
std::string getExePathForPid(proc_id_t pid);
bool isSuspiciousPath(const std::string &path);
bool shouldSkipDir(const std::string &path);

void scanFilesystemRec(const std::string &rootDir,
                       std::vector<std::string> &suspiciousFiles,
                       int depth = 0,
                       int maxDepth = 25);

void resetScanStats();
long long getDirCount();
long long getFileCount();

std::map<std::string, std::vector<proc_id_t>> buildExeToPidMap();

std::vector<SuspiciousRecord> runPidScreamerScan(double cpuThreshold,
                                                 int sampleMs,
                                                 const std::vector<std::string> &roots);

void writePidScreamerReport(const std::vector<SuspiciousRecord> &records,
                            double cpuThreshold,
                            int sampleMs,
                            const std::string &reportPath = "suspicious_report.txt");
