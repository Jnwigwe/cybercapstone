#include "simple_pid_screamer.h"

#include <dirent.h>
#include <sys/stat.h>
#include <iostream>
#include <string>

// Global-ish counters for one scan run
static long long DIR_COUNTER  = 0;
static long long FILE_COUNTER = 0;

void resetScanStats() {
    DIR_COUNTER  = 0;
    FILE_COUNTER = 0;
}

long long getDirCount() {
    return DIR_COUNTER;
}

long long getFileCount() {
    return FILE_COUNTER;
}

// Recursive scanner
void scanFilesystemRec(const std::string &rootDir,
                       std::vector<std::string> &suspiciousFiles,
                       int depth,
                       int maxDepth)
{
    if (depth > maxDepth) return;
    if (shouldSkipDir(rootDir)) return;

    std::cout << "[DIR] #" << ++DIR_COUNTER
              << " Entering: " << rootDir << "\n";

    DIR *dir = opendir(rootDir.c_str());
    if (!dir) return;

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
            std::cout << "[SCAN] #" << ++FILE_COUNTER
                      << " " << fullPath << "\n";

            if (isSuspiciousPath(fullPath)) {
                suspiciousFiles.push_back(fullPath);
            }
        }
    }

    closedir(dir);
}
