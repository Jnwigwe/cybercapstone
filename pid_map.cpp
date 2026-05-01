#include "simple_pid_screamer.h"

#include <dirent.h>
#include <iostream>


std::map<std::string, std::vector<pid_t>> buildExeToPidMap() {
    std::map<std::string, std::vector<pid_t>> exeToPid;

    DIR *procDir = opendir("/proc");
    if (!procDir) {
        std::cerr << "[!] Failed to open /proc. Are we on Linux?\n";
        return exeToPid;
    }

    struct dirent *entry;
    while ((entry = readdir(procDir)) != nullptr) {
        std::string name = entry->d_name;

        if (!isNumericPidDir(name)) {
            continue;
        }

        pid_t pid = static_cast<pid_t>(std::stoi(name));
        std::string exePath = getExePathForPid(pid);
        if (exePath.empty()) {
            continue;
        }

        exeToPid[exePath].push_back(pid);
    }

    closedir(procDir);
    return exeToPid;
}
