#include "simple_pid_screamer.h"

#include <algorithm>
#include <limits.h>
#include <unistd.h>
#include <cctype>


bool isUnderPrefix(const std::string &path, const std::string &prefix) {
    if (path == prefix) {
        return true;
    }
    if (path.size() >= prefix.size() &&
        path.compare(0, prefix.size(), prefix) == 0) {
        return true;
    }
    return false;
}


bool isSystemPath(const std::string &path) {
    for (const auto &prefix : SYSTEM_DIR_PREFIXES) {
        if (isUnderPrefix(path, prefix)) {
            return true;
        }
    }
    return false;
}


bool isNumericPidDir(const std::string &name) {
    if (name.empty()) {
        return false;
    }
    for (char c : name) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}


std::string getExePathForPid(pid_t pid) {
    char buffer[PATH_MAX];
    std::string linkPath = "/proc/" + std::to_string(pid) + "/exe";

    ssize_t len = readlink(linkPath.c_str(), buffer, sizeof(buffer) - 1);
    if (len == -1) {
        return "";
    }

    buffer[len] = '\0';
    return std::string(buffer);
}


bool isSuspiciousPath(const std::string &path) {
    if (path.empty()) {
        return false;
    }

    if (isSystemPath(path)) {
        return false;
    }

    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (lower.find("/tmp/") != std::string::npos) {
        return true;
    }
    if (lower.find("/dev/shm/") != std::string::npos) {
        return true;
    }
    if (lower.find("rk_") != std::string::npos) {
        return true;
    }
    if (lower.find("rootkit") != std::string::npos) {
        return true;
    }
    if (lower.find(".hidden") != std::string::npos) {
        return true;
    }

    return false;
}


bool shouldSkipDir(const std::string &path) {
    if (path == "/proc" || path.rfind("/proc/", 0) == 0) return true;
    if (path == "/sys"  || path.rfind("/sys/", 0)  == 0) return true;
    if (path == "/dev"  || path.rfind("/dev/", 0)  == 0) return true;
    if (path == "/run"  || path.rfind("/run/", 0)  == 0) return true;
    return false;
}
