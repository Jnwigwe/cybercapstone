#include "simple_pid_screamer.h"


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
