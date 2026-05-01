#pragma once
#include <string>
#include <vector>
#include <chrono>
#include "Threat.h"

struct ScanRecord {
    std::chrono::system_clock::time_point timestamp;
    std::string scanType;          
    int filesChecked = 0;
    std::vector<Threat> threats;   
    std::string overallAction;     
};
