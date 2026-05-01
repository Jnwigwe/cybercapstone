#include "ScanHistoryManager.h"
#include <chrono>
#include <algorithm>
#include <cctype>

void ScanHistoryManager::addRecord(const ScanRecord &record) {
    records.push_back(record);
    purgeOldRecords();
}

std::vector<ScanRecord> ScanHistoryManager::getAllVisible() const {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto cutoff = now - hours(24 * 90);

    std::vector<ScanRecord> result;
    for (const auto &r : records) {
        if (r.timestamp >= cutoff) {
            result.push_back(r);
        }
    }
    return result;
}

std::vector<ScanRecord> ScanHistoryManager::search(
    const std::string &queryText,
    const std::string &scanTypeFilter,
    bool onlyWithThreats) const
{
    std::string q = toLower(queryText);
    auto all = getAllVisible();
    std::vector<ScanRecord> result;

    for (const auto &record : all) {
        if (!scanTypeFilter.empty() &&
            toLower(record.scanType) != toLower(scanTypeFilter)) {
            continue;
        }

        if (onlyWithThreats && record.threats.empty()) {
            continue;
        }

        if (q.empty()) {
            result.push_back(record);
            continue;
        }

        bool match = false;
        for (const auto &t : record.threats) {
            if (toLower(t.name).find(q) != std::string::npos ||
                toLower(t.filePath).find(q) != std::string::npos) {
                match = true;
                break;
            }
        }
        if (match) {
            result.push_back(record);
        }
    }
    return result;
}

std::string ScanHistoryManager::toLower(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

void ScanHistoryManager::purgeOldRecords() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto cutoff = now - hours(24 * 90);

    records.erase(
        std::remove_if(records.begin(), records.end(),
                       [&](const ScanRecord &r) {
                           return r.timestamp < cutoff;
                       }),
        records.end()
    );
}
