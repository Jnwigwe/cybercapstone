#pragma once
#include <vector>
#include <string>
#include "ScanRecord.h"

class ScanHistoryManager {
public:
    void addRecord(const ScanRecord &record);


    std::vector<ScanRecord> getAllVisible() const;

    std::vector<ScanRecord> search(const std::string &queryText,
                                   const std::string &scanTypeFilter,
                                   bool onlyWithThreats) const;

private:
    std::vector<ScanRecord> records;

    static std::string toLower(const std::string &s);
    void purgeOldRecords();
};
