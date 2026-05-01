#pragma once

#include <string>
#include <vector>

struct VTDetectionStats {
    int malicious = 0;
    int suspicious = 0;
    int harmless = 0;
    int undetected = 0;
    int timeout = 0;
    int confirmed_timeout = 0;
    int failure = 0;
    int type_unsupported = 0;
};

struct VTFileResult {
    std::string file;
    std::string sha256;
    VTDetectionStats stats;
    std::string severity;
    std::string recommended;
    bool used_existing_report = false;
    std::string quarantined_to;
    long http_status_initial = 0;
};

struct VTScanOptions {
    bool recursive = true;
    int max_files = 200;
    double max_mb = 32.0;
    int poll_attempts = 12;
    int poll_sleep_sec = 15;
    int between_uploads_ms = 350;
    std::string out_report = "scan_report.json";
    std::string events_log = "malware_events.jsonl";
    std::string promoted_log = "promoted_logs.jsonl";
    std::string quarantine_dir = "quarantine";
    bool enable_quarantine = true;
};

struct VTRunResult {
    std::vector<VTFileResult> results;
    int scanned = 0;
    int high_count = 0;
    int med_count = 0;
    int low_count = 0;
    std::string report_json_text;
};

std::string vt_sha256_file(const std::string& path);

VTRunResult runVirusTotalScan(const std::string& apiKey,
                              const std::string& targetPath,
                              const VTScanOptions& opt);

int runVirusTotalCli(int argc, char** argv);
