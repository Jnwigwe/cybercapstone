// File Scanner Module
// By: Gavin Hecke

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <dirent.h>
#include <algorithm>
#include <ctime>

using namespace std;

// Log file stream — opened once by run_scan() before scanning begins
static ofstream log_file;

// Suspicious strings that could indicate malicious activity
static const vector<string> suspicious_strings = {
    "/bin/bash -i",    // Interactive shell
    "/bin/sh -i",      // Interactive shell
    "nc -e",           // Netcat execution
    "/dev/tcp/",       // Bash reverse shell
    "eval(",           // Code evaluation
    "exec(",           // Code execution
    "system(",         // System calls
    "wget http",       // Download files
    "curl http",       // Download files
    "chmod 777",       // Permission changes
    "chmod +x",        // Make executable
    "/etc/shadow",     // Password file access
    "/etc/passwd",     // Password file access
    "LD_PRELOAD",      // Library injection
    "rm -rf",          // Destructive commands
    "dd if=",          // Disk operations
    "mkfifo",          // Named pipes
    "> /dev/null",     // Hide output
    "base64 -d"        // Decode hidden data
};

// Whitelisted file extensions (typically safe documentation/config)
static const vector<string> whitelisted_extensions = {
    ".md",
    ".rst",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".log"
};

/**
 * Helper function to get file extension
 */
string get_extension(const string& filepath) {
    size_t dot_pos = filepath.find_last_of(".");
    if (dot_pos != string::npos && dot_pos < filepath.length() - 1) {
        return filepath.substr(dot_pos);
    }
    return "";
}

/**
 * Check if a file should be whitelisted (skipped from scanning)
 * Returns true if file is in a safe category that commonly has false positives
 * Only whitelists by file extension for security
 * 
 * @param filepath - Full path to the file
 * @return true if file should be whitelisted, false otherwise
 */
bool is_whitelisted(const string& filepath) {
    string ext = get_extension(filepath);
    if (!ext.empty()) {
        // Convert to lowercase for case-insensitive comparison
        string ext_lower = ext;
        transform(ext_lower.begin(), ext_lower.end(), ext_lower.begin(), ::tolower);

        for (const auto& wl_ext : whitelisted_extensions) {
            if (ext_lower == wl_ext) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Scans a file for suspicious strings and returns a threat score.
 * Adjusts score based on file type and ignores commented lines.
 * 
 * @param filepath - Path to the file to scan
 * @return Adjusted number of suspicious strings found, or -1 if skipped due to size
 */
int scan_suspicious_strings(const string& filepath) {
    // Open file in binary mode
    ifstream file(filepath, ios::binary);
    if (!file) {
        return 0;  // Can't open file
    }
    
    // Get file size
    file.seekg(0, ios::end);
    streamsize fsize = file.tellg();
    file.seekg(0, ios::beg);
    
    // Skip very large files for performance reasons (>50MB)
    if (fsize <= 0 || fsize > 50 * 1024 * 1024) {
        return -1;  // Return -1 to indicate file was skipped due to size
    }
    
    // Read entire file into string
    string content;
    content.resize(fsize);
    if (!file.read(&content[0], fsize)) {
        return 0;  // Read failed
    }
    file.close();
    
    // Split content into lines for comment detection
    vector<string> lines;
    string line;
    for (size_t i = 0; i < content.length(); i++) {
        if (content[i] == '\n') {
            lines.push_back(line);
            line.clear();
        } else {
            line += content[i];
        }
    }
    if (!line.empty()) {
        lines.push_back(line);
    }
    
    // Count suspicious strings, skipping commented lines
    int count = 0;
    for (const auto& suspicious_str : suspicious_strings) {
        for (const auto& line : lines) {
            // Remove leading whitespace
            string trimmed = line;
            size_t start = trimmed.find_first_not_of(" \t");
            if (start != string::npos) {
                trimmed = trimmed.substr(start);
            }
            
            // Check for common comment patterns
            bool is_comment = false;
            if (trimmed.length() >= 1 && trimmed[0] == '#') is_comment = true;  // Python, Bash, Ruby
            if (trimmed.length() >= 2 && trimmed[0] == '/' && trimmed[1] == '/') is_comment = true;  // C++, JS, Java
            if (trimmed.length() >= 2 && trimmed[0] == '/' && trimmed[1] == '*') is_comment = true;  // C-style block
            if (trimmed.length() >= 2 && trimmed[0] == '-' && trimmed[1] == '-') is_comment = true;  // SQL, Lua
            
            if (!is_comment && line.find(suspicious_str) != string::npos) {
                count++;
                break;  // Only count once per suspicious string
            }
        }
    }

    // Adjust score based on file type risk profile
    string ext = get_extension(filepath);
    if      (ext == ".md"  || ext == ".txt" || ext == ".rst")                              count = count / 3;
    else if (ext == ".conf"|| ext == ".cfg" || ext == ".ini" || ext == ".yaml" || ext == ".yml") count = count * 2 / 3;
    else if (ext == ".cpp" || ext == ".c"   || ext == ".java"|| ext == ".go")              count = count * 4 / 5;
    // .sh, .py, .rb, .pl, .js and unknown types keep the full score

    return count;
}

/**
 * Main scanning function used to scan files
 * Focuses on suspicious string detection
 * 
 * @param filepath - Full path to the file to scan
 * @return 3 for malicious, 2 for suspicious, 1 for safe, 0 for skipped
 */
int scan_file(const string& filepath) {
    // Verify the file exists and is a regular file (not a directory, symlink, etc.)
    struct stat st;
    if (stat(filepath.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        return 0;  // Skipped
    }
    
    // Check whitelist before scanning
    if (is_whitelisted(filepath)) {
        return 0;  // Skipped - whitelisted
    }
    
    int suspicious_count = scan_suspicious_strings(filepath);
    
    if (suspicious_count == -1) {
        return 0;  // Skipped - file too large
    }
    
    // Determine threat level
    // 5+ hits = malicious, 3-4 = suspicious, <3 = safe
    if (suspicious_count >= 5) return 3;
    if (suspicious_count >= 3) return 2;
    return 1;
}

/**
 * Recursively scans all files in a directory
 * 
 * @param dirpath - Path to the directory to scan
 * @param results - Vector to store results (filepath, scan result)
 */
void scan_directory(const string& dirpath, vector<pair<string, int>>& results) {
    DIR* dir = opendir(dirpath.c_str());
    if (!dir) {
        if (log_file.is_open()) {
            time_t now = time(nullptr);
            char buf[20];
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
            log_file << "[" << buf << "] Cannot open directory: " << dirpath << endl;
        }
        return;
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (string(entry->d_name) == "." || string(entry->d_name) == "..") continue;
        
        string fullpath = dirpath + "/" + entry->d_name;
        
        struct stat st;
        if (stat(fullpath.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                scan_directory(fullpath, results);
            } else if (S_ISREG(st.st_mode)) {
                results.push_back({fullpath, scan_file(fullpath)});
            }
        }
    }
    
    closedir(dir);
}

/**
 * Runs a full directory scan and writes all results to a log file.
 *
 * @param dirpath  - Directory to scan
 * @param log_path - Path to the log file (created if it doesn't exist, appended otherwise)
 */
void run_scan(const string& dirpath, const string& log_path) {
    log_file.open(log_path, ios::app);
    if (!log_file.is_open()) {
        cerr << "Error: Could not open log file: " << log_path << endl;
        return;
    }

    // Helper to get a timestamp string inline
    auto timestamp = []() {
        time_t now = time(nullptr);
        char buf[20];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        return string(buf);
    };

    time_t start_time = time(nullptr);

    log_file << "Scan started:       " << timestamp() << endl;
    log_file << "Scanning directory: " << dirpath << endl;
    log_file << "========================================" << endl;
    log_file << endl;

    vector<pair<string, int>> results;
    scan_directory(dirpath, results);

    int malicious_count = 0, suspicious_count = 0, clean_count = 0, skipped_count = 0;

    for (const auto& result : results) {
        log_file << "File: " << result.first << endl;
        switch (result.second) {
            case 3: log_file << "  Result: [MALICIOUS]"  << endl; malicious_count++;  break;
            case 2: log_file << "  Result: [SUSPICIOUS]" << endl; suspicious_count++; break;
            case 1: log_file << "  Result: [CLEAN]"      << endl; clean_count++;      break;
            case 0: log_file << "  Result: [SKIPPED]"    << endl; skipped_count++;    break;
        }
        log_file << endl;
    }

    int elapsed = static_cast<int>(difftime(time(nullptr), start_time));

    log_file << "========================================" << endl;
    log_file << "SCAN SUMMARY:" << endl;
    log_file << "  Total files: " << results.size()   << endl;
    log_file << "  Malicious:   " << malicious_count  << endl;
    log_file << "  Suspicious:  " << suspicious_count << endl;
    log_file << "  Clean:       " << clean_count      << endl;
    log_file << "  Skipped:     " << skipped_count    << endl;
    log_file << endl;
    log_file << "Scan completed:     " << timestamp() << endl;
    log_file << "Elapsed time:       " << elapsed << " second(s)" << endl;
    log_file << "========================================" << endl;
    log_file << endl;

    log_file.close();
}
