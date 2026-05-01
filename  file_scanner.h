// File Scanner Module - Header
// By: Gavin Hecke

#ifndef FILE_SCANNER_H
#define FILE_SCANNER_H

#include <string>
#include <vector>

using namespace std;

/**
 * Helper function to get file extension
 *
 * @param filepath - Path to the file
 * @return File extension including the dot (e.g., ".cpp"), or empty string if none
 */
string get_extension(const string& filepath);

/**
 * Check if a file should be whitelisted (skipped from scanning)
 * Returns true if file is in a safe category that commonly has false positives
 *
 * @param filepath - Full path to the file
 * @return true if file should be whitelisted, false otherwise
 */
bool is_whitelisted(const string& filepath);

/**
 * Scans a file for suspicious strings and returns a threat score.
 * Adjusts score based on file type and ignores commented lines.
 *
 * @param filepath - Path to the file to scan
 * @return Adjusted number of suspicious strings found, or -1 if skipped due to size
 */
int scan_suspicious_strings(const string& filepath);

/**
 * Main scanning function used to scan files
 * Focuses on suspicious string detection
 *
 * @param filepath - Full path to the file to scan
 * @return 3 for malicious, 2 for suspicious, 1 for safe, 0 for skipped
 */
int scan_file(const string& filepath);

/**
 * Recursively scans all files in a directory
 *
 * @param dirpath - Path to the directory to scan
 * @param results - Vector to store results (filepath, scan result)
 */
void scan_directory(const string& dirpath, vector<pair<string, int>>& results);

/**
 * Runs a full directory scan and writes all results to a log file.
 * This is the main entry point — call this instead of scan_directory() directly
 * when you want logging.
 *
 * The log captures: scan start time, per-file results, summary counts,
 * scan completion time, and total elapsed time.
 *
 * @param dirpath  - Directory to scan
 * @param log_path - Path to the log file (created if it doesn't exist, appended otherwise)
 */
void run_scan(const string& dirpath, const string& log_path);

#endif // FILE_SCANNER_H
