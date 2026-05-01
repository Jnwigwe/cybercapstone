#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <dirent.h>
#include <algorithm>
#include <ctime>
using namespace std;

#include "file_scanner.cpp"

int main(int argc, char* argv[]) {
    string testDir = (argc > 1) ? argv[1] : "test_case_for_suspicious_strings";

    cout << "============================================" << endl;
    cout << "  JNPR4 - ACCEPTANCE TEST" << endl;
    cout << "  InfectionPoint Malware Scanner v2.5.0" << endl;
    cout << "============================================" << endl;
    cout << "Scanning directory: " << testDir << endl;
    cout << "============================================" << endl << endl;

    vector<pair<string, int>> results;
    scan_directory(testDir, results);

    int malicious = 0, suspicious = 0, clean = 0, skipped = 0;

    for (const auto& r : results) {
        string label;
        switch (r.second) {
            case 3: label = "[MALICIOUS] "; malicious++;  break;
            case 2: label = "[SUSPICIOUS]"; suspicious++; break;
            case 1: label = "[CLEAN]     "; clean++;      break;
            default:label = "[SKIPPED]   "; skipped++;    break;
        }
        string fname = r.first;
        size_t pos = fname.rfind("/");
        string display = (pos != string::npos) ? fname.substr(pos+1) : fname;
        cout << label << "  " << display << endl;
    }

    cout << endl;
    cout << "============================================" << endl;
    cout << "ACCEPTANCE TEST SUMMARY" << endl;
    cout << "============================================" << endl;
    cout << "Total files scanned : " << results.size()  << endl;
    cout << "Malicious detected  : " << malicious        << endl;
    cout << "Suspicious flagged  : " << suspicious       << endl;
    cout << "Clean (safe)        : " << clean            << endl;
    cout << "Skipped (whitelist) : " << skipped          << endl;
    cout << "--------------------------------------------" << endl;
    bool pass = (malicious >= 3 && clean >= 3 && skipped >= 1);
    cout << "Malicious detection : " << (malicious >= 3 ? "PASS" : "FAIL") << endl;
    cout << "Clean file accuracy : " << (clean >= 3     ? "PASS" : "FAIL") << endl;
    cout << "Whitelist skipping  : " << (skipped >= 1   ? "PASS" : "FAIL") << endl;
    cout << "--------------------------------------------" << endl;
    cout << "OVERALL RESULT      : " << (pass ? "ACCEPTED" : "REJECTED") << endl;
    cout << "============================================" << endl;
    return pass ? 0 : 1;
}