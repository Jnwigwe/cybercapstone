// Include necessary libraries for file operations, system calls, and I/O
#include <iostream>      // For input/output operations (cout, cin)
#include <fstream>       // For file stream operations (reading/writing files)
#include <string>        // For string handling
#include <filesystem>    // For filesystem operations (C++17)
#include <ctime>         // For timestamp operations
#include <sys/stat.h>    // For file permissions (chmod)

using namespace std;
namespace fs = filesystem;  // Alias for filesystem namespace to avoid conflicts

// Main class for handling file quarantine operations
class BubblewrapQuarantine {
private:
    // Private member variables to store directory paths
    string quarantineDir;  // Directory where quarantined files are stored
    string logFile;        // Path to log file for activity tracking

    // Helper function to get current timestamp in readable format
    string getCurrentTimestamp() {
        time_t now = time(nullptr);  // Get current time
        char buf[100];
        // Format timestamp as YYYY-MM-DD HH:MM:SS
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        return string(buf);
    }

    // Log activity to both console and log file for audit trail
    void logActivity(const string& message) {
        ofstream log(logFile, ios::app);  // Open log file in append mode
        if (log) {
            log << "[" << getCurrentTimestamp() << "] " << message << endl;
        }
        cout << "[LOG] " << message << endl;  // Also print to console
    }

public:
    // Constructor: Initialize quarantine system with directory paths
    BubblewrapQuarantine(const string& quarantineDirectory = "/tmp/quarantine",
                         const string& logFilePath = "/tmp/quarantine.log")
        : quarantineDir(quarantineDirectory), 
          logFile(logFilePath) {
        
        // Create quarantine directory if it doesn't exist
        if (!fs::exists(quarantineDir)) {
            fs::create_directories(quarantineDir);
        }

        logActivity("Quarantine System initialized");
    }

    // Main function to quarantine a suspicious file
    // Copies file to quarantine, locks permissions, writes metadata, removes original
    bool quarantineFile(const string& filepath, const string& reason = "Malicious") {
        try {
            // Check if file exists before attempting to quarantine
            if (!fs::exists(filepath)) {
                logActivity("ERROR: File does not exist: " + filepath);
                return false;
            }

            // Generate unique quarantine filename using timestamp
            string filename = fs::path(filepath).filename().string();
            time_t now = time(nullptr);
            string quarantinePath = quarantineDir + "/" + 
                to_string(now) + "_" + filename;

            // Copy file to quarantine
            fs::copy_file(filepath, quarantinePath, fs::copy_options::overwrite_existing);

            // Change permissions to read-only (owner read only: S_IRUSR)
            // This prevents accidental execution of quarantined malware
            chmod(quarantinePath.c_str(), S_IRUSR);

            // Save metadata about the quarantined file
            string metadataFile = quarantinePath + ".metadata";
            ofstream metadata(metadataFile);
            if (metadata) {
                metadata << "Original Path: " << filepath << endl;
                metadata << "Quarantine Time: " << getCurrentTimestamp() << endl;
                metadata << "Reason: " << reason << endl;
                metadata << "File Size: " << fs::file_size(filepath) << " bytes" << endl;
            }

            // Remove original file so it is truly moved into quarantine
            fs::remove(filepath);

            logActivity("File quarantined: " + filepath + " -> " + quarantinePath);
            cout << "[QUARANTINED] " << filepath << " has been quarantined." << endl;
            return true;

        } catch (const fs::filesystem_error& e) {
            logActivity("ERROR: Failed to quarantine " + filepath + ": " + e.what());
            return false;
        }
    }

    // List all files currently in quarantine with their metadata
    void listQuarantinedFiles() {
        cout << "\n=== Quarantined Files ===" << endl;

        if (!fs::exists(quarantineDir) || fs::is_empty(quarantineDir)) {
            cout << "No quarantined files." << endl;
            return;
        }

        int count = 0;
        for (const auto& entry : fs::directory_iterator(quarantineDir)) {
            if (entry.path().extension() != ".metadata") {
                count++;
                cout << "\n" << count << ". " << entry.path().filename().string() << endl;

                string metadataPath = entry.path().string() + ".metadata";
                ifstream metadata(metadataPath);
                if (metadata) {
                    string line;
                    while (getline(metadata, line)) {
                        cout << "   " << line << endl;
                    }
                }
            }
        }

        if (count == 0) {
            cout << "No quarantined files." << endl;
        }
    }

    // Restore a quarantined file to a specified location
    // USE WITH CAUTION: Only restore if you're certain the file is safe
    bool restoreFile(const string& quarantinedFile, const string& destinationPath) {
        string fullPath = quarantineDir + "/" + quarantinedFile;

        // Verify quarantined file exists
        if (!fs::exists(fullPath)) {
            logActivity("ERROR: Quarantined file not found: " + fullPath);
            return false;
        }

try {
    // Prompt for confirmation before restoring
    cout << "Are you sure you want to restore \"" << quarantinedFile << "\"? [Y/N]: ";
    string confirm;
    cin >> confirm;
    if (confirm != "y" && confirm != "Y") {
        cout << "[CANCELLED] Restore cancelled." << endl;
        return false;
    }

    // Copy file to destination
    fs::copy_file(fullPath, destinationPath, fs::copy_options::overwrite_existing);

        // Restore full permissions (read, write, execute for owner)
        chmod(destinationPath.c_str(), S_IRUSR | S_IWUSR | S_IXUSR);

        // Remove file from quarantine folder after restoring
        chmod(fullPath.c_str(), S_IRUSR | S_IWUSR);
        string rmCmd = "rm -f \"" + fullPath + "\" \"" + fullPath + ":Zone.Identifier\" 2>/dev/null";
        system(rmCmd.c_str());

    // Remove metadata file as well
    string metadataPath = fullPath + ".metadata";
    if (fs::exists(metadataPath)) {
        fs::remove(metadataPath);
    }

    logActivity("File restored: " + quarantinedFile + " -> " + destinationPath);
    cout << "[RESTORED] File has been restored to: " << destinationPath << endl;
    cout << "[WARNING] Ensure the file is safe before executing!" << endl;
    return true;
        } catch (const fs::filesystem_error& e) {
            logActivity("ERROR: Failed to restore file: " + string(e.what()));
            return false;
        }
    }

    // Permanently delete a quarantined file and its metadata
    bool deleteQuarantinedFile(const string& quarantinedFile) {
        string fullPath = quarantineDir + "/" + quarantinedFile;
        string metadataPath = fullPath + ".metadata";

        try {
if (fs::exists(fullPath)) {
    // Read original path from metadata to clean up Zone Identifier there too
    string originalPath;
    ifstream metaRead(metadataPath);
    if (metaRead) {
        string line;
        while (getline(metaRead, line)) {
            if (line.rfind("Original Path: ", 0) == 0) {
                originalPath = line.substr(15);
            }
        }
    }

    // Restore write permission before deleting (file is stored read-only)
    chmod(fullPath.c_str(), S_IRUSR | S_IWUSR);
    // Use rm to also strip any Windows Zone Identifier metadata (WSL)
    string rmCmd = "rm -f \"" + fullPath + "\" \"" + fullPath + ":Zone.Identifier\" 2>/dev/null";
    system(rmCmd.c_str());

    // Delete Zone Identifier left at the original destination
    if (!originalPath.empty()) {
        string zoneCmd = "rm -f \"" + originalPath + ":Zone.Identifier\" 2>/dev/null";
        system(zoneCmd.c_str());
    }
}
            if (fs::exists(metadataPath)) {
                fs::remove(metadataPath);
            }

            logActivity("Permanently deleted: " + quarantinedFile);
            cout << "[DELETED] " << quarantinedFile << " has been permanently removed." << endl;
            return true;
        } catch (const fs::filesystem_error& e) {
            logActivity("ERROR: Failed to delete: " + string(e.what()));
            return false;
        }
    }
};

// Main function: Command-line interface for the quarantine system
int main(int argc, char* argv[]) {
    cout << "=== File Quarantine System ===" << endl;
    cout << "Linux Malware Quarantine Tool\n" << endl;

    // Create quarantine system instance with default directories
    BubblewrapQuarantine quarantine;

    // Display help if no command provided
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <command> [arguments]" << endl;
        cout << "\nCommands:" << endl;
        cout << "   quarantine <file> [reason]        - Quarantine a suspicious file" << endl;
        cout << "   list                              - List all quarantined files" << endl;
        cout << "   restore <quarantined_file> <dest> - Restore a quarantined file" << endl;
        cout << "   delete <quarantined_file>         - Permanently delete quarantined file" << endl;
        return 1;
    }

    // Parse command from command-line arguments
    string command = argv[1];

    if (command == "quarantine" && argc >= 3) {
        string file = argv[2];
        string reason = (argc >= 4) ? argv[3] : "Malicious";
        quarantine.quarantineFile(file, reason);

    } else if (command == "list") {
        quarantine.listQuarantinedFiles();

    } else if (command == "restore" && argc >= 4) {
        string file = argv[2];
        string dest = argv[3];
        quarantine.restoreFile(file, dest);

    } else if (command == "delete" && argc >= 3) {
        string file = argv[2];

        // Prompt for confirmation before permanent deletion
        cout << "Are you sure you want to PERMANENTLY delete \"" << file << "\"? [Y/N]: ";
        string confirm;
        cin >> confirm;
        if (confirm == "y" || confirm == "Y") {
            quarantine.deleteQuarantinedFile(file);
        } else {
            cout << "[CANCELLED] Deletion cancelled." << endl;
        }

    } else {
        cout << "Invalid command or missing arguments." << endl;
        return 1;
    }

    return 0;
}
