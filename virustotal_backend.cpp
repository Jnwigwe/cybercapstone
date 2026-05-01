#include "virustotal_backend.h"

#include <curl/curl.h>
#include <openssl/sha.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <stdexcept>
#include <vector>
#include <filesystem>
#include <algorithm>

using json = nlohmann::json;
namespace fs = std::filesystem;

static size_t WriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* responseStr = static_cast<std::string*>(userdata);
    responseStr->append(ptr, size * nmemb);
    return size * nmemb;
}

static std::string iso8601_now_utc() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string vt_sha256_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Failed to open file: " + path);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    char buf[8192];
    while (file.good()) {
        file.read(buf, sizeof(buf));
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            SHA256_Update(&ctx, buf, static_cast<size_t>(bytesRead));
        }
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    std::ostringstream oss;
    for (unsigned char byte : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    return oss.str();
}

struct HttpResponse {
    long status = 0;
    std::string body;
};

static HttpResponse http_get_json(const std::string& url, const std::string& api_key) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    std::string responseBody;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, ("x-apikey: " + api_key).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);

    HttpResponse out;
    if (res != CURLE_OK) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        throw std::runtime_error(std::string("GET failed: ") + curl_easy_strerror(res));
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out.status);
    out.body = std::move(responseBody);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return out;
}

static std::string vt_upload_file_for_analysis(const std::string& file_path, const std::string& api_key) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    std::string responseBody;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, ("x-apikey: " + api_key).c_str());

    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_filedata(part, file_path.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, "https://www.virustotal.com/api/v3/files");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);

    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_mime_free(mime);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("POST failed: ") + curl_easy_strerror(res));
    }
    if (status < 200 || status >= 300) {
        throw std::runtime_error("Upload failed HTTP " + std::to_string(status) +
                                 " body: " + responseBody);
    }

    auto j = json::parse(responseBody);
    return j["data"]["id"].get<std::string>();
}

static VTDetectionStats parse_stats_from_analysis_json(const json& j) {
    VTDetectionStats st{};
    const auto& stats = j["data"]["attributes"]["stats"];
    st.malicious          = stats.value("malicious", 0);
    st.suspicious         = stats.value("suspicious", 0);
    st.harmless           = stats.value("harmless", 0);
    st.undetected         = stats.value("undetected", 0);
    st.timeout            = stats.value("timeout", 0);
    st.confirmed_timeout  = stats.value("confirmed-timeout", 0);
    st.failure            = stats.value("failure", 0);
    st.type_unsupported   = stats.value("type-unsupported", 0);
    return st;
}

static VTDetectionStats parse_stats_from_file_report_json(const json& j) {
    VTDetectionStats st{};
    const auto& stats = j["data"]["attributes"]["last_analysis_stats"];
    st.malicious  = stats.value("malicious", 0);
    st.suspicious = stats.value("suspicious", 0);
    st.harmless   = stats.value("harmless", 0);
    st.undetected = stats.value("undetected", 0);
    return st;
}

static std::string severity_from(const VTDetectionStats& st) {
    if (st.malicious >= 3) return "HIGH";
    if (st.malicious >= 1 || st.suspicious >= 2) return "MEDIUM";
    return "LOW";
}

static std::string recommended_action(const VTDetectionStats& st, const std::string& severity) {
    if (severity == "HIGH") return "QUARANTINE (high confidence detections; isolate file; do not execute)";
    if (severity == "MEDIUM") return "REVIEW (some detections; verify source; consider isolating)";
    if (st.malicious == 0 && st.suspicious == 0) return "ALLOW (no detections; keep monitoring; verify source if unknown)";
    return "REVIEW (low signals present; verify source)";
}

static void append_event_jsonl(const std::string& events_path,
                               const std::string& file_path,
                               const std::string& threat_type,
                               const std::string& action_taken) {
    json ev = {
        {"timestamp", iso8601_now_utc()},
        {"file_path", file_path},
        {"threat_type", threat_type},
        {"action_taken", action_taken}
    };
    std::ofstream out(events_path, std::ios::app);
    out << ev.dump() << "\n";
}

static void append_compliance_audit_jsonl(const std::string& audit_path,
                                          const std::string& file_path,
                                          const std::string& sha256,
                                          const VTDetectionStats& stats,
                                          const std::string& severity,
                                          const std::string& recommended,
                                          const std::string& action_taken,
                                          bool used_existing_report,
                                          long http_status_initial,
                                          const std::string& quarantined_to) {
    json audit = {
        {"timestamp", iso8601_now_utc()},
        {"file_path", file_path},
        {"sha256", sha256},
        {"severity", severity},
        {"recommended_action", recommended},
        {"action_taken", action_taken},
        {"used_existing_report", used_existing_report},
        {"http_status_initial", http_status_initial},
        {"stats", {
            {"malicious", stats.malicious},
            {"suspicious", stats.suspicious},
            {"harmless", stats.harmless},
            {"undetected", stats.undetected},
            {"timeout", stats.timeout},
            {"confirmed-timeout", stats.confirmed_timeout},
            {"failure", stats.failure},
            {"type-unsupported", stats.type_unsupported}
        }}
    };

    if (!quarantined_to.empty()) {
        audit["quarantined_to"] = quarantined_to;
    }

    std::ofstream out(audit_path, std::ios::app);
    out << audit.dump() << "\n";
}

static void append_promoted_log_jsonl(const std::string& promoted_path,
                                      const std::string& file_path,
                                      const std::string& sha256,
                                      const std::string& severity,
                                      const std::string& recommended,
                                      const std::string& action_taken) {
    json promoted = {
        {"timestamp", iso8601_now_utc()},
        {"file_path", file_path},
        {"sha256", sha256},
        {"severity", severity},
        {"recommended_action", recommended},
        {"action_taken", action_taken}
    };

    std::ofstream out(promoted_path, std::ios::app);
    out << promoted.dump() << "\n";
}

static void ensure_quarantine_dir(const fs::path& qdir) {
    std::error_code ec;
    fs::create_directories(qdir, ec);
    fs::permissions(qdir, fs::perms::owner_all, fs::perm_options::replace, ec);
}

static bool quarantine_file(const fs::path& file, const fs::path& qdir, std::string& moved_to) {
    ensure_quarantine_dir(qdir);
    std::error_code ec;

    fs::path target = qdir / file.filename();
    target += ".quarantined";

    int n = 1;
    while (fs::exists(target, ec)) {
        target = qdir / (file.filename().string() + "." + std::to_string(n) + ".quarantined");
        n++;
    }

    fs::rename(file, target, ec);
    if (ec) return false;

    moved_to = target.string();
    return true;
}

static bool has_opt(const std::vector<std::string>& args, const std::string& opt) {
    return std::find(args.begin(), args.end(), opt) != args.end();
}

static std::string get_opt_value(const std::vector<std::string>& args,
                                 const std::string& opt,
                                 const std::string& def = "") {
    for (size_t i = 0; i + 1 < args.size(); i++) {
        if (args[i] == opt) return args[i + 1];
    }
    return def;
}

static int get_opt_int(const std::vector<std::string>& args,
                       const std::string& opt,
                       int def) {
    std::string v = get_opt_value(args, opt, "");
    if (v.empty()) return def;
    try { return std::stoi(v); } catch (...) { return def; }
}

static double get_opt_double(const std::vector<std::string>& args,
                             const std::string& opt,
                             double def) {
    std::string v = get_opt_value(args, opt, "");
    if (v.empty()) return def;
    try { return std::stod(v); } catch (...) { return def; }
}

static bool is_regular_file_ok(const fs::path& p, double max_mb) {
    std::error_code ec;
    if (!fs::is_regular_file(p, ec)) return false;
    auto sz = fs::file_size(p, ec);
    if (ec) return false;
    double mb = (double)sz / (1024.0 * 1024.0);
    return mb <= max_mb;
}

static VTFileResult scan_one_file(const std::string& api_key,
                                  const fs::path& file_path,
                                  const VTScanOptions& opt) {
    VTFileResult fr{};
    fr.file = file_path.string();
    fr.sha256 = vt_sha256_file(fr.file);

    std::string file_report_url = "https://www.virustotal.com/api/v3/files/" + fr.sha256;
    HttpResponse file_report = http_get_json(file_report_url, api_key);
    fr.http_status_initial = file_report.status;

    if (file_report.status == 200) {
        auto j = json::parse(file_report.body);
        fr.stats = parse_stats_from_file_report_json(j);
        fr.used_existing_report = true;
        fr.severity = severity_from(fr.stats);
        fr.recommended = recommended_action(fr.stats, fr.severity);
        return fr;
    }

    std::string analysis_id = vt_upload_file_for_analysis(fr.file, api_key);
    std::string analysis_url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id;

    for (int attempt = 1; attempt <= opt.poll_attempts; attempt++) {
        HttpResponse analysis_resp = http_get_json(analysis_url, api_key);
        if (analysis_resp.status != 200) {
            throw std::runtime_error("Analysis fetch failed HTTP " + std::to_string(analysis_resp.status) +
                                     " body: " + analysis_resp.body);
        }

        auto aj = json::parse(analysis_resp.body);
        std::string status = aj["data"]["attributes"].value("status", "");
        std::cout << "[i] Poll " << attempt << "/" << opt.poll_attempts
                  << " status=" << status << "\n";

        if (status == "completed") {
            fr.stats = parse_stats_from_analysis_json(aj);
            fr.severity = severity_from(fr.stats);
            fr.recommended = recommended_action(fr.stats, fr.severity);
            return fr;
        }

        std::this_thread::sleep_for(std::chrono::seconds(opt.poll_sleep_sec));
    }

    fr.severity = "LOW";
    fr.recommended = "REVIEW (analysis did not complete within poll window)";
    return fr;
}

VTRunResult runVirusTotalScan(const std::string& apiKey,
                              const std::string& targetPath,
                              const VTScanOptions& opt) {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    VTRunResult run{};
    json report;
    report["started_at"] = iso8601_now_utc();
    report["target"] = targetPath;
    report["results"] = json::array();

    try {
        std::vector<fs::path> files;
        std::error_code ec;
        fs::path target(targetPath);

        if (fs::is_regular_file(target, ec)) {
            files.push_back(target);
        } else if (fs::is_directory(target, ec)) {
            if (opt.recursive) {
                for (auto& entry : fs::recursive_directory_iterator(
                        target, fs::directory_options::skip_permission_denied, ec)) {
                    if (ec) continue;
                    if ((int)files.size() >= opt.max_files) break;
                    if (entry.is_regular_file(ec)) files.push_back(entry.path());
                }
            } else {
                for (auto& entry : fs::directory_iterator(
                        target, fs::directory_options::skip_permission_denied, ec)) {
                    if (ec) continue;
                    if ((int)files.size() >= opt.max_files) break;
                    if (entry.is_regular_file(ec)) files.push_back(entry.path());
                }
            }
        } else {
            throw std::runtime_error("Target is not a file or directory: " + target.string());
        }

        std::cout << "[+] Analyzing file(s) with VirusTotal API...\n";
        std::cout << "[i] Candidate files: " << files.size()
                  << " (max-files=" << opt.max_files << ", max-mb=" << opt.max_mb << ")\n";

        for (const auto& f : files) {
            if (run.scanned >= opt.max_files) break;
            if (!is_regular_file_ok(f, opt.max_mb)) continue;

            run.scanned++;
            std::cout << "\n[+] (" << run.scanned << ") Scanning: " << f.string() << "\n";

            VTFileResult r = scan_one_file(apiKey, f, opt);

            std::string action_taken = "report_only";
            if (opt.enable_quarantine && r.severity == "HIGH") {
                std::string moved_to;
                if (quarantine_file(f, fs::path(opt.quarantine_dir), moved_to)) {
                    r.quarantined_to = moved_to;
                    action_taken = "quarantined";
                } else {
                    action_taken = "quarantine_failed";
                }
            }

            if (r.severity == "HIGH") run.high_count++;
            else if (r.severity == "MEDIUM") run.med_count++;
            else run.low_count++;

            if (r.severity != "LOW") {
                append_event_jsonl(opt.events_log, r.file, r.severity, action_taken);
            }

            append_compliance_audit_jsonl(
                opt.events_log,
                r.file,
                r.sha256,
                r.stats,
                r.severity,
                r.recommended,
                action_taken,
                r.used_existing_report,
                r.http_status_initial,
                r.quarantined_to
            );

            if (r.severity == "MEDIUM" || r.severity == "HIGH") {
                append_promoted_log_jsonl(
                    opt.promoted_log,
                    r.file,
                    r.sha256,
                    r.severity,
                    r.recommended,
                    action_taken
                );
            }

            std::cout
                << "\n========================================\n"
                << "File:     " << r.file << "\n"
                << "SHA-256:  " << r.sha256 << "\n"
                << "Severity: " << r.severity << "\n"
                << "----------------------------------------\n"
                << "Stats:\n"
                << "  malicious:         " << r.stats.malicious << "\n"
                << "  suspicious:        " << r.stats.suspicious << "\n"
                << "  harmless:          " << r.stats.harmless << "\n"
                << "  undetected:        " << r.stats.undetected << "\n"
                << "  timeout:           " << r.stats.timeout << "\n"
                << "  confirmed-timeout: " << r.stats.confirmed_timeout << "\n"
                << "  failure:           " << r.stats.failure << "\n"
                << "  type-unsupported:  " << r.stats.type_unsupported << "\n"
                << "----------------------------------------\n"
                << "Recommended action: " << r.recommended << "\n";

            if (!r.quarantined_to.empty()) {
                std::cout << "Quarantined to: " << r.quarantined_to << "\n";
            }

            std::cout << "========================================\n";

            json jr = {
                {"file", r.file},
                {"sha256", r.sha256},
                {"severity", r.severity},
                {"recommended_action", r.recommended},
                {"used_existing_report", r.used_existing_report},
                {"http_status_initial", r.http_status_initial},
                {"stats", {
                    {"malicious", r.stats.malicious},
                    {"suspicious", r.stats.suspicious},
                    {"harmless", r.stats.harmless},
                    {"undetected", r.stats.undetected},
                    {"timeout", r.stats.timeout},
                    {"confirmed-timeout", r.stats.confirmed_timeout},
                    {"failure", r.stats.failure},
                    {"type-unsupported", r.stats.type_unsupported}
                }}
            };

            if (!r.quarantined_to.empty()) {
                jr["quarantined_to"] = r.quarantined_to;
            }

            report["results"].push_back(jr);
            run.results.push_back(r);

            std::this_thread::sleep_for(std::chrono::milliseconds(opt.between_uploads_ms));
        }

        report["finished_at"] = iso8601_now_utc();
        report["summary"] = {
            {"total_scanned", run.scanned},
            {"low", run.low_count},
            {"medium", run.med_count},
            {"high", run.high_count}
        };

        run.report_json_text = report.dump(2);

        std::ofstream out(opt.out_report);
        out << run.report_json_text << "\n";

        std::cout << "\n[✓] Session complete. Total files scanned: " << run.scanned << "\n";
        std::cout << "[✓] Report written to: " << opt.out_report << "\n";
        std::cout << "[✓] Event log (JSONL) at: " << opt.events_log << "\n";
        std::cout << "[✓] Promoted log (JSONL) at: " << opt.promoted_log << "\n";

        curl_global_cleanup();
        return run;

    } catch (...) {
        curl_global_cleanup();
        throw;
    }
}

static void print_usage(const char* exe) {
    std::cerr <<
R"(Usage (NEW):
  )" << exe << R"( <VT_API_KEY> <file_or_dir> [options]

Usage (LEGACY):
  )" << exe << R"( --path <file_or_dir> [--log <jsonl>] [--report <json>] [--poll-seconds N] [--max-polls N]
  (Legacy mode reads VT_API_KEY from the environment)

Options:
  --no-recursive
  --max-files N
  --max-mb M
  --out FILE            (alias: --report)
  --events FILE         (alias: --log)
  --promoted FILE
  --no-quarantine
  --quarantine-dir DIR
  --sleep-ms MS
  --poll-attempts N     (alias: --max-polls)
  --poll-sleep SEC      (alias: --poll-seconds)
)";
}

static std::string env_or_empty(const char* name) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
}

int runVirusTotalCli(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    bool legacy_mode = (std::string(argv[1]) == "--path");

    std::string api_key;
    std::string target;
    std::vector<std::string> args;

    if (legacy_mode) {
        if (argc < 3) {
            std::cerr << "Error: --path requires a value\n";
            print_usage(argv[0]);
            return 1;
        }
        api_key = env_or_empty("VT_API_KEY");
        if (api_key.empty()) {
            std::cerr << "Error: Legacy mode requires VT_API_KEY in the environment.\n";
            return 1;
        }
        target = argv[2];
        for (int i = 3; i < argc; i++) args.emplace_back(argv[i]);
    } else {
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        if (!std::string(argv[1]).empty() && argv[1][0] == '-') {
            std::cerr << "Unknown arg: " << argv[1] << "\n";
            print_usage(argv[0]);
            return 1;
        }
        api_key = argv[1];
        target = argv[2];
        for (int i = 3; i < argc; i++) args.emplace_back(argv[i]);
    }

    VTScanOptions opt;
    opt.recursive = !has_opt(args, "--no-recursive");
    opt.max_files = get_opt_int(args, "--max-files", opt.max_files);
    opt.max_mb = get_opt_double(args, "--max-mb", opt.max_mb);
    opt.out_report = get_opt_value(args, "--out",
                    get_opt_value(args, "--report", opt.out_report));
    opt.events_log = get_opt_value(args, "--events",
                    get_opt_value(args, "--log", opt.events_log));
    opt.promoted_log = get_opt_value(args, "--promoted", opt.promoted_log);
    opt.enable_quarantine = !has_opt(args, "--no-quarantine");
    opt.quarantine_dir = get_opt_value(args, "--quarantine-dir", opt.quarantine_dir);
    opt.between_uploads_ms = get_opt_int(args, "--sleep-ms", opt.between_uploads_ms);
    opt.poll_attempts = get_opt_int(args, "--poll-attempts",
                       get_opt_int(args, "--max-polls", opt.poll_attempts));
    opt.poll_sleep_sec = get_opt_int(args, "--poll-sleep",
                       get_opt_int(args, "--poll-seconds", opt.poll_sleep_sec));

    try {
        runVirusTotalScan(api_key, target, opt);
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
