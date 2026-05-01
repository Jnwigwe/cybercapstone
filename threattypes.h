#ifndef THREATTYPES_H
#define THREATTYPES_H

#include <QString>
#include <QDateTime>
#include <QVector>

enum class ThreatLevel {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW
};

enum class ThreatType {
    TROJAN,
    RANSOMWARE,
    SPYWARE,
    ADWARE,
    WORM,
    ROOTKIT,
    VIRUS,
    MALWARE
};

struct ScanResult {
    QString fileName;
    QString filePath;
    qint64 fileSize;
    bool isThreat;
    ThreatType threatType;
    ThreatLevel threatLevel;
    bool isQuarantined;
    bool isRemoved;
    bool isSuspicious;
};

struct ScanStatistics {
    int totalScanned = 0;
    int cleanFiles = 0;
    int threatsDetected = 0;
    int quarantined = 0;
    int removed = 0;
    int suspicious = 0;
    QDateTime scanStartTime;
    QDateTime scanEndTime;
};

struct QuarantineEntry {
    QString name;
    QString originalPath;
    qint64 size;
    QString fileType;
    ThreatType threatType;
    ThreatLevel threatLevel;
    QDateTime quarantineDate;
    QString md5Hash;
    QString quarantineId;
};

inline QString threatTypeToString(ThreatType type) {
    switch(type) {
        case ThreatType::TROJAN: return "Trojan";
        case ThreatType::RANSOMWARE: return "Ransomware";
        case ThreatType::SPYWARE: return "Spyware";
        case ThreatType::ADWARE: return "Adware";
        case ThreatType::WORM: return "Worm";
        case ThreatType::ROOTKIT: return "Rootkit";
        case ThreatType::VIRUS: return "Virus";
        case ThreatType::MALWARE: return "Malware";
        default: return "Unknown";
    }
}

inline QString threatLevelToString(ThreatLevel level) {
    switch(level) {
        case ThreatLevel::CRITICAL: return "CRITICAL";
        case ThreatLevel::HIGH: return "HIGH";
        case ThreatLevel::MEDIUM: return "MEDIUM";
        case ThreatLevel::LOW: return "LOW";
        default: return "UNKNOWN";
    }
}

inline QString formatFileSize(qint64 bytes) {
    if (bytes == 0) return "0 Bytes";
    const qint64 k = 1024;
    const QStringList sizes = {"Bytes", "KB", "MB", "GB", "TB"};
    int i = 0;
    double size = bytes;
    while (size >= k && i < sizes.size() - 1) {
        size /= k;
        i++;
    }
    return QString("%1 %2").arg(QString::number(size, 'f', 2)).arg(sizes[i]);
}

#endif // THREATTYPES_H




