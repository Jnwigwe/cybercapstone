#include "scanengine.h"
#include <QFile>
#include <QFileInfo>
#include <QThread>
#include <QRandomGenerator>
#include <QCryptographicHash>

ScanEngine::ScanEngine(QObject *parent)
    : QObject(parent), shouldStop(false)
{
}

ScanEngine::~ScanEngine()
{
}

void ScanEngine::scanFiles(const QStringList &filePaths)
{
    shouldStop = false;
    results.clear();
    logs.clear();
    
    statistics = ScanStatistics();
    statistics.scanStartTime = QDateTime::currentDateTime();
    statistics.totalScanned = 0;
    
    emit scanStarted(filePaths.size());
    emit logMessage("==================== SCAN INITIATED ====================", "success");
    emit logMessage(QString("Scan started at: %1").arg(statistics.scanStartTime.toString()), "info");
    emit logMessage(QString("Total files to scan: %1").arg(filePaths.size()), "info");
    
    performScan(filePaths);
}

void ScanEngine::stopScan()
{
    shouldStop = true;
}

void ScanEngine::performScan(const QStringList &filePaths)
{
    int totalFiles = filePaths.size();
    
    for (int i = 0; i < totalFiles && !shouldStop; ++i) {
        const QString &filePath = filePaths[i];
        QFileInfo fileInfo(filePath);
        
        emit fileScanned(fileInfo.fileName(), i + 1, totalFiles);
        emit logMessage(QString("Scanning file [%1/%2]: %3")
            .arg(i + 1).arg(totalFiles).arg(filePath), "info");
        
        ScanResult result = scanFile(filePath);
        results.append(result);
        
        // Update statistics
        statistics.totalScanned++;
        
        if (result.isThreat) {
            statistics.threatsDetected++;
            
            if (result.isQuarantined) {
                statistics.quarantined++;
                emit logMessage(QString("  └─ ⚠️ THREAT DETECTED [%1] - File QUARANTINED")
                    .arg(threatTypeToString(result.threatType)), "error");
            } else if (result.isRemoved) {
                statistics.removed++;
                emit logMessage(QString("  └─ ⚠️ THREAT DETECTED [%1] - File REMOVED")
                    .arg(threatTypeToString(result.threatType)), "error");
            } else if (result.isSuspicious) {
                statistics.suspicious++;
                emit logMessage(QString("  └─ ⚠️ SUSPICIOUS FILE detected [Potential %1]")
                    .arg(threatTypeToString(result.threatType)), "warning");
            }
        } else {
            statistics.cleanFiles++;
            emit logMessage("  └─ ✓ Clean - No threats detected", "success");
        }
        
        // Calculate progress
        int progress = ((i + 1) * 100) / totalFiles;
        emit scanProgress(progress);
        
        // Simulate scan time (100-300ms per file)
        QThread::msleep(QRandomGenerator::global()->bounded(100, 300));
    }
    
    statistics.scanEndTime = QDateTime::currentDateTime();
    
    emit logMessage("==================== SCAN COMPLETED ====================", "success");
    emit logMessage(QString("Scan finished at: %1").arg(statistics.scanEndTime.toString()), "info");
    emit logMessage(QString("Total files scanned: %1").arg(statistics.totalScanned), "success");
    
    emit scanCompleted(statistics);
}

ScanResult ScanEngine::scanFile(const QString &filePath)
{
    ScanResult result;
    QFileInfo fileInfo(filePath);
    
    result.fileName = fileInfo.fileName();
    result.filePath = filePath;
    result.fileSize = fileInfo.size();
    
    emit logMessage(QString("  ├─ Size: %1").arg(formatFileSize(result.fileSize)), "info");
    emit logMessage(QString("  ├─ Type: %1").arg(fileInfo.suffix()), "info");
    
    // Simulate threat detection (5% chance)
    result.isThreat = (QRandomGenerator::global()->bounded(100) < 5);
    
    if (result.isThreat) {
        // Random threat type
        int threatTypeRand = QRandomGenerator::global()->bounded(8);
        result.threatType = static_cast<ThreatType>(threatTypeRand);
        
        // Random threat level
        int threatLevelRand = QRandomGenerator::global()->bounded(3);
        result.threatLevel = static_cast<ThreatLevel>(threatLevelRand);
        
        // Random action
        int action = QRandomGenerator::global()->bounded(100);
        if (action < 60) {
            result.isQuarantined = true;
        } else if (action < 85) {
            result.isRemoved = true;
        } else {
            result.isSuspicious = true;
        }
    }
    
    return result;
}

QString ScanEngine::generateMD5Hash()
{
    QString hash;
    for (int i = 0; i < 32; ++i) {
        hash += QString::number(QRandomGenerator::global()->bounded(16), 16);
    }
    return hash;
}




