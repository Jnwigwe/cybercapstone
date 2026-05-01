#ifndef SCANENGINE_H
#define SCANENGINE_H

#include <QObject>
#include <QVector>
#include <QString>
#include <QFileInfo>
#include <QThread>
#include "threattypes.h"

class ScanEngine : public QObject
{
    Q_OBJECT
    
public:
    explicit ScanEngine(QObject *parent = nullptr);
    ~ScanEngine();
    
    void scanFiles(const QStringList &filePaths);
    void stopScan();
    
    const ScanStatistics& getStatistics() const { return statistics; }
    const QVector<ScanResult>& getResults() const { return results; }
    const QVector<QString>& getLogs() const { return logs; }
    
signals:
    void scanStarted(int totalFiles);
    void fileScanned(const QString &fileName, int current, int total);
    void scanProgress(int percentage);
    void scanCompleted(const ScanStatistics &stats);
    void logMessage(const QString &message, const QString &level);
    
private:
    void performScan(const QStringList &filePaths);
    ScanResult scanFile(const QString &filePath);
    QString generateMD5Hash();
    
    ScanStatistics statistics;
    QVector<ScanResult> results;
    QVector<QString> logs;
    bool shouldStop;
};

#endif // SCANENGINE_H




