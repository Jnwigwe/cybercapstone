#include "mainwindow.h"

#include <QApplication>
#include <QFile>
#include <QTextStream>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    
    // Set application info
    QApplication::setApplicationName("Malware Scanner");
    QApplication::setApplicationVersion("2.5.0");
    QApplication::setOrganizationName("Security Solutions");
    
    // Load and apply stylesheet
    QFile styleFile(":/styles/darktheme.qss");
    if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
        QTextStream styleStream(&styleFile);
        a.setStyleSheet(styleStream.readAll());
        styleFile.close();
    }
    
    MainWindow w;
    w.show();
    return a.exec();
}




