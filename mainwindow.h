#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QButtonGroup>
#include <QTimer>
#include <QThread>
#include <QJsonObject>
#include <QJsonArray>
#include <QProcess>

#include "packetcapture.h"

class ThroughputGraphWidget;
class NetworkTelemetry;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onNavButtonClicked(QAbstractButton *btn);
    void onClockTick();
    void onTelemetryUpdated(const QJsonObject &data);
    void onQuickScanFinished(const QJsonArray &devices);
    void onActionStatus(const QString &message, bool success);

    // Wireshark Packet Analyzer Slots
    void onCaptureStartClicked();
    void onCaptureStopClicked();
    void onCaptureRestartClicked();
    void onCaptureClearClicked();
    void onApplyPacketFilterClicked();
    void onClearPacketFilterClicked();
    void onOpenPcapClicked();
    void onSavePcapClicked();
    void onPacketSelected(int row, int col);
    void onPacketAdded(const DissectedPacket &packet);
    void onCaptureStateChanged(bool active);

    // Tools Page
    void onToolPingClicked();
    void onToolTracerouteClicked();
    void onToolDnsClicked();
    void onToolFlushDnsClicked();
    void onClearConsoleClicked();

    // Ports Page
    void onSearchTextChanged(const QString &query);
    void onRefreshSocketsClicked();

    // Settings & About
    void onApplySettingsClicked();
    void onAboutClicked();

private:
    void setupUiCustomizations();
    void setupPacketAnalyzer();
    void refreshPacketTable();
    bool matchesFilter(const DissectedPacket &pkt, const QString &filter);
    void displayPacketDetails(const DissectedPacket &pkt);

    void updateGreeting();
    void updateSocketsTables();
    void appendConsole(const QString &text, const QString &color = "#38bdf8");

    Ui::MainWindow *ui;
    QButtonGroup *mNavGroup{nullptr};
    QTimer *mClockTimer{nullptr};

    ThroughputGraphWidget *mGraphWidget{nullptr};

    QThread *mTelemetryThread{nullptr};
    NetworkTelemetry *mTelemetry{nullptr};

    // Packet Analyzer Engine
    PacketCaptureEngine *mPacketEngine{nullptr};
    QVector<DissectedPacket> mAllPackets;
    QVector<int> mDisplayedIndices;
    QString mCurrentFilter;

    QProcess *mToolProcess{nullptr};

    QString mUnits{"Mbps"};
    double mPeakDown{0.0};
    double mPeakUp{0.0};

    QJsonObject mLastTelemetry;
};

#endif // MAINWINDOW_H
