#ifndef NETTELEMETRY_H
#define NETTELEMETRY_H

#include <QObject>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>
#include <QProcess>
#include <QVector>

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <windows.h>
#endif

class NetworkTelemetry : public QObject
{
    Q_OBJECT
public:
    explicit NetworkTelemetry(QObject *parent = nullptr);
    ~NetworkTelemetry();

public slots:
    void start();
    void stop();
    void setRefreshInterval(int seconds);
    void runQuickScan();
    void flushDns();

signals:
    void telemetryUpdated(const QJsonObject &data);
    void quickScanFinished(const QJsonArray &devices);
    void actionStatus(const QString &message, bool success);

private slots:
    void onTick();
    void onWslDataReady();
    void onWslProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);

private:
    void collectWindowsTelemetry(QJsonObject &out);
    void discoverPrimaryAdapter();
    void checkHostMonitorsRoundRobin(QJsonObject &out);
    void startWslStream();
    double pingHost(const QString &ip, int timeoutMs = 40);

    QTimer *mTimer{nullptr};
    int mIntervalMs{1000};

    quint64 mPrevRxBytes{0};
    quint64 mPrevTxBytes{0};
    qint64 mPrevTimestampMs{0};
    bool mHasPrevCounters{false};

    double mPeakDown{0.0};
    double mPeakUp{0.0};

    QProcess *mWslProcess{nullptr};
    QByteArray mWslBuffer;
    bool mWslAvailable{false};

    QString mLocalIp{"172.18.144.100"};
    QString mGatewayIp{"172.18.144.1"};
    QString mDnsIp{"8.8.8.8"};

#ifdef Q_OS_WIN
    HANDLE mIcmpHandle{INVALID_HANDLE_VALUE};
#endif

    struct HostStatus {
        QString name;
        QString ip;
        bool online{true};
        double latencyMs{1.5};
    };
    QVector<HostStatus> mCachedHosts;
    int mHostCheckIndex{0};
    double mGatewayLatency{1.2};
};

#endif // NETTELEMETRY_H
