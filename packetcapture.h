#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <QObject>
#include <QByteArray>
#include <QString>
#include <QVector>
#include <QColor>
#include <QDateTime>
#include <QElapsedTimer>
#include <QThread>
#include <QMutex>

struct DissectedField {
    QString label;
    QVector<QString> subFields;
};

struct DissectedPacket {
    quint64 number{0};
    double relTimeSec{0.0};
    QString timeStr;
    QString source;
    QString destination;
    QString protocol;
    int length{0};
    QString info;
    QByteArray rawData;
    QColor bgColor{"#ffffff"};
    QColor textColor{"#0f172a"};
    QVector<DissectedField> layers;
};

class PacketDissector
{
public:
    static DissectedPacket dissect(const QByteArray &data, quint64 num, double relTime, bool isEthernet = true);
    static QString formatHexDump(const QByteArray &data);

private:
    static QString parseDnsName(const unsigned char *buf, int len, int &offset);
};

class PacketCaptureWorker : public QObject
{
    Q_OBJECT
public:
    explicit PacketCaptureWorker(QObject *parent = nullptr);
    ~PacketCaptureWorker();

public slots:
    void startCapture(const QString &interfaceName);
    void stopCapture();
    void loadPcapFile(const QString &filePath);
    void savePcapFile(const QString &filePath, const QVector<QByteArray> &packets);

signals:
    void packetReceived(const DissectedPacket &packet);
    void captureStarted(const QString &interfaceName);
    void captureStopped(quint64 totalPackets);
    void captureError(const QString &error);
    void pcapLoaded(int count);

private slots:
    void pollLoop();

private:
    bool initRawSocket(const QString &interfaceIp);
    void captureSampleTraffic();

    bool mRunning{false};
    quint64 mPacketIndex{0};
    QElapsedTimer mElapsedTimer;
    QString mSelectedInterface;

#ifdef Q_OS_WIN
    uintptr_t mRawSocket{0}; // SOCKET
#endif
};

class PacketCaptureEngine : public QObject
{
    Q_OBJECT
public:
    explicit PacketCaptureEngine(QObject *parent = nullptr);
    ~PacketCaptureEngine();

    void start(const QString &interfaceName);
    void stop();
    void clear();
    void loadPcap(const QString &filePath);
    void savePcap(const QString &filePath);

    bool isCapturing() const { return mCapturing; }
    QStringList availableInterfaces() const;

signals:
    void packetAdded(const DissectedPacket &packet);
    void captureStateChanged(bool active);
    void statusMessage(const QString &msg);

private slots:
    void onPacketReceived(const DissectedPacket &packet);

private:
    QThread *mWorkerThread{nullptr};
    PacketCaptureWorker *mWorker{nullptr};
    bool mCapturing{false};
    QVector<QByteArray> mCapturedRawPackets;
};

#endif // PACKETCAPTURE_H
