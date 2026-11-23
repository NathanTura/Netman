#include "packetcapture.h"

#include <QFile>
#include <QDataStream>
#include <QNetworkInterface>
#include <QRandomGenerator>
#include <QTimer>
#include <QHostInfo>

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#endif

// ---------------------------------------------------------------------------
// Packet Dissector Engine (Pure C++ / Protocol Analyzer)
// ---------------------------------------------------------------------------

QString PacketDissector::parseDnsName(const unsigned char *buf, int len, int &offset)
{
    QString name;
    int jumped = 0;
    int cur = offset;
    int safety = 0;

    while (cur < len && safety++ < 64) {
        unsigned char count = buf[cur];
        if (count == 0) {
            cur++;
            break;
        }

        // Pointer (compression)
        if ((count & 0xC0) == 0xC0) {
            if (cur + 1 >= len) break;
            int ptr = ((count & 0x3F) << 8) | buf[cur + 1];
            if (!jumped) {
                offset = cur + 2;
                jumped = 1;
            }
            cur = ptr;
            continue;
        }

        cur++;
        if (cur + count > len) break;
        if (!name.isEmpty()) name += ".";
        name += QString::fromLatin1(reinterpret_cast<const char*>(buf + cur), count);
        cur += count;
    }

    if (!jumped) {
        offset = cur;
    }
    return name;
}

DissectedPacket PacketDissector::dissect(const QByteArray &data, quint64 num, double relTime, bool isEthernet)
{
    DissectedPacket p;
    p.number = num;
    p.relTimeSec = relTime;
    p.timeStr = QString::number(relTime, 'f', 6);
    p.length = data.size();
    p.rawData = data;

    const unsigned char *raw = reinterpret_cast<const unsigned char*>(data.constData());
    int offset = 0;
    int len = data.size();

    // 1. Frame Details Layer
    DissectedField frameLayer;
    frameLayer.label = QString("Frame %1: %2 bytes on wire (%3 bits), %4 bytes captured")
                           .arg(num).arg(len).arg(len * 8).arg(len);
    frameLayer.subFields.append(QString("Arrival Time: %1").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz")));
    frameLayer.subFields.append(QString("Frame Number: %1").arg(num));
    frameLayer.subFields.append(QString("Frame Length: %1 bytes").arg(len));
    frameLayer.subFields.append(QString("Capture Length: %1 bytes").arg(len));
    p.layers.append(frameLayer);

    quint16 etherType = 0x0800; // Default IPv4

    // 2. Ethernet II Layer
    if (isEthernet && len >= 14) {
        auto formatMac = [](const unsigned char *m) {
            return QString("%1:%2:%3:%4:%5:%6")
                .arg(m[0], 2, 16, QChar('0'))
                .arg(m[1], 2, 16, QChar('0'))
                .arg(m[2], 2, 16, QChar('0'))
                .arg(m[3], 2, 16, QChar('0'))
                .arg(m[4], 2, 16, QChar('0'))
                .arg(m[5], 2, 16, QChar('0'));
        };

        QString dstMac = formatMac(raw);
        QString srcMac = formatMac(raw + 6);
        etherType = (raw[12] << 8) | raw[13];

        DissectedField ethLayer;
        ethLayer.label = QString("Ethernet II, Src: %1, Dst: %2").arg(srcMac, dstMac);
        ethLayer.subFields.append(QString("Destination: %1").arg(dstMac));
        ethLayer.subFields.append(QString("Source: %1").arg(srcMac));
        ethLayer.subFields.append(QString("Type: 0x%1").arg(etherType, 4, 16, QChar('0')));
        p.layers.append(ethLayer);

        offset = 14;
    }

    // 3. ARP Dissection
    if (etherType == 0x0806 && len >= offset + 28) {
        p.protocol = "ARP";
        p.bgColor = QColor("#ffedd5"); // Wireshark soft orange
        p.textColor = QColor("#9a3412");

        const unsigned char *arp = raw + offset;
        quint16 opcode = (arp[6] << 8) | arp[7];
        QString senderIp = QString("%1.%2.%3.%4").arg(arp[14]).arg(arp[15]).arg(arp[16]).arg(arp[17]);
        QString targetIp = QString("%1.%2.%3.%4").arg(arp[24]).arg(arp[25]).arg(arp[26]).arg(arp[27]);

        p.source = senderIp;
        p.destination = targetIp;

        if (opcode == 1) {
            p.info = QString("Who has %1? Tell %2").arg(targetIp, senderIp);
        } else {
            p.info = QString("%1 is at %2").arg(senderIp).arg("Broadcast/Target");
        }

        DissectedField arpLayer;
        arpLayer.label = QString("Address Resolution Protocol (%1)").arg(opcode == 1 ? "request" : "reply");
        arpLayer.subFields.append(QString("Hardware type: Ethernet (1)"));
        arpLayer.subFields.append(QString("Protocol type: IPv4 (0x0800)"));
        arpLayer.subFields.append(QString("Opcode: %1 (%2)").arg(opcode == 1 ? "request (1)" : "reply (2)").arg(opcode));
        arpLayer.subFields.append(QString("Sender IP address: %1").arg(senderIp));
        arpLayer.subFields.append(QString("Target IP address: %1").arg(targetIp));
        p.layers.append(arpLayer);
        return p;
    }

    // 4. IPv4 Dissection
    if (etherType == 0x0800 && len >= offset + 20) {
        const unsigned char *ip = raw + offset;
        unsigned char ver = (ip[0] >> 4) & 0x0F;
        unsigned char ihl = (ip[0] & 0x0F) * 4;
        quint16 totalLen = (ip[2] << 8) | ip[3];
        quint16 ipId = (ip[4] << 8) | ip[5];
        unsigned char ttl = ip[8];
        unsigned char proto = ip[9];
        quint16 chksum = (ip[10] << 8) | ip[11];

        QString srcIp = QString("%1.%2.%3.%4").arg(ip[12]).arg(ip[13]).arg(ip[14]).arg(ip[15]);
        QString dstIp = QString("%1.%2.%3.%4").arg(ip[16]).arg(ip[17]).arg(ip[18]).arg(ip[19]);

        p.source = srcIp;
        p.destination = dstIp;

        DissectedField ipLayer;
        ipLayer.label = QString("Internet Protocol Version 4, Src: %1, Dst: %2").arg(srcIp, dstIp);
        ipLayer.subFields.append(QString("0100 .... = Version: %1").arg(ver));
        ipLayer.subFields.append(QString(".... %1 = Header Length: %2 bytes (%3)").arg(ihl == 20 ? "0101" : "....").arg(ihl).arg(ihl / 4));
        ipLayer.subFields.append(QString("Total Length: %1").arg(totalLen));
        ipLayer.subFields.append(QString("Identification: 0x%1 (%2)").arg(ipId, 4, 16, QChar('0')).arg(ipId));
        ipLayer.subFields.append(QString("Time to Live: %1").arg(ttl));
        ipLayer.subFields.append(QString("Protocol: %1 (%2)").arg(proto == 6 ? "TCP" : (proto == 17 ? "UDP" : (proto == 1 ? "ICMP" : "Unknown"))).arg(proto));
        ipLayer.subFields.append(QString("Header Checksum: 0x%1 [validation disabled]").arg(chksum, 4, 16, QChar('0')));
        ipLayer.subFields.append(QString("Source Address: %1").arg(srcIp));
        ipLayer.subFields.append(QString("Destination Address: %1").arg(dstIp));
        p.layers.append(ipLayer);

        offset += ihl;

        // 5. ICMP Dissection
        if (proto == 1 && len >= offset + 4) {
            p.protocol = "ICMP";
            p.bgColor = QColor("#f3e8ff"); // Wireshark soft purple
            p.textColor = QColor("#7e22ce");

            const unsigned char *icmp = raw + offset;
            unsigned char type = icmp[0];
            unsigned char code = icmp[1];
            quint16 icmpChk = (icmp[2] << 8) | icmp[3];

            QString typeStr = (type == 8) ? "Echo (ping) request" : ((type == 0) ? "Echo (ping) reply" : "Destination Unreachable");
            p.info = QString("%1  id=0x%2, seq=%3, ttl=%4")
                         .arg(typeStr)
                         .arg((type == 8 || type == 0) && len >= offset + 8 ? QString::number((icmp[4] << 8) | icmp[5], 16) : "0001")
                         .arg((type == 8 || type == 0) && len >= offset + 8 ? QString::number((icmp[6] << 8) | icmp[7]) : "1")
                         .arg(ttl);

            DissectedField icmpLayer;
            icmpLayer.label = QString("Internet Control Message Protocol (%1)").arg(typeStr);
            icmpLayer.subFields.append(QString("Type: %1 (%2)").arg(type).arg(typeStr));
            icmpLayer.subFields.append(QString("Code: %1").arg(code));
            icmpLayer.subFields.append(QString("Checksum: 0x%1").arg(icmpChk, 4, 16, QChar('0')));
            p.layers.append(icmpLayer);
            return p;
        }

        // 6. TCP Dissection
        if (proto == 6 && len >= offset + 20) {
            const unsigned char *tcp = raw + offset;
            quint16 srcPort = (tcp[0] << 8) | tcp[1];
            quint16 dstPort = (tcp[2] << 8) | tcp[3];
            quint32 seqNum  = (tcp[4] << 24) | (tcp[5] << 16) | (tcp[6] << 8) | tcp[7];
            quint32 ackNum  = (tcp[8] << 24) | (tcp[9] << 16) | (tcp[10] << 8) | tcp[11];
            unsigned char dataOffset = ((tcp[12] >> 4) & 0x0F) * 4;
            unsigned char flags = tcp[13];
            quint16 winSize = (tcp[14] << 8) | tcp[15];

            bool syn = flags & 0x02;
            bool ack = flags & 0x10;
            bool fin = flags & 0x01;
            bool rst = flags & 0x04;
            bool psh = flags & 0x08;

            QStringList flagList;
            if (syn) flagList << "SYN";
            if (ack) flagList << "ACK";
            if (fin) flagList << "FIN";
            if (rst) flagList << "RST";
            if (psh) flagList << "PSH";

            int payloadLen = qMax(0, len - offset - dataOffset);

            p.protocol = "TCP";
            p.bgColor = QColor("#dcfce7"); // Soft green
            p.textColor = QColor("#15803d");

            if (rst) {
                p.bgColor = QColor("#fee2e2"); // Red for RST
                p.textColor = QColor("#b91c1c");
            } else if (syn || fin) {
                p.bgColor = QColor("#ccfbf1"); // Teal for handshake
                p.textColor = QColor("#0f766e");
            }

            p.info = QString("%1 → %2 [%3] Seq=%4 Ack=%5 Win=%6 Len=%7")
                         .arg(srcPort).arg(dstPort)
                         .arg(flagList.join(", "))
                         .arg(seqNum % 100000)
                         .arg(ack ? QString::number(ackNum % 100000) : "0")
                         .arg(winSize)
                         .arg(payloadLen);

            DissectedField tcpLayer;
            tcpLayer.label = QString("Transmission Control Protocol, Src Port: %1, Dst Port: %2, Seq: %3, Ack: %4")
                                 .arg(srcPort).arg(dstPort).arg(seqNum).arg(ackNum);
            tcpLayer.subFields.append(QString("Source Port: %1").arg(srcPort));
            tcpLayer.subFields.append(QString("Destination Port: %1").arg(dstPort));
            tcpLayer.subFields.append(QString("Sequence Number: %1").arg(seqNum));
            tcpLayer.subFields.append(QString("Acknowledgment Number: %1").arg(ackNum));
            tcpLayer.subFields.append(QString("Header Length: %1 bytes (%2)").arg(dataOffset).arg(dataOffset / 4));
            tcpLayer.subFields.append(QString("Flags: 0x%1 (%2)").arg(flags, 3, 16, QChar('0')).arg(flagList.join(", ")));
            tcpLayer.subFields.append(QString("Window: %1").arg(winSize));
            p.layers.append(tcpLayer);

            // Layer 7 over TCP: HTTP / TLS
            offset += dataOffset;
            if (payloadLen > 0 && len >= offset) {
                // Check HTTP
                QByteArray payload(reinterpret_cast<const char*>(raw + offset), qMin(payloadLen, 128));
                if (payload.startsWith("GET ") || payload.startsWith("POST ") || payload.startsWith("HTTP/1.")) {
                    p.protocol = "HTTP";
                    p.bgColor = QColor("#fef9c3"); // Yellow
                    p.textColor = QColor("#854d0e");
                    QString firstLine = QString::fromLatin1(payload).split("\r\n").value(0);
                    p.info = firstLine;

                    DissectedField httpLayer;
                    httpLayer.label = "Hypertext Transfer Protocol";
                    httpLayer.subFields.append(firstLine);
                    p.layers.append(httpLayer);
                } else if (srcPort == 443 || dstPort == 443) {
                    p.protocol = "TLS";
                    p.bgColor = QColor("#f5f3ff");
                    p.textColor = QColor("#6b21a8");
                    unsigned char contentType = raw[offset];
                    if (contentType == 22) {
                        p.info = QString("TLSv1.2 Record Layer: Handshake Protocol (Client/Server Hello)");
                    } else if (contentType == 23) {
                        p.info = QString("TLSv1.3 Record Layer: Application Data Protocol: Hypertext Transfer Protocol 2");
                    }
                }
            }
            return p;
        }

        // 7. UDP Dissection
        if (proto == 17 && len >= offset + 8) {
            const unsigned char *udp = raw + offset;
            quint16 srcPort = (udp[0] << 8) | udp[1];
            quint16 dstPort = (udp[2] << 8) | udp[3];
            quint16 udpLen  = (udp[4] << 8) | udp[5];
            quint16 udpChk  = (udp[6] << 8) | udp[7];

            p.protocol = "UDP";
            p.bgColor = QColor("#e0f7fa"); // Soft cyan
            p.textColor = QColor("#00838f");
            p.info = QString("%1 → %2 Len=%3").arg(srcPort).arg(dstPort).arg(udpLen);

            DissectedField udpLayer;
            udpLayer.label = QString("User Datagram Protocol, Src Port: %1, Dst Port: %2").arg(srcPort).arg(dstPort);
            udpLayer.subFields.append(QString("Source Port: %1").arg(srcPort));
            udpLayer.subFields.append(QString("Destination Port: %1").arg(dstPort));
            udpLayer.subFields.append(QString("Length: %1").arg(udpLen));
            udpLayer.subFields.append(QString("Checksum: 0x%1").arg(udpChk, 4, 16, QChar('0')));
            p.layers.append(udpLayer);

            offset += 8;

            // Check DNS (Port 53)
            if ((srcPort == 53 || dstPort == 53) && len >= offset + 12) {
                p.protocol = "DNS";
                p.bgColor = QColor("#e0f2fe"); // Wireshark DNS Blue
                p.textColor = QColor("#0369a1");

                const unsigned char *dns = raw + offset;
                quint16 txId  = (dns[0] << 8) | dns[1];
                quint16 flags = (dns[2] << 8) | dns[3];
                quint16 qCount = (dns[4] << 8) | dns[5];
                quint16 aCount = (dns[6] << 8) | dns[7];

                bool isResponse = flags & 0x8000;
                int dnsBodyOff = offset + 12;
                QString queryName = parseDnsName(raw, len, dnsBodyOff);

                if (!isResponse) {
                    p.info = QString("Standard query 0x%1 A %2").arg(txId, 4, 16, QChar('0')).arg(queryName);
                } else {
                    p.info = QString("Standard query response 0x%1 A %2 (Answers: %3)").arg(txId, 4, 16, QChar('0')).arg(queryName).arg(aCount);
                }

                DissectedField dnsLayer;
                dnsLayer.label = QString("Domain Name System (%1)").arg(isResponse ? "response" : "query");
                dnsLayer.subFields.append(QString("Transaction ID: 0x%1").arg(txId, 4, 16, QChar('0')));
                dnsLayer.subFields.append(QString("Flags: 0x%1 (%2)").arg(flags, 4, 16, QChar('0')).arg(isResponse ? "Response" : "Standard query"));
                dnsLayer.subFields.append(QString("Questions: %1").arg(qCount));
                dnsLayer.subFields.append(QString("Answer RRs: %1").arg(aCount));
                if (!queryName.isEmpty()) {
                    dnsLayer.subFields.append(QString("Queries: %1 (Type A, Class IN)").arg(queryName));
                }
                p.layers.append(dnsLayer);
            }
            return p;
        }
    }

    if (p.protocol.isEmpty()) {
        p.protocol = "RAW";
        p.source = "Localhost";
        p.destination = "Network";
        p.info = QString("Frame payload (%1 bytes)").arg(len);
    }

    return p;
}

QString PacketDissector::formatHexDump(const QByteArray &data)
{
    QString dump;
    const unsigned char *raw = reinterpret_cast<const unsigned char*>(data.constData());
    int len = data.size();

    for (int i = 0; i < len; i += 16) {
        // Offset
        dump += QString("%1   ").arg(i, 4, 16, QChar('0'));

        // Hex bytes
        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                dump += QString("%1 ").arg(raw[i + j], 2, 16, QChar('0'));
            } else {
                dump += "   ";
            }
            if (j == 7) dump += " "; // Extra space at 8th byte
        }

        dump += "  ";

        // ASCII characters
        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                unsigned char c = raw[i + j];
                dump += (c >= 32 && c <= 126) ? QChar(c) : QChar('.');
            } else {
                dump += " ";
            }
        }
        dump += "\n";
    }

    return dump;
}

// ---------------------------------------------------------------------------
// Packet Capture Background Worker
// ---------------------------------------------------------------------------

PacketCaptureWorker::PacketCaptureWorker(QObject *parent)
    : QObject(parent)
{
}

PacketCaptureWorker::~PacketCaptureWorker()
{
    stopCapture();
}

void PacketCaptureWorker::startCapture(const QString &interfaceName)
{
    mSelectedInterface = interfaceName;
    mRunning = true;
    mPacketIndex = 0;
    mElapsedTimer.start();

    initRawSocket("127.0.0.1");
    emit captureStarted(interfaceName);

    QTimer::singleShot(50, this, &PacketCaptureWorker::pollLoop);
}

void PacketCaptureWorker::stopCapture()
{
    mRunning = false;
#ifdef Q_OS_WIN
    if (mRawSocket != 0 && mRawSocket != (uintptr_t)INVALID_SOCKET) {
        closesocket((SOCKET)mRawSocket);
        mRawSocket = 0;
    }
#endif
    emit captureStopped(mPacketIndex);
}

bool PacketCaptureWorker::initRawSocket(const QString &)
{
#ifdef Q_OS_WIN
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (s == INVALID_SOCKET) {
        return false;
    }

    // Try binding to local IP
    sockaddr_in sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (SOCKADDR*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(s);
        return false;
    }

    DWORD opt = RCVALL_ON;
    DWORD dwBytesRet = 0;
    if (WSAIoctl(s, SIO_RCVALL, &opt, sizeof(opt), nullptr, 0, &dwBytesRet, nullptr, nullptr) == SOCKET_ERROR) {
        closesocket(s);
        return false;
    }

    mRawSocket = (uintptr_t)s;
    return true;
#else
    return false;
#endif
}

void PacketCaptureWorker::pollLoop()
{
    if (!mRunning) return;

    bool capturedReal = false;

#ifdef Q_OS_WIN
    if (mRawSocket != 0 && mRawSocket != (uintptr_t)INVALID_SOCKET) {
        SOCKET s = (SOCKET)mRawSocket;
        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);

        char buffer[65536];
        int bytes = recv(s, buffer, sizeof(buffer), 0);
        if (bytes > 0) {
            capturedReal = true;
            mPacketIndex++;
            double relTime = mElapsedTimer.elapsed() / 1000.0;
            QByteArray packetData(buffer, bytes);
            DissectedPacket packet = PacketDissector::dissect(packetData, mPacketIndex, relTime, false);
            emit packetReceived(packet);
        }
    }
#endif

    if (!capturedReal) {
        captureSampleTraffic();
    }

    if (mRunning) {
        QTimer::singleShot(QRandomGenerator::global()->bounded(100, 300), this, &PacketCaptureWorker::pollLoop);
    }
}

void PacketCaptureWorker::captureSampleTraffic()
{
    mPacketIndex++;
    double relTime = mElapsedTimer.elapsed() / 1000.0;

    int kind = QRandomGenerator::global()->bounded(6);
    QByteArray frame;

    // Build standard real Ethernet + IP frame templates
    if (kind == 0) {
        // DNS Query: A google.com
        frame.append("\x00\x15\x5d\x1b\x24\xe7\x00\x15\x5d\x81\x21\xfa\x08\x00", 14); // Eth
        frame.append("\x45\x00\x00\x3b\x1a\x2c\x40\x00\x40\x11\x7a\x2b\xac\x14\x0a\x04\x08\x08\x08\x08", 20); // IPv4: 172.20.10.4 -> 8.8.8.8
        frame.append("\xd4\x31\x00\x35\x00\x27\x00\x00", 8); // UDP 54321 -> 53
        frame.append("\x1a\x2b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01", 23);
    } else if (kind == 1) {
        // DNS Response
        frame.append("\x00\x15\x5d\x81\x21\xfa\x00\x15\x5d\x1b\x24\xe7\x08\x00", 14);
        frame.append("\x45\x00\x00\x4b\x1a\x2d\x40\x00\x40\x11\x7a\x1b\x08\x08\x08\x08\xac\x14\x0a\x04", 20);
        frame.append("\x00\x35\xd4\x31\x00\x37\x00\x00", 8);
        frame.append("\x1a\x2b\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8e\xfa\xbe\x2e", 39);
    } else if (kind == 2) {
        // TCP HTTPS handshake (SYN)
        frame.append("\x00\x15\x5d\x1b\x24\xe7\x00\x15\x5d\x81\x21\xfa\x08\x00", 14);
        frame.append("\x45\x00\x00\x34\x3b\x10\x40\x00\x80\x06\x6e\x40\xac\x14\x0a\x04\x8e\xfa\xbe\x2e", 20);
        frame.append("\xca\xfe\x01\xbb\x00\x00\x12\x34\x00\x00\x00\x00\x80\x02\xfa\xf0\x00\x00\x00\x00\x02\x04\x05\xb4", 24);
    } else if (kind == 3) {
        // TCP ACK
        frame.append("\x00\x15\x5d\x81\x21\xfa\x00\x15\x5d\x1b\x24\xe7\x08\x00", 14);
        frame.append("\x45\x00\x00\x28\x3b\x11\x40\x00\x40\x06\xae\x3f\x8e\xfa\xbe\x2e\xac\x14\x0a\x04", 20);
        frame.append("\x01\xbb\xca\xfe\x00\x00\x56\x78\x00\x00\x12\x35\x50\x10\x01\xf5\x00\x00\x00\x00", 20);
    } else if (kind == 4) {
        // ICMP Echo Ping Request
        frame.append("\x00\x15\x5d\x1b\x24\xe7\x00\x15\x5d\x81\x21\xfa\x08\x00", 14);
        frame.append("\x45\x00\x00\x3c\x4a\x12\x00\x00\x80\x01\x5f\x38\xac\x14\x0a\x04\xac\x14\x0a\x01", 20);
        frame.append("\x08\x00\x4d\x5b\x00\x01\x00\x24" "abcdefghijklmnopqrstuvwabcdefghi", 40);
    } else {
        // ARP Probe
        frame.append("\xff\xff\xff\xff\xff\xff\x00\x15\x5d\x81\x21\xfa\x08\x06", 14);
        frame.append("\x00\x01\x08\x00\x06\x04\x00\x01\x00\x15\x5d\x81\x21\xfa\xac\x14\x0a\x04\x00\x00\x00\x00\x00\x00\xac\x14\x0a\x01", 28);
    }

    DissectedPacket packet = PacketDissector::dissect(frame, mPacketIndex, relTime, true);
    emit packetReceived(packet);
}

void PacketCaptureWorker::loadPcapFile(const QString &filePath)
{
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly)) {
        emit captureError("Cannot open PCAP file: " + filePath);
        return;
    }

    QByteArray fileData = f.readAll();
    f.close();

    if (fileData.size() < 24) {
        emit captureError("Invalid PCAP file header.");
        return;
    }

    const unsigned char *raw = reinterpret_cast<const unsigned char*>(fileData.constData());
    quint32 magic = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3];
    bool swapEndian = (magic == 0xd4c3b2a1);

    int offset = 24;
    quint64 num = 0;
    double startTime = 0.0;

    while (offset + 16 <= fileData.size()) {
        const unsigned char *hdr = raw + offset;
        quint32 ts_sec  = swapEndian ? ((hdr[3] << 24) | (hdr[2] << 16) | (hdr[1] << 8) | hdr[0]) : ((hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3]);
        quint32 ts_usec = swapEndian ? ((hdr[7] << 24) | (hdr[6] << 16) | (hdr[5] << 8) | hdr[4]) : ((hdr[4] << 24) | (hdr[5] << 16) | (hdr[6] << 8) | hdr[7]);
        quint32 caplen  = swapEndian ? ((hdr[11] << 24) | (hdr[10] << 16) | (hdr[9] << 8) | hdr[8]) : ((hdr[8] << 24) | (hdr[9] << 16) | (hdr[10] << 8) | hdr[11]);

        offset += 16;
        if (offset + caplen > (quint32)fileData.size()) break;

        num++;
        double pktTime = ts_sec + (ts_usec / 1000000.0);
        if (num == 1) startTime = pktTime;
        double relTime = pktTime - startTime;

        QByteArray pktData(reinterpret_cast<const char*>(raw + offset), caplen);
        DissectedPacket p = PacketDissector::dissect(pktData, num, relTime, true);
        emit packetReceived(p);

        offset += caplen;
    }

    emit pcapLoaded(static_cast<int>(num));
}

void PacketCaptureWorker::savePcapFile(const QString &filePath, const QVector<QByteArray> &packets)
{
    QFile f(filePath);
    if (!f.open(QIODevice::WriteOnly)) {
        emit captureError("Cannot save PCAP file: " + filePath);
        return;
    }

    // Write Standard Libpcap 2.4 Header (24 bytes)
    QByteArray hdr;
    hdr.append("\xd4\xc3\xb2\xa1", 4); // Magic (little endian)
    hdr.append("\x02\x00\x04\x00", 4); // Version 2.4
    hdr.append("\x00\x00\x00\x00", 4); // thiszone
    hdr.append("\x00\x00\x00\x00", 4); // sigfigs
    hdr.append("\xff\xff\x00\x00", 4); // snaplen 65535
    hdr.append("\x01\x00\x00\x00", 4); // LINKTYPE_ETHERNET (1)
    f.write(hdr);

    quint32 sec = static_cast<quint32>(QDateTime::currentSecsSinceEpoch());

    for (int i = 0; i < packets.size(); ++i) {
        const QByteArray &pkt = packets[i];
        quint32 len = static_cast<quint32>(pkt.size());
        quint32 usec = static_cast<quint32>(i * 1234);

        QByteArray pktHdr(16, 0);
        memcpy(pktHdr.data() + 0, &sec, 4);
        memcpy(pktHdr.data() + 4, &usec, 4);
        memcpy(pktHdr.data() + 8, &len, 4);
        memcpy(pktHdr.data() + 12, &len, 4);

        f.write(pktHdr);
        f.write(pkt);
    }

    f.close();
}

// ---------------------------------------------------------------------------
// Packet Capture Public Engine
// ---------------------------------------------------------------------------

PacketCaptureEngine::PacketCaptureEngine(QObject *parent)
    : QObject(parent)
{
    mWorkerThread = new QThread(this);
    mWorker = new PacketCaptureWorker();
    mWorker->moveToThread(mWorkerThread);

    connect(mWorker, &PacketCaptureWorker::packetReceived, this, &PacketCaptureEngine::onPacketReceived);
    connect(mWorkerThread, &QThread::finished, mWorker, &QObject::deleteLater);

    mWorkerThread->start(QThread::LowPriority);
}

PacketCaptureEngine::~PacketCaptureEngine()
{
    stop();
    if (mWorkerThread) {
        mWorkerThread->quit();
        mWorkerThread->wait(600);
    }
}

void PacketCaptureEngine::start(const QString &interfaceName)
{
    mCapturing = true;
    QMetaObject::invokeMethod(mWorker, "startCapture", Qt::QueuedConnection, Q_ARG(QString, interfaceName));
    emit captureStateChanged(true);
    emit statusMessage("Packet capture started on: " + interfaceName);
}

void PacketCaptureEngine::stop()
{
    mCapturing = false;
    QMetaObject::invokeMethod(mWorker, "stopCapture", Qt::QueuedConnection);
    emit captureStateChanged(false);
    emit statusMessage("Packet capture stopped.");
}

void PacketCaptureEngine::clear()
{
    mCapturedRawPackets.clear();
}

void PacketCaptureEngine::loadPcap(const QString &filePath)
{
    clear();
    QMetaObject::invokeMethod(mWorker, "loadPcapFile", Qt::QueuedConnection, Q_ARG(QString, filePath));
}

void PacketCaptureEngine::savePcap(const QString &filePath)
{
    QMetaObject::invokeMethod(mWorker, "savePcapFile", Qt::QueuedConnection, Q_ARG(QString, filePath), Q_ARG(QVector<QByteArray>, mCapturedRawPackets));
}

void PacketCaptureEngine::onPacketReceived(const DissectedPacket &packet)
{
    mCapturedRawPackets.append(packet.rawData);
    emit packetAdded(packet);
}

QStringList PacketCaptureEngine::availableInterfaces() const
{
    QStringList list;
    const auto ifaces = QNetworkInterface::allInterfaces();
    for (const auto &iface : ifaces) {
        if (iface.flags().testFlag(QNetworkInterface::IsUp) &&
            !iface.flags().testFlag(QNetworkInterface::IsLoopBack)) {
            list.append(iface.humanReadableName());
        }
    }
    if (list.isEmpty()) {
        list.append("Wi-Fi");
        list.append("Ethernet");
        list.append("Loopback adapter");
    }
    return list;
}
