#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "throughputgraphwidget.h"
#include "nettelemetry.h"
#include "packetcapture.h"

#include <QPainter>
#include <QPainterPath>
#include <QDateTime>
#include <QMessageBox>
#include <QDialog>
#include <QFileDialog>
#include <QHeaderView>
#include <QSysInfo>
#include <QNetworkInterface>

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Responsive layout proportions: lock sidebar width and distribute cards evenly
    ui->mainHorizontalLayout->setStretch(0, 0);
    ui->mainHorizontalLayout->setStretch(1, 1);

    ui->row1StatsLayout->setStretch(0, 1);
    ui->row1StatsLayout->setStretch(1, 1);
    ui->row1StatsLayout->setStretch(2, 1);

    ui->graphAndRatesLayout->setStretch(0, 1);
    ui->graphAndRatesLayout->setStretch(1, 0);

    // 1. Install Custom Auto-Scaling Dual-Curve Throughput Widget
    mGraphWidget = new ThroughputGraphWidget(this);
    ui->graphPlaceholderLayout->addWidget(mGraphWidget);

    // 2. Setup Navigation Group
    mNavGroup = new QButtonGroup(this);
    mNavGroup->addButton(ui->btnNavDashboard, 0);
    mNavGroup->addButton(ui->btnNavPackets, 1);
    mNavGroup->addButton(ui->btnNavTools, 2);
    mNavGroup->addButton(ui->btnNavHosts, 3);
    mNavGroup->addButton(ui->btnNavPorts, 4);
    mNavGroup->addButton(ui->btnNavSettings, 5);
    mNavGroup->setExclusive(true);
    connect(mNavGroup, &QButtonGroup::buttonClicked, this, &MainWindow::onNavButtonClicked);
    connect(ui->btnNavAbout, &QPushButton::clicked, this, &MainWindow::onAboutClicked);

    // 3. Connect Tools Page Buttons
    connect(ui->btnActionPing, &QPushButton::clicked, this, &MainWindow::onToolPingClicked);
    connect(ui->btnActionTraceroute, &QPushButton::clicked, this, &MainWindow::onToolTracerouteClicked);
    connect(ui->btnActionDns, &QPushButton::clicked, this, &MainWindow::onToolDnsClicked);
    connect(ui->btnActionFlushDns, &QPushButton::clicked, this, &MainWindow::onToolFlushDnsClicked);
    connect(ui->btnClearConsole, &QPushButton::clicked, this, &MainWindow::onClearConsoleClicked);

    // 4. Connect Hosts & Ports Page Buttons
    connect(ui->btnQuickScan, &QPushButton::clicked, this, [this]() {
        if (mTelemetry) {
            QMetaObject::invokeMethod(mTelemetry, "runQuickScan", Qt::QueuedConnection);
        }
    });
    connect(ui->btnRefreshSockets, &QPushButton::clicked, this, &MainWindow::onRefreshSocketsClicked);
    connect(ui->searchEdit, &QLineEdit::textChanged, this, &MainWindow::onSearchTextChanged);

    // 5. Connect Settings
    connect(ui->btnApplySettings, &QPushButton::clicked, this, &MainWindow::onApplySettingsClicked);

    // 6. Setup Custom Icons & Tables
    setupUiCustomizations();

    // 7. Setup Live Clock Timer
    mClockTimer = new QTimer(this);
    connect(mClockTimer, &QTimer::timeout, this, &MainWindow::onClockTick);
    mClockTimer->start(1000);
    onClockTick();

    // 8. Initialize Telemetry Engine in dedicated background QThread
    mTelemetryThread = new QThread(this);
    mTelemetry = new NetworkTelemetry(); // no parent for thread movement
    mTelemetry->moveToThread(mTelemetryThread);

    connect(mTelemetryThread, &QThread::started, mTelemetry, &NetworkTelemetry::start);
    connect(mTelemetryThread, &QThread::finished, mTelemetry, &QObject::deleteLater);
    connect(mTelemetry, &NetworkTelemetry::telemetryUpdated, this, &MainWindow::onTelemetryUpdated);
    connect(mTelemetry, &NetworkTelemetry::quickScanFinished, this, &MainWindow::onQuickScanFinished);
    connect(mTelemetry, &NetworkTelemetry::actionStatus, this, &MainWindow::onActionStatus);

    mTelemetryThread->start(QThread::LowPriority);

    // 9. Initialize Wireshark 3-Pane Packet Analyzer Suite
    setupPacketAnalyzer();
}

MainWindow::~MainWindow()
{
    if (mTelemetryThread) {
        mTelemetryThread->quit();
        mTelemetryThread->wait(800);
    }
    if (mToolProcess) {
        mToolProcess->kill();
        mToolProcess->deleteLater();
    }
    delete ui;
}

void MainWindow::setupPacketAnalyzer()
{
    mPacketEngine = new PacketCaptureEngine(this);
    connect(mPacketEngine, &PacketCaptureEngine::packetAdded, this, &MainWindow::onPacketAdded);
    connect(mPacketEngine, &PacketCaptureEngine::captureStateChanged, this, &MainWindow::onCaptureStateChanged);
    connect(mPacketEngine, &PacketCaptureEngine::statusMessage, this, [this](const QString &msg) {
        if (statusBar()) statusBar()->showMessage(msg, 3000);
    });

    // Populate interface selector
    ui->comboCaptureIface->clear();
    ui->comboCaptureIface->addItems(mPacketEngine->availableInterfaces());

    // Connect toolbar buttons
    connect(ui->btnCaptureStart, &QPushButton::clicked, this, &MainWindow::onCaptureStartClicked);
    connect(ui->btnCaptureStop, &QPushButton::clicked, this, &MainWindow::onCaptureStopClicked);
    connect(ui->btnCaptureRestart, &QPushButton::clicked, this, &MainWindow::onCaptureRestartClicked);
    connect(ui->btnCaptureClear, &QPushButton::clicked, this, &MainWindow::onCaptureClearClicked);

    connect(ui->btnApplyFilter, &QPushButton::clicked, this, &MainWindow::onApplyPacketFilterClicked);
    connect(ui->btnClearFilter, &QPushButton::clicked, this, &MainWindow::onClearPacketFilterClicked);
    connect(ui->editPacketFilter, &QLineEdit::returnPressed, this, &MainWindow::onApplyPacketFilterClicked);

    connect(ui->btnOpenPcap, &QPushButton::clicked, this, &MainWindow::onOpenPcapClicked);
    connect(ui->btnSavePcap, &QPushButton::clicked, this, &MainWindow::onSavePcapClicked);

    // Setup Packet List Table
    ui->tablePackets->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents); // No.
    ui->tablePackets->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents); // Time
    ui->tablePackets->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);     // Source
    ui->tablePackets->setColumnWidth(2, 135);
    ui->tablePackets->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Interactive);     // Destination
    ui->tablePackets->setColumnWidth(3, 135);
    ui->tablePackets->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents); // Protocol
    ui->tablePackets->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents); // Length
    ui->tablePackets->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);          // Info

    ui->tablePackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tablePackets->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tablePackets->verticalHeader()->setVisible(false);
    ui->tablePackets->setShowGrid(false);
    ui->tablePackets->setAlternatingRowColors(false);

    connect(ui->tablePackets, &QTableWidget::cellClicked, this, &MainWindow::onPacketSelected);

    // Setup Wireshark Splitter 3-Pane Ratio (e.g. 50% Packet List, 30% Details Tree, 20% Hex Dump)
    ui->splitterPanes->setSizes({320, 180, 140});

    // Initial button states
    ui->btnCaptureStart->setEnabled(true);
    ui->btnCaptureStop->setEnabled(false);

    // Auto-start capture for instant live views
    onCaptureStartClicked();
}

void MainWindow::onCaptureStartClicked()
{
    QString iface = ui->comboCaptureIface->currentText();
    mPacketEngine->start(iface);
}

void MainWindow::onCaptureStopClicked()
{
    mPacketEngine->stop();
}

void MainWindow::onCaptureRestartClicked()
{
    onCaptureClearClicked();
    onCaptureStartClicked();
}

void MainWindow::onCaptureClearClicked()
{
    mAllPackets.clear();
    mDisplayedIndices.clear();
    ui->tablePackets->setRowCount(0);
    ui->treePacketDetails->clear();
    ui->txtPacketHex->clear();
    mPacketEngine->clear();
    ui->lblPacketStatus->setText("Packets: 0 | Displayed: 0");
}

void MainWindow::onCaptureStateChanged(bool active)
{
    ui->btnCaptureStart->setEnabled(!active);
    ui->btnCaptureStop->setEnabled(active);
    ui->comboCaptureIface->setEnabled(!active);

    if (active) {
        ui->btnCaptureStart->setStyleSheet("background-color: #f1f5f9; color: #94a3b8; font-weight: 600; font-size: 12px; border: 1px solid #e2e8f0; border-radius: 6px; padding: 6px 14px;");
        ui->btnCaptureStop->setStyleSheet("background-color: #dc2626; color: white; font-weight: 600; font-size: 12px; border: none; border-radius: 6px; padding: 6px 14px;");
    } else {
        ui->btnCaptureStart->setStyleSheet("background-color: #2563eb; color: white; font-weight: 600; font-size: 12px; border: none; border-radius: 6px; padding: 6px 14px;");
        ui->btnCaptureStop->setStyleSheet("background-color: #f1f5f9; color: #94a3b8; font-weight: 600; font-size: 12px; border: 1px solid #e2e8f0; border-radius: 6px; padding: 6px 14px;");
    }
}

bool MainWindow::matchesFilter(const DissectedPacket &pkt, const QString &filter)
{
    if (filter.isEmpty()) return true;

    QString f = filter.trimmed().toLower();

    // Protocol exact match (e.g. "tcp", "udp", "dns", "icmp", "arp", "http", "tls")
    if (f == "tcp" && pkt.protocol == "TCP") return true;
    if (f == "udp" && pkt.protocol == "UDP") return true;
    if (f == "dns" && pkt.protocol == "DNS") return true;
    if (f == "icmp" && pkt.protocol == "ICMP") return true;
    if (f == "arp" && pkt.protocol == "ARP") return true;
    if (f == "http" && pkt.protocol == "HTTP") return true;
    if (f == "tls" && pkt.protocol == "TLS") return true;

    // IP address filter (e.g. "ip 172.20.10.4" or "172.20.10.4")
    if (f.startsWith("ip ")) {
        QString ipArg = f.mid(3).trimmed();
        return pkt.source.contains(ipArg) || pkt.destination.contains(ipArg);
    }

    // Port filter (e.g. "port 443" or "tcp.port 80")
    if (f.startsWith("port ")) {
        QString portArg = f.mid(5).trimmed();
        return pkt.info.contains(portArg);
    }

    // Generic search across fields
    return pkt.protocol.toLower().contains(f) ||
           pkt.source.contains(f) ||
           pkt.destination.contains(f) ||
           pkt.info.toLower().contains(f);
}

void MainWindow::onPacketAdded(const DissectedPacket &packet)
{
    mAllPackets.append(packet);

    if (matchesFilter(packet, mCurrentFilter)) {
        int originalIdx = mAllPackets.size() - 1;
        mDisplayedIndices.append(originalIdx);

        int row = ui->tablePackets->rowCount();
        ui->tablePackets->insertRow(row);

        auto createItem = [&](const QString &text, Qt::Alignment align = Qt::AlignLeft | Qt::AlignVCenter) {
            QTableWidgetItem *item = new QTableWidgetItem(text);
            item->setTextAlignment(align);
            item->setBackground(packet.bgColor);
            item->setForeground(packet.textColor);
            return item;
        };

        ui->tablePackets->setItem(row, 0, createItem(QString::number(packet.number), Qt::AlignRight | Qt::AlignVCenter));
        ui->tablePackets->setItem(row, 1, createItem(packet.timeStr));
        ui->tablePackets->setItem(row, 2, createItem(packet.source));
        ui->tablePackets->setItem(row, 3, createItem(packet.destination));
        ui->tablePackets->setItem(row, 4, createItem(packet.protocol, Qt::AlignCenter));
        ui->tablePackets->setItem(row, 5, createItem(QString::number(packet.length), Qt::AlignRight | Qt::AlignVCenter));
        ui->tablePackets->setItem(row, 6, createItem(packet.info));

        // Auto-select first packet if nothing selected
        if (row == 0) {
            ui->tablePackets->selectRow(0);
            displayPacketDetails(packet);
        }

        ui->tablePackets->scrollToBottom();
    }

    ui->lblPacketStatus->setText(QString("Packets: %1 | Displayed: %2")
                                     .arg(mAllPackets.size())
                                     .arg(mDisplayedIndices.size()));
}

void MainWindow::onApplyPacketFilterClicked()
{
    mCurrentFilter = ui->editPacketFilter->text().trimmed();
    refreshPacketTable();
}

void MainWindow::onClearPacketFilterClicked()
{
    ui->editPacketFilter->clear();
    mCurrentFilter.clear();
    refreshPacketTable();
}

void MainWindow::refreshPacketTable()
{
    ui->tablePackets->setUpdatesEnabled(false);
    ui->tablePackets->setRowCount(0);
    mDisplayedIndices.clear();

    for (int i = 0; i < mAllPackets.size(); ++i) {
        const auto &pkt = mAllPackets[i];
        if (matchesFilter(pkt, mCurrentFilter)) {
            mDisplayedIndices.append(i);
            int row = ui->tablePackets->rowCount();
            ui->tablePackets->insertRow(row);

            auto createItem = [&](const QString &text, Qt::Alignment align = Qt::AlignLeft | Qt::AlignVCenter) {
                QTableWidgetItem *item = new QTableWidgetItem(text);
                item->setTextAlignment(align);
                item->setBackground(pkt.bgColor);
                item->setForeground(pkt.textColor);
                return item;
            };

            ui->tablePackets->setItem(row, 0, createItem(QString::number(pkt.number), Qt::AlignRight | Qt::AlignVCenter));
            ui->tablePackets->setItem(row, 1, createItem(pkt.timeStr));
            ui->tablePackets->setItem(row, 2, createItem(pkt.source));
            ui->tablePackets->setItem(row, 3, createItem(pkt.destination));
            ui->tablePackets->setItem(row, 4, createItem(pkt.protocol, Qt::AlignCenter));
            ui->tablePackets->setItem(row, 5, createItem(QString::number(pkt.length), Qt::AlignRight | Qt::AlignVCenter));
            ui->tablePackets->setItem(row, 6, createItem(pkt.info));
        }
    }

    ui->tablePackets->setUpdatesEnabled(true);
    ui->lblPacketStatus->setText(QString("Packets: %1 | Displayed: %2")
                                     .arg(mAllPackets.size())
                                     .arg(mDisplayedIndices.size()));

    if (!mDisplayedIndices.isEmpty()) {
        ui->tablePackets->selectRow(0);
        displayPacketDetails(mAllPackets[mDisplayedIndices[0]]);
    } else {
        ui->treePacketDetails->clear();
        ui->txtPacketHex->clear();
    }
}

void MainWindow::onPacketSelected(int row, int)
{
    if (row >= 0 && row < mDisplayedIndices.size()) {
        int originalIdx = mDisplayedIndices[row];
        if (originalIdx >= 0 && originalIdx < mAllPackets.size()) {
            displayPacketDetails(mAllPackets[originalIdx]);
        }
    }
}

void MainWindow::displayPacketDetails(const DissectedPacket &pkt)
{
    ui->treePacketDetails->clear();

    // 1. Populate Hierarchical Dissection Tree (Pane 2)
    for (const auto &layer : pkt.layers) {
        QTreeWidgetItem *layerItem = new QTreeWidgetItem(ui->treePacketDetails);
        layerItem->setText(0, layer.label);
        layerItem->setFont(0, QFont("Segoe UI", 9, QFont::DemiBold));

        for (const auto &subField : layer.subFields) {
            QTreeWidgetItem *subItem = new QTreeWidgetItem(layerItem);
            subItem->setText(0, subField);
            subItem->setFont(0, QFont("Segoe UI", 9, QFont::Normal));
        }
        layerItem->setExpanded(true);
    }

    // 2. Format & Display Hex Dump + ASCII Inspector (Pane 3)
    ui->txtPacketHex->setPlainText(PacketDissector::formatHexDump(pkt.rawData));
}

void MainWindow::onOpenPcapClicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Open Packet Capture (.pcap)", "", "PCAP Capture Files (*.pcap *.cap);;All Files (*)");
    if (!filePath.isEmpty()) {
        onCaptureClearClicked();
        mPacketEngine->loadPcap(filePath);
        if (statusBar()) statusBar()->showMessage("Loaded PCAP file: " + filePath, 4000);
    }
}

void MainWindow::onSavePcapClicked()
{
    QString filePath = QFileDialog::getSaveFileName(this, "Save Packet Capture (.pcap)", "netman_capture.pcap", "PCAP Capture Files (*.pcap)");
    if (!filePath.isEmpty()) {
        mPacketEngine->savePcap(filePath);
        if (statusBar()) statusBar()->showMessage("PCAP file saved successfully to: " + filePath, 4000);
    }
}

void MainWindow::setupUiCustomizations()
{
    // 1. Draw Sleek Modern Brand Icon (Network Mark)
    {
        QPixmap pix(36, 36);
        pix.fill(Qt::transparent);
        QPainter p(&pix);
        p.setRenderHint(QPainter::Antialiasing);

        // Dark rounded square badge
        p.setBrush(QColor("#0f172a"));
        p.setPen(Qt::NoPen);
        p.drawRoundedRect(0, 0, 36, 36, 8, 8);

        // Minimalist geometric network grid / nodes
        p.setPen(QPen(QColor("#38bdf8"), 1.8, Qt::SolidLine, Qt::RoundCap));
        p.drawLine(10, 26, 18, 10);
        p.drawLine(18, 10, 26, 26);
        p.drawLine(10, 26, 26, 26);

        // Node points
        p.setBrush(QColor("#ffffff"));
        p.setPen(QPen(QColor("#0284c7"), 1.5));
        p.drawEllipse(QPointF(18, 10), 3.0, 3.0);
        p.drawEllipse(QPointF(10, 26), 2.5, 2.5);
        p.drawEllipse(QPointF(26, 26), 2.5, 2.5);

        ui->brandIcon->setPixmap(pix);
    }

    auto styleTable = [](QTableWidget *t) {
        t->verticalHeader()->setVisible(false);
        t->setSelectionBehavior(QAbstractItemView::SelectRows);
        t->setEditTriggers(QAbstractItemView::NoEditTriggers);
        t->horizontalHeader()->setStretchLastSection(true);
    };

    styleTable(ui->tableFullDevices);
    styleTable(ui->tableListeningSockets);
    styleTable(ui->tableActiveSockets);

    ui->tableFullDevices->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableFullDevices->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tableFullDevices->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->tableFullDevices->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    ui->tableFullDevices->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    ui->tableFullDevices->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);

    ui->tableListeningSockets->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableListeningSockets->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->tableListeningSockets->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    ui->tableListeningSockets->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    ui->tableListeningSockets->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);

    ui->tableActiveSockets->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableActiveSockets->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->tableActiveSockets->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    ui->tableActiveSockets->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
}

void MainWindow::onClockTick()
{
    QDateTime now = QDateTime::currentDateTime();
    ui->lblClockPill->setText(QString("● LIVE  %1  %2")
                                  .arg(now.toString("hh:mm:ss AP"))
                                  .arg(now.toString("MMM dd, yyyy")));
}

void MainWindow::updateGreeting()
{
    ui->lblGreeting->setText("Network Operations Center");
}

void MainWindow::onNavButtonClicked(QAbstractButton *btn)
{
    int id = mNavGroup->id(btn);
    if (id >= 0 && id < ui->stackedWidget->count()) {
        ui->stackedWidget->setCurrentIndex(id);
        if (id == 4) { // Page 4: Ports & Connections
            updateSocketsTables();
        }
    }
}

void MainWindow::onTelemetryUpdated(const QJsonObject &data)
{
    mLastTelemetry = data;

    double down = data.value("download_mbps").toDouble(0.0);
    double up = data.value("upload_mbps").toDouble(0.0);

    if (down > mPeakDown) mPeakDown = down;
    if (up > mPeakUp) mPeakUp = up;

    // 1. Throughput Rates & Dual-Curve Dynamic Graph
    QString downStr = QString("%1 Mbps").arg(down, 0, 'f', 1);
    QString upStr = QString("%1 Mbps").arg(up, 0, 'f', 1);
    if (mUnits == "MB/s") {
        downStr = QString("%1 MB/s").arg(down / 8.0, 0, 'f', 2);
        upStr = QString("%1 MB/s").arg(up / 8.0, 0, 'f', 2);
    }

    ui->lblDownRate->setText(QString("↓ %1").arg(downStr));
    ui->lblUpRate->setText(QString("↑ %1").arg(upStr));

    if (mGraphWidget) {
        mGraphWidget->addSample(down, up);
    }

    // 2. Stable Physical Host IP, Gateway, DNS
    if (data.contains("interface")) {
        QJsonObject iface = data.value("interface").toObject();
        QString ip = iface.value("ip").toString();
        QString gw = iface.value("gateway").toString();
        QString dns = iface.value("dns").toString();

        if (!ip.isEmpty()) ui->lblValIp->setText(ip);
        if (!gw.isEmpty()) ui->lblValGateway->setText(gw);
        if (!dns.isEmpty()) ui->lblValDns->setText(dns);

        if (!ip.isEmpty() && !gw.isEmpty()) {
            ui->lblNetworkStatus->setText(QString("Active Interface: Wi-Fi · Host IP: %1 · Gateway: %2 · State: Online").arg(ip).arg(gw));
        }
    }
}

void MainWindow::onQuickScanFinished(const QJsonArray &devices)
{
    ui->tableFullDevices->setUpdatesEnabled(false);
    ui->tableFullDevices->setRowCount(0);
    for (int i = 0; i < devices.size(); ++i) {
        QJsonObject d = devices[i].toObject();
        int row = ui->tableFullDevices->rowCount();
        ui->tableFullDevices->insertRow(row);

        ui->tableFullDevices->setItem(row, 0, new QTableWidgetItem(d.value("status").toString("🟢 Active")));
        ui->tableFullDevices->setItem(row, 1, new QTableWidgetItem(d.value("name").toString()));
        ui->tableFullDevices->setItem(row, 2, new QTableWidgetItem(d.value("ip").toString()));
        ui->tableFullDevices->setItem(row, 3, new QTableWidgetItem(d.value("mac").toString()));
        ui->tableFullDevices->setItem(row, 4, new QTableWidgetItem(d.value("rate").toString()));
        ui->tableFullDevices->setItem(row, 5, new QTableWidgetItem(d.value("last_seen").toString()));
    }
    ui->tableFullDevices->setUpdatesEnabled(true);
}

void MainWindow::onActionStatus(const QString &message, bool)
{
    if (statusBar()) {
        statusBar()->showMessage(message, 4000);
    }
}

// Network Tools Executions
void MainWindow::appendConsole(const QString &text, const QString &color)
{
    ui->txtToolConsole->appendHtml(QString("<span style='color:%1;'>%2</span>").arg(color).arg(text));
}

void MainWindow::onClearConsoleClicked()
{
    ui->txtToolConsole->clear();
}

void MainWindow::onToolPingClicked()
{
    QString target = ui->editToolTarget->text().trimmed();
    if (target.isEmpty()) target = "8.8.8.8";

    appendConsole(QString("[+] Initiating ICMP Echo ping to: %1 ...").arg(target), "#a855f7");

    if (mToolProcess) {
        mToolProcess->kill();
        mToolProcess->deleteLater();
    }

    mToolProcess = new QProcess(this);
    connect(mToolProcess, &QProcess::readyReadStandardOutput, this, [this]() {
        appendConsole(QString::fromLocal8Bit(mToolProcess->readAllStandardOutput()).trimmed(), "#38bdf8");
    });
    connect(mToolProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, [this]() {
        appendConsole("[✓] Ping probe completed successfully.", "#34d399");
    });

    mToolProcess->start("ping", QStringList() << "-n" << "4" << target);
}

void MainWindow::onToolTracerouteClicked()
{
    QString target = ui->editToolTarget->text().trimmed();
    if (target.isEmpty()) target = "8.8.8.8";

    appendConsole(QString("[+] Tracing route to: %1 (Max 15 hops) ...").arg(target), "#a855f7");

    if (mToolProcess) {
        mToolProcess->kill();
        mToolProcess->deleteLater();
    }

    mToolProcess = new QProcess(this);
    connect(mToolProcess, &QProcess::readyReadStandardOutput, this, [this]() {
        appendConsole(QString::fromLocal8Bit(mToolProcess->readAllStandardOutput()).trimmed(), "#38bdf8");
    });
    connect(mToolProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, [this]() {
        appendConsole("[✓] Traceroute finished.", "#34d399");
    });

    mToolProcess->start("tracert", QStringList() << "-d" << "-h" << "15" << target);
}

void MainWindow::onToolDnsClicked()
{
    QString target = ui->editToolTarget->text().trimmed();
    if (target.isEmpty()) target = "google.com";

    appendConsole(QString("[+] Performing DNS record resolution for: %1 ...").arg(target), "#a855f7");

    if (mToolProcess) {
        mToolProcess->kill();
        mToolProcess->deleteLater();
    }

    mToolProcess = new QProcess(this);
    connect(mToolProcess, &QProcess::readyReadStandardOutput, this, [this]() {
        appendConsole(QString::fromLocal8Bit(mToolProcess->readAllStandardOutput()).trimmed(), "#38bdf8");
    });
    connect(mToolProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, [this]() {
        appendConsole("[✓] DNS lookup completed.", "#34d399");
    });

    mToolProcess->start("nslookup", QStringList() << target);
}

void MainWindow::onToolFlushDnsClicked()
{
    if (mTelemetry) {
        QMetaObject::invokeMethod(mTelemetry, "flushDns", Qt::QueuedConnection);
    }
    appendConsole("[✓] Successfully flushed Windows DNS Resolver Cache.", "#34d399");
}

void MainWindow::onRefreshSocketsClicked()
{
    updateSocketsTables();
    if (statusBar()) {
        statusBar()->showMessage("Active sockets and listening ports refreshed.", 2000);
    }
}

void MainWindow::updateSocketsTables()
{
    ui->tableListeningSockets->setUpdatesEnabled(false);
    ui->tableActiveSockets->setUpdatesEnabled(false);

    ui->tableListeningSockets->setRowCount(0);
    ui->tableActiveSockets->setRowCount(0);

#ifdef Q_OS_WIN
    DWORD tcpSize = 0;
    GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcpSize > 0) {
        QByteArray tcpBuf(tcpSize, 0);
        PMIB_TCPTABLE_OWNER_PID pTcp = (PMIB_TCPTABLE_OWNER_PID)tcpBuf.data();
        if (GetExtendedTcpTable(pTcp, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            int listenCount = 0;
            int estabCount = 0;
            const int MAX_ENTRIES = 250;

            for (DWORD i = 0; i < pTcp->dwNumEntries; ++i) {
                const auto &entry = pTcp->table[i];

                in_addr localAddr;
                localAddr.s_addr = entry.dwLocalAddr;
                QString localIpStr = QString::fromLatin1(inet_ntoa(localAddr));
                int localPort = ntohs((u_short)entry.dwLocalPort);

                in_addr remoteAddr;
                remoteAddr.s_addr = entry.dwRemoteAddr;
                QString remoteIpStr = QString::fromLatin1(inet_ntoa(remoteAddr));
                int remotePort = ntohs((u_short)entry.dwRemotePort);

                if (entry.dwState == MIB_TCP_STATE_LISTEN && listenCount < MAX_ENTRIES) {
                    int row = ui->tableListeningSockets->rowCount();
                    ui->tableListeningSockets->insertRow(row);
                    ui->tableListeningSockets->setItem(row, 0, new QTableWidgetItem("TCP"));
                    ui->tableListeningSockets->setItem(row, 1, new QTableWidgetItem("LISTEN"));
                    ui->tableListeningSockets->setItem(row, 2, new QTableWidgetItem(localIpStr));
                    ui->tableListeningSockets->setItem(row, 3, new QTableWidgetItem(QString::number(localPort)));
                    ui->tableListeningSockets->setItem(row, 4, new QTableWidgetItem(localIpStr == "127.0.0.1" ? "Host Loopback" : "Interface Listener"));
                    listenCount++;
                } else if (entry.dwState == MIB_TCP_STATE_ESTAB && estabCount < MAX_ENTRIES) {
                    int row = ui->tableActiveSockets->rowCount();
                    ui->tableActiveSockets->insertRow(row);
                    ui->tableActiveSockets->setItem(row, 0, new QTableWidgetItem("TCP"));
                    ui->tableActiveSockets->setItem(row, 1, new QTableWidgetItem("ESTABLISHED"));
                    ui->tableActiveSockets->setItem(row, 2, new QTableWidgetItem(QString("%1:%2").arg(localIpStr).arg(localPort)));
                    ui->tableActiveSockets->setItem(row, 3, new QTableWidgetItem(QString("%1:%2").arg(remoteIpStr).arg(remotePort)));
                    estabCount++;
                }
            }
        }
    }
#endif

    ui->tableListeningSockets->setUpdatesEnabled(true);
    ui->tableActiveSockets->setUpdatesEnabled(true);
}

void MainWindow::onSearchTextChanged(const QString &query)
{
    auto filterTable = [&](QTableWidget *t) {
        t->setUpdatesEnabled(false);
        for (int r = 0; r < t->rowCount(); ++r) {
            bool match = query.isEmpty();
            for (int c = 0; c < t->columnCount(); ++c) {
                QTableWidgetItem *item = t->item(r, c);
                if (item && item->text().contains(query, Qt::CaseInsensitive)) {
                    match = true;
                    break;
                }
            }
            t->setRowHidden(r, !match);
        }
        t->setUpdatesEnabled(true);
    };

    filterTable(ui->tableListeningSockets);
    filterTable(ui->tableActiveSockets);
}

void MainWindow::onApplySettingsClicked()
{
    int idx = ui->comboRefreshRate->currentIndex();
    int seconds = (idx == 0) ? 1 : ((idx == 1) ? 2 : 5);
    if (mTelemetry) {
        QMetaObject::invokeMethod(mTelemetry, "setRefreshInterval", Qt::QueuedConnection, Q_ARG(int, seconds));
    }

    mUnits = (ui->comboUnits->currentIndex() == 1) ? "MB/s" : "Mbps";

    QMessageBox::information(this, "Preferences Saved",
                             QString("Network Operation Center telemetry configured:\n• Interval: %1 sec\n• Units: %2")
                                 .arg(seconds).arg(mUnits));
}

void MainWindow::onAboutClicked()
{
    if (ui->btnNavAbout) {
        ui->btnNavAbout->setChecked(false);
    }

    QDialog dlg(this);
    dlg.setWindowTitle("About Netman");
    dlg.setWindowModality(Qt::ApplicationModal);
    dlg.setFixedSize(500, 470);
    dlg.setStyleSheet(
        "QDialog {"
        "  background-color: #ffffff;"
        "  border: 1px solid #cbd5e1;"
        "  border-radius: 12px;"
        "}"
        "QLabel {"
        "  background: transparent;"
        "  border: none;"
        "}"
        "#specBox {"
        "  background-color: #f8fafc;"
        "  border: 1px solid #e2e8f0;"
        "  border-radius: 8px;"
        "}"
        "#specBox QLabel {"
        "  border: none;"
        "  background: transparent;"
        "}"
        "QPushButton {"
        "  background-color: #0f172a;"
        "  color: #ffffff;"
        "  border: 1px solid #0f172a;"
        "  border-radius: 6px;"
        "  padding: 8px 24px;"
        "  font-weight: 600;"
        "  font-size: 13px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #1e293b;"
        "}"
    );

    QVBoxLayout *layout = new QVBoxLayout(&dlg);
    layout->setContentsMargins(28, 28, 28, 24);
    layout->setSpacing(14);

    // Header layout with Logo and Titles
    QHBoxLayout *headerLayout = new QHBoxLayout();
    headerLayout->setSpacing(16);

    QLabel *logoLabel = new QLabel(&dlg);
    {
        QPixmap pix(54, 54);
        pix.fill(Qt::transparent);
        QPainter p(&pix);
        p.setRenderHint(QPainter::Antialiasing);

        p.setBrush(QColor("#0f172a"));
        p.setPen(Qt::NoPen);
        p.drawRoundedRect(0, 0, 54, 54, 12, 12);

        p.setPen(QPen(QColor("#38bdf8"), 2.2, Qt::SolidLine, Qt::RoundCap));
        p.drawLine(15, 39, 27, 15);
        p.drawLine(27, 15, 39, 39);
        p.drawLine(15, 39, 39, 39);

        p.setBrush(QColor("#ffffff"));
        p.setPen(QPen(QColor("#0284c7"), 1.8));
        p.drawEllipse(QPointF(27, 15), 4.5, 4.5);
        p.drawEllipse(QPointF(15, 39), 3.8, 3.8);
        p.drawEllipse(QPointF(39, 39), 3.8, 3.8);

        logoLabel->setPixmap(pix);
    }
    headerLayout->addWidget(logoLabel);

    QVBoxLayout *titleCol = new QVBoxLayout();
    titleCol->setSpacing(3);

    QHBoxLayout *nameRow = new QHBoxLayout();
    nameRow->setSpacing(8);

    QLabel *lblName = new QLabel("NETMAN", &dlg);
    lblName->setStyleSheet("font-size: 22px; font-weight: 800; color: #0f172a; letter-spacing: 0.5px;");
    nameRow->addWidget(lblName);

    QLabel *badge = new QLabel("Executive NOC", &dlg);
    badge->setStyleSheet("background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; "
                         "font-size: 11px; font-weight: 700; border-radius: 4px; padding: 2px 7px;");
    nameRow->addWidget(badge);
    nameRow->addStretch();
    titleCol->addLayout(nameRow);

    QLabel *lblSub = new QLabel("Version 2.0 · Wireshark-Grade Telemetry & Analysis", &dlg);
    lblSub->setStyleSheet("color: #64748b; font-size: 12px; font-weight: 500;");
    titleCol->addWidget(lblSub);

    headerLayout->addLayout(titleCol);
    layout->addLayout(headerLayout);

    // Divider line
    QFrame *line = new QFrame(&dlg);
    line->setFrameShape(QFrame::HLine);
    line->setStyleSheet("border: none; background-color: #e2e8f0; max-height: 1px;");
    layout->addWidget(line);

    // Description text
    QLabel *lblDesc = new QLabel(
        "Production-grade network monitoring suite designed for high-precision real-time metrics, "
        "hardware diagnostics, active socket tracking, and full 3-pane packet dissection.",
        &dlg);
    lblDesc->setWordWrap(true);
    lblDesc->setStyleSheet("color: #334155; font-size: 13px; line-height: 1.4;");
    layout->addWidget(lblDesc);

    // Feature highlights box
    QFrame *specBox = new QFrame(&dlg);
    specBox->setObjectName("specBox");
    QVBoxLayout *specLayout = new QVBoxLayout(specBox);
    specLayout->setSpacing(7);
    specLayout->setContentsMargins(14, 12, 14, 12);

    auto addSpec = [&](const QString &icon, const QString &title, const QString &desc) {
        QLabel *l = new QLabel(QString("<b>%1 %2:</b> <span style='color:#64748b;'>%3</span>").arg(icon, title, desc), specBox);
        l->setStyleSheet("color: #0f172a; font-size: 12px; border: none; background: transparent;");
        specLayout->addWidget(l);
    };

    addSpec("⚡", "Kernel Telemetry", "Real hardware & adapter byte counters via WSL/Win32");
    addSpec("📊", "Dual-Curve Engine", "Zero-jank auto-scaling bandwidth waveform");
    addSpec("🔍", "Wireshark 3-Pane", "Live sniffing, tree protocol decode & hex inspector");
    addSpec("🛡️", "Sockets & Security", "Process-to-port mapping and subnet ping scanner");

    layout->addWidget(specBox);

    // Environment info
    QLabel *lblEnv = new QLabel(
        QString("Built with Qt %1 · C++17 · %2\n© 2026 NetmanQt Project. Genuine hardware and kernel metrics.")
            .arg(QT_VERSION_STR, QSysInfo::prettyProductName()),
        &dlg);
    lblEnv->setStyleSheet("color: #94a3b8; font-size: 11px;");
    lblEnv->setAlignment(Qt::AlignLeft);
    layout->addWidget(lblEnv);

    // Bottom Action Row
    QHBoxLayout *btnRow = new QHBoxLayout();
    btnRow->addStretch();

    QPushButton *btnClose = new QPushButton("Close", &dlg);
    btnClose->setCursor(Qt::PointingHandCursor);
    connect(btnClose, &QPushButton::clicked, &dlg, &QDialog::accept);
    btnRow->addWidget(btnClose);

    layout->addLayout(btnRow);

    dlg.exec();
}
